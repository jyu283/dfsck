#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/genalloc.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/moduleparam.h>
#include <linux/refcount.h>
#include <linux/dirent.h>
#include <linux/falloc.h>
#include <linux/interval_tree.h>
#include <linux/bitops.h>
#include <linux/bit_spinlock.h>
#include <linux/statfs.h>
#include <linux/anon_inodes.h>
#include <linux/stat.h>

#include <linux/icache-pack.h>
#include <linux/densefs.h>

#define DFS_META_ALLOCORDER 5
#define DFS_META_ALLOCUNIT (1ULL << DFS_META_ALLOCORDER)
#define DFS_DATA_ALLOCORDER 12
#define DFS_DATA_ALLOCUNIT (1ULL << DFS_DATA_ALLOCORDER)

static struct kmem_cache* filecache;

/* large enough for NUL-terminated "." and ".." */
#define DFS_DENTRY_INLINE_LEN 3

struct dfs_dentry {
	struct hlist_node list;
	struct dfs_inode* inode;
	struct kref refs;
	uint8_t namelen; /* not incl. NUL terminator */
	char name[DFS_DENTRY_INLINE_LEN];
};

/*
 * Each of these points to one or more contiguous DFS_DATA_ALLOCUNIT-byte
 * units containing file data at a DFS_DATA_ALLOCUNIT-aligned offset within
 * the file.
 */
struct dfs_datachunk {
	struct interval_tree_node it;
	bool initialized;
	void* data;
};

// Offset of start of interval of dfs data chunk
static inline off_t chunk_off(const struct dfs_datachunk* dc)
{
	return dc->it.start;
}

// Length of dfs data chunk
static inline off_t chunk_len(const struct dfs_datachunk* dc)
{
	return dc->it.last - dc->it.start + 1;
}

struct imeta {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

typedef uint16_t metaidx_t;

#define LMS_METAIDX_POS 47

/* sub-fields on __lock_metaidx_size */
#define LMS_LOCKBIT 63
#define LMS_METAIDX_MASK GENMASK(LMS_LOCKBIT - 1, LMS_METAIDX_POS)
#define LMS_SIZE_MASK GENMASK(LMS_METAIDX_POS - 1, 0)

#define DFS_TIMESTAMP_BYTES 5
#define DFS_TIMESTAMP_BITS (8 * DFS_TIMESTAMP_BYTES)
#define DFS_TIMESTAMP_NS_SHIFT 21
typedef struct {
	uint32_t __low;
	uint8_t __high;
} __packed dfstime_t;

struct dfs_inode {
	uint16_t nlink;
	dfstime_t mtime, ctime;
	refcount_t pincount;
	unsigned long __lock_metaidx_size;

	union {
		struct hlist_head dirents; // Root of h-list (if directory)
		struct rb_root chunks; // Root of red-black tree (if regular file)
	} data;

	/* Only used for directories ("." and ".." entries) */
	struct dfs_dentry dot_dents[];
};

/* Indices into dfs_inode.data.dot_dents */
#define DENT_SELF 0 /* "." */
#define DENT_PARENT 1 /* ".." */

#ifdef CONFIG_DENSEFS_ENABLE_CHECKS
#define DFS_CHECK(x) BUG_ON(!(x))
#else
#define DFS_CHECK(x) do { } while (0)
#endif

struct dfs_fs {
	struct dfs_dentry rootdir; // Root directory
	void* mem; // Pointer to beginning of file system memory region
	size_t size; // Size of file system memory region
	struct gen_pool data_pool;
	struct gen_pool meta_pool;
//#ifdef CONFIG_DENSEFS_NEXTFIT
	//unsigned long meta_ptr;
	//unsigned long data_ptr;
//#endif
	/*
	 * Secret used to avoid leaking raw kernel addresses (or offsets) to
	 * userspace. TODO: initialize this with appropriate entropy at
	 * "mkfs"-time.
	 */
	unsigned long ino_key;

	struct {
		struct imeta* arr;
		metaidx_t num;
		/*
		 * This could of course be done better with an rwlock or rcu
		 * (and allocation in larger chunks to reduce the frequency of
		 * reallocations/pointer-updates), but for now a plain
		 * spinlock will suffice...
		 */
#ifdef CONFIG_DENSEFS_FGLOCK
		spinlock_t lock;
#endif
	} imeta;

#ifdef CONFIG_DENSEFS_FGLOCK
	spinlock_t data_alloc_lock;
	spinlock_t meta_alloc_lock;
	spinlock_t rename_lock;
#else
	spinlock_t lock;
#endif
};

static inline void lock_dfs(struct dfs_fs* d)
{
#ifndef CONFIG_DENSEFS_FGLOCK
	spin_lock(&d->lock);
#endif
}

static inline void unlock_dfs(struct dfs_fs* d)
{
#ifndef CONFIG_DENSEFS_FGLOCK
	spin_unlock(&d->lock);
#endif
}

static inline void dfs_meta_alloc_lock(struct dfs_fs* d)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	spin_lock(&d->meta_alloc_lock);
#endif
}

static inline void dfs_meta_alloc_unlock(struct dfs_fs* d)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	spin_unlock(&d->meta_alloc_lock);
#endif
}

static inline void dfs_data_alloc_lock(struct dfs_fs* d)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	spin_lock(&d->data_alloc_lock);
#endif
}

static inline void dfs_data_alloc_unlock(struct dfs_fs* d)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	spin_unlock(&d->data_alloc_lock);
#endif
}

static inline void dfs_imeta_lock(struct dfs_fs* d)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	spin_lock(&d->imeta.lock);
#endif
}

static inline void dfs_imeta_unlock(struct dfs_fs* d)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	spin_unlock(&d->imeta.lock);
#endif
}

static inline void dfs_lock_inode(struct dfs_inode* inode)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	bit_spin_lock(LMS_LOCKBIT, &inode->__lock_metaidx_size);
#endif
}

static inline void dfs_unlock_inode(struct dfs_inode* inode)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	bit_spin_unlock(LMS_LOCKBIT, &inode->__lock_metaidx_size);
#endif
}

static inline off_t dfs_inode_get_size(const struct dfs_inode* inode)
{
	return inode->__lock_metaidx_size & LMS_SIZE_MASK;
}

static inline void dfs_inode_set_size(struct dfs_inode* inode, off_t newsz)
{
	unsigned long newbits = newsz & LMS_SIZE_MASK;
	set_mask_bits(&inode->__lock_metaidx_size, LMS_SIZE_MASK, newbits);
}

static inline void dfs_inode_size_add(struct dfs_inode* inode, off_t delta)
{
	dfs_inode_set_size(inode, dfs_inode_get_size(inode) + delta);
}

static inline void dfs_inode_size_sub(struct dfs_inode* inode, off_t delta)
{
	dfs_inode_size_add(inode, -delta);
}

static inline metaidx_t dfs_inode_get_meta_idx(const struct dfs_inode* inode)
{
	return (inode->__lock_metaidx_size & LMS_METAIDX_MASK) >> LMS_METAIDX_POS;
}

static inline void dfs_inode_set_meta_idx(struct dfs_inode* inode, metaidx_t newidx)
{
	unsigned long newbits = ((unsigned long)newidx << LMS_METAIDX_POS) & LMS_METAIDX_MASK;
	set_mask_bits(&inode->__lock_metaidx_size, LMS_METAIDX_MASK, newbits);
}

static inline u64 dfstime_to_ns(dfstime_t dt)
{
	BUILD_BUG_ON(sizeof(dfstime_t) != DFS_TIMESTAMP_BYTES);
	return ((u64)dt.__low | ((u64)dt.__high << 32)) << DFS_TIMESTAMP_NS_SHIFT;
}

static inline dfstime_t ns_to_dfstime(u64 ns)
{
	dfstime_t dt;
	u64 stored = ns >> DFS_TIMESTAMP_NS_SHIFT;
	DFS_CHECK(stored < (1ULL << DFS_TIMESTAMP_BITS));
	dt.__low = stored & 0xffffffff;
	dt.__high = (stored >> 32) & 0xff;
	return dt;
}

static inline dfstime_t timespec_to_dfstime(struct timespec ts)
{
	return ns_to_dfstime(timespec_to_ns(&ts));
}

static inline struct timespec dfstime_to_timespec(dfstime_t dt)
{
	return ns_to_timespec(dfstime_to_ns(dt));
}

static struct dfs_fs* dfs;

static inline void* dfs_meta_alloc(size_t s)
{
	void* p;

	dfs_meta_alloc_lock(dfs);
	p = (void*)gen_pool_alloc(&dfs->meta_pool, s);
	dfs_meta_alloc_unlock(dfs);

	return p;
}

static inline void dfs_meta_free(void* p, size_t s)
{
	dfs_meta_alloc_lock(dfs);
	gen_pool_free(&dfs->meta_pool, (unsigned long)p, s);
	dfs_meta_alloc_unlock(dfs);
}

static inline void* dfs_data_alloc(size_t s)
{
	void* p;

	dfs_data_alloc_lock(dfs);
	p = (void*)gen_pool_alloc(&dfs->data_pool, s);
	dfs_data_alloc_unlock(dfs);

	return p;
}

static inline void dfs_data_free(void* p, size_t s)
{
	dfs_data_alloc_lock(dfs);
	gen_pool_free(&dfs->data_pool, (unsigned long)p, s);
	dfs_data_alloc_unlock(dfs);
}

static inline struct dfs_datachunk* dfs_new_datachunk(off_t off, off_t len)
{
	off_t allocbase = round_down(off, DFS_DATA_ALLOCUNIT);
	off_t allocsize = round_up(len + (off - allocbase), DFS_DATA_ALLOCUNIT);
	struct dfs_datachunk* dc = dfs_meta_alloc(sizeof(*dc));

	if (dc) {
		dc->data = dfs_data_alloc(allocsize);
		if (!dc->data) {
			dfs_meta_free(dc, sizeof(*dc));
			dc = NULL;
		} else {
			dc->it.start = allocbase;
			dc->it.last = allocbase + allocsize - 1;
			dc->initialized = false;
		}
	}
	return dc;
}

static inline void dfs_free_datachunk(struct dfs_datachunk* dc)
{
	dfs_data_free(dc->data, chunk_len(dc));
	dfs_meta_free(dc, sizeof(*dc));
}

/*
 * Callback types for iter_inode_range().  If they return non-zero the
 * iteration is terminated and iter_inode_range() returns that value.  If they
 * make any modifications to the inode's chunk tree they must set *modified to
 * true (otherwise they must leave it untouched).
 */
typedef int (*iter_hole_cb)(struct dfs_inode* inode, off_t start, off_t len,
                            void* arg, bool* modified);
typedef int (*iter_chunk_cb)(struct dfs_inode* inode, struct dfs_datachunk* dc,
                            void* arg, bool* modified);

static int iter_inode_range(struct dfs_inode* inode, off_t start, off_t len, void* arg,
                            iter_hole_cb on_hole, iter_chunk_cb on_chunk)
{
	bool reset_iter;
	struct interval_tree_node* it;
	struct interval_tree_node* next;
	struct dfs_datachunk* dc;
	off_t pos = start, end = start + len - 1;
	int status = 0;

reset:
	it = interval_tree_iter_first(&inode->data.chunks, pos, end);
	while (it) {
		next = interval_tree_iter_next(it, it->last + 1, end);
		dc = container_of(it, struct dfs_datachunk, it);

		reset_iter = false;

		if (it->start > pos && on_hole) {
			status = on_hole(inode, pos, it->start - pos, arg, &reset_iter);
			if (status)
				return status;
		}

		if (on_chunk) {
			status = on_chunk(inode, dc, arg, &reset_iter);
			if (status)
				return status;
		}

		pos = it->last + 1;

		if (reset_iter)
			goto reset;

		it = next;
	}

	if (end >= pos && on_hole)
		status = on_hole(inode, pos, end - pos + 1, arg, &reset_iter);

	return status;
}

static inline size_t dfs_dentry_size_for_len(size_t namelen)
{
	size_t extra;
	if ((namelen + 1) <= DFS_DENTRY_INLINE_LEN)
		extra = 0;
	else
		extra = namelen + 1 - DFS_DENTRY_INLINE_LEN;
	return sizeof(struct dfs_dentry) + extra;
}

static inline size_t dfs_dentry_size(const struct dfs_dentry* dent)
{
	return dfs_dentry_size_for_len(dent->namelen);
}

__icache_aligned
static int free_chunk_fn(struct dfs_inode* inode, struct dfs_datachunk* dc,
                         void* arg, bool* modified)
{
	interval_tree_remove(&dc->it, &inode->data.chunks);
	*modified = true;
	dfs_free_datachunk(dc);
	return 0;
}

static struct dfs_dentry* dir_lookup(struct dfs_inode* dir, const char* name);
static void dfs_dec_nlink(struct dfs_inode* inode);

#define TOUCH_CTIME (1 << 0)
#define TOUCH_MTIME (1 << 1)
#define TOUCH_ATIME (1 << 2)

static void touch_inode(struct dfs_inode* inode, int flags)
{
	dfstime_t now = timespec_to_dfstime(current_kernel_time());

	if (flags & TOUCH_CTIME)
		inode->ctime = now;
	if (flags & (TOUCH_MTIME|TOUCH_ATIME))
		inode->mtime = now;
}

static void dfs_free_dentry(struct dfs_dentry* dent)
{
	dfs_meta_free(dent, dfs_dentry_size(dent));
}

static void dfs_release_dentry(struct kref* kr)
{
	struct dfs_dentry* dent = container_of(kr, struct dfs_dentry, refs);

	dfs_dec_nlink(dent->inode);
	dfs_free_dentry(dent);
}

static inline void grab_dentry(struct dfs_dentry* dent)
{
	kref_get(&dent->refs);
}

static inline void drop_dentry(struct dfs_dentry* dent)
{
	kref_put(&dent->refs, dfs_release_dentry);
}

static inline void read_imeta(metaidx_t idx, kuid_t* uid, kgid_t* gid, umode_t* mode)
{
	struct imeta* p;
	dfs_imeta_lock(dfs);
	DFS_CHECK(idx < dfs->imeta.num);
	p = &dfs->imeta.arr[idx];
	if (uid)
		*uid = p->uid;
	if (gid)
		*gid = p->gid;
	if (mode)
		*mode = p->mode;
	dfs_imeta_unlock(dfs);
}

static inline umode_t inode_mode(const struct dfs_inode* inode)
{
	umode_t mode;
	read_imeta(dfs_inode_get_meta_idx(inode), NULL, NULL, &mode);
	return mode;
}

static inline bool isdir(const struct dfs_inode* inode)
{
	return S_ISDIR(inode_mode(inode));
}

/* outward-facing version of the above */
bool dfs_isdir(const struct dfs_inode* inode)
{
	return isdir(inode);
}

/*
 * HACK: this races against things adding to (and hence
 * reallocating/replacing) the imeta array...I'm ~90% confident this could be
 * done with comparably low read-side overhead with RCU, I just haven't
 * implemented it at the moment (because I'm lazy).
 */
static inline bool __racy_isdir(const struct dfs_inode* inode)
{
	return S_ISDIR(dfs->imeta.arr[dfs_inode_get_meta_idx(inode)].mode);
}

static inline bool isreg(const struct dfs_inode* inode)
{
	return S_ISREG(inode_mode(inode));
}

__icache_aligned
static void free_inode(struct dfs_inode* inode)
{
	size_t size = sizeof(*inode);
	if (isdir(inode))
		size += 2 * sizeof(struct dfs_dentry);
	dfs_meta_free(inode, size);
}

__icache_aligned
static void __dfs_kill_inode(struct dfs_inode* inode)
{
	struct dfs_dentry* dent;
	struct hlist_node* tmp;
	struct dfs_dentry* parent;
	if (isdir(inode)) {
		if (inode != dfs->rootdir.inode) {
			parent = dir_lookup(inode, "..");
			DFS_CHECK(parent);
			DFS_CHECK(parent->inode->nlink > 1);
			dfs_dec_nlink(parent->inode);
			drop_dentry(parent);
		}
		hlist_for_each_entry_safe (dent, tmp, &inode->data.dirents, list) {
			hlist_del(&dent->list);
			dfs_inode_size_sub(inode, dfs_dentry_size(dent));
			dfs_free_dentry(dent);
		}
	} else if (isreg(inode) && !RB_EMPTY_ROOT(&inode->data.chunks))
		iter_inode_range(inode, 0, dfs_inode_get_size(inode), NULL, NULL,
		                 free_chunk_fn);

	free_inode(inode);
}

static bool inode_disconnected(struct dfs_inode* inode)
{
	return unlikely(!inode->nlink) || unlikely(isdir(inode) && inode->nlink <= 1);
}

static void dfs_inc_nlink(struct dfs_inode* inode)
{
	inode->nlink += 1;
	touch_inode(inode, TOUCH_CTIME);
}

__icache_aligned
static void dfs_dec_nlink(struct dfs_inode* inode)
{
	inode->nlink -= 1;
	if (inode_disconnected(inode) && !refcount_read(&inode->pincount))
		__dfs_kill_inode(inode);
	else
		touch_inode(inode, TOUCH_CTIME);
}

void dfs_pin_inode(struct dfs_inode* inode)
{
	refcount_inc(&inode->pincount);
}

void dfs_unpin_inode(struct dfs_inode* inode)
{
	if (refcount_dec_and_test(&inode->pincount)
	    && unlikely(inode_disconnected(inode)))
		__dfs_kill_inode(inode);
}

static void dfs_release_file(struct kref* kr)
{
	struct dfs_file* file = container_of(kr, struct dfs_file, count);

	dfs_unpin_inode(file->inode);

	kmem_cache_free(filecache, file);
}

void dfs_get_file(struct dfs_file* f)
{
	kref_get(&f->count);
}

void dfs_put_file(struct dfs_file* f)
{
	kref_put(&f->count, dfs_release_file);
}

__icache_aligned
static void init_dentry(struct dfs_dentry* dent, const char* name, struct dfs_inode* inode)
{
	INIT_HLIST_NODE(&dent->list);
	dent->inode = inode;
	dfs_inc_nlink(inode);
	kref_init(&dent->refs);
	dent->namelen = strlen(name);
	strcpy(dent->name, name);
}

static struct dfs_dentry* new_dentry(const char* name, struct dfs_inode* inode)
{
	size_t namelen = strlen(name);
	struct dfs_dentry* dent = dfs_meta_alloc(dfs_dentry_size_for_len(namelen));

	BUILD_BUG_ON(sizeof(struct dfs_dentry) != 32);

	if (!dent)
		return NULL;
	init_dentry(dent, name, inode);
	return dent;
}

static metaidx_t find_imeta_idx(umode_t mode, kuid_t uid, kgid_t gid)
{
	struct imeta* p;
	struct imeta* new;
	metaidx_t idx;

	dfs_imeta_lock(dfs);

	for (p = dfs->imeta.arr; p < dfs->imeta.arr + dfs->imeta.num; p++) {
		if (p->mode == mode && uid_eq(p->uid, uid) && gid_eq(p->gid, gid)) {
			idx = p - dfs->imeta.arr;
			goto out;
		}
	}

	new = dfs_meta_alloc((dfs->imeta.num + 1) * sizeof(*new));
	/*
	 * Obviously this is crap, but proper handling would complicate the
	 * API in ways I don't want to deal with right now.
	 */
	if (!new)
		panic("ENOSPC during attempt to update imeta array");

	memcpy(new, dfs->imeta.arr, dfs->imeta.num * sizeof(*new));
	idx = dfs->imeta.num++;
	p = &new[idx];
	p->uid = uid;
	p->gid = gid;
	p->mode = mode;

	dfs_meta_free(dfs->imeta.arr, idx * sizeof(*new));
	dfs->imeta.arr = new;

out:
	dfs_imeta_unlock(dfs);
	return idx;
}

#define ROOT_PARENT_SELF ((struct dfs_inode*)1UL)

#define DFS_EMPTYDIR_SIZE (dfs_dentry_size_for_len(strlen(".")) \
                           + dfs_dentry_size_for_len(strlen("..")))

__icache_aligned
static struct dfs_inode* create_inode(umode_t mode, struct dfs_inode* dir_parent)
{
	struct dfs_inode* inode;
	size_t alloc_size = sizeof(*inode);

	if (S_ISDIR(mode))
		alloc_size += 2 * sizeof(struct dfs_dentry); // Allocate directory entries for . and ..

	inode = dfs_meta_alloc(alloc_size);
	if (!inode)
		return NULL;

	/* initialize lock (unlocked) and size (zero) */
	inode->__lock_metaidx_size = 0;
	dfs_inode_set_meta_idx(inode, find_imeta_idx(mode, GLOBAL_ROOT_UID,
	                                             GLOBAL_ROOT_GID)); /* FIXME: current->{uid,gid} */

	inode->nlink = 0;

	if (S_ISDIR(mode)) { // Directory
		INIT_HLIST_HEAD(&inode->data.dirents);
		init_dentry(&inode->dot_dents[DENT_SELF], ".", inode);
		init_dentry(&inode->dot_dents[DENT_PARENT], "..",
		            dir_parent == ROOT_PARENT_SELF ? inode : dir_parent); // Root parent is self, else parent
		dfs_inode_set_size(inode, DFS_EMPTYDIR_SIZE);
	} else if (S_ISREG(mode)) // Regular file?
		inode->data.chunks = RB_ROOT;
	else
		panic("invalid mode in init_inode()");
	touch_inode(inode, TOUCH_ATIME|TOUCH_MTIME|TOUCH_CTIME); // Update timestamps

	refcount_set(&inode->pincount, 1);

	return inode;
}

static int dfs_create_root(void)
{
	struct dfs_inode* ri;

	ri = create_inode(S_IFDIR | 01777, ROOT_PARENT_SELF);
	if (!ri)
		return -ENOMEM;

	dfs_unpin_inode(ri);

	dfs->rootdir.inode = ri;
	dfs->rootdir.namelen = 0;
	dfs->rootdir.name[0] = '\0';

	return 0;
}

static int mount_dfs(size_t size)
{
	int ret;
	void* mem;
	size_t sbsize, metasize, datasize;

	if (dfs) {
		ret = -EEXIST;
		goto out;
	}

	/*
	 * Semi-arbitrary minimum size (4M), just so we've got a reasonable
	 * amount of space to fit the "superblock" struct in before the
	 * metadata & data partitions...
	 */
	if (size < (1ULL << 22)) {
		ret = -EINVAL;
		goto out;
	}

	mem = vmalloc(size);
	if (!mem) {
		ret = -ENOMEM;
		goto out;
	}

	/* Scribble it to catch use-before-init problems */
	memset(mem, 0x3c, size); // <

	dfs = mem;
	dfs->mem = mem;
	dfs->size = size;

#ifdef CONFIG_DENSEFS_FGLOCK
	spin_lock_init(&dfs->data_alloc_lock);
	spin_lock_init(&dfs->meta_alloc_lock);
	spin_lock_init(&dfs->rename_lock);
	spin_lock_init(&dfs->imeta.lock);
#else
	spin_lock_init(&dfs->lock);
#endif

	sbsize = round_up(sizeof(*dfs), 4096);
	metasize = size >> 4; /* reserve ~6% for metadata */
	datasize = size - (metasize + sbsize); /* rest is data */

	gen_pool_init(&dfs->meta_pool, DFS_META_ALLOCORDER); // 5
	gen_pool_init(&dfs->data_pool, DFS_DATA_ALLOCORDER); // 12
/*#ifdef CONFIG_DENSEFS_NEXTFIT
	gen_pool_set_algo(&dfs->meta_pool, gen_pool_next_fit, &dfs->meta_ptr);
	gen_pool_set_algo(&dfs->data_pool, gen_pool_next_fit, &dfs->data_ptr);
#endif*/

	ret = gen_pool_add_internal(&dfs->meta_pool, (unsigned long)dfs->mem + sbsize, metasize, -1);
	if (ret)
		goto out_free_mem;

	ret = gen_pool_add_internal(&dfs->data_pool, (unsigned long)dfs->mem + sbsize + metasize,
	                            datasize, -1);
	if (ret)
		goto out_destroy_meta_pool;

	dfs->imeta.num = 3;
	dfs->imeta.arr = dfs_meta_alloc(dfs->imeta.num * sizeof(*dfs->imeta.arr));
	if (!dfs->imeta.arr) {
		ret = -ENOSPC;
		goto out_destroy_data_pool;
	}
	dfs->imeta.arr[0] = (struct imeta){ .mode = S_IFDIR|01777,
	                                    .uid = GLOBAL_ROOT_UID,
	                                    .gid = GLOBAL_ROOT_GID, };
	dfs->imeta.arr[1] = (struct imeta){ .mode = S_IFDIR|00755,
	                                    .uid = GLOBAL_ROOT_UID,
	                                    .gid = GLOBAL_ROOT_GID, };
	dfs->imeta.arr[2] = (struct imeta){ .mode = S_IFREG|00644,
	                                    .uid = GLOBAL_ROOT_UID,
	                                    .gid = GLOBAL_ROOT_GID, };

	ret = dfs_create_root();
	if (ret)
		goto out_free_imeta;
	else
		goto out;

out_free_imeta:
	dfs_meta_free(dfs->imeta.arr, dfs->imeta.num * sizeof(*dfs->imeta.arr));
out_destroy_data_pool:
	__gen_pool_rmchunks(&dfs->data_pool, false);
out_destroy_meta_pool:
	__gen_pool_rmchunks(&dfs->meta_pool, false);
out_free_mem:
	vfree(dfs->mem);
	dfs = NULL;
out:
	return ret;
}

SYSCALL_DEFINE1(dfs_mount, size_t, size)
{
	return mount_dfs(size);
}

/*
 * Returning from a macro is weird, but this is going to be in (basically)
 * every syscall.
 */
#define CHECK_MOUNTED \
	do { \
		if (!dfs) \
			return -ENODEV; \
	} while (0)

SYSCALL_DEFINE0(dfs_umount)
{
	/* FIXME: need some sort of global external lock to serialize this properly... */

	CHECK_MOUNTED;

	vfree(dfs->mem);
	dfs = NULL;

	return 0;
}

struct dfs_inode* dfs_get_root_inode(void)
{
	return dfs ? dfs->rootdir.inode : NULL;
}

struct dfs_pathbuf {
	bool in_use;
	char buf[PATH_MAX];
};
#define NUM_PATHBUFS 8
static struct dfs_pathbuf pathbufs[NUM_PATHBUFS];

static inline bool try_get_pathbuf(struct dfs_pathbuf* pb)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	return pb->in_use ? false : cmpxchg(&pb->in_use, false, true) == false;
#else
	if (pb->in_use)
		return false;
	else {
		pb->in_use = true;
		return true;
	}
#endif
}

static inline char* copy_user_path(const char __user* p)
{
	int i, len;
	struct dfs_pathbuf* pb = NULL;

	for (i = 0; i < NUM_PATHBUFS; i++) {
		if (try_get_pathbuf(&pathbufs[i])) {
			pb = &pathbufs[i];
			break;
		}
	}

	if (unlikely(!pb))
		return ERR_PTR(-ENOMEM);

	len = strncpy_from_user(pb->buf, p, sizeof(pb->buf));
	if (unlikely(len < 0)) {
		pb->in_use = false;
		return ERR_PTR(len);
	}
	return pb->buf;
}

static inline void free_copied_path(char* p)
{
	char (*bufptr)[PATH_MAX] = (char (*)[PATH_MAX])p;
	struct dfs_pathbuf* pb = container_of(bufptr, struct dfs_pathbuf, buf);
	pb->in_use = false;
}

static const char* skip_slashes(const char* s)
{
	while (*s == '/')
		s++;
	return s;
}

static int get_path_component(const char* path, const char** tail, char* name)
{
	int i;
	const char* next;

	/* Advance to first slash or end */
	for (i = 0; path[i] && path[i] != '/' && i < NAME_MAX; i++)
		name[i] = path[i];

	if (i == NAME_MAX)
		return -EINVAL;

	name[i] = '\0';

	if (path[i]) {
		next = skip_slashes(&path[i]);
		if (*next)
			*tail = next;
		else
			*tail = NULL;
	} else
		*tail = NULL;

	return 0;
}

/* Caller must hold lock on dir */
__icache_aligned
static struct dfs_dentry* dir_lookup(struct dfs_inode* dir, const char* name)
{
	struct dfs_dentry* dent;

	DFS_CHECK(isdir(dir));

	if (!strcmp(name, ".")) {
		dent = &dir->dot_dents[DENT_SELF];
		grab_dentry(dent);
		return dent;
	}

	if (!strcmp(name, "..")) {
		dent = &dir->dot_dents[DENT_PARENT];
		grab_dentry(dent);
		return dent;
	}

	hlist_for_each_entry (dent, &dir->data.dirents, list) {
		if (!strcmp(dent->name, name)) {
			grab_dentry(dent);
			return dent;
		}
	}

	return NULL;
}

/* Caller holds lock on dir */
static struct dfs_dentry* dfs_lookup_step(struct dfs_inode* dir, const char* name)
{
	struct dfs_dentry* found;

	if (unlikely(!isdir(dir)))
		return ERR_PTR(-ENOTDIR);

	found = dir_lookup(dir, name);

	return found ? found : ERR_PTR(-ENOENT);
}

/*
 * Out-params (optional, if not NULL):
 *  - dentp: dentry pointing to returned inode (with an additional ref)
 *  - pdirp: inode of parent directory (container of dentp; with an additional ref)
 *  - lastp: substring of 'path' (its final component)
 *
 * Return value: the looked-up inode (with additional ref) on success, ERR_PTR
 * otherwise.  In the case of ENOENT on the final path component, *parent will
 * be set to the parent directory; otherwise (e.g. on ENOENT or ENOTDIR on an
 * intermediate component) it will be set to NULL.
 */
static struct dfs_inode* dfs_lookup(struct dfs_inode* start, const char* path,
                                    struct dfs_dentry** dentp,
                                    struct dfs_inode** pdirp, char* lastbuf)
{
	char name[NAME_MAX+1];
	const char* rest;
	struct dfs_dentry* dent;
	struct dfs_inode* previ;
	struct dfs_inode* curi = start;

	/*
	 * Callers shouldn't be trying to use the dentry without also using
	 * the parent directory.
	 */
	if (dentp)
		DFS_CHECK(pdirp);

	rest = skip_slashes(path);

	if (pdirp)
		*pdirp = NULL;
	if (dentp)
		*dentp = NULL;
	if (lastbuf)
		*lastbuf = '\0';

	/*
	 * This reference will be dropped by the last iteration of the loop
	 * (each iteration assumes curi was pinned by the last one, so this
	 * preps us for the first iteration).
	 */
	dfs_pin_inode(curi);

	while (rest && *rest) {
		if (get_path_component(rest, &rest, name)) {
			curi = ERR_PTR(-EINVAL);
			break;
		}

		dfs_lock_inode(curi);
		dent = dfs_lookup_step(curi, name);
		dfs_unlock_inode(curi);

		previ = curi;

		if (IS_ERR(dent))
			curi = ERR_CAST(dent);
		else {
			curi = dent->inode;
			dfs_pin_inode(curi);
		}

		if (!rest || !*rest) {
			if (!IS_ERR(dent) || PTR_ERR(dent) == -ENOENT) {
				if (pdirp)
					*pdirp = previ;
				else
					dfs_unpin_inode(previ);

				if (lastbuf)
					strcpy(lastbuf, name);
			} else
				dfs_unpin_inode(previ);

			if (!IS_ERR(dent)) {
				if (dentp)
					*dentp = dent;
				else
					drop_dentry(dent);
			}

			break;
		} else if (!IS_ERR(dent))
			drop_dentry(dent);

		dfs_unpin_inode(previ);

		if (IS_ERR(curi))
			break;
	}

	return curi;
}

/* For external use */
struct dfs_inode* dfs_lookup_path(struct dfs_inode* start, const char* path)
{
	return dfs_lookup(start, path, NULL, NULL, NULL);
}

__icache_aligned
static struct dfs_inode* lookup_path(struct dfs_inode* start, const char* path, struct dfs_dentry** dent,
                                     struct dfs_inode** parent, char* lastbuf)
{
	return dfs_lookup(start ? start : dfs->rootdir.inode, path, dent, parent, lastbuf);
}

static bool dfs_dir_empty(const struct dfs_inode* dir)
{
	DFS_CHECK(isdir(dir));

	if (dir->nlink != 2 || !hlist_empty(&dir->data.dirents)) {
		DFS_CHECK(dfs_inode_get_size(dir) > DFS_EMPTYDIR_SIZE);
		return false;
	} else {
		DFS_CHECK(dfs_inode_get_size(dir) == DFS_EMPTYDIR_SIZE);
		return true;
	}
}

__icache_aligned
static struct dfs_dentry* add_dirent(struct dfs_inode* dir, const char* name,
                                     struct dfs_inode* inode)
{
	struct dfs_dentry* newent = new_dentry(name, inode);

	DFS_CHECK(isdir(dir));

	if (!newent)
		return ERR_PTR(-ENOMEM);

	hlist_add_head(&newent->list, &dir->data.dirents);
	dfs_inode_size_add(dir, dfs_dentry_size(newent));

	touch_inode(dir, TOUCH_MTIME|TOUCH_CTIME);

	return newent;
}

/* Caller must hold lock on dir */
__icache_aligned
static int dfs_remove_dent(struct dfs_inode* dir, const char* name)
{
	struct dfs_dentry* dent;

	dent = dir_lookup(dir, name);
	if (!dent)
		return -ENOENT;

	hlist_del(&dent->list);
	dfs_inode_size_sub(dir, dfs_dentry_size(dent));

	/* One to balance dir_lookup(), one for the actual removal. */
	drop_dentry(dent);
	drop_dentry(dent);

	touch_inode(dir, TOUCH_MTIME|TOUCH_CTIME);

	return 0;
}

/*
 * Caller must hold dfs->lock.  The newly-created dentry->inode will have a
 * pincount of 1 on successful return.
 */
static struct dfs_dentry* do_mknodat(struct dfs_inode* dir, const char* path, mode_t mode,
                                     struct dfs_inode** pinode)
{
	char name[NAME_MAX+1];
	struct dfs_inode* parent;
	struct dfs_inode* inode;
	struct dfs_dentry* dent;

	inode = lookup_path(dir, path, NULL, &parent, name);
	if (unlikely(!IS_ERR(inode))) {
		dent = ERR_PTR(-EEXIST);
		goto out;
	} else if (unlikely(PTR_ERR(inode) != -ENOENT || !parent)) {
		dent = ERR_CAST(inode);
		goto out;
	}

	inode = create_inode(mode, S_ISDIR(mode) ? parent : NULL);
	if (!inode) {
		dent = ERR_PTR(-ENOMEM);
		goto out_unpin_parent;
	}

	dent = add_dirent(parent, name, inode);
	if (IS_ERR(dent))
		goto out_free_inode;

	if (pinode) {
		/* Grab an extra ref for the caller */
		dfs_pin_inode(parent);
		*pinode = parent;
	}

	goto out_unpin_parent;

out_free_inode:
	free_inode(inode);
out_unpin_parent:
	if (parent)
		dfs_unpin_inode(parent);
out:
	return dent;
}

struct dfs_file* dfs_openat(struct dfs_inode* start, const char* path, int flags, mode_t mode)
{
	struct dfs_file* file;
	struct dfs_dentry* dent;
	struct dfs_inode* inode;
	int cx = flags & (O_CREAT | O_EXCL);

	lock_dfs(dfs);

	if (cx == (O_CREAT | O_EXCL)) {
		dent = do_mknodat(start, path, S_IFREG | (mode & 0777), NULL);
		inode = IS_ERR(dent) ? ERR_CAST(dent) : dent->inode;
	} else
		inode = lookup_path(start, path, NULL, NULL, NULL);

	if (IS_ERR(inode)) {
		if (PTR_ERR(inode) == -ENOENT && cx == O_CREAT) {
			dent = do_mknodat(start, path, S_IFREG | (mode & 0777), NULL);
			inode = IS_ERR(dent) ? ERR_CAST(dent) : dent->inode;
		}
		if (IS_ERR(inode)) {
			file = ERR_CAST(inode);
			goto out;
		}
	}

	file = kmem_cache_alloc(filecache, GFP_KERNEL);
	if (!file) {
		file = ERR_PTR(-ENOMEM);
		goto out_unpin;
	}

	kref_init(&file->count);
	file->offset = 0;
	file->inode = inode;

	goto out;

out_unpin:
	dfs_unpin_inode(inode);
out:
	unlock_dfs(dfs);
	return file;
}

int dfs_close(struct dfs_file* file)
{
	CHECK_MOUNTED;

	lock_dfs(dfs);

	/* Balance dfs_open(). */
	dfs_put_file(file);

	unlock_dfs(dfs);
	return 0;
}

static inline ino_t inum(const struct dfs_inode* inode)
{
	unsigned long off = (unsigned long)inode - (unsigned long)dfs->mem;
	return (ino_t)(off ^ dfs->ino_key);
}

static void inode_to_kstat(const struct dfs_inode* inode, struct kstat* st)
{
	st->dev = 0;
	st->ino = inum(inode);
	st->nlink = inode->nlink;
	read_imeta(dfs_inode_get_meta_idx(inode), &st->uid, &st->gid,
	           &st->mode);
	st->rdev = 0;
	st->size = dfs_inode_get_size(inode);
	st->blksize = DFS_DATA_ALLOCUNIT;
	st->blocks = DIV_ROUND_UP(dfs_inode_get_size(inode), st->blksize);

	st->atime = st->mtime = dfstime_to_timespec(inode->mtime);
	st->ctime = dfstime_to_timespec(inode->ctime);

	st->result_mask = STATX_BASIC_STATS;
	st->attributes_mask = 0;
}

int dfs_stat(struct dfs_inode* start, const char* path, struct kstat* st)
{
	int ret;
	struct dfs_inode* inode;

	CHECK_MOUNTED;

	lock_dfs(dfs);

	if (!path) {
		inode = start;
		dfs_pin_inode(inode);
	} else {
		inode = lookup_path(start, path, NULL, NULL, NULL);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out;
		}
	}

	inode_to_kstat(inode, st);

	ret = 0;

	dfs_unpin_inode(inode);
out:
	return ret;
}

struct read_cb_params {
	/* Input */
	void __user* buf;
	off_t offset;
	size_t len;

	/* Output */
	ssize_t transferred;
};

static int read_chunk_fn(struct dfs_inode* inode, struct dfs_datachunk* dc,
                         void* arg, bool* modified)
{
	int status;
	void __user* dst;
	const void* src;
	off_t startoff, endoff;
	size_t nbytes;
	struct read_cb_params* params = arg;

	if (chunk_off(dc) >= params->offset) {
		dst = params->buf + (chunk_off(dc) - params->offset);
		src = dc->data;
	} else {
		dst = params->buf;
		src = dc->data + (params->offset - chunk_off(dc));
	}

	startoff = max(chunk_off(dc), params->offset);
	endoff = min(min(dfs_inode_get_size(inode), chunk_off(dc) + chunk_len(dc)),
	             (off_t)(params->offset + params->len));
	nbytes = (endoff >= startoff) ? (endoff - startoff) : 0;

	if (dc->initialized)
		status = copy_to_user(dst, src, nbytes);
	else
		status = clear_user(dst, nbytes);

	if (!status)
		params->transferred += nbytes;
	return status;
}

static int read_hole_fn(struct dfs_inode* inode, off_t start, off_t len,
                        void* arg, bool* modified)
{
	int status;
	void __user* dst;
	off_t startoff, endoff;
	size_t nbytes;
	struct read_cb_params* params = arg;

	if (start >= params->offset)
		dst = params->buf + (start - params->offset);
	else
		dst = params->buf;

	startoff = max(start, params->offset);
	endoff = min(min(dfs_inode_get_size(inode), start + len),
	             (off_t)(params->offset + params->len));
	nbytes = (endoff >= startoff) ? (endoff - startoff) : 0;

	status = clear_user(dst, nbytes);
	if (!status)
		params->transferred += nbytes;
	return status;
}

static ssize_t dfs_inode_read(struct dfs_inode* inode, off_t off,
                              void __user* buf, size_t count)
{
	int status;
	struct read_cb_params params = {
		.buf = buf,
		.len = count,
		.offset = off,
		.transferred = 0,
	};

	DFS_CHECK(isreg(inode));

	status = iter_inode_range(inode, off, count, &params,
	                          read_hole_fn, read_chunk_fn);
	return params.transferred ? params.transferred : status;
}

/* off == -1 means use and update offset of fd */
static ssize_t do_dfs_read(struct dfs_file* file, void __user* buf, size_t count, off_t off)
{
	ssize_t ret;
	struct dfs_inode* inode = file->inode;

	if (!isreg(inode)) {
		ret = -EINVAL;
		goto out;
	}

	ret = dfs_inode_read(inode, off == -1 ? file->offset : off, buf, count);
	if (ret > 0 && off == -1)
		file->offset += ret;

out:
	return ret;
}

ssize_t dfs_read(struct dfs_file* file, void __user* buf, size_t count)
{
	ssize_t ret;

	CHECK_MOUNTED;

	lock_dfs(dfs);

	ret = do_dfs_read(file, buf, count, -1);

	unlock_dfs(dfs);
	return ret;
}

struct write_cb_params {
	/* Input */
	const void __user* buf;
	off_t offset;
	size_t len;

	/* Output */
	ssize_t transferred;
};

static int write_chunk_fn(struct dfs_inode* inode, struct dfs_datachunk* dc,
                          void* arg, bool* modified)
{
	int status;
	void* dst;
	const void __user* src;
	size_t nbytes;
	off_t end;
	size_t prebytes, postbytes;
	struct write_cb_params* params = arg;

	if (chunk_off(dc) >= params->offset) {
		src = params->buf + (chunk_off(dc) - params->offset);
		dst = dc->data;
	} else {
		src = params->buf;
		dst = dc->data + (params->offset - chunk_off(dc));
	}

	nbytes = min(chunk_len(dc) - (dst - (void*)dc->data),
	             (off_t)(params->len - (src - params->buf)));

	status = copy_from_user(dst, src, nbytes);
	if (!status) {
		params->transferred += nbytes;
		end = chunk_off(dc) + (dst - (void*)dc->data) + nbytes;
		if (end > dfs_inode_get_size(inode))
			dfs_inode_set_size(inode, end);

		if (!dc->initialized) {
			prebytes = dst - (void*)dc->data;
			if (prebytes)
				memset(dc->data, 0, prebytes);
			postbytes = chunk_len(dc) - (prebytes + nbytes);
			if (postbytes)
				memset(dst + nbytes, 0, postbytes);
			dc->initialized = true;
		}
	}

	return status;
}

static int write_hole_fn(struct dfs_inode* inode, off_t start, off_t len,
                         void* arg, bool* modified)
{
	struct dfs_datachunk* dc;

	dc = dfs_new_datachunk(start, len);
	if (!dc)
		return -ENOSPC;

	interval_tree_insert(&dc->it, &inode->data.chunks);
	*modified = true;

	return write_chunk_fn(inode, dc, arg, NULL);
}

static ssize_t dfs_inode_write(struct dfs_inode* inode, off_t off,
                               const void __user* buf, size_t count)
{
	int status;
	struct write_cb_params params = {
		.buf = buf,
		.len = count,
		.offset = off,
		.transferred = 0,
	};

	DFS_CHECK(isreg(inode));

	status = iter_inode_range(inode, off, count, &params,
	                          write_hole_fn, write_chunk_fn);

	if (!params.transferred)
		return status;
	else {
		touch_inode(inode, TOUCH_MTIME|TOUCH_CTIME);
		return params.transferred;
	}
}

ssize_t dfs_write(struct dfs_file* file, const void __user* buf, size_t count)
{
	ssize_t ret;
	struct dfs_inode* inode = file->inode;

	CHECK_MOUNTED;

	lock_dfs(dfs);

	if (!isreg(inode)) {
		ret = -EINVAL;
		goto out;
	}

	ret = dfs_inode_write(inode, file->offset, buf, count);

	if (ret > 0)
		file->offset += ret;

out:
	unlock_dfs(dfs);
	return ret;
}

int dfs_mkdirat(struct dfs_inode* start, const char* path, mode_t mode)
{
	int ret;
	struct dfs_dentry* dent;
	struct dfs_inode* inode;

	lock_dfs(dfs);

	dent = do_mknodat(start, path, S_IFDIR | (mode & 0777), NULL);
	if (IS_ERR(dent)) {
		ret = PTR_ERR(dent);
		goto out;
	}

	inode = dent->inode;

	dfs_unpin_inode(inode);
	ret = 0;

out:
	unlock_dfs(dfs);
	return ret;
}

int dfs_unlink(struct dfs_inode* start, const char* path, int flags)
{
	int ret;
	struct dfs_dentry* dent;
	struct dfs_inode* inode;
	struct dfs_inode* parent = NULL;
	int rmdir = flags & AT_REMOVEDIR;

	if (flags & ~AT_REMOVEDIR)
		return -EINVAL;

	lock_dfs(dfs);

	inode = lookup_path(start, path, &dent, &parent, NULL);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	} else if (!dent) {
		ret = -EBUSY;
		goto out;
	}

	if (rmdir) {
		if (!isdir(inode)) {
			ret = -ENOTDIR;
			goto out_release;
		} else if (!dfs_dir_empty(inode)) {
			ret = -ENOTEMPTY;
			goto out_release;
		}
	} else {
		if (isdir(inode)) {
			ret = -EISDIR;
			goto out_release;
		}
	}

	dfs_lock_inode(parent);
	ret = dfs_remove_dent(parent, dent->name);
	dfs_unlock_inode(parent);

out_release:
	dfs_unpin_inode(parent);
	drop_dentry(dent);
	dfs_unpin_inode(inode);
out:
	unlock_dfs(dfs);
	return ret;
}

int dfs_linkat(struct dfs_inode* ostart, const char* oldpath,
                     struct dfs_inode* nstart, const char* newpath)
{
	int ret;
	char newname[NAME_MAX+1];
	struct dfs_dentry* newdent;
	struct dfs_inode* existing;
	struct dfs_inode* inode;
	struct dfs_inode* newpdir = NULL;

	lock_dfs(dfs);

	inode = lookup_path(ostart, oldpath, NULL, NULL, NULL);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto out;
	}

	existing = lookup_path(nstart, newpath, NULL, &newpdir, newname);
	if (!IS_ERR(existing) || PTR_ERR(existing) != -ENOENT || !newpdir) {
		if (!newpdir && IS_ERR(existing))
			ret = PTR_ERR(existing);
		else if (!IS_ERR(existing) && newpdir)
			ret = -EEXIST;
		else
			panic("something unexpected happened in link dest lookup");
		goto out_unpin;
	}

	dfs_lock_inode(newpdir);
	newdent = add_dirent(newpdir, newname, inode);
	dfs_unlock_inode(newpdir);

	ret = IS_ERR(newdent) ? PTR_ERR(newdent) : 0;

out_unpin:
	if (newpdir)
		dfs_unpin_inode(newpdir);
	if (!IS_ERR(existing))
		dfs_unpin_inode(existing);
	dfs_unpin_inode(inode);
out:
	unlock_dfs(dfs);
	return ret;
}

static int fallocate_hole_fn(struct dfs_inode* inode, off_t start, off_t len,
                             void* arg, bool* modified)
{
	struct dfs_datachunk* dc = dfs_new_datachunk(start, len);
	if (!dc)
		return -ENOSPC;
	interval_tree_insert(&dc->it, &inode->data.chunks);
	*modified = true;
	return 0;
}

int dfs_fallocate(struct dfs_file* file, int mode, off_t offset, off_t len)
{
	int ret, flags;
	struct dfs_inode* inode;

	CHECK_MOUNTED;

	if (mode != 0 && mode != FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	lock_dfs(dfs);

	inode = file->inode;

	if (!isreg(inode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = iter_inode_range(inode, offset, len, NULL, fallocate_hole_fn, NULL);
	if (ret)
		goto out;

	flags = TOUCH_CTIME;
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		dfs_inode_set_size(inode, max(dfs_inode_get_size(inode), offset + len));
		flags |= TOUCH_MTIME;
	}
	touch_inode(inode, flags);

out:
	unlock_dfs(dfs);
	return ret;
}

/* Shamelessly copied from fs/readdir.c... */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

static int read_dent(struct dfs_dentry* dent, int off, struct linux_dirent __user* udent,
                     struct linux_dirent __user* dirp, unsigned int count)
{
	struct linux_dirent tmpdent;
	char d_type = __racy_isdir(dent->inode) ? DT_DIR : DT_REG; /* FIXME if other types added */

	tmpdent.d_ino = inum(dent->inode);
	tmpdent.d_reclen = offsetof(struct linux_dirent, d_name) + dent->namelen + 2;
	tmpdent.d_off = off + tmpdent.d_reclen;

	if ((char __user*)udent + tmpdent.d_reclen >= (char __user*)dirp + count)
		return 0;

	if (copy_to_user(udent, &tmpdent, sizeof(tmpdent))
	    || copy_to_user(udent->d_name, dent->name, dent->namelen)
	    || put_user('\0', &udent->d_name[dent->namelen])
	    || put_user(d_type, &udent->d_name[dent->namelen+1]))
		return -EFAULT;

	return tmpdent.d_reclen;
}

int dfs_getdents(struct dfs_file* file, struct linux_dirent __user* dirp,
                 unsigned int count)
{
	int ret, tmp;
	struct dfs_inode* inode;
	struct dfs_dentry* dent;
	struct linux_dirent __user* udent;
	off_t offdelta = 0;

	CHECK_MOUNTED;

	inode = file->inode;
	if (!isdir(inode)) {
		ret = -ENOTDIR;
		goto out;
	}

	if (file->offset > 0) {
		if (file->offset >= dfs_inode_get_size(inode))
			ret = 0;
		else /* Punt. */
			ret = -EOPNOTSUPP;
		goto out;
	}

	udent = dirp;
	ret = 0;

	tmp = read_dent(&inode->dot_dents[DENT_SELF], ret, udent, dirp, count);
	if (!tmp)
		goto done;
	ret += tmp;
	offdelta += dfs_dentry_size(&inode->dot_dents[DENT_SELF]);
	udent = (struct linux_dirent __user*)((char*)udent + tmp);

	tmp = read_dent(&inode->dot_dents[DENT_PARENT], ret, udent, dirp, count);
	if (!tmp)
		goto done;
	ret += tmp;
	offdelta += dfs_dentry_size(&inode->dot_dents[DENT_PARENT]);
	udent = (struct linux_dirent __user*)((char*)udent + tmp);

	/* Now read out the "real" entries */
	hlist_for_each_entry (dent, &inode->data.dirents, list) {
		tmp = read_dent(dent, ret, udent, dirp, count);
		if (!tmp)
			break;
		ret += tmp;
		offdelta += dfs_dentry_size(dent);
		udent = (struct linux_dirent __user*)((char*)udent + tmp);
	}

done:
	file->offset += offdelta;

	if (!ret)
		ret = -EINVAL; /* Result buffer too small */

out:
	return ret;
}

int dfs_utimensat(struct dfs_inode* start, const char* path,
                  struct timespec* utimes, int flags)
{
	int ret, touchflags = 0;
	struct dfs_inode* inode;
	struct timespec times[2];

	CHECK_MOUNTED;

	if (utimes) {
		ret = copy_from_user(times, utimes, sizeof(times));
		if (ret)
			return ret;
		if (times[0].tv_nsec == UTIME_NOW)
			times[0] = current_kernel_time();
		if (times[1].tv_nsec == UTIME_NOW)
			times[1] = current_kernel_time();
	} else
		times[0] = times[1] = current_kernel_time();

	lock_dfs(dfs);

	if (start && !path) {
		inode = start;
		dfs_pin_inode(inode);
	} else if (path) {
		inode = lookup_path(start, path, NULL, NULL, NULL);
		if (IS_ERR(inode)) {
			ret = PTR_ERR(inode);
			goto out;
		}
	} else {
		ret = -EINVAL;
		goto out;
	}

	if (times[0].tv_nsec != UTIME_OMIT) {
		inode->mtime = timespec_to_dfstime(times[0]);
		touchflags = TOUCH_CTIME;
	}
	if (times[1].tv_nsec != UTIME_OMIT) {
		inode->mtime = timespec_to_dfstime(times[1]);
		touchflags = TOUCH_CTIME;
	}
	touch_inode(inode, touchflags);

	ret = 0;

	dfs_unpin_inode(inode);

out:
	unlock_dfs(dfs);
	return ret;
}

static void lock_rename_dirs(struct dfs_inode* a, struct dfs_inode* b)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	if (a == b) {
		dfs_lock_inode(a);
		return;
	}

	if (a < b) {
		dfs_lock_inode(a);
		dfs_lock_inode(b);
	} else {
		dfs_lock_inode(b);
		dfs_lock_inode(a);
	}

	spin_lock(&dfs->rename_lock);
#endif
}

static void unlock_rename_dirs(struct dfs_inode* a, struct dfs_inode* b)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	if (a == b) {
		dfs_unlock_inode(a);
		return;
	}

	if (a < b) {
		dfs_unlock_inode(b);
		dfs_unlock_inode(a);
	} else {
		dfs_unlock_inode(a);
		dfs_unlock_inode(b);
	}

	spin_unlock(&dfs->rename_lock);
#endif
}

/*
 * This is missing some important checks (e.g. to prevent renaming a directory
 * into itself, replacing a non-empty directory, etc.).
 */
int dfs_renameat(struct dfs_inode* ostart, const char* oldpath,
                       struct dfs_inode* nstart, const char* newpath)
{
	int ret;
	char newname[NAME_MAX+1], oldname[NAME_MAX+1];
	struct dfs_dentry* newdent;
	struct dfs_inode* victim;
	struct dfs_inode* inode;
	struct dfs_inode* oldpdir = NULL;
	struct dfs_inode* newpdir = NULL;

	lock_dfs(dfs);

	inode = lookup_path(ostart, oldpath, NULL, &oldpdir, oldname);
	if (unlikely(IS_ERR(inode))) {
		ret = PTR_ERR(inode);
		goto out;
	}

	victim = lookup_path(nstart, newpath, NULL, &newpdir, newname);

	lock_rename_dirs(oldpdir, newpdir);

	if (!IS_ERR(victim)) {
		ret = dfs_remove_dent(newpdir, newname);
		dfs_unpin_inode(victim);
		if (unlikely(ret))
			goto out_unlock_dirs;
	} else if (unlikely(!newpdir)) {
		ret = PTR_ERR(victim);
		goto out_unlock_dirs;
	}

	newdent = add_dirent(newpdir, newname, inode);
	if (unlikely(IS_ERR(newdent))) {
		ret = PTR_ERR(newdent);
		goto out_unlock_dirs;
	}

	ret = dfs_remove_dent(oldpdir, oldname);

out_unlock_dirs:
	unlock_rename_dirs(oldpdir, newpdir);
	dfs_unpin_inode(inode);
	if (likely(newpdir))
		dfs_unpin_inode(newpdir);
	if (likely(oldpdir))
		dfs_unpin_inode(oldpdir);
out:
	unlock_dfs(dfs);
	return ret;
}

off_t dfs_lseek(struct dfs_file* file, off_t offset, int whence)
{
	int ret;
	off_t pre;

	CHECK_MOUNTED;

	lock_dfs(dfs);

	switch (whence) {
	case SEEK_SET: pre = 0; break;
	case SEEK_CUR: pre = file->offset; break;
	case SEEK_END: pre = dfs_inode_get_size(file->inode); break;
	default:
		ret = -EINVAL;
		goto out;
	}

	if (pre + offset < 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = file->offset = pre + offset;

out:
	unlock_dfs(dfs);
	return ret;
}

__icache_aligned
static int truncate_chunk_fn(struct dfs_inode* inode, struct dfs_datachunk* dc,
                             void* arg, bool* modified)
{
	off_t trunclen = *(off_t*)arg;

	if (trunclen <= chunk_off(dc))
		return free_chunk_fn(inode, dc, NULL, modified);
	else
		return 0;
}

int dfs_ftruncate(struct dfs_file* file, loff_t length)
{
	int ret;
	struct dfs_inode* inode;

	CHECK_MOUNTED;

	lock_dfs(dfs);

	if (length < 0) {
		ret = -EINVAL;
		goto out;
	}

	inode = file->inode;

	if (isdir(inode)) {
		ret = -EISDIR;
		goto out;
	}

	if (length < dfs_inode_get_size(inode))
		ret = iter_inode_range(inode, length, dfs_inode_get_size(inode),
		                       &length, NULL, truncate_chunk_fn);
	else if (length > dfs_inode_get_size(inode)) {
		dfs_inode_set_size(inode, length);
		ret = 0;
	} else
		ret = 0;

	if (!ret)
		touch_inode(inode, TOUCH_CTIME|TOUCH_MTIME);

out:
	unlock_dfs(dfs);
	return ret;
}

// -1 uid/gid means keep the former
int change_imeta(struct dfs_inode** inode, uid_t uid, gid_t gid, umode_t* mode) // double pointer to avoid dereferencing file outside the dfs lock
{
	struct imeta* im;
	int ret = 0;
	kuid_t kuid;
	kgid_t kgid;
	metaidx_t new;
	
	CHECK_MOUNTED;
	lock_dfs(dfs);
	
	new = dfs_inode_get_meta_idx(*inode);
	im = dfs->imeta.arr + new;
	if (uid == -1)
		kuid = im->uid;
	else
		kuid = make_kuid(current_user_ns(), uid);
	if (gid == -1)
		kgid = im->gid;
	else
		kgid = make_kgid(current_user_ns(), gid);
	if (!mode)
		mode = &im->mode;
	else
		*mode = (im->mode & ~S_IALLUGO) | (*mode & S_IALLUGO);
	
	new = find_imeta_idx(*mode, kuid, kgid);
	if (new > 0)
		dfs_inode_set_meta_idx(*inode, new);
	else
		ret = -ENOSPC;
	
	unlock_dfs(dfs);
	return ret;
}

int dfs_fchmod(struct dfs_file* file, umode_t mode)
{
	return change_imeta(&file->inode, -1, -1, &mode);
}

int dfs_fchown(struct dfs_file* file, uid_t uid, gid_t gid)
{
	return change_imeta(&file->inode, uid, gid, NULL);
}

int dfs_chmod(struct dfs_inode* inode, umode_t mode)
{
	return change_imeta(&inode, -1, -1, &mode);
}

int dfs_chown(struct dfs_inode* inode, uid_t uid, gid_t gid)
{
	return change_imeta(&inode, uid, gid, NULL);
}

int dfs_getcwd(struct dfs_inode* pwd, char __user* buf, size_t buflen)
{
	if (buflen < 4)
		return -ERANGE;
	return copy_to_user(buf, "/@@/", 4) ? -EFAULT : 4;
}

int dfs_statfsat(struct dfs_inode* start_ignored, const char* path_ignored,
                 struct kstatfs *st)
{
	st->f_type = 0xdf5df5df;
	st->f_bsize = DFS_DATA_ALLOCUNIT;
	st->f_blocks = dfs->size >> DFS_DATA_ALLOCORDER;
	st->f_bfree = gen_pool_avail(&dfs->data_pool) >> DFS_DATA_ALLOCORDER;
	st->f_bavail = st->f_bfree;
	st->f_files = gen_pool_size(&dfs->meta_pool) >> DFS_META_ALLOCORDER;
	st->f_ffree = gen_pool_avail(&dfs->meta_pool) >> DFS_META_ALLOCORDER;

	/* quoth statfs(2): "Nobody knows what f_fsid is supposed to contain" */
	memset(&st->f_fsid, 'x', sizeof(st->f_fsid));

	st->f_namelen = 256;

	return 0;
}

static size_t automount_bytes;
module_param(automount_bytes, ulong, 0);

static ssize_t dfsdump_read(struct file *file, char __user *buf, size_t count,
                            loff_t *ppos)
{
	size_t nbytes;

	DFS_CHECK(file->private_data == dfs);

	if (*ppos >= dfs->size)
		return 0;

	nbytes = min((loff_t)count, (loff_t)dfs->size - *ppos);
	if (copy_to_user(buf, dfs->mem + *ppos, nbytes))
		return -EFAULT;

	*ppos += nbytes;

	return nbytes;
}

static const struct file_operations dfsdump_fops = {
	.read		= dfsdump_read,
	.llseek		= generic_file_llseek,
};

SYSCALL_DEFINE0(dfs_opendump)
{
	return anon_inode_getfd("[densefs-dump]", &dfsdump_fops, &dfs, O_RDONLY);
}

int __init init_densefs(void)
{
	int status;
#ifndef CONFIG_DENSEFS_FGLOCK
	spin_lock_init(&dfs->lock);
#endif
	filecache = kmem_cache_create("dfs_file", sizeof(struct dfs_file), 0, 0, NULL);
	if (!filecache)
		return -ENOMEM;

	if (!automount_bytes)
		status = 0;
	else {
		status = mount_dfs(automount_bytes);
		if (status)
			kmem_cache_destroy(filecache);
	}
	return status;
}
fs_initcall(init_densefs);
