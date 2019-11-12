/*
	Enable prints: Replace //pr_crit(.*) with pr_crit(\1)
	Disable prints: Replace (?<!//)pr_crit(.*) with //pr_crit(\1)
*/

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

#include <linux/icache-pack.h>
#include <linux/densefs.h>

//#define DFS_META_ALLOCORDER 5
//#define DFS_META_ALLOCUNIT (1ULL << DFS_META_ALLOCORDER)
#define DFS_DATA_ALLOCORDER 12
#define DFS_DATA_ALLOCUNIT (1ULL << DFS_DATA_ALLOCORDER)

#define BITS_PER_UINT (BITS_PER_BYTE * sizeof(unsigned int)) 
#define DFS_CACHE_SIZE 64
#define DFS_CACHE_ROUND_UP(x) ((x + DFS_CACHE_SIZE - 1) & ~(DFS_CACHE_SIZE - 1))

#define META_LIST_HEAD_LOCK_BIT 63
#define META_LIST_HEAD_CHUNK_BIT 62 // Used for first run
#define META_LIST_HEAD_INDEX_START_BIT 58
#define META_LIST_HEAD_INDEX_END_BIT 61
#define DFS_META_NUM_CHUNKS (DFS_CACHE_SIZE * BITS_PER_BYTE)
#define DFS_META_CHUNK_BIT(x) (((x)->capacity & (1UL << META_LIST_HEAD_CHUNK_BIT)) > 0)
#define DFS_META_CHUNK_CAPACITY(x) ((x)->capacity & GENMASK(META_LIST_HEAD_INDEX_START_BIT - 1, 0))
#define DFS_META_CHUNK_FULL(d, x, s) (DFS_META_CHUNK_CAPACITY(x) + 1 >= d->chunk_size / s) // Technically, will BECOME full after increment
#define DFS_META_CHUNK_UNFULL(d, x, s) (DFS_META_CHUNK_CAPACITY(x) >= d->chunk_size / s) // Technically, will BECOME unfull after decrement
#define DFS_META_CHUNK_EMPTY(x) (DFS_META_CHUNK_CAPACITY(x) == 1) // Technically, will BECOME empty after decrement
#define DFS_DATA_ADDR(x) ((void*)(x & ~(1ULL)))

#define DFS_CACHE_LOW(x) ((x & DFS_CACHE_SIZE >> 1) == 0)
#define DFS_INODE_CACHE_NEIGHBOR(x) ((DFS_CACHE_LOW(x))? x + DFS_CACHE_SIZE / 2 : x - DFS_CACHE_SIZE / 2)

static struct kmem_cache* filecache;

/* large enough for NUL-terminated "." and ".." */
#define DFS_DENTRY_INLINE_LEN 3

struct dfs_dentry {
	struct dentrylist_node list;
	struct dfs_inode* parent;
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
	struct dfs_inode* parent;
	unsigned long data_initialized;
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
	uint16_t refs;
	unsigned short chksum;
}__packed;

typedef uint16_t metaidx_t;

#define DFS_IMETA_PER_LIST_NODE 4

struct imeta_list_node{ // 64 bytes	
	struct imeta imeta[DFS_IMETA_PER_LIST_NODE];		
	metaidx_t next;		
	metaidx_t base;
	int padding;//FUTURE USE	
};		
struct imeta_stack{		
	struct imeta_stack* next;		
	struct imeta_stack* prev;		
};		

/* sub-fields on __lock_metaidx_size */
#define LMS_LOCKBIT 63
#define LMS_METAIDX_POS (LMS_LOCKBIT - sizeof(metaidx_t) * BITS_PER_BYTE)
#define LMS_METAIDX_MASK GENMASK(LMS_LOCKBIT - 1, LMS_METAIDX_POS)
#define LMS_SIZE_MASK GENMASK(LMS_METAIDX_POS - 1, 0)

#define DFS_TIMESTAMP_BYTES 5
#define DFS_TIMESTAMP_BITS (8 * DFS_TIMESTAMP_BYTES)
#define DFS_TIMESTAMP_NS_SHIFT 21
typedef struct {
	uint32_t __low;
	uint8_t __high;
} __packed dfstime_t;

struct inode_extra{
	struct dfs_inode* parent;
};

struct dfs_inode {
	uint16_t nlink;
	dfstime_t mtime, ctime;
	refcount_t pincount;
	unsigned long __lock_metaidx_size;

	union {
		struct dentrylist_node dirents; // Root of dentry-list (if directory)
		struct rb_root chunks; // Root of red-black tree (if regular file)
	} data;

	/* Only used for directories */
	struct inode_extra extra[];
};

#ifdef CONFIG_DENSEFS_ENABLE_CHECKS
#define DFS_CHECK(x) BUG_ON(!(x))
#else
#define DFS_CHECK(x) do { } while (0)
#endif

#define DFS_META_SIZE_GRANULARITY (DFS_CACHE_SIZE / 2)

#define DFS_META_FILE_INODE_BITMAP 0
#define DFS_META_DATACHUNK_BITMAP 1
#define DFS_META_DIR_INODE_BITMAP 2
#define DFS_META_FREE_BITMAP 12
#define DFS_META_DENTRY_BITMAP(x) (DFS_META_DIR_INODE_BITMAP + (x - 1) / DFS_META_SIZE_GRANULARITY + 1)

struct chunk_bitmap{
	unsigned int ints[DFS_META_NUM_CHUNKS / BITS_PER_UINT];
};

struct meta_list_node{
	struct meta_list_node* next;
};

struct meta_list_head{
	size_t capacity;
	struct meta_list_node* head;
};

struct dfs_fs {
	struct chunk_bitmap chunk_bitmaps[DFS_META_FREE_BITMAP + 1]; // free list initially 1s
	
	struct meta_list_head* heads;
	char* chunks;
	size_t chunk_size; // in bytes
	size_t meta_size; // in bytes
	
	struct dfs_dentry rootdir; // Root directory
	void* mem; // Pointer to beginning of file system memory region
	size_t size; // Size of file system memory region
	struct gen_pool data_pool;
	
	/*
	 * Secret used to avoid leaking raw kernel addresses (or offsets) to
	 * userspace. TODO: initialize this with appropriate entropy at
	 * "mkfs"-time.
	 */
	unsigned long ino_key;

	struct {
		struct imeta_list_node* arr;
		metaidx_t sz;
		struct imeta_list_node* dup_arr;
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

static inline void dfs_meta_chunk_lock(struct meta_list_head* head)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	bit_spin_lock(META_LIST_HEAD_LOCK_BIT, &head->capacity);
#endif
}

static inline void dfs_meta_chunk_unlock(struct meta_list_head* head)
{
#ifdef CONFIG_DENSEFS_FGLOCK
	bit_spin_unlock(META_LIST_HEAD_LOCK_BIT, &head->capacity);
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


unsigned short crc16b(unsigned char *message, int message_size) {		
   int i, j;		
   unsigned short byte, crc, mask;		
   i = 0;		
   crc = 0xFFFF;		
   while (i < message_size) {		
      byte = message[i];            // Get next byte.		
      crc = crc ^ byte;		
      for (j = 7; j >= 0; j--) {    // Do eight times.		
         mask = -(crc & 1);		
         crc = (crc >> 1) ^ (0xEDB8 & mask);		
      }		
      i = i + 1;		
   }		
   return ~crc;		
}


static inline size_t dfs_meta_index_to_size(int sz_index)
{
	size_t ret;
	switch(sz_index){
		case DFS_META_FILE_INODE_BITMAP:
			ret = 1;
			break;
		case DFS_META_DATACHUNK_BITMAP:
		case DFS_META_DIR_INODE_BITMAP:
			ret = 2;
			break;
		default:
			ret = sz_index - 2;
	}
	return ret * DFS_META_SIZE_GRANULARITY;
}

void* dfs_meta_alloc(size_t sz, int sz_index){
	struct meta_list_head* head;
	struct meta_list_node* next;
	char* chunk;
	struct chunk_bitmap* bm, *bm2;
	void* ret;
	int group, i, bit;
	//pr_crit("Starting dfs_meta_alloc with size %lu (size index %d)\n", sz, sz_index);
	bm2 = bm = dfs->chunk_bitmaps + sz_index;
	//alloc_sz = (sz + DFS_META_SIZE_GRANULARITY - 1) & ~(DFS_META_SIZE_GRANULARITY - 1);
	dfs_meta_alloc_lock(dfs);
	
	// Search chunk bitmap
start:
	for (i = 0; i < DFS_META_NUM_CHUNKS / BITS_PER_UINT; i++){
		if (bm2->ints[i] > 0){
			bit = ffs(bm2->ints[i]) - 1;
			if (unlikely(bm2 == dfs->chunk_bitmaps + DFS_META_FREE_BITMAP)){
				// found bit in free list; allocate new chunk
				//pr_crit("Allocating new chunk (%lu)\n", i * BITS_PER_UINT + bit);
				bm2->ints[i] &= ~(1 << bit);
				bm->ints[i] |= 1 << bit;
			}
			group = i;
			goto found_chunk;
		}
	}
	if (unlikely(bm2 == dfs->chunk_bitmaps + DFS_META_FREE_BITMAP)){
		dfs_meta_alloc_unlock(dfs);
		return NULL; // No chunk found in free list; fail
	}
	bm2 = dfs->chunk_bitmaps + DFS_META_FREE_BITMAP; // No chunk found; go to free list
	goto start;
	
found_chunk:
	//pr_crit("found chunk: %lu\n", group * BITS_PER_UINT + bit);
	head = dfs->heads + bit + group * BITS_PER_UINT;
	chunk = dfs->chunks + (bit + group * BITS_PER_UINT) * dfs->chunk_size;
	
	dfs_meta_chunk_lock(head);
	ret = head->head; // return value
	if (unlikely(DFS_META_CHUNK_FULL(dfs, head, sz))){ // Check if chunk is about to become full
		//pr_crit("chunk full\n");
		bm->ints[group] &= ~(1 << bit); // Unset bit in chunk bitmap for this alloc size
	}
	dfs_meta_alloc_unlock(dfs);
	
	head->capacity++;
	head->capacity |= ((unsigned long)sz_index) << META_LIST_HEAD_INDEX_START_BIT;
	
	if (!DFS_META_CHUNK_BIT(head)){
		// In first run of list; advance head to adjacent node
		next = (struct meta_list_node*)((char*)(head->head) + sz);
		next->next = head->head->next;
		head->head = next;
		
		//pr_crit("next: %p, sz: %d, chunk: %p, chunk size: %lu\n", next, sz, chunk, dfs->chunk_size);
		if (unlikely((char*)next + sz * 2 > chunk + dfs->chunk_size)){
			//pr_crit("setting first run bit\n");
			head->capacity |= 1UL << META_LIST_HEAD_CHUNK_BIT; // If next adjacent node is outside chunk, set bit to indicate that the first run is over
		}
	}
	else{
		head->head = head->head->next; // Pop off the head
	}
	memset(ret, 0x0, sz); // Clear new allocation space
	dfs_meta_chunk_unlock(head);
	//pr_crit("Finishing dfs_meta_alloc with size %lu\n", sz);
	return ret;
}

void dfs_meta_free(void* ptr, int sz_index){
	struct meta_list_head* head;
	struct meta_list_node* addr;
	int chunk_index, group, bit;
	//pr_crit("Starting dfs_meta_free with size index %d\n", sz_index);
	addr = (struct meta_list_node*)ptr;
	chunk_index = ((char*)ptr - dfs->chunks) / dfs->chunk_size;
	//pr_crit("chunk %d\n", chunk_index);
	head = dfs->heads + chunk_index;
	group = chunk_index / BITS_PER_UINT;
	bit = chunk_index % BITS_PER_UINT;
	
	dfs_meta_alloc_lock(dfs);
	dfs_meta_chunk_lock(head);
	
	if (unlikely(DFS_META_CHUNK_UNFULL(dfs, head, dfs_meta_index_to_size(sz_index)))){ // Check if chunk is about to become unfull
		//pr_crit("chunk unfilled\n");
		dfs->chunk_bitmaps[sz_index].ints[group] |= 1 << bit; // Set bit in chunk bitmap for this sigma
	}
	else if (unlikely(DFS_META_CHUNK_EMPTY(head))){ // Check if chunk is about to become empty
		// deallocate chunk
		//pr_crit("chunk emptied\n");
		dfs->chunk_bitmaps[sz_index].ints[group] &= ~(1 << bit); // Unset bit in chunk bitmap for this sigma
		dfs->chunk_bitmaps[DFS_META_FREE_BITMAP].ints[group] |= 1 << bit; // Set bit in free list
		dfs_meta_alloc_unlock(dfs);
		head->head = (struct meta_list_node*)(dfs->chunks + chunk_index * dfs->chunk_size); // Set head to base
		head->head->next = NULL; // Detach list
		head->capacity = 0;
		return;
	}
	dfs_meta_alloc_unlock(dfs);
	
	head->capacity--;
	if (!DFS_META_CHUNK_BIT(head)){
		// In first run of list; place after head node	
		addr->next = head->head->next;
		head->head->next = addr;
	}
	else{
		// Place as head node
		addr->next = head->head;
		head->head = addr;
	}
	dfs_meta_chunk_unlock(head);
	//pr_crit("Finishing dfs_meta_free with size index %d\n", sz_index);
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

static inline struct dfs_datachunk* dfs_new_datachunk(off_t off, off_t len, struct dfs_inode* inode)
{
	off_t allocbase = round_down(off, DFS_DATA_ALLOCUNIT);
	off_t allocsize = round_up(len + (off - allocbase), DFS_DATA_ALLOCUNIT);
	struct dfs_datachunk* dc;
	//pr_crit("alloc from dfs_new_datachunk\n");
	dc = dfs_meta_alloc(sizeof(*dc), DFS_META_DATACHUNK_BITMAP);

	if (dc) {
		dc->data_initialized = (unsigned long)dfs_data_alloc(allocsize);
		if (!dc->data_initialized) {
			//pr_crit("free from dfs_new_datachunk\n");
			dfs_meta_free(dc, DFS_META_DATACHUNK_BITMAP);
			dc = NULL;
		} else {
			dc->it.start = allocbase;
			dc->it.last = allocbase + allocsize - 1;
			dc->parent = inode;
			// set initialized to 0, while keeping data the same
			dc->data_initialized &= ~(1ULL);
		}
	}
	return dc;
}

static inline void dfs_free_datachunk(struct dfs_datachunk* dc)
{
	dfs_data_free((void *)DFS_DATA_ADDR(dc->data_initialized), chunk_len(dc));
	//pr_crit("free from dfs_free_datachunk\n");
	dfs_meta_free(dc, DFS_META_DATACHUNK_BITMAP);
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

static struct dfs_dentry* dir_lookup(struct dfs_inode* dir, const char* name, struct dentrylist_node** pprev);
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
	//pr_crit("free from dfs_free_dentry\n");
	dfs_meta_free(dent, DFS_META_DENTRY_BITMAP(dfs_dentry_size(dent)));
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
	DFS_CHECK(idx < dfs->imeta.sz);
	p = &(dfs->imeta.arr[idx / DFS_IMETA_PER_LIST_NODE].imeta[idx % DFS_IMETA_PER_LIST_NODE]);
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
	metaidx_t idx = dfs_inode_get_meta_idx(inode);
	return S_ISDIR(dfs->imeta.arr[idx / DFS_IMETA_PER_LIST_NODE].imeta[idx % DFS_IMETA_PER_LIST_NODE].mode);
}

static inline bool isreg(const struct dfs_inode* inode)
{
	return S_ISREG(inode_mode(inode));
}

__icache_aligned
static void free_inode(struct dfs_inode* inode)
{
	int sz_index;
	metaidx_t idx;
	//pr_crit("free from free_inode\n");
	if (isdir(inode))
		sz_index = DFS_META_DIR_INODE_BITMAP;
	else
		sz_index = DFS_META_FILE_INODE_BITMAP;
	idx = dfs_inode_get_meta_idx(inode);
	dfs_imeta_lock(dfs);
	dfs->imeta.arr[idx / DFS_IMETA_PER_LIST_NODE].imeta[idx % DFS_IMETA_PER_LIST_NODE].refs--;
	dfs_imeta_unlock(dfs);
	dfs_meta_free(inode, sz_index);
}

__icache_aligned
static void __dfs_kill_inode(struct dfs_inode* inode)
{
	struct dfs_dentry* dent;
	struct dfs_inode* parent;
	if (isdir(inode)) {
		if (inode != dfs->rootdir.inode) {
			parent = inode->extra->parent;
			DFS_CHECK(parent);
			DFS_CHECK(parent->nlink > 1);
			dfs_dec_nlink(parent);
		}
		dentrylist_for_each_entry_del (dent, &inode->data.dirents, list) {
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
	INIT_DENTRYLIST_NODE(&dent->list);
	dent->inode = inode;
	dfs_inc_nlink(inode);
	kref_init(&dent->refs);
	dent->namelen = strlen(name);
	strcpy(dent->name, name);
}

static struct dfs_dentry* new_dentry(const char* name, struct dfs_inode* inode)
{
	size_t namelen = strlen(name);
	size_t alloc_sz;
	struct dfs_dentry* dent;
	//pr_crit("alloc from new_dentry\n");
	alloc_sz = dfs_dentry_size_for_len(namelen);
	dent = dfs_meta_alloc((alloc_sz + DFS_META_SIZE_GRANULARITY - 1) & ~(DFS_META_SIZE_GRANULARITY - 1), DFS_META_DENTRY_BITMAP(alloc_sz));

	BUILD_BUG_ON(sizeof(struct dfs_dentry) != 32);

	if (!dent)
		return NULL;
	init_dentry(dent, name, inode);
	return dent;
}

	static metaidx_t imeta_hash(umode_t mode, kuid_t uid, kgid_t gid)		
{		
    unsigned int new_uid = uid.val;		
    unsigned int new_gid = gid.val;		
    unsigned int merge_id = new_uid >= new_gid ? new_uid * new_uid + new_uid + new_gid : new_uid + new_gid * new_gid;		
    unsigned int hash = (mode + merge_id) * (mode + merge_id + 1) / 2 + mode;		
    return (metaidx_t)(((hash >> 16) ^ ((hash & 0xffff) * 2654435761)) % (dfs->imeta.sz - 1) + 1);		
}

static metaidx_t find_imeta_idx(umode_t mode, kuid_t uid, kgid_t gid)
{
	struct imeta_list_node* orig, *curr;
	struct imeta* im;
	struct imeta* im_dup;
	struct imeta_stack* stack1, *stack2;
	metaidx_t* prev;
	int i, imcount;
	metaidx_t idx = imeta_hash(mode, uid, gid);
	bool set_idx = false;

	orig = dfs->imeta.arr + idx;
	
	dfs_imeta_lock(dfs);
	if (orig->base == 0 && orig->next == 0){
		stack2 = (struct imeta_stack*)orig;
		stack1 = stack2->prev;
		if (stack1 != NULL){
			stack1->next = stack2->next;
		}
		if (stack1->next != NULL){
			stack1->next->prev = stack1;
		}
		stack2->prev = stack2->next = NULL;
		
		orig->next = orig->base = idx;
		idx = idx * DFS_IMETA_PER_LIST_NODE;
		im = orig->imeta;
		goto found_new;
	}
	prev = &orig->base;
	curr = dfs->imeta.arr + orig->base;

	while (prev != &curr->next){
		imcount = 0;
		for (i = 0; i < DFS_IMETA_PER_LIST_NODE; i++){
			im = curr->imeta + i;
			if (im->refs > 0){
				if (im->mode == mode && uid_eq(im->uid, uid) && gid_eq(im->gid, gid) && im->refs < (uint16_t)(-1)){
					idx = (curr - dfs->imeta.arr) * DFS_IMETA_PER_LIST_NODE + i;
					goto out;
				}
				imcount++;
			}
			else if (unlikely(!set_idx)){
				set_idx = true;
				idx = (curr - dfs->imeta.arr) * DFS_IMETA_PER_LIST_NODE + i;
			}
		}
		if (unlikely(imcount == 0)){ // empty node; remove
			if (curr->next == curr - dfs->imeta.arr){
				if (curr == orig){
					im = orig->imeta;
					goto found_new;
				}
				*prev = ((char*)prev - (char*)(dfs->imeta.arr)) / sizeof(struct imeta_list_node);
			}
			else{
				*prev = curr->next;
			}
			if (unlikely(idx / DFS_IMETA_PER_LIST_NODE == curr - dfs->imeta.arr)){ // unset free space if it was just set
				idx = 0;
				set_idx = false;
			}
			curr->next = curr->base = 0;
			// Push to free list
			stack1 = (struct imeta_stack*)(dfs->imeta.arr);
			stack2 = (struct imeta_stack*)curr;
			stack2->next = stack1->next;
			stack2->prev = stack1;
			stack1->next = stack2;
			if (stack2->next != NULL){
				stack2->next->prev = stack2;
			}
		}
		else{
			prev = &curr->next;
		}
		curr = dfs->imeta.arr + *prev;
	}
	
	if (!set_idx){
		// exhausted chain; pop from stack
		stack1 = (struct imeta_stack*)(dfs->imeta.arr);
		stack2 = stack1->next;
		if (stack2 == NULL){
			dfs_imeta_unlock(dfs);
			return 0;
		}
		stack1->next = stack2->next;
		if (stack1->next != NULL){
			stack1->next->prev = stack1;
		}
		stack2->prev = stack2->next = NULL;
		
		curr = (struct imeta_list_node*)stack2;
		idx = (*prev = curr->next = curr - dfs->imeta.arr) * DFS_IMETA_PER_LIST_NODE;
		im = curr->imeta;
		goto found_new;
	}
	im = dfs->imeta.arr[idx / DFS_IMETA_PER_LIST_NODE].imeta + idx % DFS_IMETA_PER_LIST_NODE;
found_new:
	im->uid = uid;
	im->gid = gid;
	im->mode = mode;
	im_dup = dfs->imeta.dup_arr[idx / DFS_IMETA_PER_LIST_NODE].imeta + idx % DFS_IMETA_PER_LIST_NODE;
	im_dup->uid = uid;
	im_dup->gid = gid;
	im_dup->mode = mode;
out:
	im->refs++;
	im->chksum = crc16b((unsigned char*)im, sizeof(struct imeta) - sizeof(((struct imeta*)0)->chksum));
	im_dup = dfs->imeta.dup_arr[idx / DFS_IMETA_PER_LIST_NODE].imeta + idx % DFS_IMETA_PER_LIST_NODE;
	im_dup->refs++;
	im_dup->chksum = crc16b((unsigned char*)im_dup, sizeof(struct imeta) - sizeof(((struct imeta*)0)->chksum));
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
	metaidx_t idx;
	//pr_crit("alloc from create_inode\n");
	if (S_ISDIR(mode)){
		// Allocate mock directory entries for . and ..
		inode = dfs_meta_alloc(dfs_meta_index_to_size(DFS_META_DIR_INODE_BITMAP), DFS_META_DIR_INODE_BITMAP);
	}
	else{
		inode = dfs_meta_alloc(sizeof(*inode), DFS_META_FILE_INODE_BITMAP);
	}
	if (!inode)
		return NULL;

	/* initialize lock (unlocked) and size (zero) */
	idx = find_imeta_idx(mode, GLOBAL_ROOT_UID, GLOBAL_ROOT_GID);
	if (idx == 0){
		if (S_ISDIR(mode)){
			dfs_meta_free(inode, DFS_META_DIR_INODE_BITMAP);
		}else{
			dfs_meta_free(inode, DFS_META_FILE_INODE_BITMAP);
		}
		return NULL;
	}

	/* initialize lock (unlocked) and size (zero) */
	inode->__lock_metaidx_size = 0;
	dfs_inode_set_meta_idx(inode, idx);

	//inode->nlink = 0; //memset in dfs_meta_alloc already does this

	if (S_ISDIR(mode)) { // Directory
		INIT_DENTRYLIST_NODE(&inode->data.dirents);
		dfs_inode_set_size(inode, DFS_EMPTYDIR_SIZE);
		dfs_inc_nlink(inode);
		inode->extra->parent = (dir_parent == ROOT_PARENT_SELF) ? inode : dir_parent;
		dfs_inc_nlink(inode->extra->parent);
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
	int ret, i;
	void* mem;
	struct imeta_list_node* iter;
	struct meta_list_head* head;
	char* chunk;
	size_t sbsize, metasize, imeta_sz, chunk_size, imeta_space;
	unsigned int hash;
	
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
	memset(mem, 0x0, size); // 0
	
	dfs = mem;
	dfs->mem = mem;
	dfs->size = size;
	hash = (unsigned int)((size-1)*95483 ^ (size >> 32) ^ 2654435761);
	hash ^= hash << 3;		
    hash += hash >> 5;		
    hash ^= hash << 4;		
    hash += hash >> 17;		
	dfs->ino_key = hash;
	
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
	
	// ~1/64th of metadata is for the imeta table
	imeta_sz = (metasize >> 6) / sizeof(struct imeta_list_node); // curate for metaidx_t
	if (imeta_sz > (metaidx_t)(-1) / DFS_IMETA_PER_LIST_NODE)
		imeta_sz = (metaidx_t)(-1) / DFS_IMETA_PER_LIST_NODE;
	else if (imeta_sz < 4)
		imeta_sz = 4;
	dfs->imeta.sz = imeta_sz;
	
	imeta_space = DFS_CACHE_ROUND_UP(imeta_sz * sizeof(struct imeta_list_node));
	metasize -= imeta_space + sizeof(struct meta_list_head) * DFS_META_NUM_CHUNKS;
	dfs->imeta.arr = mem + sbsize;

	// Setting up the free stack of imeta
	iter = dfs->imeta.arr;
	((struct imeta_stack*)iter)->next = (struct imeta_stack*)(iter + 1);
	for (iter++; iter < dfs->imeta.arr + imeta_sz - 1; iter++){
		((struct imeta_stack*)iter)->next = (struct imeta_stack*)(iter + 1);
		((struct imeta_stack*)iter)->prev = (struct imeta_stack*)(iter - 1);
	}
	((struct imeta_stack*)iter)->prev = (struct imeta_stack*)(iter - 1);

	dfs->heads = (struct meta_list_head*)(mem + sbsize + imeta_space);
	
	dfs->chunks = (char*)(dfs->heads + DFS_META_NUM_CHUNKS);
	chunk_size = metasize / (DFS_META_NUM_CHUNKS * DFS_CACHE_SIZE);
	
	if (chunk_size * DFS_META_NUM_CHUNKS * DFS_CACHE_SIZE + DFS_META_NUM_CHUNKS * DFS_CACHE_SIZE / 2 >= metasize){
		chunk_size++;
	}
	
	dfs->chunk_size = chunk_size * DFS_CACHE_SIZE;
	
	//pr_crit("allocs/chunk:\n");
	//pr_crit("\tbitmap %d (file inodes): %lu\n", DFS_META_FILE_INODE_BITMAP, dfs->chunk_size / (sizeof(struct dfs_inode)));
	//pr_crit("\tbitmap %d (datachunks): %lu\n", DFS_META_DATACHUNK_BITMAP, dfs->chunk_size / (sizeof(struct dfs_datachunk)));
	//pr_crit("\tbitmap %d (dir inodes): %lu\n", DFS_META_DIR_INODE_BITMAP, dfs->chunk_size / (sizeof(struct dfs_inode) + 2 * sizeof(struct dfs_dentry)));
	for (i = DFS_META_DIR_INODE_BITMAP + 1; i < DFS_META_FREE_BITMAP; i++){
		//pr_crit("\tbitmap %d (dentries): %lu\n", i, dfs->chunk_size / ((i - DFS_META_DIR_INODE_BITMAP) * DFS_META_SIZE_GRANULARITY));
	}
	
	dfs->imeta.dup_arr = (struct imeta_list_node*)(mem + sbsize + imeta_space + (dfs->chunk_size + sizeof(struct meta_list_head)) * DFS_META_NUM_CHUNKS);
	dfs->meta_size = (dfs->chunk_size + sizeof(struct meta_list_head)) * DFS_META_NUM_CHUNKS + imeta_space * 2;
	
	// Initialize the head of the chain for each chunk
	for (head = dfs->heads, chunk = dfs->chunks; chunk < dfs->chunks + DFS_META_NUM_CHUNKS * dfs->chunk_size; chunk += dfs->chunk_size, head++){
		head->head = (struct meta_list_node*)chunk;
	}
	
	memset(dfs->chunk_bitmaps + DFS_META_FREE_BITMAP, 0xff, DFS_META_NUM_CHUNKS / BITS_PER_BYTE); // Initialize free bitmap to 1s
	
	gen_pool_init(&dfs->data_pool, DFS_DATA_ALLOCORDER); // 12
	
	ret = gen_pool_add_internal(&dfs->data_pool, round_up((unsigned long)(dfs->mem + sbsize + dfs->meta_size), DFS_DATA_ALLOCUNIT),
	                            size - (dfs->meta_size + sbsize), -1);
	
	if (ret)
		goto out_free_mem;
	
	ret = dfs_create_root();
	if (ret)
		goto out_destroy_data_pool;
	else
		goto out;
	
out_destroy_data_pool:
	__gen_pool_rmchunks(&dfs->data_pool, false);
out_free_mem:
	vfree(dfs->mem);
	dfs = NULL;
out:
	//*
	pr_crit("meta sz: %lu\nimeta: %lu\n\tsz: %lu\ncaps: %lu\n\tsz: %lu\nchunks: %lu\n\tsz: %lu\n", dfs->meta_size,
		(unsigned long)(dfs->imeta.arr), dfs->imeta.sz * sizeof(struct imeta),
		(unsigned long)(dfs->heads), DFS_META_NUM_CHUNKS * sizeof(struct meta_list_head),
		(unsigned long)(dfs->chunks), DFS_META_NUM_CHUNKS * dfs->chunk_size);
		//*/
	printk("Mount terminated with code %d\n", ret);
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
static struct dfs_dentry* dir_lookup(struct dfs_inode* dir, const char* name, struct dentrylist_node** pprev)
{
	struct dfs_dentry* dent;
	struct dentrylist_node* prev;

	DFS_CHECK(isdir(dir));

	prev = &dir->data.dirents;
	dentrylist_for_each_entry (dent, &dir->data.dirents, list) {
		if (!strcmp(dent->name, name)) {
			grab_dentry(dent);
			if (pprev){
				*pprev = prev;
				if (prev != &dir->data.dirents)
					grab_dentry(container_of(prev, struct dfs_dentry, list));
			}
			return dent;
		}
		prev = &dent->list;
	}

	return NULL;
}

/* Caller holds lock on dir */
static struct dfs_dentry* dfs_lookup_step(struct dfs_inode* dir, const char* name)
{
	struct dfs_dentry* found;

	if (unlikely(!isdir(dir)))
		return ERR_PTR(-ENOTDIR);

	found = dir_lookup(dir, name, NULL);

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

		previ = curi;
		dent = NULL;
		if (!strcmp(name, "."));
		else if (!strcmp(name, "..")){
			dfs_lock_inode(previ);
			curi = previ->extra->parent;
			dfs_unlock_inode(previ);
		}
		else{
			dfs_lock_inode(previ);
			dent = dfs_lookup_step(previ, name);
			dfs_unlock_inode(previ);
			if (IS_ERR(dent)){
				curi = ERR_CAST(dent);
				goto nopin;
			}
			else{
				curi = dent->inode;
			}
		}
		dfs_pin_inode(curi);
nopin:
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
				if (dentp){
					if (!dent)
						*dentp = ERR_PTR(-ENONET);
					else
						*dentp = dent;
				}
				else if (dent != NULL)
					drop_dentry(dent);
			}

			break;
		} else if (!IS_ERR(dent) && dent != NULL)
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

	if (dir->nlink != 2 || !dentrylist_empty(&dir->data.dirents)) {
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

	newent->parent = dir;
	dentrylist_add_after(&newent->list, &dir->data.dirents);
	dfs_inode_size_add(dir, dfs_dentry_size(newent));

	touch_inode(dir, TOUCH_MTIME|TOUCH_CTIME);

	return newent;
}

/* Caller must hold lock on dir */
__icache_aligned
static int dfs_remove_dent(struct dfs_inode* dir, const char* name)
{
	struct dfs_dentry* dent;
	struct dentrylist_node* prev;

	dent = dir_lookup(dir, name, &prev);
	if (!dent)
		return -ENOENT;

	dentrylist_del_after(prev);
	dfs_inode_size_sub(dir, dfs_dentry_size(dent));

	if (prev != &dir->data.dirents)
		drop_dentry(container_of(prev, struct dfs_dentry, list));
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
		src = DFS_DATA_ADDR(dc->data_initialized);
	} else {
		dst = params->buf;
		src = DFS_DATA_ADDR(dc->data_initialized) + (params->offset - chunk_off(dc));
	}

	startoff = max(chunk_off(dc), params->offset);
	endoff = min(min(dfs_inode_get_size(inode), chunk_off(dc) + chunk_len(dc)),
	             (off_t)(params->offset + params->len));
	nbytes = (endoff >= startoff) ? (endoff - startoff) : 0;

	if ((dc->data_initialized & 1ULL))
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
		dst = DFS_DATA_ADDR(dc->data_initialized);
	} else {
		src = params->buf;
		dst = DFS_DATA_ADDR(dc->data_initialized) + (params->offset - chunk_off(dc));
	}

	nbytes = min(chunk_len(dc) - (dst - (void*)DFS_DATA_ADDR(dc->data_initialized)),
	             (off_t)(params->len - (src - params->buf)));

	status = copy_from_user(dst, src, nbytes);
	if (!status) {
		params->transferred += nbytes;
		end = chunk_off(dc) + (dst - (void*)DFS_DATA_ADDR(dc->data_initialized)) + nbytes;
		if (end > dfs_inode_get_size(inode))
			dfs_inode_set_size(inode, end);

		if (!(dc->data_initialized & 1ULL)) {
			prebytes = dst - (void*)DFS_DATA_ADDR(dc->data_initialized);
			if (prebytes)
				memset(DFS_DATA_ADDR(dc->data_initialized), 0, prebytes);
			postbytes = chunk_len(dc) - (prebytes + nbytes);
			if (postbytes)
				memset(dst + nbytes, 0, postbytes);
			dc->data_initialized |= 1ULL;
		}
	}

	return status;
}

static int write_hole_fn(struct dfs_inode* inode, off_t start, off_t len,
                         void* arg, bool* modified)
{
	struct dfs_datachunk* dc;

	dc = dfs_new_datachunk(start, len, inode);
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
	int ret = 0;
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

	if (!IS_ERR(dent)){
		dfs_lock_inode(parent);
		ret = dfs_remove_dent(parent, dent->name);
		dfs_unlock_inode(parent);
	}

out_release:
	dfs_unpin_inode(parent);
	if (!IS_ERR(dent))
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
	struct dfs_datachunk* dc = dfs_new_datachunk(start, len, inode);
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
	unsigned short reclen = offsetof(struct linux_dirent, d_name) + 3;
	char tmpdentbuf[reclen + 1];
	struct linux_dirent* tmpdent = (struct linux_dirent*)tmpdentbuf;
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

	if (reclen >= count)
		goto done;
	tmpdent->d_ino = inum(inode);
	tmpdent->d_off = reclen;
	tmpdent->d_reclen = reclen;
	tmpdent->d_name[0] = '.';
	tmpdent->d_name[1] = '\0';
	tmpdent->d_name[2] = DT_DIR;
	
	if (copy_to_user(udent, tmpdentbuf, reclen)){
		ret = -EFAULT;
		goto done;
	}
	offdelta = 32;
	
	if (2 * reclen + 1 >= count)
		goto done;
	ret = reclen;
	udent = (struct linux_dirent __user*)((char*)udent + reclen);
	reclen++;
	
	tmpdent->d_ino = inum(inode->extra->parent);
	tmpdent->d_off += reclen;
	tmpdent->d_reclen = reclen;
	tmpdent->d_name[1] = '.';
	tmpdent->d_name[2] = '\0';
	tmpdent->d_name[3] = DT_DIR;
	
	if (copy_to_user(udent, tmpdentbuf, reclen)){
		ret = -EFAULT;
		goto done;
	}
	offdelta += 32;
	ret += reclen;
	udent = (struct linux_dirent __user*)((char*)udent + reclen);

	/* Now read out the "real" entries */
	dentrylist_for_each_entry (dent, &inode->data.dirents, list) {
		tmp = read_dent(dent, ret, udent, dirp, count);
		if (!tmp)
			break;
		if (tmp == -EFAULT){
			ret = tmp;
			break;
		}
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

int dfs_fchown(struct dfs_file* file, uid_t uid, gid_t gid)
{
	int ret;
	struct dfs_inode* inode;
	mode_t mode;
	metaidx_t old, new;
	struct imeta *orig, *dup;

	CHECK_MOUNTED;
	
	//pr_crit("starting chown\n");

	lock_dfs(dfs);

	inode = file->inode;
	mode = inode_mode(inode);
	old = dfs_inode_get_meta_idx(inode);
	//pr_crit("old: %d\n", old);
	new = find_imeta_idx(mode, make_kuid(current_user_ns(), uid), make_kgid(current_user_ns(), gid));
	if (new > 0){
		dfs_inode_set_meta_idx(inode, new);
		dfs_imeta_lock(dfs);
		orig = dfs->imeta.arr[old / DFS_IMETA_PER_LIST_NODE].imeta + old % DFS_IMETA_PER_LIST_NODE;
		dup = dfs->imeta.dup_arr[old / DFS_IMETA_PER_LIST_NODE].imeta + old % DFS_IMETA_PER_LIST_NODE;
		orig->refs--;
		orig->chksum = crc16b((unsigned char*)orig, sizeof(struct imeta) - sizeof(((struct imeta*)0)->chksum));
		dup->refs--;
		dup->chksum = crc16b((unsigned char*)dup, sizeof(struct imeta) - sizeof(((struct imeta*)0)->chksum));
		dfs_imeta_unlock(dfs);
		ret = 0;
	}
	else{
		ret = 1;
	}

	unlock_dfs(dfs);
	
	//pr_crit("finishing chown\n");
	return ret;
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
	st->f_files = dfs->meta_size; // TODO: gen_pool_size(&dfs->meta_pool) >> DFS_META_ALLOCORDER;
	st->f_ffree = 0; // TODO: gen_pool_avail(&dfs->meta_pool) >> DFS_META_ALLOCORDER;

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
