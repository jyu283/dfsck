#ifndef DFS_H
#define DFS_H

#include <stdbool.h>
#include <pthread.h>

#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP

#define BITS_PER_BYTE       8
#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define PGSIZE              0x1000

// #define DFS_SUPERBLOCK_SIZE round_up(sizeof(struct dfs_fs), PGSIZE) [> Change back to 0x1000 if snafu <]
#define DFS_SUPERBLOCK_SIZE 0x1000
#define DFS_DATA_ALLOCORDER 12
#define DFS_DATA_ALLOCUNIT (1ULL << DFS_DATA_ALLOCORDER)

#define BITS_PER_UINT       (BITS_PER_BYTE * sizeof(unsigned int)) 
#define DFS_CACHE_SIZE      64
#define DFS_CACHE_ROUND_UP(x)   ((x + DFS_CACHE_SIZE - 1) & ~(DFS_CACHE_SIZE - 1))

#define LAZY_LIST_HEAD_LOCK_BIT         63
#define LAZY_LIST_HEAD_CHUNK_BIT        62
#define LAZY_LIST_HEAD_INDEX_END_BIT    61
#define LAZY_LIST_HEAD_INDEX_START_BIT  58
#define DFS_META_NUM_CHUNKS             (DFS_CACHE_SIZE * BITS_PER_BYTE)
#define DFS_META_CHUNK_BIT(x)           (((x)->capacity & (1UL << LAZY_LIST_HEAD_CHUNK_BIT)) > 0)
#define DFS_META_CHUNK_CAPACITY(x)      ((x)->capacity & GENMASK(LAZY_LIST_HEAD_CHUNK_BIT - 1, 0))
#define DFS_META_CHUNK_FULL(d, x, s)    (DFS_META_CHUNK_CAPACITY(x) + 1 >= d->chunk_size / s) 
                                        // Technically, will BECOME full after increment
#define DFS_META_CHUNK_UNFULL(d, x, s)  (DFS_META_CHUNK_CAPACITY(x) >= d->chunk_size / s) 
                                        // Technically, will BECOME unfull after decrement
#define DFS_META_CHUNK_EMPTY(x)         (DFS_META_CHUNK_CAPACITY(x) == 1) 
                                        // Technically, will BECOME empty after decrement
#define DFS_DATA_ADDR(x)                ((void*)(x & ~(1ULL)))

typedef unsigned short uint16_t;
typedef uint16_t metaidx_t;

// DFS_DENTRY ================================================

typedef struct { //4
    int counter;
} atomic_t;

typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

struct kref {
	refcount_t refcount;
};

typedef unsigned char uint8_t;
typedef unsigned long long phys_addr_t;

/* large enough for NUL-terminated "." and ".." */
#define DFS_DENTRY_INLINE_LEN   3

struct dentrylist_node {
    struct dentrylist_node  *next;
};

struct dfs_dentry {
    struct dentrylist_node  list;
    struct dfs_inode        *parent;
    struct dfs_inode        *inode;
    struct kref             refs;
    uint8_t                 namelen;
    char                    name[DFS_DENTRY_INLINE_LEN];
};

// DFS_DATACHUNK ===============================================

struct rb_node {
	unsigned long           __rb_parent_color;
	struct rb_node          *rb_right;
	struct rb_node          *rb_left;
} __attribute__((aligned(sizeof(long))));

struct interval_tree_node {
	struct rb_node          rb;
	unsigned long           start;	/* Start of interval */
	unsigned long           last;	/* Last location _in_ interval */
	unsigned long           __subtree_last;
};

struct dfs_datachunk {
	struct interval_tree_node   it;
	struct dfs_inode            *parent;
	unsigned long               data_initialized;
};

// IMETA =======================================================

#define DFS_IMETA_PER_LIST_NODE     4

typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef unsigned short umode_t;

typedef struct{ // 4
	// Internal kernal uid
	uid_t val;
} kuid_t;

typedef struct { // 4
	// Internal kernel gid
	gid_t val;
} kgid_t;

struct imeta {
	kuid_t          uid;    /* 4 bytes */
	kgid_t          gid;    /* 4 bytes */
	umode_t         mode;   /* 2 bytes */
    uint16_t        refs;   /* 2 bytes */
    unsigned short  chksum; /* 2 bytes */
} __attribute__((packed));  /* __packed total: 14 bytes */

struct imeta_list_node{ // 64 bytes	
	struct imeta  imeta[DFS_IMETA_PER_LIST_NODE];   /* 14 x 4 = 56 bytes */
	metaidx_t     next;		    /* 2 bytes */
	metaidx_t     base;         /* 2 bytes */
	int           padding;      /* 4 bytes */
};  /* Total size with __packed imeta: 64 bytes */		

struct imeta_stack {		
	struct imeta_stack *next;		
	struct imeta_stack *prev;		
};		

// DFS_INODE =====================================================

#define LMS_METAIDX_POS     47
/* sub-fields on __lock_metaidx_size */
#define LMS_LOCKBIT         63
#define BITS_PER_LONG       64
#define LMS_LOCKMASK        (1ULL << LMS_LOCKBIT)
#define GENMASK(h, l) \
        (((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define LMS_METAIDX_MASK GENMASK(LMS_LOCKBIT - 1, LMS_METAIDX_POS)
#define LMS_SIZE_MASK GENMASK(LMS_METAIDX_POS - 1, 0)

#define DFS_TIMESTAMP_BYTES 5
#define DFS_TIMESTAMP_BITS (8 * DFS_TIMESTAMP_BYTES)
#define DFS_TIMESTAMP_NS_SHIFT 21

typedef unsigned int uint32_t;

typedef struct {
	uint32_t    __low;
	uint8_t     __high;
} __attribute__((__packed__)) dfstime_t;

struct rb_root {
	struct rb_node *rb_node;
};

struct inode_extra {
    struct dfs_inode    *parent;
};

struct dfs_inode {
	uint16_t        nlink;//2 bytes
	dfstime_t       mtime, ctime;//10 bytes
	refcount_t      pincount;//4
	unsigned long   __lock_metaidx_size;//8

	union {
		struct dentrylist_node  dirents;
		struct rb_root          chunks;
	} data;

	/* Only used for directories ("." and ".." entries) */
    struct inode_extra      extra[];
};

// LINUX BUILT-IN STRUCTS

typedef struct {
	volatile unsigned int lock;
} arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
} spinlock_t;

struct gen_pool;
/**
 * typedef genpool_algo_t: Allocation callback function type definition
 * @map: Pointer to bitmap
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @data: optional additional data used by the callback
 * @pool: the pool being allocated from
 */
typedef unsigned long (*genpool_algo_t)(unsigned long *map,
			unsigned long size,
			unsigned long start,
			unsigned int nr,
			void *data, struct gen_pool *pool);

struct list_head {
    struct list_head *next, *prev;
};

struct gen_pool {
	spinlock_t lock;//4+4padding
	struct list_head chunks;//16	/* list of chunks in this pool */
	int min_alloc_order;//4		/* minimum allocation order */

	genpool_algo_t algo;//8		/* allocation function */
	void *data;//8

	const char *name;//8
};

/*
 *  General purpose special memory pool chunk descriptor.
 */
struct gen_pool_chunk {
        struct list_head next_chunk;    /* next chunk in pool */
        atomic_t avail;
        int internal;
        phys_addr_t phys_addr;          /* physical starting address of memory chunk */
        unsigned long start_addr;       /* start address of memory chunk */
        unsigned long end_addr;         /* end address of memory chunk (inclusive) */
        unsigned long bits[0];          /* bitmap for allocating memory chunk */
};

// DFS_FS (The Superblock) =======================================

#define DFS_META_SIZE_GRANULARITY   (DFS_CACHE_SIZE / 2)

// Really long thing that the author of the checker doesn't know does what
#define DFS_META_INDEX_TO_SIZE(x) \
    (((x <= DFS_META_DIR_INODE_BITMAP)? x + 1 \
        : x - DFS_META_DIR_INODE_BITMAP) * DFS_META_SIZE_GRANULARITY)

#define DFS_META_FILE_INODE_BITMAP  0
#define DFS_META_DATACHUNK_BITMAP   1
#define DFS_META_DIR_INODE_BITMAP   2
#define DFS_META_FREE_BITMAP        12
#define DFS_META_DENTRY_BITMAP(x) \
            (DFS_META_DIR_INODE_BITMAP + (x - 1) / DFS_META_SIZE_GRANULARITY + 1)

struct chunk_bitmap {
	unsigned int ints[DFS_META_NUM_CHUNKS / BITS_PER_UINT];
};

struct lazy_list_node {
	struct lazy_list_node *next;
};

struct lazy_list_head {
	size_t capacity;
	struct lazy_list_node *head;
};

/* The superblock */
struct dfs_fs {
	struct chunk_bitmap     chunk_bitmaps[DFS_META_FREE_BITMAP + 1]; 
	
	struct lazy_list_head   *heads;
	char                    *chunks;
	size_t                  chunk_size;  // in bytes
	size_t                  meta_size;   // in bytes
	
	struct dfs_dentry       rootdir;     // root directory dentry
	void                    *mem;        // ptr to beginning of FS memory region
	size_t                  size;        // size of file system memory region
	struct gen_pool         data_pool;
	
	unsigned long           ino_key;

	struct {
		struct imeta_list_node  *arr;
		metaidx_t               sz;
		struct imeta_list_node  *dup_arr;
	} imeta;
};

#endif // DFS_H
