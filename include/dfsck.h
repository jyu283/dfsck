#ifndef DFSCK_H
#define DFSCK_H

#include <stdbool.h>
#include <pthread.h>

#include "dfs.h"

#define KUIDT_INIT(value) (kuid_t){ value }
#define KGIDT_INIT(value) (kgid_t){ value }

#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define GLOBAL_ROOT_GID KGIDT_INIT(0)

#define ALLOC_SZ    100
#define UL_SZ       sizeof(unsigned long) 

/* Actual size of a directory inode */
#define __DIR_INODE_SZ      sizeof(struct dfs_inode) + sizeof(struct inode_extra)  
/* Size with internal padding, used for traversing raw data */
#define DIR_INODE_SZ        round_up(__DIR_INODE_SZ, DFS_META_SIZE_GRANULARITY) 

#define FILE_INODE_SZ       sizeof(struct dfs_inode)

#define DENTRY_BAD_THRESHOLD        2  
#define FILE_INODE_BAD_THRESHOLD    2
#define DIR_INODE_BAD_THRESHOLD     2
#define DATACHUNK_BAD_THRESHOLD     4

/* data structure checking return values */
#define TARGET_FOUND             -314

#define DENTRY_GOOD               0
#define DENTRY_BAD               -1
#define DENTRY_BAD_ADDR          -2
#define DENTRY_LOST_INODE        -3
#define DENTRY_LOST_NEXT         -4
#define DENTRY_LST_INO_NXT       -5
#define DENTRY_BAD_INODE         -6

#define INODE_GOOD                0
#define INODE_BAD                -1
#define INODE_BAD_ADDR           -2
#define INODE_LOST_DATA          -3

#define DATACHUNK_GOOD            0
#define DATACHUNK_BAD            -1
#define DATACHUNK_LOST_LCHLD     -2
#define DATACHUNK_LOST_RCHLD     -3
#define DATACHUNK_BAD_DATA       -4

#define NO_DATACHUNK_FOUND        0
#define NO_ROOT_CHUNK_FOUND      -1
#define FOUND_ROOT_DATACHUNK      1

#define RECOVERED_FILE_NAMELEN    16 

struct dentry_item {
	struct dfs_dentry *dentry; //mmapped addr
    int parent_inode_index;
    void *prev;
};

struct inode_item {
	struct dfs_inode *inode; //mmapped addr of inode
    int parent_inode_index;
    int data_index;  
	uint16_t nlink_count; //check inode nlink count
};

struct datachunk_item {
	//mmapped addr of datachunk
    struct dfs_datachunk *datachunk; 
    int parent_inode_index;
};

extern struct dfs_fs *sb;
extern struct lazy_list_head *llist_heads;
extern char *chunks;
extern void *mem, *image_mem;
extern size_t chunk_capacity_limit[DFS_META_FREE_BITMAP + 1];

#endif // DFSCK_H
