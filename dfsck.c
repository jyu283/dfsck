/*
 * DenseFS Consistency checKer (DFSCK) v2.0
 * A not-very-creatively-named checker for DenseFS: A Cache-Compact File System.
 * Capable of recovering the internal consistency of the file system from the
 * corruption of any number of metadata pointers (not including meta-metadata)
 * such as dentry next pointers, datachunk child pointers.
 *
 * AUTHOR'S NOTE:
 *     As the author of this program, I should like to extend to you, dear reader,
 * my most sincere apology for the undesirable effectiveness and lackluster
 * performance of this checker.
 *     I was meant to be on my summer holiday. Not that I'm complaining.
 *     Throughout this program's source code you will notice my weak attempt at
 * achieving a marginal degree of professionalism, and my ineffectual endeavour
 * to make this code as readable as possible. Again, sorry.
 *     Jerry Yu (jyu283@wisc.edu)
 *     17 August 2019
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "include/dfsck.h"
#include "include/dfs.h"
#include "include/stack.h"
#include "include/list.h"
#include "include/dfs_allocation.h"
#include "include/dfsck_util.h"
#include "include/interval_tree_util.h"
#include "rbtree.h"


#define DB_MODE         1   /* Set to 1 to enable debug printouts. */
/* Frequently used image addresses */
struct dfs_fs *sb;   // superblock
struct lazy_list_head *llist_heads;  // lazy list heads
char *chunks;    // start of chunks (where metadata is actually allocated)
void *mem, *image_mem;  // mem: start of mmap'd fs; img: start of actual image

static size_t chunk_size, meta_size, data_size;  
static struct gen_pool_chunk *metachunk, *datachunk;  // meta region, data region

/* Checker self-maintained record of all meta structures */
static struct dentry_item *dentries;
static struct inode_item *dirs, *files;
static struct datachunk_item *datachunks;
static size_t dentries_size = ALLOC_SZ, dirs_size = ALLOC_SZ,
              files_size = ALLOC_SZ, datachunks_size = ALLOC_SZ;
static int dentry_count = 0, file_count = 0, dir_count = 0, chunk_count = 0;
static struct stack *lost_files, *corrupt_datachunks, 
                    *bad_datachunks, *good_files, *corrupt_files;

/* Checker self-maintained metadata info */
static struct chunk_bitmap *meta_bitmaps;
static struct chunk_bitmap *img_meta_bitmaps;
static size_t *meta_chunk_capacity; 
static struct list **chunk_records;
static size_t checker_bitmap_num_bytes;
static unsigned long *checker_meta_bitmap;

/* Checker self-maintained data bitmap */
static unsigned long *data_bitmap; 
static unsigned long *img_data_bitmap;
static size_t data_bm_bytes;    // number of bytes in the data bitmap
static size_t d_bits_allocated = 0;;

/* Error counters */
static int bad_dentry_cnt = 0, bad_prev_cnt = 0, bad_next_cnt = 0, bad_inode_cnt = 0,
           bad_dot_cnt = 0, bad_dotdot_cnt = 0, bad_nlink_cnt = 0, bad_it_cnt = 0;
static int bad_interval_cnt = 0;

/* Other stuff */
size_t chunk_capacity_limit[DFS_META_FREE_BITMAP + 1];
static int dentries_traversed = 0;
static int lost_dentry_chunk = 0;
static unsigned long lost_dentry_offset = 0;
// TODO: this shouldnt be hard coded, whats the solution?
static int curr_dentry_size = 32;
static unsigned long total_good_file_bytes = 0, total_bad_file_bytes = 0;

/* Ignore these */
static int no_counter = 0, *NO_COUNTER = &no_counter;

/* Some function declarations because I can't be bothered to organise my code properly. */
static void DB_print_data_bitmap(unsigned long *bitmap);
static void DB_print_data_region(unsigned long *bitmap);
static void DB_print_meta_bitmap(struct chunk_bitmap *bitmap);
static void DB_print_check_meta_bitmap();
static void DB_print_bitmaps();
static void DB_compare_capacity();
static inline unsigned long DB_get_off(void *addr);
static void dfsck_exit();
static int traverse_bitmap(size_t size_index, struct dfs_dentry *dentry, struct dfs_inode *inode,
                    int (*fix_func)(struct dfs_dentry *, struct dfs_inode *, size_t, size_t));

/* 
 * Check if an address is within the bounds of the meta region.
 * USE IMAGE ADDRESSES.
 */
static inline int check_meta_addr(void *addr)
{
    if ((((unsigned long)addr) & 31) != 0)
        return 1;
    if (addr < mem_to_img(metachunk) || addr >= mem_to_img(datachunk))
        return 1;
    return 0;
}

/*
 * Check if an address is within the bounds of the data region.
 * USE IMAGE ADDRESSES.
 */
static inline int check_data_addr(void *addr)
{
    if ((((unsigned long)addr) & 31) != 0)
        return 1;
    if (addr < (void *)datachunk->start_addr || addr >= (void *)datachunk->end_addr)
        return 1;
    return 0;
}

/* DEBUG: Calculate offset based on memory address to address seen in hexdumps */
static inline unsigned long DB_get_off(void *addr)
{
    return (unsigned long)(mem_to_img(addr) - image_mem);
}

/*
 * Generate a random string. Used for lost+found files' names.
 */
static void rand_str(char *dest, size_t length) {
    char charset[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *dest++ = charset[index];
    }
    *dest = '\0';
}

static inline bool dentry_visited(struct dfs_dentry *dentry)
{
    for (int i = 0; i < dentry_count; i++) {
        if (dentries[i].dentry == dentry) {
            return true;
        }
    }
    return false;
}

static inline bool dir_inode_visited(struct dfs_inode *inode)
{
    for (int i = 0; i < dir_count; i++) {
        if (dirs[i].inode == inode) 
            return true;
    }
    return false;
}

static inline bool file_inode_visited(struct dfs_inode *inode)
{
    for (int i = 0; i < file_count; i++) {
        if (files[i].inode == inode) 
            return true;
    }
    return false;
}

static inline bool datachunk_visited(struct dfs_datachunk *dc)
{
    for (int i = 0; i < chunk_count; i++) {
        if (datachunks[i].datachunk == dc) {
            return true;
        }
    }
    return false;
}

/* Calculate the chunk that a structure at the given address resides in. */
static inline void *lazylist_get_chunk(void *addr)
{
    unsigned long relative_addr = addr - (void *)chunks;
    unsigned long offset = relative_addr % sb->chunk_size;
    return (void *)(addr - (void *)offset);
}

/* Calculates the number of chunk a structure at the given address resides in. */
static inline int lazylist_get_chunk_index(void *addr)
{
    return ((addr - (void *)chunks) / chunk_size);
}

static inline size_t lazylist_get_capacity(int chunk_index)
{
    if (chunk_records[chunk_index] == NULL)
        return 0;
    else 
        return chunk_records[chunk_index]->size;
}

static inline bool lazylist_get_firstrun(int chunk_index)
{
    return (meta_chunk_capacity[chunk_index] >> LAZY_LIST_HEAD_CHUNK_BIT);
}

static inline void meta_chunk_set_firstrun(int chunk_index)
{
    llist_heads[chunk_index].capacity |= 1UL << LAZY_LIST_HEAD_CHUNK_BIT;
}

static inline size_t meta_chunk_get_size_index(int chunk_index)
{
    size_t capacity = llist_heads[chunk_index].capacity;
    int left_shift = BITS_PER_LONG - 1 - LAZY_LIST_HEAD_INDEX_END_BIT;
    int right_shift = LAZY_LIST_HEAD_INDEX_START_BIT;
    return ((capacity << left_shift) >> left_shift) >> right_shift;
}

static inline void print_size_index_name(size_t size_index)
{
    if (size_index == 0)
        printf("FILE INO  ");
    else if (size_index == 1)
        printf("DATACHUNK ");
    else if (size_index == 2)
        printf("DIR INO   ");
    else {
        int size = (size_index - (DFS_META_DIR_INODE_BITMAP)) * DFS_META_SIZE_GRANULARITY;
        printf("DENTRY %-3d", size);
    }
}

static inline void meta_chunk_set_size_index(int chunk_index, int size_index)
{
    // bool print_flag = 0;
    // if (llist_heads[chunk_index].capacity == 0x3d3d3d3d3d3d3d3d)
        // print_flag = 1;
    // SET_CLR(MAG);
    // if (print_flag)
        // printf("meta_chunk_set_size_index: before: %lx, ", llist_heads[chunk_index].capacity);
    unsigned long reset_mask = ~((unsigned long)0xF << LAZY_LIST_HEAD_INDEX_START_BIT);
    llist_heads[chunk_index].capacity &= reset_mask;
    unsigned long size_index_mask = ((unsigned long)size_index) 
                                            << LAZY_LIST_HEAD_INDEX_START_BIT;
    llist_heads[chunk_index].capacity |= size_index_mask;
    // if (print_flag) {
        // printf("after: %lx. (si: %d ", llist_heads[chunk_index].capacity, size_index);
        // print_size_index_name(meta_chunk_get_size_index(chunk_index));
        // printf(").\n");
    // }
    // SET_CLR(RESET);
}

static inline bool meta_chunk_get_lock(int chunk_index)
{
    size_t capacity = llist_heads[chunk_index].capacity; 
    return (capacity & (1UL << LAZY_LIST_HEAD_LOCK_BIT));
}

static inline void meta_chunk_unlock(int chunk_index)
{
    llist_heads[chunk_index].capacity &= ~(1UL << LAZY_LIST_HEAD_LOCK_BIT);
}

static inline size_t meta_chunk_get_capacity(int chunk_index)
{
    size_t capacity = llist_heads[chunk_index].capacity;
    int shift = BITS_PER_BYTE - 1 - LAZY_LIST_HEAD_INDEX_START_BIT;
    return ((capacity << shift) >> shift);
}

static inline void meta_chunk_set_capacity(int chunk_index, size_t capacity)
{
    // printf(":: Setting capacity for chunk #%d.\n", chunk_index);
    unsigned long clear_mask, capacity_mask;
    clear_mask = 0x3FUL << LAZY_LIST_HEAD_INDEX_START_BIT;
    capacity_mask = (unsigned long)capacity;
    llist_heads[chunk_index].capacity &= clear_mask;
    llist_heads[chunk_index].capacity |= capacity_mask;
}

/*
 * Remove a dentry from the linked list of dentries in a directory inode.
 */
static void remove_dentry(struct dfs_inode *dir, struct dfs_dentry *dentry)
{
    struct dfs_dentry *curr_dentry = get_first_dentry(dir);
    if (curr_dentry == dentry) {
        dir->data.dirents.next = curr_dentry->list.next;
        return;
    }

    struct dfs_dentry *prev_dentry = curr_dentry;
    while (curr_dentry != NULL && curr_dentry != dentry) {
         prev_dentry = curr_dentry;
         curr_dentry = img_to_mem(curr_dentry->list.next);
    }

    if (curr_dentry != NULL) {
        prev_dentry->list.next = curr_dentry->list.next;
    }

    return;
}

/* Set a bit to 1. */
static void bitmap_set_bit(struct chunk_bitmap *bitmap, int chunk_index)
{
    int group = chunk_index / BITS_PER_UINT;
    int bit = chunk_index % BITS_PER_UINT;
    bitmap->ints[group] |= 1 << bit;
}

/* Set a bit to 0. */
static void bitmap_unset_bit(struct chunk_bitmap *bitmap, int chunk_index)
{
    int group = chunk_index / BITS_PER_UINT;
    int bit = chunk_index % BITS_PER_UINT;
    bitmap->ints[group] &= ~(1 << bit);
}

static bool bitmap_get_bit(struct chunk_bitmap *bitmap, int chunk_index)
{
    int group = chunk_index / BITS_PER_UINT;
    int bit = chunk_index % BITS_PER_UINT;
    if ((bitmap->ints[group] >> bit) % 2 == 0) {
        return 0;
    } else {
        return 1;
    }
}

static inline void image_flip_bit(int size_index, int chunk_index)
{
    struct chunk_bitmap *bitmap = (struct chunk_bitmap *)mem + size_index;
    if (bitmap_get_bit(bitmap, chunk_index) == 1) {  /* bit is currently 1 */
        bitmap_unset_bit(bitmap, chunk_index);
    } else {                                         /* bit is currently 0 */
        bitmap_set_bit(bitmap, chunk_index);
    }
}

static inline bool lazylist_get_bit(int size_index, int chunk_index)
{
    struct chunk_bitmap *bitmap = (struct chunk_bitmap *)mem + size_index;
    return bitmap_get_bit(bitmap, chunk_index);
}

static inline bool checker_meta_get_bit(int size_index, int chunk_index)
{
    struct chunk_bitmap *bitmap = &meta_bitmaps[size_index];
    return bitmap_get_bit(bitmap, chunk_index);
}

static inline int lazylist_get_chunk_size_index(int chunk_index)
{
    unsigned long capacity = llist_heads[chunk_index].capacity;
    int left_shift = 63 - LAZY_LIST_HEAD_INDEX_END_BIT;
    int right_shift = left_shift + LAZY_LIST_HEAD_INDEX_START_BIT;
    return ((capacity << left_shift) >> right_shift);
} 

static inline void lazylist_set_chunk_size_index(int chunk_index, unsigned long size_index)
{
    llist_heads[chunk_index].capacity |= size_index << LAZY_LIST_HEAD_INDEX_START_BIT;
}

static bool get_data_block_status(char *bitmap, int block_index)
{
    int group = block_index / BITS_PER_BYTE;
    int bit = block_index % BITS_PER_BYTE;
    return (*(bitmap + group) >> bit) % 2;
}

static inline bool get_img_data_block_status(int block_index)
{
    return get_data_block_status((char *)img_data_bitmap, block_index);
}

static inline bool get_checker_data_block_status(int block_index)
{
    return get_data_block_status((char *)data_bitmap, block_index);
}

static inline bool compare_data_block_status(int block_index)
{
    return (get_img_data_block_status(block_index) == get_checker_data_block_status(block_index));
}

/* Returns image address */
static inline void *get_data_addr(int block_index)
{
    return ((void *)datachunk->start_addr + block_index * PGSIZE);
}

static int traverse_bitmap(size_t size_index, struct dfs_dentry *dentry, struct dfs_inode *inode,
                    int (*fix_func)(struct dfs_dentry *, struct dfs_inode *, size_t, size_t))
{
    int ret = 0, tmp;
    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        if (meta_chunk_get_capacity(i) == 0)
            continue;
        if (meta_chunk_get_size_index(i) == size_index) {
            tmp = (*fix_func)(dentry, inode, i, size_index);
            if (tmp == TARGET_FOUND)
                return TARGET_FOUND;
            else
                ret += tmp;
        }
    }
    return ret;
}

// /* Finds a chunk that cointains dentries with the curr_dentry_size
//    if none are found, then it increments curr_dentry_size and looks
//    for those chunks and so on...*/
// static int find_dentry_chunk()
// {
//     int ret = 0, tmp;
//     for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
//         if (meta_chunk_get_capacity(i) == 0)
//             continue;
//         if (meta_chunk_get_size_index(i) == size_index) {
//             tmp = (*fix_func)(dentry, inode, i, size_index);
//             if (tmp == TARGET_FOUND)
//                 return TARGET_FOUND;
//             else
//                 ret += tmp;
//         }
//     }
//     return ret;
// }

/*
 * Search a chunk for dentries that belong to a directory inode
 * and add them to the end of the dentry list
 */
static int relink_dentries(struct dfs_dentry *dentry, struct dfs_inode *dir_inode,
                                            size_t chunk_index, size_t size_index)
{
    int found_count = 0;
    struct dfs_dentry *curr_dentry = (struct dfs_dentry *)
                                     ((char *)chunks + chunk_index * sb->chunk_size);

    struct dfs_dentry *list_tail = get_first_dentry(dir_inode);
    void *target_addr = mem_to_img(dir_inode);
    struct stack *visited_dents = (struct stack *)dentry;

    // if list is not empty, move tail to the end
    if (list_tail != NULL) {
        while (list_tail->list.next != NULL) {
            list_tail = img_to_mem(list_tail->list.next);
            if (list_tail != NULL && check_meta_addr(list_tail)) {
                break; 
            }
        }
    }

    SET_CLR(YEL);
    for (int i = 0; i < chunk_capacity_limit[size_index]; i++) {
        if (curr_dentry->parent == target_addr) {
            bool visited = stack_find(curr_dentry, visited_dents);
            if (!visited) {
                if (DB_MODE) {
                    printf(GRN "\t> Found lost dentry (%s) at %lx (size = %ld)!\n" RESET,
                        curr_dentry->name, DB_get_off(curr_dentry), dfs_dentry_size(curr_dentry));
                }
                found_count++;
                // Attach newly found dentry to the end of the list
                if (list_tail == NULL) {  // empty list
                    dir_inode->data.dirents.next = mem_to_img(curr_dentry);
                } else {
                    list_tail->list.next = (void *)unmap_dentry(curr_dentry);
                }
                list_tail = curr_dentry;
                list_tail->list.next = NULL;
            }
        }
        curr_dentry = (void *)curr_dentry + 
                        round_up(dfs_dentry_size(curr_dentry), DFS_META_SIZE_GRANULARITY);
    }
    SET_CLR(RESET);
    return found_count;
}

/*
 * TODO: Might not need three status codes.
 * NOTE: This fix_func function interprets the dentry parameter as
 * the PARENT datachunk, i.e. the datachunk whose child(ren) the function is trying
 * to recover.
 */
static int find_child_datachunk(struct dfs_dentry *datachunk, struct dfs_inode *lost_child,
                                            size_t chunk_index, size_t size_index)
{
    struct dfs_datachunk *parent_dc = (struct dfs_datachunk *)datachunk;
    struct dfs_datachunk *curr_dc = (struct dfs_datachunk *)
                                    ((char *)chunks + chunk_index * sb->chunk_size);
    int child = *((int *)lost_child);
    for (int i = 0; i < chunk_capacity_limit[size_index]; i++) {
        // Datachunk's parent must first of all be the one in question
        if (get_datachunk_parent(curr_dc) != parent_dc) {
            curr_dc = (void *)curr_dc + round_up(sizeof(struct dfs_datachunk), 
                                                            DFS_META_SIZE_GRANULARITY);
            continue;
        }
        if (child == -1) {  // recover left child
            if (curr_dc->it.__subtree_last + 1 == parent_dc->it.start) {
                // printf(GRN "    Found left child of %p at %p!\n" RESET, parent_dc, curr_dc);
                parent_dc->it.rb.rb_left = mem_to_img(curr_dc);
                return TARGET_FOUND;
            }
        }
        if (child == 1) {  // recover right child
            if (curr_dc->it.__subtree_last == parent_dc->it.__subtree_last) {
                // printf(GRN "    Found right child of %p at %p!\n" RESET, parent_dc, curr_dc);
                parent_dc->it.rb.rb_right = mem_to_img(curr_dc);
                return TARGET_FOUND;
            }
        }
        curr_dc = (void *)curr_dc + round_up(sizeof(struct dfs_datachunk), 
                                                                DFS_META_SIZE_GRANULARITY);
    }
    return 0;
}

/*
 * Search a chunk for a root datachunk (parent node is NULL) that points back to the 
 * given file inode. Used to restore the link between a file inode and its root datachunk.
 */
static int find_root_datachunk(struct dfs_dentry *dentry, struct dfs_inode *file_inode,
                                                   size_t chunk_index, size_t size_index)
{
    int ret = NO_DATACHUNK_FOUND;   // desired root datachunk is not in this chunk
    struct dfs_datachunk *curr_dc = (struct dfs_datachunk *)
                                    ((char *)chunks + chunk_index * sb->chunk_size);
    for (int i = 0; i < chunk_capacity_limit[size_index]; i++) {
        if (curr_dc->parent == unmap_inode(file_inode)) {
            ret = NO_ROOT_CHUNK_FOUND;  // found datachunk that belongs to this file
            if (get_datachunk_parent(curr_dc) == NULL) {
                // printf(GRN "\t> Found lost root datachunk at %p!\n" RESET, curr_dc);
                file_inode->data.chunks.rb_node = mem_to_img(curr_dc);
                ret = TARGET_FOUND;  // found desired root datachunk
                break;
            }
        }
        curr_dc = (void *)curr_dc + round_up(sizeof(struct dfs_datachunk), 
                                                                DFS_META_SIZE_GRANULARITY); 
    }
    return ret;
}

static int find_dir_inode(struct dfs_dentry *dentry, struct dfs_inode *parent_dir_inode,
                                              size_t chunk_index, size_t size_index)
{
    int inodes_traversed = 0;
    struct dfs_inode *curr_inode = (struct dfs_inode *)
                               ((char *)img_to_mem(sb->chunks) + chunk_index * sb->chunk_size);
    // FIXME: This is not safe. Need a good traverse function
    struct dfs_inode *curr_parent;
    while ((void *)curr_inode < img_to_mem(llist_heads[chunk_index].head)) {
        curr_parent = curr_inode->extra->parent;
        // printf(MAG ":: DEBUG: curr: %lx, curr_parent: %lx, target: %lx. [of chunk #%ld]\n" RESET,
                    // DB_get_off(curr_inode), DB_get_off(img_to_mem(curr_parent)),
                    // DB_get_off(parent_dir_inode), chunk_index);
        if (curr_parent == unmap_inode(parent_dir_inode)
                                && curr_inode != map_inode(sb->rootdir.inode)) {
            // Make sure no other dentry in the same directory points to this inode
            bool visited = 0;
            struct dfs_dentry *curr_dentry = get_first_dentry(parent_dir_inode);
            while (curr_dentry != NULL) {
                if (curr_dentry->inode == unmap_inode(curr_inode)) {
                    visited = 1;
                    break;
                }
                curr_dentry = img_to_mem(curr_dentry->list.next);
            }

            if (!visited) {
                if (DB_MODE) {
                printf(GRN "  > Found lost dir inode at %p (%lx)! (#%d of %lx ~ %lx)\n" RESET,
                        curr_inode, DB_get_off(curr_inode), inodes_traversed,
                        DB_get_off((char *)chunks + chunk_index * sb->chunk_size),
                        DB_get_off((char *)chunks + (chunk_index + 1) * sb->chunk_size));
                }
                dentry->inode = unmap_inode(curr_inode);
                return TARGET_FOUND;
            }
        }
        curr_inode = (void *)curr_inode + DIR_INODE_SZ;
        inodes_traversed++;
    }
    return 0;
}

/* 
 * Given a dentry missing its contents, look through the bitmap to find
 * unrecorded dentries that have back pointers to the directory inode,
 * and rebuild the dentry linked list in the inode, as well as add the 
 * recovered dentries to the array to be checked later.
 */
static void recover_dentries(struct dfs_inode *dir_inode, struct stack *visited_dents)
{
    int total_found = 0;
    if (DB_MODE)
        printf(BLU ":: Attempting to recover dentries, directory inode: %p.\n" RESET, dir_inode);
    for (int size_index = DFS_META_DIR_INODE_BITMAP + 1;
                            size_index < DFS_META_FREE_BITMAP; size_index++) {
        total_found += traverse_bitmap(size_index, 
                                    (void *)visited_dents, dir_inode, &relink_dentries);
    }
    if (DB_MODE)
        printf(BLU "  Total: recovered %d dentries.\n" RESET, total_found);
}

/*
 * Given a file inode missing its root datachunk, look through the bitmap for 
 * datachunk allocations to find datachunks that point back to the file inode
 * and is a root (parent = NULL). Once found, relink the root to the file inode.
 */
static void recover_root_datachunk(struct dfs_inode *file_inode)
{
    int ret;
    // printf(BLU "  Attempting to recover root datachunk, target inode: %p.\n" RESET,
                                                                // unmap_inode(file_inode));
    // Search entire metadata region for root datachunk
    int size_index = DFS_META_DATACHUNK_BITMAP;
    ret = traverse_bitmap(size_index, NULL, file_inode, &find_root_datachunk);

    if (ret == TARGET_FOUND) {
        // printf(GRN "  Root datachunk is recovered.\n" RESET);
        return;
    } else if (ret == NO_ROOT_CHUNK_FOUND) {
        // TODO: Gather all datachunks and reconstruct tree
    } else if (ret == NO_DATACHUNK_FOUND) {
        file_inode->data.chunks.rb_node = NULL;
    }
}

/*
 * Recover a datachunk's lost child.
 * lost_child:   -1 = left_child; 0 = both children; 1 = right_child
 */
static void recover_datachunk_child(struct dfs_datachunk *dc, int lost_child)
{
    if (lost_child == -1) {
        // printf(BLU "  Attempting to recover left child of datachunk %p.\n" RESET, dc);
        dc->it.rb.rb_left = NULL;
    } else if (lost_child == 1) {
        // printf(BLU "  Attempting to recover right child of datachunk %p.\n" RESET, dc);
        dc->it.rb.rb_right = NULL;
    } else {
        // printf(BLU "  Attempting to recover both children of datachunk %p.\n" RESET, dc);
        dc->it.rb.rb_left = NULL;
        dc->it.rb.rb_right = NULL;
    }

    int size_index = DFS_META_DATACHUNK_BITMAP;
    int ret;
    ret = traverse_bitmap(size_index, (void *)dc, 
                                    (void *)&lost_child, &find_child_datachunk);
    if (ret != TARGET_FOUND) {
        // printf(YEL "    No datachunk found.\n" RESET);
        /*printf(YEL "    DEBUG: start: %lx last: %lx st_last: %lx, parent: %p.\n" RESET,*/
                                /*dc->it.start, dc->it.last, dc->it.__subtree_last, dc);*/
    }
}

/*
 * Given a dentry with its inode missing, look through the bitmap for directory inode
 * allocations to find inodes whose ".." dentries point to the inode which contains 
 * the parameter dentry. Then look for an inode that none of these dentries are linked to.
 */
static void recover_dir_inode(struct dfs_dentry *dentry, struct dfs_inode *parent_inode)
{
    if (DB_MODE)
        printf(BLU ":: Attempting to recover inode of dentry %s (%lx), target parent %p.\n" RESET,
                                               dentry->name, DB_get_off(dentry), parent_inode);
    // Scan through directory inode bitmap
    int size_index = DFS_META_DIR_INODE_BITMAP;
    traverse_bitmap(size_index, dentry, parent_inode, &find_dir_inode);
}

/* Check the integrity and correctness of the fields in root_dentry */
static void check_root_dentry(struct dfs_dentry *root_dentry)
{
    struct dfs_inode *root_inode = (struct dfs_inode *)sb->chunks;
    if (DB_MODE)
        printf("\n:: Checking root dentry... (root inode: %p)\n", img_to_mem(root_inode));

    check_ptr(root_dentry->list.next, NULL,  "root dentry next", NO_COUNTER);
    check_ptr(root_dentry->parent, NULL, "root dentry parent", NO_COUNTER);
    check_ptr(root_dentry->inode, root_inode, "root dentry inode address", NO_COUNTER);
    check_val(root_dentry->refs.refcount.refs.counter, 0, 
            "root dentry ref count", NO_COUNTER);
    check_val(root_dentry->namelen, 0, "root dentry name length", NO_COUNTER);
    check_val(root_dentry->name[0], '\0', "root dentry name", NO_COUNTER);
    if (DB_MODE)
        printf(GRN "  Dentry good!\n" RESET);
}

/* Checks if the . and .. entries in of an inode are correct. */
static int check_dot_dents(struct dfs_inode *inode, struct dfs_inode *parent_inode)
{
    int err_cnt = 0;
    check_ptr(inode->extra->parent, mem_to_img(parent_inode), 
                                            "inode parent pointer", &err_cnt);
    return err_cnt;
}

/* Check the integrity and correctness of the root inode */
static void check_root_inode(struct dfs_inode *root_inode)
{
    check_val(root_inode->pincount.refs.counter, 0, "root ref count", NO_COUNTER);

    if (root_inode->data.dirents.next != NULL
            && check_meta_addr(root_inode->data.dirents.next)) {
        if (DB_MODE)
            printf(RED "Corrupt: root inode data corrupted. ptr: %p\n" RESET, 
                                                        root_inode->data.dirents.next);
        root_inode->data.dirents.next = NULL;
        if (DB_MODE)
            printf("Recovering root directory contents...\n");
        recover_dentries(root_inode, NULL);
        bad_dentry_cnt++;
    }

    check_dot_dents(root_inode, root_inode);
}

/*
 * Checks the integrity of the root dentry and the root inode itself.
 * Adds the dentry and inode to respective checker data structures.
 */
static inline void check_root()
{
    struct dfs_dentry *root_dentry = &sb->rootdir;
    check_root_dentry(root_dentry);
    check_root_inode(img_to_mem(root_dentry->inode));
}

static inline unsigned int get_imeta_chksum(struct imeta *p)
{
    return crc32b((unsigned char *)p, 
                        sizeof(struct imeta) - sizeof(((struct imeta *)0)->chksum));
}

static void copy_imeta(struct imeta *dst, struct imeta *src)
{
    dst->uid.val = src->uid.val;
    dst->gid.val = src->gid.val;
    dst->mode = src->mode;
    dst->refs = src->refs;
    dst->chksum = get_imeta_chksum(dst);
}

static inline int imeta_is_unused(struct imeta *imeta) {
    if (imeta->refs == 0)
        return 1;
    else
        return 0;
}

static inline void print_imeta(struct imeta *imeta)
{
    printf("uid: %d, gid: %d, mode: %d, refs: %d, chksum: %d.\n",
            imeta->uid.val, imeta->gid.val, imeta->mode, imeta->refs, imeta->chksum);
}

/* FIXME
 * TODO: What if an index is not used?
 * Check the imeta array 
 */
static int check_imeta_arr()
{
    struct imeta *orig = img_to_mem(sb->imeta.arr);
    struct imeta *dup = img_to_mem(sb->imeta.dup_arr);
    struct imeta *p, *p_dup;    // loop var

    if (DB_MODE)
        printf(":: Checking imeta array...\n");

    for (int i = 1; i < sb->imeta.sz; i++) {
        p = orig + i;
        p_dup = dup + i;

        if (imeta_is_unused(p) && imeta_is_unused(p_dup))
            continue;
        
        unsigned int p_chksum = get_imeta_chksum(p);
        unsigned int p_dup_chksum = get_imeta_chksum(p_dup);
        /* both chksum values check out */
        if (p->chksum == p_chksum && p_dup->chksum == p_dup_chksum)
            continue;
        /* orig corrupt and duplicate good */
        if (p->chksum != p_chksum && p_dup->chksum == p_dup_chksum) {
            if (DB_MODE)
                printf(YEL "Corrupt: imeta item #%d corrupted in first copy.\n" RESET, i);
            copy_imeta(p, p_dup);
            continue;
        }
        /* orig good and duplicate corrupt */
        if (p->chksum == p_chksum && p_dup->chksum != p_dup_chksum) {
            if (DB_MODE)
                printf(YEL "Corrupt: imeta item #%d corrupted in second copy.\n" RESET, i);
            copy_imeta(p_dup, p);
            continue;
        }
        /* Both c**ked. */
        if (p->chksum != p_chksum && p_dup->chksum != p_dup_chksum) {
            // TODO: What to do? You're kinda screwed.
            if (DB_MODE) {
                SET_CLR(RED);
                printf("Corrupt: imeta item #%d is corrupt and not recoverable.\n", i);
                printf(" [1]");
                print_imeta(p);
                printf(" [2]");
                print_imeta(p_dup);
                SET_CLR(RESET);
            }
            return -1;
        }
    }
    
    if (DB_MODE)
        printf(GRN "  Imeta array checks out!\n" RESET);
    return 0;
}

/* 
 * Select the majority (most frequent occuring candidate) from an array.
 * Used to confirm the location of the image starting location just in case
 * sb->mem is corrupted.
 */
static void *select_majority(void **candidates, int num_candidates)
{
    void **unique_candidates = calloc(num_candidates,sizeof(void*));
    int *counts = calloc(num_candidates,sizeof(int));
    int highest = -1;
    void *majority;
    int num_unique = 0;

    // counting
    for (int i = 0; i < num_candidates; i++) {
        int duplicate = 0;
        for (int j = 0; j < num_unique; j++) {
            if (candidates[i] == unique_candidates[j]) {
                duplicate = 1;
                counts[j]++;
                break;
            }
        }
        if (!duplicate) {
            unique_candidates[num_unique] = candidates[i];
            counts[num_unique]++;
            num_unique++;
        }
    }

    // selection
    for (int i = 0; i < num_unique; i++) {
        if (counts[i] > highest){
            highest = counts[i];
            majority = unique_candidates[i];
        }
    }
    free(unique_candidates);
    free(counts);
    return majority;
}

/*
 *  TODO: Find as many ways to calculate the location of mem as possible
 *  and use select_majority to pick the one most likely to be the true
 *  location mem.
 */
static void *find_image_mem(struct dfs_fs *sb)
{
    void *mem_candidates[16];

    mem_candidates[0] = sb->mem;

    /*return select_majority(mem_candidates, 16);*/
    return mem_candidates[0];
}

/* Check the integrity and correctness of fields in the data_pool data structre. */
static void check_data_pool(struct gen_pool *data_pool)
{
    check_val(data_pool->lock.rlock.raw_lock.lock, 0, "data_pool lock", NO_COUNTER);
    check_ptr(data_pool->chunks.next, mem_to_img(datachunk), 
                                                "data pool next address", NO_COUNTER);
    check_ptr(data_pool->chunks.prev, mem_to_img(datachunk), 
                                                "data pool prev address", NO_COUNTER);
    check_val(data_pool->min_alloc_order, DFS_DATA_ALLOCORDER, 
                                                "data pool alloc order", NO_COUNTER);
    // ignore algo field
    check_ptr(data_pool->data, NULL, "data pool data address", NO_COUNTER);
    check_ptr(data_pool->name, NULL, "data pool name", NO_COUNTER);
}

static inline size_t get_imeta_size(size_t meta_size)
{
    /* Copied from densefs.c */
    size_t imeta_sz = (meta_size >> 6) / sizeof(struct imeta_list_node);
    if (imeta_sz > (metaidx_t)(-1) / DFS_IMETA_PER_LIST_NODE)
        imeta_sz = (metaidx_t)(-1) / DFS_IMETA_PER_LIST_NODE;
    else if (imeta_sz < 4)
        imeta_sz = 4;
    return imeta_sz;
}

/* FIXME: Add new changes.
 * Load data from the superblock while simultaneously making sure 
 * the information stored in the superblock is not corrupted.
 * 
 * Refer to mount_dfs in densefs.c for detailed arrangement within the superblock.
 */
static void load_superblock(size_t fs_size) 
{
    sb = (struct dfs_fs *)mem; 

    SET_CLR(YEL);

    image_mem = find_image_mem(sb);
    check_ptr(sb->mem, image_mem, "file system start address in superblock", NO_COUNTER);
    check_val(sb->size, fs_size, "file system size in superblock", NO_COUNTER);

    size_t meta_size = fs_size >> 4;  /* ~6% of entire file system */

    // FIXME: can't seem to get imeta_sz right?
    // size_t imeta_sz = get_imeta_size(meta_size);
    size_t imeta_sz = (meta_size >> 6) / sizeof(struct imeta_list_node);
    if (imeta_sz > (metaidx_t)(-1) / DFS_IMETA_PER_LIST_NODE)
        imeta_sz = (metaidx_t)(-1) / DFS_IMETA_PER_LIST_NODE;
    else if (imeta_sz < 4)
        imeta_sz = 4;
    check_val(sb->imeta.sz, imeta_sz, "imeta size in superblock", NO_COUNTER);

    int imeta_space = DFS_CACHE_ROUND_UP(imeta_sz * sizeof(struct imeta_list_node));
    meta_size -= imeta_space + sizeof(struct lazy_list_head) * DFS_META_NUM_CHUNKS;

    struct imeta_list_node *imeta_arr = image_mem + DFS_SUPERBLOCK_SIZE;
    check_ptr(sb->imeta.arr, imeta_arr, "imeta copy #1 pointer in superblock", NO_COUNTER);

    // TODO: free stack of imeta?

    llist_heads = (struct lazy_list_head *)(image_mem + DFS_SUPERBLOCK_SIZE + imeta_space);
    check_ptr(sb->heads, llist_heads, "lazy list pointer in superblock", NO_COUNTER);

    chunks = (char *)(llist_heads + DFS_META_NUM_CHUNKS);
    check_ptr(sb->chunks, chunks, "lazy list chunks pointer in superblock", NO_COUNTER);
    chunks = (char *)img_to_mem(chunks);

    chunk_size = meta_size / (DFS_META_NUM_CHUNKS * DFS_CACHE_SIZE);
    if (chunk_size * DFS_META_NUM_CHUNKS * DFS_CACHE_SIZE 
                                + DFS_META_NUM_CHUNKS * DFS_CACHE_SIZE / 2 >= meta_size) {
        chunk_size++;
    }
    chunk_size = chunk_size * DFS_CACHE_SIZE;
    check_val(sb->chunk_size, chunk_size, "chunk size in superblock", NO_COUNTER);

    /* My god what on Earth is this? */
    struct imeta_list_node *imeta_dup = (struct imeta_list_node *)(image_mem + DFS_SUPERBLOCK_SIZE
            + imeta_space + (chunk_size + sizeof(struct lazy_list_head)) * DFS_META_NUM_CHUNKS);
    check_ptr(sb->imeta.dup_arr, imeta_dup, "imeta copy #2 pointer in superblock", NO_COUNTER);

    meta_size = (chunk_size + sizeof(struct lazy_list_head)) 
                                            * DFS_META_NUM_CHUNKS + imeta_space * 2;
    check_val(sb->meta_size, meta_size, "meta size in superblock", NO_COUNTER);

    SET_CLR(RESET);

    metachunk = (struct gen_pool_chunk *)(mem + DFS_SUPERBLOCK_SIZE);
    datachunk = (struct gen_pool_chunk *)round_up((unsigned long)metachunk + meta_size, PGSIZE);

    llist_heads = (struct lazy_list_head *)img_to_mem(llist_heads);
    // printf(":: DEBUG: lazy list heads start location: %lx.\n", DB_get_off(llist_heads));

    data_size = fs_size - DFS_SUPERBLOCK_SIZE - meta_size;

    /* Calculate in advance the capacity limits of each lazy list chunk */
    chunk_capacity_limit[DFS_META_FILE_INODE_BITMAP] = 
                                    sb->chunk_size / FILE_INODE_SZ;
    chunk_capacity_limit[DFS_META_DATACHUNK_BITMAP] =  
                                    sb->chunk_size / sizeof(struct dfs_datachunk);
    chunk_capacity_limit[DFS_META_DIR_INODE_BITMAP] = 
                                    sb->chunk_size / DIR_INODE_SZ;
    for (int i = DFS_META_DIR_INODE_BITMAP + 1; i < DFS_META_FREE_BITMAP; i++) {
        chunk_capacity_limit[i] = sb->chunk_size / 
                        (DFS_META_SIZE_GRANULARITY * (i - DFS_META_DIR_INODE_BITMAP));
    }

    if (DB_MODE) {
        SET_CLR(GRN);
        printf("DEBUG: limits: \n");
        for (int i = 0; i < DFS_META_FREE_BITMAP; i++) {
            printf("%ld ", chunk_capacity_limit[i]);
        }
        SET_CLR(RESET);
    }

    check_data_pool(&sb->data_pool);
    if (DB_MODE)
        printf(GRN "\n>> Superblock check completed.\n\n" RESET);
}

/*
 * Check if the checker has already checkered a certain structure at the given address
 * This bitmap is a tradition bitmap that is a record of all the chunks in the lazy list.
 * USES IMAGE ADDRESSES
 */
static int check_checker_meta_bitmap(void *addr, int size)
{
    void *addr_copy = addr;
    void *chunks_start = chunks;
    void *chunks_end = datachunk;
    unsigned long chunk_offset;
    int index, bit;
    int bitmap_unit = DFS_META_SIZE_GRANULARITY;

    addr = img_to_mem(addr);
    size = round_up(size, bitmap_unit);

    for (int i = 0; i < size / bitmap_unit; i++) {
        if (addr > chunks_end || addr < chunks_start || ((unsigned long)addr & 31) != 0) {
            printf(RED "Error: ccmb: address (%p, %lx) outside valid metadata \
                    allocation area.\n" RESET, addr, DB_get_off(addr));
            return -1;
        }
        chunk_offset = addr - chunks_start;
        index = chunk_offset >> 11;
        bit = (chunk_offset >> 5) & 63;
        if (((checker_meta_bitmap[index] >> bit) & 1) == 1) {
            printf(RED "Error: ccmb: meta space already in use. (orig: %p (%lx), offn: %p (%lx))\n" RESET, 
		    img_to_mem(addr_copy), DB_get_off(img_to_mem(addr_copy)), addr, DB_get_off(addr));
            return 1;
        }
        addr += 32;
    }
    return 0;  
}

/*
 * USES IMAGE ADDRESSES
 */
static int update_checker_meta_bitmap(void *addr, int size)
{
    void *chunks_start = chunks;
    void *chunks_end = datachunk;
    unsigned long chunk_offset;
    int index, bit;
    int bitmap_unit = DFS_META_SIZE_GRANULARITY;

    addr = img_to_mem(addr);
    size = round_up(size, bitmap_unit);

    for (int i = 0; i < size / bitmap_unit; i++) {
        if (addr > chunks_end || addr < chunks_start) {
            printf(RED "Error: ucmb: address (%p) outside valid metadata \
                    allocation area.\n" RESET, addr);
            return -1;
        }
        if (((unsigned long)addr & 31) != 0) {
            printf(RED "Error: ucmb: address not properly aligned.\n" RESET);
            return -1;
        }
        chunk_offset = addr - chunks_start;
        index = chunk_offset >> 11;
        bit = (chunk_offset >> 5) & 63;
        if (((checker_meta_bitmap[index] >> bit) & 1) == 1) {
            printf(RED "Error: ucmb: meta space already in use. (%p, %lx)\n" RESET,
                                                                addr, DB_get_off(addr));
            return 1;
        } else {
            checker_meta_bitmap[index] |= (1ULL << bit);
            // TODO: bits allocated for update avail?
        }
        addr += 32;
    }
    return 0;
}

/* 
 * Given an address and the size of the structure it points to,
 * update the bitmaps and the lazy list head it corresponds to.
 * TAKES IMAGE ADDR AND CONVERTS IT TO MEM ADDR
 */
static int lazylist_alloc(void *addr, int size_index, size_t size)
{
    if (check_meta_addr(addr)) {
        printf(RED "Error: lla: attempting to update bitmap with " \
                "non-meta region adress %p.\n" RESET, addr);
        return -1;
    }

    addr = img_to_mem(addr);
    int chunk_index = lazylist_get_chunk_index(addr); 
    
    // Add address to the chunk record, or if the address has already been
    // recorded before, return an error.
    if (chunk_records[chunk_index] == NULL) {
        chunk_records[chunk_index] = list_init();
    }
    if (list_find(addr, chunk_records[chunk_index])) {
        printf(RED "Error: lla: address %p is already in use.\n" RESET, addr);
        return -1;
    }

    int group = chunk_index / BITS_PER_UINT;
    int bit = chunk_index % BITS_PER_UINT;

    /*printf("chunk_index: %d, size_index: %d, group: %d, bit: %d\n",*/
    /*chunk_index, size_index, group, bit);*/

    struct chunk_bitmap *bitmap = meta_bitmaps + size_index;
    struct chunk_bitmap *free_bitmap = meta_bitmaps + DFS_META_FREE_BITMAP;

    // update corresponding head
    // TODO: first run bit stuff, is there anything to be done?
    size_t capacity_limit = chunk_capacity_limit[size_index];

    // Update bitmap
    if ((free_bitmap->ints[group] >> bit) % 2 == 1) {   /* free bit is 1 */
        // empty chunk, set free bit to 0, chunk bit to 1 (both indicate in use.)
        bitmap->ints[group] |= 1 << bit;
        free_bitmap->ints[group] &= ~(1 << bit);
    } else {   /* free bit is 0 */
        // free bit and chunk bit both 0, indicates full chunk
        if ((bitmap->ints[group] >> bit) % 2 == 0 
                    && lazylist_get_capacity(chunk_index) > 0) {
            if (DB_MODE) {
                printf(RED "Error: chunk already full. " \
                            "(index: %d, current capacity: %ld)\n" RED, 
                                chunk_index, lazylist_get_capacity(chunk_index));
            }
            return 1;
        }
        // Non-empty chunk, set bit to 0 if becomes full after update
        if (lazylist_get_capacity(chunk_index) + 1 >= capacity_limit) { 
            // unset bit in chunk bitmap for this size
            // if (DB_MODE)
                // printf(MAG ":: DEBUG: Chunk #%d became full.\n" RESET, chunk_index);
            bitmap->ints[group] &= ~(1 << bit); 
        } else {
            /*printf("Chunk not full nor empty.\n");*/
        }
    }
    
    list_insert(list_new_node(addr), chunk_records[chunk_index]);
    meta_chunk_set_size_index(chunk_index, size_index);

    return 0; 
}

/* 
 * Does what it says.
 * TAKES IMAGE ADDRESSES. (just for the sake of consistency)
 */
static void lazylist_free(void *addr, int size_index, size_t size)
{
    if (check_meta_addr(addr)) {
        printf(RED "Error: llf: attempting to free a non-meta address (%p).\n" RESET, addr);
        return;
    }

    addr = img_to_mem(addr);
    int chunk_index = lazylist_get_chunk_index(addr);
    if (list_remove_by_value(addr, chunk_records[chunk_index]) == -1) {
        printf(RED "Error: llf: address %p in chunk %d is not used.\n" RESET, 
                                                                    addr, chunk_index);
    }

    int group = chunk_index / BITS_PER_UINT;
    int bit = chunk_index % BITS_PER_UINT;

    struct chunk_bitmap *bitmap = meta_bitmaps + size_index;
    struct chunk_bitmap *free_bitmap = meta_bitmaps + DFS_META_FREE_BITMAP;

    if ((free_bitmap->ints[group] >> bit) % 2 == 1) {
        // CASE: chunk already empty
        printf(RED "Error: attempting to free address in empty chunk.\n" RESET);
        return;
    } else {
        // CASE: chunk currently full but about to become unfull, set size map to 1
        if ((bitmap->ints[group] >> bit) % 2 == 0
                && lazylist_get_capacity(chunk_index) > 0) {
            bitmap->ints[group] |= (1 << bit); 
            return;
        } 
        // CASE: chunk will become empty after freeing
        if (lazylist_get_capacity(chunk_index) == 0) {
            free_bitmap->ints[group] |= (1 << bit);
            bitmap->ints[group] &= ~(1 << bit);
        }
    }
}

static int check_data_bitmap(void *addr, int size)
{
    void *data_start = (void *)datachunk->start_addr;
    void *data_end = (void *)datachunk->end_addr;
    unsigned long data_addr;
    int index, bit;

    size = round_up(size, PGSIZE);
    for (int i = 0; i < size / PGSIZE; i++) {
        if (!(addr >= data_start && addr <= data_end) || ((unsigned long)addr & 31) != 0) {
            printf(RED "Error: Address is outside of Datachunk.\n" RESET);
            return 1;
        }
        data_addr = addr - data_start;
        index = data_addr >> 18; 
        bit = (data_addr >> 12) & 63;
        if (((data_bitmap[index] >> bit) & 1) == 1) {
            printf(RED "Error: Data space already in use.\n" RESET);
            return 1;
        } 
        addr = addr + PGSIZE;
    }
    return 0;
}

/*
 * Update the checker-maintained data bitmap for a given size at a given addr.
 * Ported from old dfsck.
 */
static int update_data_bitmap(void *addr, int size)
{
    void *data_start = (void *)datachunk->start_addr;
    void *data_end = (void *)datachunk->end_addr;
    unsigned long data_addr;
    int index, bit;

    size = round_up(size, PGSIZE);
    for (int i = 0; i < size / PGSIZE; i++) {
        if (!(addr >= data_start && addr <= data_end) || ((unsigned long)addr & 31) != 0) {
            printf(RED "Error: Address is outside of data region.\n" RESET);
            return 1;
        }
        data_addr = addr - data_start;
        index = data_addr >> 18; 
        bit = (data_addr >> 12) & 63;
        if (((data_bitmap[index] >> bit) & 1) == 1) {
            printf(RED "Error: Data space already in use.\n" RESET);
            return 1;
        } else {
            data_bitmap[index] = data_bitmap[index] | (1ULL << bit);
            d_bits_allocated++;
        }
        addr = addr + PGSIZE;
    }
    return 0;
}

/* Check that all the lazy list heads are unlocked. */
static void check_lazylist_locks()
{
    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        if (meta_chunk_get_lock(i) != 0) {
            meta_chunk_unlock(i);
        }
    }
}

static int check_interval_alignment(struct dfs_datachunk *dc)
{
    int ret = 0;
    unsigned long start = dc->it.start, last = dc->it.last;
    if ((start & 0xfff) != 0) 
        ret++;
    if ((last & 0xfff) != 0xfff)
        ret++;
    return ret;
}

/* 
 * TAKES IMAGE ADDRESSES OF DC, MMAP ADDR OF FILE_INODE AND PARENT
 * Assumes address is valid.
 * Check datachunk integrity.
 * When the data pointer of a datachunk is corrupted, there is not much
 * the checker can do since there is no way to retrieve that data.
 */
static int check_datachunk(struct dfs_datachunk *dc, 
        struct dfs_inode *file_inode, struct dfs_datachunk *parent)
{
    int ret = DATACHUNK_GOOD;
    int err_count = 0;

    if (check_checker_meta_bitmap(dc, sizeof(struct dfs_datachunk))) {
        // printf(RED "Corrupt: datachunk bad.\n" RESET);
        return DATACHUNK_BAD;
    }

    dc = map_datachunk(dc);
    check_ptr(dc->parent, mem_to_img(file_inode), "datachunk file backpointer", &err_count);

    // check __rb_parent_color, mask out last two bits used to indicate color
    struct rb_node *dc_node = &dc->it.rb;
    if ((dc_node->__rb_parent_color & (~3UL)) != (unsigned long)mem_to_img(parent)) {
        if (DB_MODE) {
            printf(YEL "Corrupt: datachunk parent node pointer. (exp: %p, img: %p)\n" RESET,
                    mem_to_img(parent), (void *)(dc_node->__rb_parent_color & (~3UL)));
        }
        dc_node->__rb_parent_color &= 3UL;  // clear out old parent addr
        dc_node->__rb_parent_color |= (unsigned long)mem_to_img(parent);
        err_count++;
    }

    // check initialized bit in data_initialized field, mask out last bit
    if (!(dc->data_initialized & 1UL)) {
        if (DB_MODE)
            printf(YEL "Corrupt: datachunk initialized bit wrong.\n" RESET);
        dc->data_initialized |= 1UL;
        err_count++;
    }

    err_count += check_interval_alignment(dc);

    // check if left or right child is lost. 
    struct rb_node *left = dc->it.rb.rb_left, *right = dc->it.rb.rb_right; 
    if (left != NULL && check_meta_addr(left)) {
        recover_datachunk_child(dc, -1);
        err_count++;
        ret = DATACHUNK_LOST_LCHLD;     // lost left child
    }
    if (right != NULL && check_meta_addr(right)) {
        if (dc->it.last == dc->it.__subtree_last) {
            // there is not right child
            dc->it.rb.rb_right = NULL;
            err_count++;
        }
        recover_datachunk_child(dc, 1);
        err_count++;
        ret = DATACHUNK_LOST_RCHLD;     // lost right child
    }

    // if too many errors, declare datachunk unrecoverable
    if (err_count > DATACHUNK_BAD_THRESHOLD) 
        return DATACHUNK_BAD;
    
    // Lastly, check the data pointer.
    void *data = (void *)(dc->data_initialized & (~1UL));
    size_t data_size = dc->it.last - dc->it.start + 1;
    if (check_data_addr(data) || check_data_bitmap(data, data_size)) {
        if (DB_MODE)
            printf(RED "Corrupt: datachunk data pointer (%p) invalid.\n" RESET, data);
        stack_push(stack_new_node(dc), corrupt_datachunks);
    }

    return ret;
}

/*
 * Insert a datachunk to the checker-maintained data structure, while
 * updating all three bitmaps.
 */
static void insert_datachunk(struct dfs_datachunk *dc)
{
    datachunks = (struct datachunk_item *)check_capacity(datachunks, &datachunks_size, 
                                                chunk_count, sizeof(struct datachunk_item));
    datachunks[chunk_count].datachunk = dc;
    update_checker_meta_bitmap(mem_to_img(dc), sizeof(struct dfs_datachunk));
    lazylist_alloc(mem_to_img(dc), DFS_META_DATACHUNK_BITMAP, sizeof(struct dfs_datachunk));
    size_t data_size = dc->it.last - dc->it.start + 1;
    void *data = (void *)(dc->data_initialized & (~1UL));
    update_data_bitmap(data, data_size);
    chunk_count++;
}

/*
 * Traverse through the interval tree of a given file and check every
 * datachunk along the way and insert all the datachunks to the checker-
 * maintained array.
 */
static int traverse_datachunks(struct dfs_datachunk *dc, struct dfs_inode *file, 
        struct dfs_datachunk *parent)
{
    if (dc == NULL)
        return 0; 
    int ret = 0;

    int ret_check = check_datachunk(dc, file, parent);
    if (ret_check == DATACHUNK_BAD) {
        memset(img_to_mem(dc), 0x0, sizeof(struct dfs_datachunk));
        stack_push(stack_new_node(img_to_mem(dc)), bad_datachunks);
        return 1;
    }
    else if (ret_check == DATACHUNK_LOST_LCHLD || ret_check == DATACHUNK_LOST_RCHLD) {
        ret += 1;
    } 

    // parent null means root, file's data starts at this chunk
    if (parent == NULL) 
        files[file_count].data_index = chunk_count;

    dc = map_datachunk(dc);
    ret += traverse_datachunks((struct dfs_datachunk *)dc->it.rb.rb_left, file, dc);
    insert_datachunk(dc);
    ret += traverse_datachunks((struct dfs_datachunk *)dc->it.rb.rb_right, file, dc);

    return ret;
}

/* 
 * TAKES IMAGE ADDRESS OF INODES
 * Assumes inode address is valid.
 */
static int check_dir_inode(struct dfs_inode *inode, struct dfs_inode *parent)
{
    int count = 0; 
    int *err_count = &count;

    if (check_checker_meta_bitmap(inode, DIR_INODE_SZ)) {
        if (DB_MODE)
            printf(RED "Corrupt: directory inode bad.\n" RESET);
        return INODE_BAD;
    }

    inode = map_inode(inode);
    if (get_first_dentry(inode) != NULL
                && check_meta_addr(inode->data.dirents.next)) {
        if (DB_MODE)
            printf(RED "Corrupt: directory inode data lost.\n" RESET);
        inode->data.dirents.next = NULL;
        return INODE_LOST_DATA;
    }

    *err_count += check_dot_dents(inode, parent);
    check_val(inode->pincount.refs.counter, 0, "directory inode pincount", err_count);
    if ((inode->__lock_metaidx_size & LMS_LOCKMASK) != 0) {
        if (DB_MODE)
            printf(YEL "Corrupt: file inode locked.\n" RESET);
        inode->__lock_metaidx_size = inode->__lock_metaidx_size & (~LMS_LOCKMASK);
        ++*err_count;
    }

    if (*err_count > FILE_INODE_BAD_THRESHOLD) {
        return INODE_BAD;
    }

    return INODE_GOOD;
}

/* 
 * TAKES IMAGE ADDRESS OF INODES
 * Assume inode address is valid
 */
static int check_file_inode(struct dfs_inode *inode)
{
    int count = 0;
    int *err_count = &count;    // I know this is weird

    if (check_checker_meta_bitmap(inode, FILE_INODE_SZ)) {
        if (DB_MODE)
            printf(RED "Corrupt: file inode bad.\n" RESET);
        return INODE_BAD;
    }

    inode = map_inode(inode);
    if (inode->data.chunks.rb_node != NULL 
            && check_meta_addr(inode->data.chunks.rb_node)) {
        if (DB_MODE)
            printf(RED "Corrupt: file inode data lost.\n" RESET);
        inode->data.chunks.rb_node = NULL;
        return INODE_LOST_DATA;
    }
    check_val(inode->pincount.refs.counter, 0, 
            "file inode reference counter", err_count);
    check_val(inode->nlink, 1, "file inode nlink", err_count);

    if ((inode->__lock_metaidx_size & LMS_LOCKMASK) != 0) {
        if (DB_MODE)
            printf(YEL "Corrupt: file inode locked.\n" RESET);
        inode->__lock_metaidx_size = inode->__lock_metaidx_size & (~LMS_LOCKMASK);
        ++*err_count;
    }

    // size_t file_size = dfs_inode_get_size(inode);
    // int tree_node_count = get_node_count(inode);
    // if (file_size < DATA_BLOCK_MAX_SZ * (tree_node_count - 1)
                // || file_size > DATA_BLOCK_MAX_SZ * tree_node_count) {
        // printf(YEL "Corrupt: file inode size not in reasonable range.\n" RESET);
        // TODO: This involves set_mask_bits.
    // }

    if (*err_count > FILE_INODE_BAD_THRESHOLD) {
        return INODE_BAD;
    }

    return INODE_GOOD;
}

/*
 * TAKES IMAGE ADDRESSES OF DENTRIES, MEM ADDRESES OF INDOES
 * Checks the integrity of a dentry:
 * - its pprev pointer should point back into the inode
 * - its next pointer should point to a valid metadata address
 * - its reference counter should not be 1 (according to old dfsck)
 * - its name should not be empty (check both namelen and name)
 */
static int check_dentry(struct dfs_dentry *dentry, struct dfs_inode *parent_inode)
{
    int ret = DENTRY_GOOD;
    int err_count = 0;

    // Dentry pointer is corrupted, halt all checks and declare dentry dead
    if (check_meta_addr(dentry)) {
        // TODO: Do something to hopefully find the actual dentry location?
        if (DB_MODE)
            printf(RED "Corrupt: invalid dentry address.\n" RESET);
        bad_dentry_cnt++;
        return DENTRY_BAD;
    }

    if (DB_MODE) {
        printf(":: Checking dentry: %s (%p) [Parent ino: %p]...\n",
                    (map_dentry(dentry))->name, map_dentry(dentry), parent_inode);
    }

    dentry = map_dentry(dentry);

    // TODO: (low priority) handle corrupt names differently
    if (dentry->namelen == 0) {
        if (DB_MODE)
            printf(YEL "Corrupt: nameless dentry.\n" RESET);
        dentry->name[0] = '\0';
        err_count++;
    }

    for (int i = 0; i < dentry->namelen; i++) {
        if (dentry->name[i] == '\0') {
            if (DB_MODE)
                printf(YEL "Corrupt: dentry name is shorter than namelen indicates.\n" RESET);
            dentry->namelen = i;
            err_count++;
            break;
        }
    }

    int dentry_size;
    if (err_count == 0) { 
        dentry_size = 30 + dentry->namelen;
    } else {
        int dentry_chunk_index = lazylist_get_chunk_index(lazylist_get_chunk(dentry)); 
        int dentry_size_index = meta_chunk_get_size_index(dentry_chunk_index);
        dentry_size = sizeof(struct dfs_dentry)
                      * (dentry_size_index - DFS_META_DIR_INODE_BITMAP);
    }

    if (check_checker_meta_bitmap(unmap_dentry(dentry), dentry_size)) {
        // the location pointed to by dentry is already occupied 
        // by something else, meaning this is a bad address
        if (DB_MODE)
            printf(RED "Corrupt: dentry address corrupted.\n" RESET);
        return DENTRY_BAD_ADDR;
    }

    if (dentry->parent != unmap_inode(parent_inode)) {
        if (DB_MODE)
            printf(YEL "Corrupt: dentry back pointer corrupted.\n" RESET);
        dentry->parent = unmap_inode(parent_inode);
        err_count++;
    }

    check_val(dentry->refs.refcount.refs.counter, 1, 
            "dentry reference counter", &err_count);

    // Make sure inode pointer is also intact
    if (check_meta_addr(dentry->inode)) {
        if (DB_MODE)
            printf(YEL "Corrupt: dentry has lost its inode.\n" RESET);
        bad_dentry_cnt++;
        dentry->inode = NULL;
        ret = DENTRY_LOST_INODE;
    }
    
    // Inode pointer is good, check that inode
    if (ret != DENTRY_LOST_INODE) {
        if (DB_MODE)
            printf(  "Attempting to recover inode...\n");
        struct dfs_inode *inode = map_inode(dentry->inode);
        int inode_err_code;
        if (isdir(inode)) {
            inode_err_code = check_dir_inode(mem_to_img(inode), parent_inode);
        } else if (isreg(inode)) {
            inode_err_code = check_file_inode(mem_to_img(inode));
        } else {
            // inode is not file or directory, corrupted
            if (DB_MODE)
                printf(RED "Corrupt: inode of %s is neither a file nor a directory.\n" RESET, 
                                                                dentry->name);
            inode_err_code = INODE_BAD;
        }

        if (inode_err_code >= 0) {
            err_count += inode_err_code;
        } else if (inode_err_code == INODE_BAD) {
            printf(RED "INODE BAD.\n" RESET);
            return DENTRY_BAD_INODE;
        } else if (inode_err_code == INODE_LOST_DATA) {
            if (isreg(inode)) {
                // file inode, recover the root datachunk
                recover_root_datachunk(inode);
                ret = DENTRY_GOOD;
            } else {
                // directory inode, recover all the dentries
                recover_dentries(inode, NULL);
                ret = DENTRY_GOOD;
            }
        }
    }

    if (dentry->list.next != NULL && check_meta_addr(dentry->list.next)) {
        if (DB_MODE)
            printf(RED "Corrupt: dentry (%s) NEXT pointer corrupted! (%p)\n" RESET, 
                                            dentry->name, dentry->list.next);
        dentry->list.next = NULL;
        if (ret == DENTRY_LOST_INODE) {
            if (DB_MODE) {
                printf(RED " DEBUG (DENTRY_LST_INO_NXT): C**KING NORA. --JAMES MAY\n" RESET);
            }
            ret = DENTRY_LST_INO_NXT; 
        } else {
            ret = DENTRY_LOST_NEXT;
        }
        err_count++;
    }

    printf("  >> %d.\n", err_count);
    if (err_count > DENTRY_BAD_THRESHOLD) {
        // Screw you guys. I'm going home.  -Eric Cartman
        return DENTRY_BAD;
    }
    return ret;
}

/* 
 * TAKES MMAP'D ADDRESSES
 * Shamelessly copied over from original dfsck, check logic
 */
static void insert_dentry(struct dfs_dentry *dentry, int parent_inode_index)
{
    dentries = (struct dentry_item *) check_capacity(dentries, 
                &dentries_size, dentry_count, sizeof(struct dentry_item));
    dentries[dentry_count].dentry = dentry;
    dentries[dentry_count].parent_inode_index = parent_inode_index;

    size_t dentry_size = dfs_dentry_size(dentry);
    dentry = mem_to_img(dentry);
    update_checker_meta_bitmap(dentry, dentry_size);
    lazylist_alloc(dentry, DFS_META_DENTRY_BITMAP(dentry_size), dentry_size);

    dentry = (struct dfs_dentry *)img_to_mem(dentry);
    struct dfs_inode *inode = map_inode(dentry->inode);
    if (isdir(inode)) {
        lazylist_alloc(unmap_inode(inode), DFS_META_DIR_INODE_BITMAP, DIR_INODE_SZ);
        update_checker_meta_bitmap(unmap_inode(inode), DIR_INODE_SZ);
    } else if (isreg(inode)) {
        lazylist_alloc(unmap_inode(inode), DFS_META_FILE_INODE_BITMAP, FILE_INODE_SZ);
        update_checker_meta_bitmap(unmap_inode(inode), FILE_INODE_SZ);
    }
    dentry_count++;
}


/*
 * Insert a file inode into the checker record. Check the interval tree for any errors.
 */
static void insert_file_inode(struct dfs_inode *inode, int parent_inode_index)
{
    struct dfs_datachunk *curr_dc = (struct dfs_datachunk *)inode->data.chunks.rb_node;
    bool good_file = 1;
    if (curr_dc != NULL) {
        // FIXME: structural changes here.
        int ret = traverse_datachunks(curr_dc, inode, NULL);
        if (ret != 0 && files[file_count].data_index == -1) {
            // Root is corrupted.
            inode->data.chunks.rb_node = NULL;
            stack_push(stack_new_node(inode), corrupt_files);
            good_file = 0;
        } else if (ret) {
            // TODO: Declare file dead. Should anything be done about the file?
            if (DB_MODE)
                printf(RED "File is corrupted.\n" RESET);
            stack_push(stack_new_node(inode), corrupt_files);
            good_file = 0;
        } else if (ret == 0) {
            // TODO
            // All the nodes seem to be there, check if tree is rb-correct.
            if (check_rb_property(inode) != 0) {
                stack_push(stack_new_node(inode), corrupt_files);
                good_file = 0;
            }
            // TODO: The tree is rb-correct, check intervals.
            bad_interval_cnt += check_intervals(inode);
        }
    }

    if (good_file) {
        struct dfs_datachunk *root_dc = get_root_datachunk(inode);
        if (root_dc) {
            total_good_file_bytes += get_root_datachunk(inode)->it.__subtree_last + 1;
        }  /* If no root datachunk exists, then the file is empty. */
    }
    // if (good_file) {
    //     stack_push(stack_new_node(inode), good_files);
    // }

    files = (struct inode_item *)
            check_capacity(files, &files_size, file_count, sizeof(struct inode_item));
    files[file_count].inode = inode;
    files[file_count].parent_inode_index = parent_inode_index;
    files[file_count].nlink_count++;
    files[file_count].data_index = -1;
    file_count++;
}

/*
 * Scan through the dentries pointed to by an directory inode,
 * adding itself and all the dentries to respective container 
 * data structures maintained by the checker. All dentries are
 * checked for their integrity.
 */
static void insert_dir_inode(struct dfs_inode *inode, int parent_inode_index)
{
    if (DB_MODE) {
        printf(":: Inserting directory inode %p.\n", inode);
    }
    int ret_val;

    dirs = (struct inode_item *)
            check_capacity(dirs, &dirs_size, dir_count, sizeof(struct inode_item));
    dirs[dir_count].inode = inode;
    dirs[dir_count].parent_inode_index = parent_inode_index;
    dirs[parent_inode_index].nlink_count++;
    dirs[dir_count].nlink_count = 2;

    /* traverse all dentries */
    struct dfs_dentry *curr_dentry = unmap_dentry(get_first_dentry(inode));
    struct dfs_dentry *prev_dentry = NULL;

    struct stack *corrupt_dentries = stack_init();
    struct stack *visited_dents = stack_init();

    while (curr_dentry != NULL) {
        ret_val = check_dentry(curr_dentry, inode); 
        curr_dentry = img_to_mem(curr_dentry);
        stack_push(stack_new_node(curr_dentry), visited_dents);

        if (ret_val == DENTRY_GOOD) {
            if (DB_MODE) {
                printf(GRN "  Dentry good! (inode: %p (%lx))\n" RESET,
                    map_inode(curr_dentry->inode), DB_get_off(map_inode(curr_dentry->inode)));
            }
            insert_dentry(curr_dentry, dir_count);
        } else if (ret_val == DENTRY_LST_INO_NXT) {
            // C**king nora.
            if (DB_MODE) {
                printf(YEL "  Dentry lost both inode and next pointer.\n" RESET);
            }
            recover_dentries(inode, visited_dents);
            stack_push(stack_new_node(curr_dentry), corrupt_dentries);
        } else if (ret_val == DENTRY_LOST_NEXT) {
            if (DB_MODE)
                printf(YEL "  Dentry good but lost its next pointer!\n" RESET);
            insert_dentry(curr_dentry, dir_count);
            recover_dentries(inode, visited_dents);
        } else if (ret_val == DENTRY_LOST_INODE) {
            if (DB_MODE)
                printf(RED "  Dentry has lost its node!\n" RESET);
            stack_push(stack_new_node(curr_dentry), corrupt_dentries);
        } else if (ret_val == DENTRY_BAD_INODE) {
            if (DB_MODE)
                printf(RED "  Dentry's inode corrupted.\n" RESET);
            struct dfs_dentry *bad_dent = curr_dentry;
            if (prev_dentry == NULL) {
                inode->data.dirents.next = curr_dentry->list.next;
                curr_dentry = (struct dfs_dentry *)curr_dentry->list.next; 
            } else {
                prev_dentry->list.next = curr_dentry->list.next;
                curr_dentry = (struct dfs_dentry *)curr_dentry->list.next;
            }
            // int dent_size = dfs_dentry_size(bad_dent);
            int dentry_chunk_index = lazylist_get_chunk_index(lazylist_get_chunk(bad_dent)); 
            int dentry_size_index = meta_chunk_get_size_index(dentry_chunk_index);

            dfs_meta_free(bad_dent, dentry_size_index);
            dfs_free_file_inode(map_inode(bad_dent->inode));
            // lazylist_free(mem_to_img(bad_dent), DFS_META_DENTRY_BITMAP(dent_size), dent_size);
            continue;
        } else if (ret_val == DENTRY_BAD) {    // DENTRY_BAD
            if (DB_MODE) 
                printf(RED "  Dentry bad!\n" RESET);
            // FIXME
            if (prev_dentry != NULL) {
                prev_dentry->list.next = NULL;
                recover_dentries(inode, visited_dents);
            } else {
                recover_dentries(inode, NULL);
            }

            /* Free the BAD dentry */
            // int dent_size = dfs_dentry_size(curr_dentry);
            int dentry_chunk_index = lazylist_get_chunk_index(lazylist_get_chunk(curr_dentry)); 
            int dentry_size_index = meta_chunk_get_size_index(dentry_chunk_index);

            dfs_meta_free(curr_dentry, dentry_size_index);
            // lazylist_free(mem_to_img(curr_dentry), DFS_META_DENTRY_BITMAP(dent_size), dent_size);

            curr_dentry = (struct dfs_dentry *)prev_dentry->list.next;
            continue; 
        } else if (ret_val == DENTRY_BAD_ADDR) {
            prev_dentry->list.next = NULL;
            recover_dentries(inode, visited_dents);    // TODO: Not sure about this at all.
        }
        prev_dentry = curr_dentry;
        curr_dentry = (struct dfs_dentry *)curr_dentry->list.next;
    }
    stack_free(visited_dents);
 
    // Deal with all the corrupted dentries.
    // Note: I realise this is not efficient, at all, but I can't reasonably be 
    // bothered to create a new function or copy half a page of code over.
    struct dfs_dentry *dentry;
    int lost_inode_cnt = corrupt_dentries->size;
    int i = 0;
    while (corrupt_dentries->size > 0) {
        dentry = stack_pop(corrupt_dentries)->data;
        // Attempt to recover the inode (only possible for directories)
        dentry->inode = NULL;
        recover_dir_inode(dentry, inode);
        if (dentry->inode != NULL && check_meta_addr(dentry->inode) != -1) {
            // dentry isn't the only one that lost inode, then the inode recovered
            // may not belong to this dentry, rename folder to remind user of that
            if (lost_inode_cnt > 1) {
                char new_name[32];
                char randstr[5];
                rand_str(randstr, 4);
                sprintf(new_name, "RECOVERED_DIR_%d_%s", i++, randstr);
                
                struct dfs_inode *tmp_ino = map_inode(dentry->inode);
                struct dfs_dentry *new_dent = dfs_alloc_dentry(strlen(new_name)); 
                init_dentry(new_dent, new_name, tmp_ino);

                new_dent->list.next = inode->data.dirents.next;
                inode->data.dirents.next = mem_to_img(new_dent);
                new_dent->parent = unmap_inode(inode);

                remove_dentry(inode, dentry);
                dfs_free_dentry(dentry);    
                dentry = new_dent;
                if (DB_MODE)
                    printf(BLU "Dentry renamed %s. (%p, %lx, inode: %p)\n" RESET, 
                                dentry->name, dentry, DB_get_off(dentry), map_inode(dentry->inode));
            }
            int inode_ret = check_dir_inode(dentry->inode, inode); 
            if (inode_ret == INODE_LOST_DATA) {
                recover_dentries(map_inode(dentry->inode), NULL);
                inode_ret = INODE_GOOD;
            }
            if (inode_ret == INODE_GOOD) {
                insert_dentry(dentry, dir_count);
                if (DB_MODE)
                    printf(GRN "  Dentry good!\n" RESET);
            } else {
                // TODO:
            }
        } else {    // still no inode
            // printf(YEL "  No directory inode found. \"%s\" is likely a file.\n" RESET,
                                                                                // dentry->name);
            // Delete this dentry from the list
            if (get_first_dentry(inode) == dentry) {
                inode->data.dirents.next = (void *)dentry->list.next;
            } else {
                struct dfs_dentry *curr_dentry = get_first_dentry(inode);
                while (curr_dentry->list.next != mem_to_img(dentry)) {
                    curr_dentry = img_to_mem(curr_dentry->list.next);
                }
                curr_dentry->list.next = dentry->list.next;
            }
            // Free the dentry: Since this dentry was never added to the checker lazy list,
            // there is no need to free it. Only free it in the actual image.
            dfs_free_dentry(dentry);
            dentry = NULL;  /* "Defensive programming." Hurr durr. */
        }
    }
    stack_free(corrupt_dentries);

    dir_count++;
}

static void insert_root_dentry()
{
    struct dfs_dentry *root_dentry = &sb->rootdir;
    dentries[0].dentry = root_dentry;
    dentry_count++;
    dentries_traversed++;
    lazylist_alloc(root_dentry->inode, DFS_META_DIR_INODE_BITMAP, DIR_INODE_SZ);
    update_checker_meta_bitmap(root_dentry->inode, DIR_INODE_SZ); 
    insert_dir_inode(img_to_mem(root_dentry->inode), 0);  // 0: root parent = self
}

static void print_metadata()
{
    // printf("Dentries: (Total: %d)\n", dentry_count);
    // for (int i = 0; i < dentry_count; i++) {
    //     printf("\t%s (%p) [Inode: %p]\n", dentries[i].dentry->name,
    //             dentries[i].dentry, map_inode(dentries[i].dentry->inode));
    // }
    printf("File Inodes: (Total: %d)\n", file_count);
    struct dfs_inode *file;
    for (int i = 0; i < file_count; i++) {
        file = files[i].inode;
        printf("  %p size: %lx, last interval: %lx.\n", file,
                dfs_inode_get_size(file), get_root_datachunk(file)->it.__subtree_last);
        // printf("\t%p (nlinks: %d, root: %p)\n", files[i].inode,
        //             files[i].nlink_count, img_to_mem(files[i].inode->data.chunks.rb_node));
    }
    // printf("Directory Inodes: (Total: %d)\n", dir_count);
    // for (int i = 0; i < dir_count; i++) {
    //     printf("\t%p (nlinks: %d, LMS = %lx)\n", dirs[i].inode,
    //             // map_inode(dirs[i].inode->dot_dents[DENT_SELF].inode),
    //             // map_inode(dirs[i].inode->dot_dents[DENT_PARENT].inode),
    //             dirs[i].nlink_count, dirs[i].inode->__lock_metaidx_size);
    // }
    // printf("Datachunks: (Total: %d)\n", chunk_count);
    // for (int i = 0; i < chunk_count; i++) {
    //     struct dfs_datachunk *dc = datachunks[i].datachunk;
    //     printf("\t%p L: %p, R: %p: P: %p, \n\t\t\tstart: %lx, last: %lx, size: %lx, subtree_last: %lx\n",
    //                    dc, img_to_mem(dc->it.rb.rb_left),
    //                    img_to_mem(dc->it.rb.rb_right), map_datachunk(get_datachunk_parent(dc)),
    //                    dc->it.start, dc->it.last,
    //                    dc->it.last - dc->it.start + 1, dc->it.__subtree_last);
    // }
}

static void check_nlinks()
{
    for (int i = 0; i < dir_count; i++) {
        if (dirs[i].nlink_count != dirs[i].inode->nlink) {
            dirs[i].inode->nlink = dirs[i].nlink_count;
        }
    }
}

static void check_directory_tree()
{
    struct dfs_inode *curr_inode;
    int curr_parent_inode_index;
    while (dentries_traversed < dentry_count) {
        curr_inode = map_inode(dentries[dentries_traversed].dentry->inode);
        curr_parent_inode_index = dentries[dentries_traversed].parent_inode_index;
        if (isdir(curr_inode)) {
            insert_dir_inode(curr_inode, curr_parent_inode_index);
        } else if (isreg(curr_inode)) {
            insert_file_inode(curr_inode, curr_parent_inode_index);
        } else {
            // TODO: Is this redundant?
            if (DB_MODE)
                printf(RED "Error: inode not file or directory.\n" RESET);
        }
        dentries_traversed++;
    }
}

// /* Look for illegal pointers in the metalist */
// static void check_metametadata()
// {
//     // initialized to point to the first chunk
//     void *curr_chunk_start = (void*)(llist_heads + DFS_META_NUM_CHUNKS);
//     void *curr_chunk_end = curr_chunk_start + chunk_size;
//     struct lazy_list_node *curr_head = 0;
//     for (int i = 0; i < DFS_META_NUM_CHUNKS; i++){
//         curr_head = img_to_mem(llist_heads[i].head);
//         if ((curr_head < curr_chunk_start || curr_head >= curr_chunk_end) && curr_head != NULL){
//             // free list head is corrupted, should be added to a list as suspicious?
//         }
//         void *curr_chunk_start = curr_chunk_end;
//         void *curr_chunk_end = curr_chunk_start + chunk_size;
//     }
// }

/* 
 * The big dog. Goes through the entire metadata region 
 * checking pretty much everything. 
 */
static void check_metadata() 
{
    printf(":: Checking metadata...\n");
    check_root();
    // check_imeta_arr();   /* FIXME */
    insert_root_dentry();
    
    check_directory_tree();
}

/*
 * Go through the root directory and look for a lost+found folder.
 */
static struct dfs_dentry *find_lostnfound_dir(struct dfs_inode *dir)
{
    struct dfs_dentry *curr_dentry = get_first_dentry(dir);
    while (curr_dentry != NULL) {
        if (strcmp(curr_dentry->name, "lost+found") == 0) {
            return curr_dentry;
        }
        curr_dentry = img_to_mem(curr_dentry->list.next);
    }
    return NULL;
}

/*
 * Create a lost+found directory inside the provided parent_dir
 */
static struct dfs_dentry *create_lostnfound_dir(struct dfs_inode *parent_dir)
{
    // Create the dentry
    struct dfs_dentry *lostnfound = dfs_alloc_dentry(strlen("lost+found"));
    if (lostnfound == NULL) {   // allocation failure
        printf(RED "  Internal: lost+found allocation failure.\n" RESET);
        dfsck_exit();
    }

    // Create the directory inode
    struct dfs_inode *lostnfound_inode = create_dir_inode(img_to_mem(sb->rootdir.inode));
    if (lostnfound_inode == NULL) {
        printf(RED "  Internal: lost+found inode allocation failure.\n" RESET);
        dfsck_exit();
    }
    lostnfound_inode->nlink = 2;

    init_dentry(lostnfound, "lost+found", lostnfound_inode);
    if (DB_MODE)
        printf(GRN "  Created lost+found directory at %p, inode at %p.\n" RESET,
                                                lostnfound, lostnfound_inode);
    // Insert lost+found into parent directory 
    lostnfound->list.next = parent_dir->data.dirents.next;
    parent_dir->data.dirents.next = mem_to_img(lostnfound);
    lostnfound->parent = unmap_inode(parent_dir);

    // Add lost+found to checker record
    insert_dentry(lostnfound, 0);    // root inode

    return lostnfound;
}

/* Go through the file inode bitmap and look for lost files. Add them all to 
 * a stack for another function to process. 
 */
static int find_lost_files(struct dfs_dentry *dentry, struct dfs_inode *inode,
                                               size_t chunk_index, size_t size_index)
{
    // Only traverse through those in use.
    struct dfs_inode *curr_inode = (struct dfs_inode *)
                                   ((char *)chunks + chunk_index * sb->chunk_size);

    if (!DFS_META_CHUNK_BIT(&llist_heads[chunk_index])) {   // chunk on first run
        if (DB_MODE)
            printf(MAG ":: DEBUG: Chunk on first run!\n" RESET);
        // If chunk is on its first run, then all the allocated data are laid out
        // sequentially, ending at head->head.
        void *end_point = img_to_mem(llist_heads[chunk_index].head);
        while ((void *)curr_inode < end_point) {
            // See if this inode is already in the record (i.e. not lost)
            bool visited = 0;
            for (int i = 0; i < files_size; i++) {
                if (curr_inode->data.chunks.rb_node == NULL 
                                    || curr_inode == files[i].inode) {
                    visited = 1;
                    break;
                }
            }
            if (!visited) {
                // printf(GRN "\t> Found lost inode at %p!\n" RESET, curr_inode);
                stack_push(stack_new_node(curr_inode), lost_files);
            }
            curr_inode = (void *)curr_inode + FILE_INODE_SZ;
        }
    } else if (lazylist_get_bit(size_index, chunk_index) == 1) {    // chunk not full
        if (DB_MODE)
            printf(MAG ":: DEBUG: Chunk not full!\n" RESET);
        for (int i = 0; i < chunk_capacity_limit[size_index]; i++) {
            // check if address is unused, if so, skip
            bool unused = 0;
            struct lazy_list_node *free_node = img_to_mem(llist_heads[chunk_index].head);
            while (free_node != NULL) {
                if ((void *)curr_inode == (void *)free_node) {  // inode addr is unused
                    unused = 1;
                    break;
                }
                free_node = img_to_mem(free_node->next);
            }
            if (!unused) {
                // check if inode is already recorded and therefore not lost
                bool visited = 0;
                for (int i = 0; i < files_size; i++) {
                    if (curr_inode == files[i].inode) {
                        visited = 1;
                        break;
                    }
                }
                if (!visited) {
                    // printf(GRN "\t> Found lost inode at %p!\n" RESET, curr_inode);
                    stack_push(stack_new_node(curr_inode), lost_files);
                }
            }
            curr_inode = (void *)curr_inode + FILE_INODE_SZ;
        }
    } else if (lazylist_get_bit(size_index, chunk_index) == 0) {    // chunk is full
        if (DB_MODE)
            printf(MAG ":: DEBUG: Chunk full!\n" RESET);
        for (int i = 0; i < chunk_capacity_limit[size_index]; i++) {
            bool visited = 0;
            for (int i = 0; i < files_size; i++) {
                if (curr_inode == files[i].inode) {
                    visited = 1;
                    break;
                }
            }
            if (!visited) {
                // printf(GRN "  > Found lost inode at %p!\n" RESET, curr_inode);
                stack_push(stack_new_node(curr_inode), lost_files);
            }
            curr_inode = (void *)curr_inode + FILE_INODE_SZ;
        }
    }
    return 0;
}

/* Gather lost files and return them as a stack. */
static struct stack *gather_lost_files()
{
    if (DB_MODE)
        printf(BLU "  Gathering lost files...\n" RESET);
    int size_index = DFS_META_FILE_INODE_BITMAP;
    traverse_bitmap(size_index, NULL, NULL, &find_lost_files);
    return lost_files; 
}


/*
 * Insert the lost+found directory and all its contents into the checker record.
 */
static void insert_lostnfound(int lostnfound_index)
{
    struct dfs_inode *lnf_ino = dirs[lostnfound_index].inode, *inode;  // lost+found inode
    struct dfs_dentry *curr_dentry = get_first_dentry(lnf_ino);

    while (curr_dentry != NULL) {
        if (!dentry_visited(curr_dentry)) {
            insert_dentry(curr_dentry, lostnfound_index);
            inode = map_inode(curr_dentry->inode);
            if (isdir(inode)) {
                if (!dir_inode_visited(inode))
                    insert_dir_inode(inode, lostnfound_index);
            } else {
                if (!file_inode_visited(inode))
                    insert_file_inode(inode, lostnfound_index);
            }
        }
        curr_dentry = img_to_mem(curr_dentry->list.next);
    }
}

// static struct dfs_dentry *find_lost_dentry()
// {
//     /* lost_dentry_chunk and lost_dentry_offset should be used to avoid retraversing
//         declared at the top */
//     if (lost_dentry_chunk == 0 && lost_dentry_offset == 0){
//         //find a chunk that has dentries
//     }
//     // our first job is to find chunk that has dentries
//     // I think to really save us some time and effort, we should use one of the bits in the mmaped
//         // structure to indicate this dentry was already checked, probably the least significant bit of the parent //     // once we find a dentry that hasn't been seen before check if it is a directory dentry
//     // if yes, then reutrn this dentry
// }

/*
 * Determine if a chunk contains dentries by looking at its size index.
 */
static inline bool chunk_is_dentry(int chunk_index)
{
    size_t size_index = meta_chunk_get_size_index(chunk_index);
    return (size_index > DFS_META_DIR_INODE_BITMAP && size_index < DFS_META_FREE_BITMAP);
}

// /*
//  * Find parent dentry of a given inode.
//  */
// static struct dfs_dentry *find_parent_dentry(struct dfs_inode *inode)
// {
//     size_t size_index, size_step;
//     struct dfs_inode *target = unmap_inode(inode);
//     for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
//         if (meta_chunk_get_capacity(i) == 0)
//             continue;
//         if (chunk_is_dentry(i)) {
//             size_index = meta_chunk_get_size_index(i);
//             size_step = sizeof(struct dfs_dentry) * (size_index - DFS_META_DIR_INODE_BITMAP);
//             struct dfs_dentry *curr_dentry = (struct dfs_dentry *)
//                                              ((char *)chunks + i * sb->chunk_size);
//             for (int j = 0; i < chunk_capacity_limit[size_index]; j++) {
//                 if (curr_dentry->inode == target) {
//                     return curr_dentry;
//                 } else {
//                     curr_dentry = (void *)curr_dentry + size_step;
//                 }
//             }
//         }
//     }
//     return NULL;
// }

// /*
//  * Returns a dentry that was not visited during checking.
//  */
// static struct dfs_dentry *find_unvisited_dentry()
// {
//     size_t size_index, size_step;
//     for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
//         if (meta_chunk_get_capacity(i) == 0)
//             continue;
//         if (meta_chunk_get_capacity(i) == lazylist_get_capacity(i))
//             continue;
//         if (chunk_is_dentry(i)) {
//             size_index = meta_chunk_get_size_index(i);
//             size_step = sizeof(struct dfs_dentry) * (size_index - DFS_META_DIR_INODE_BITMAP);
//             struct dfs_dentry *curr_dentry = (struct dfs_dentry *)
//                                              ((char *)chunks + i * sb->chunk_size);
//             for (int j = 0; j < chunk_capacity_limit[size_index]; j++) {
//                 if (dentry_visited(curr_dentry))    // TODO: Do Rahul's visited bit thing
//                     continue;
//                 // do some basic checks to make sure there is a valid dentry here
//                 if (curr_dentry->inode != NULL && check_meta_addr(curr_dentry->inode) == 0) {
//                     return curr_dentry;
//                 }
//                 curr_dentry = (void *)curr_dentry + size_step;
//             }
//         }
//     }
//     return NULL;
// }

// static int check_recovered_dir_inode(struct dfs_inode *inode, struct )
// {

// }

// static void recover_orphaned_dentries()
// {
//     struct dfs_dentry *orphan, *parent_dentry;
//     struct dfs_inode *parent_inode;

//     /*
//      * Find an orphaned dentry (CURR_DENTRY), try to reach the top of this subtree by:
//      *   - Going to parent inode of CURR_DENTRY, check if that inode is intact.
//      *   - Find the dentry that contains that parent inode,
//      *     this dentry will now become CURR_DENTRY
//      *     [Rinse, repeat.]
//      */
//     while ((orphan = find_unvisited_dentry())) {
//         parent_inode = img_to_mem(orphan->parent);
//         parent_dentry = find_parent_dentry(parent_inode);
//         if (parent_dentry != NULL)
//             orphan = parent_dentry;

//     }
// }

/* 
 * Repairs that can only be done after the checker has gone through the entire
 * file system and established an internal record of every data structure.
 * The main purpose of this function is to look for lost files and put them all
 * in the lost+found folder in the root directory.
 */
static void recover_orphaned_files(int lostnfound_index)
{
    printf(":: Check completed. Repairing file system.\n");
    lost_files = gather_lost_files();
    printf("   Found %lu lost files.\n", lost_files->size);
    if (lost_files->size > 0) {
        struct dfs_dentry *lostnfound = find_lostnfound_dir(map_inode(sb->rootdir.inode));

        // Fill up lost+found folder with lost files
        while (lost_files->size > 0) {
            // DB_compare_capacity();
            struct dfs_inode *inode = stack_pop(lost_files)->data;
            int ret_code = check_file_inode(mem_to_img(inode)); 
            if (ret_code == INODE_BAD) {
                continue;   // do not put bad inode in lost+found.
            } else if (ret_code == INODE_LOST_DATA) {
                // TODO: More to be done here. 
                //       Update after datachunk recovery is finished.
                recover_root_datachunk(inode); 
            } 
            inode->nlink = 0;

            // Check datachunks
            // struct dfs_datachunk *curr_dc = (struct dfs_datachunk *)inode->data.chunks.rb_node;
            // int dc_ret = traverse_datachunks(curr_dc, inode, NULL);
            // if (dc_ret) {   // interval tree is corrupted.
                // TODO: Free the tree
            //     continue;
            // }

            // Create a dentry for this file and give it a random string as name.
            char name[RECOVERED_FILE_NAMELEN];
            rand_str(name, RECOVERED_FILE_NAMELEN);
            struct dfs_dentry *dentry = dfs_alloc_dentry(strlen(name));
            init_dentry(dentry, name, inode);
            
            // insert this new dentry into the lost+found folder
            // printf(GRN "  Adding file %s.\n" RESET, dentry->name);
            struct dfs_inode *lostnfound_inode = img_to_mem(lostnfound->inode);
            dentry->list.next = lostnfound_inode->data.dirents.next;
            dentry->parent = unmap_inode(lostnfound_inode);
            lostnfound_inode->data.dirents.next = mem_to_img(dentry);
        }
    }
    insert_lostnfound(lostnfound_index);
}

static void reset_datachunk_file_pointer(struct dfs_datachunk *dc, struct dfs_inode *inode)
{
    if (dc == NULL)
        return;

    struct dfs_datachunk *left, *right;
    left = get_left_datachunk(dc);
    right = get_right_datachunk(dc);

    reset_datachunk_file_pointer(left, inode);
    dc->parent = unmap_inode(inode);
    reset_datachunk_file_pointer(right, inode);
}

static inline void update_file_tree_back_pointers(struct dfs_inode *file_inode)
{
    reset_datachunk_file_pointer(get_root_datachunk(file_inode), file_inode);
}

static struct stack *gather_lost_root_datachunks()
{
    struct stack *lost_dcs = stack_init();
    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        if (meta_chunk_get_capacity(i) == 0)
            continue;
        if (meta_chunk_get_capacity(i) == lazylist_get_capacity(i))
            continue;
        if (meta_chunk_get_size_index(i) == DFS_META_DATACHUNK_BITMAP) {
            struct dfs_datachunk *curr_dc = (struct dfs_datachunk *)
                                            ((char *)chunks + i * sb->chunk_size);
            struct dfs_inode *file;
            for (int j = 0; j < chunk_capacity_limit[DFS_META_DATACHUNK_BITMAP]; j++) {
                // printf("looking... %lu\n", (void*)curr_dc - mem);
                if (get_datachunk_parent(curr_dc) == NULL 
                                        && rb_is_black(&curr_dc->it.rb)) {    // is a root datachunk
                    file = map_inode(curr_dc->parent);
                    if (file_inode_visited(file)){
                        curr_dc = curr_dc + 1;
                        continue;
                    }
                    else {
                        // if (DB_MODE)
                            // printf(GRN "Found an orphaned datachunk.\n" RESET);
                        stack_push(stack_new_node(curr_dc), lost_dcs);
                    }
                }
                curr_dc = curr_dc + 1;  // GOOD SHIT
            }
        }
    }
    if (DB_MODE) {
        printf("Total: %ld orphaned root datachunks found.\n", lost_dcs->size);
    }
    return lost_dcs;
}

/*
 * Go through the chunks looking for root datachunks that are not associated with
 * any known file inodes.
 */
static void recover_orphaned_datachunks(int lostnfound_index)
{
    struct dfs_datachunk *dc;
    struct stack *lost_root_datachunks = gather_lost_root_datachunks();
    struct dfs_dentry *lostnfound = find_lostnfound_dir(map_inode(sb->rootdir.inode));
    struct dfs_inode *lnf_ino = map_inode(lostnfound->inode);   // lost+found inode

    while (lost_root_datachunks->size > 0) {
        dc = stack_pop(lost_root_datachunks)->data;
        struct dfs_inode *new_inode = create_file_inode();
        new_inode->data.chunks.rb_node = mem_to_img(dc); 
        update_file_tree_back_pointers(new_inode);

        char name[RECOVERED_FILE_NAMELEN];
        rand_str(name, RECOVERED_FILE_NAMELEN);
        struct dfs_dentry *new_dentry = dfs_alloc_dentry(strlen(name));
        init_dentry(new_dentry, name, new_inode);

        new_dentry->list.next = lnf_ino->data.dirents.next;
        new_dentry->parent = unmap_inode(lnf_ino);
        lnf_ino->data.dirents.next = mem_to_img(new_dentry);
    }

    stack_free(lost_root_datachunks);
    insert_lostnfound(lostnfound_index); 
}

/* 
 * Scan through both image and checker data bitmap to find 
 * a missing data block of a given size. (Returns an image address.)
 */
static void *find_lost_data_block(size_t size)
{
    int start = 0, end = 0, found = 0;
    void *addr = NULL;

    for (int i = 0; i < data_bm_bytes * BITS_PER_BYTE; i++) {
        if (compare_data_block_status(i) == 1) {    // record is consistent
            if (found) {
                size_t data_size = (end - start) * PGSIZE;
                printf(YEL "  :: DEBUG: Found missing block. Size = %lx.\n" RESET, data_size);
                // end of a missing block
                if (data_size == size) {
                    if (addr != NULL) 
                        return NULL;
                    else 
                        addr = get_data_addr(start);
                }
                found = 0;
            }
            end = start = i + 1;
        } else if (get_checker_data_block_status(i) == 0) {
            /* Checker's record bit is 0 meaning there is a missing block here. */
            found = 1;
            end = i + 1;
        } else if (get_img_data_block_status(i) == 0) {
            /* Image bitmap is wrong. Just fix it*/
        }
    }
    return addr;
}

static void recover_data()
{
    printf(":: Recovering data...\n");
    // for now: only recover data if there is ONLY ONE corrupt datachunk.
    if (corrupt_datachunks->size == 1) {
        struct dfs_datachunk *dc = stack_pop(corrupt_datachunks)->data;
        size_t data_size = dc->it.last - dc->it.start + 1;
        if (DB_MODE) {
            printf("  Only one datachunk has lost its data pointer. Proceeding...\n"); 
            printf("  :: Datachunk address: %p, data size: %lx.\n", dc, data_size);
        }
        void *addr = find_lost_data_block(data_size);
        if (addr != NULL) {
            if (DB_MODE)
                printf(GRN "  :: Recovered address: %p.\n" RESET, addr);
            dc->data_initialized = (unsigned long)addr;
            dc->data_initialized |= 1;   // set initialized bit
        } else {
            // TODO: Rebuild or what?
            dc->data_initialized = 0x0;
        }
    } else {
        struct dfs_datachunk *dc;
        while (corrupt_datachunks->size > 0) {
            dc = stack_pop(corrupt_datachunks)->data;
            dc->data_initialized = 0x0;
            stack_push(stack_new_node(dc), bad_datachunks);
        }
    }
}

/*
 * Gather all the non-BAD datachunks that belong to the given file.
 */
static struct stack *gather_all_datachunks_of_file(struct dfs_inode *inode)
{
    struct stack *all_dc = stack_init();

    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        if (meta_chunk_get_size_index(i) != DFS_META_DATACHUNK_BITMAP)
            continue;

        struct dfs_datachunk *curr_dc = (struct dfs_datachunk *)
                                        ((char *)chunks + i * sb->chunk_size);
        for (int j = 0; j < chunk_capacity_limit[DFS_META_DATACHUNK_BITMAP]; j++) {
            if (curr_dc->parent == unmap_inode(inode) 
                            && get_datachunk_data_pointer(curr_dc) != NULL) {
                if (!stack_find(curr_dc, bad_datachunks)) {
                    // printf("Found: {File: %p, S: %lx, L: %lx, Dt: %lx}.\n",
                    //             curr_dc->parent, curr_dc->it.start, curr_dc->it.last,
                    //             curr_dc->data_initialized);
                    stack_push(stack_new_node(curr_dc), all_dc);
                }
            }
            curr_dc = curr_dc + 1;
        }
    }

    return all_dc;
}

/*
 * Given a stack of datachunks, finds the one that has the smallest
 * interval start value (i.e. the first interval.)
 */
static struct dfs_datachunk *find_min_start_dc(struct stack *all_dc)
{
    unsigned long curr_min_val = ULONG_MAX;
    struct dfs_datachunk *min_dc = NULL;

    struct stack_node *curr = all_dc->first;
    struct dfs_datachunk *dc;
    while (curr != NULL) {
        dc = (struct dfs_datachunk *)curr->data;
        if (dc->it.start < curr_min_val) {
            curr_min_val = dc->it.start;
            min_dc = dc;
        }
        curr = curr->next;
    }

    return min_dc;
}


/* 
 * Comparator function for comparing two datachunks based on their
 * intervals. Provided for the RB library to perform insertion.
 */
static int dc_cmp(const void *ai, const void *bi) {
    const struct dfs_datachunk *a = (struct dfs_datachunk*)ai;
    const struct dfs_datachunk *b = (struct dfs_datachunk*)bi;
    return (int)a->it.start - (int)b->it.start;
}

/*
 * After a datachunk tree is constructed by the RB library. We need
 * to update certain fields because the library doens't work exactly
 * like the kernel RB tree code.
 */
static void reset_tree(struct dfs_datachunk *dc, struct dfs_inode *file)
{
    if (dc == NULL)
        return;

    // Make addresses image addresses, and swap left and right children.
    void *tmp;
    tmp = mem_to_img(dc->it.rb.rb_left);
    dc->it.rb.rb_left = mem_to_img(dc->it.rb.rb_right);
    dc->it.rb.rb_right = tmp;

    struct dfs_datachunk *left = get_left_datachunk(dc);
    struct dfs_datachunk *right = get_right_datachunk(dc);

    reset_tree(left, file);
    reset_tree(right, file);

    dc->parent = unmap_inode(file);
    dc_flip_color(dc);
    dc_set_subtree_last(dc);
    dc_set_rbparent(left, mem_to_img(dc));
    dc_set_rbparent(right, mem_to_img(dc));
}

/* 
 * Finds all undamaged datachunks belonging to a file inode and 
 * reconstruct an interval tree.
 *
 * "We can bring to birth a new world from the ashes of the old."
 */
static void fix_file(struct dfs_inode *file)
{
    /* rb node offset information for the library. */
    static rbop_t rbinf = {
        .cmp = dc_cmp,
        .coff = sizeof(void *),
        .boff = 0,
        .nil = NULL,
        .mask = 1, // use smallest bit
    };

    struct stack *all_dc = gather_all_datachunks_of_file(file);
    if (DB_MODE) {
        printf("  Fixing file inode %p (%lx).\n", file, DB_get_off(file));
        printf("    Total: %ld datachunks found.\n", all_dc->size);
    }


    int num_chunks = all_dc->size;
    if (num_chunks == 0)
        return; 

    struct dfs_datachunk **sorted_dc = malloc(sizeof(struct dfs_datachunks *) * num_chunks);
    unsigned long expected_start = 0;
    unsigned long shift_offset = 0;
    void *tree = rbinf.nil;

    struct dfs_datachunk *dc;
    for (int i = 0; i < num_chunks; i++) {
        dc = find_min_start_dc(all_dc);    
        stack_remove(dc, all_dc);
        /* Shift the interval if need be. */
        if (dc->it.start != expected_start) {
            shift_offset = dc->it.start - expected_start;
            dc->it.start = expected_start;
            dc->it.last -= shift_offset;
        }
        // printf("[%lx, %lx] ", dc->it.start, dc->it.last);
        expected_start = dc->it.last + 1;
        sorted_dc[i] = dc;
    }
    // printf("\n");

    /* Reconstruct the tree! */
    for (int i = 0; i < num_chunks; i++) {
        dc = sorted_dc[i];
        total_bad_file_bytes += dc->it.last - dc->it.start + 1;

        dc->it.rb.rb_left = NULL;
        dc->it.rb.rb_right = NULL;
        dc->it.rb.__rb_parent_color = 0;

        // If this datachunk is not visited before, insert it.
        if (!datachunk_visited(dc)) {
            insert_datachunk(dc);
        }

        if (add_node(&tree, sorted_dc[i], &rbinf) != rbinf.nil) {
            printf(RED "Internal: add_node failed.\n" RESET);
        } else {
            // printf(GRN "  Inserted datachunk %p.\n" RESET, sorted_dc[i]);
        }
    }

    file->data.chunks.rb_node = mem_to_img(tree);
    struct dfs_datachunk *root_dc = get_root_datachunk(file);

    /* Because the library we nicked can only do so much,
     * we need to fix certain fields in the datachunks */
    dc_set_rbparent(root_dc, NULL);
    reset_tree(root_dc, file);

    // print_interval_tree(file);  // DEBUG

    free(sorted_dc);
    stack_free(all_dc);
}

/* 
 * Frees disk space occupied by datachunks that are corrupted beyond repair.
 */
static void free_bad_datachunks()
{
    if (DB_MODE) {
        printf(":: Freeing bad datachunks (Total: %ld)...\n", bad_datachunks->size);
        // stack_print_all(bad_datachunks);
    }

    struct dfs_datachunk *dc;
    while (bad_datachunks->size > 0) {
        dc = (struct dfs_datachunk *)stack_pop(bad_datachunks)->data;
        dfs_free_datachunk(dc);
    }
}

/* 
 * Repair the interval tree of all files in which the checker had previously
 * discovered major corruption in.
 */
static void repair_files()
{
    struct dfs_inode *file;

    printf(":: Repairing %ld files...\n", corrupt_files->size);

    while (corrupt_files->size > 0) {
        file = stack_pop(corrupt_files)->data;
        fix_file(file);
    }

    free_bad_datachunks();
}

/* 
 * Given a chunk index, verify that this chunk is correctly marked in the bitmap:
 *  - If empty chunk, normal bitmaps should say 0, freemap 1.
 *  - If full chunk, normal bitmaps should say 0, freemap 0.
 *  - If half full, normal bitmap FOR THAT SIZE INDEX should say 1, freemap 0.
 */
static int meta_chunk_verify_bit(int chunk_index)
{
    int bad_bit_cnt = 0;
    int size_index = meta_chunk_get_size_index(chunk_index);

    bool checker_size_index_bit, checker_free_bit, image_size_index_bit, image_free_bit;
    checker_size_index_bit = checker_meta_get_bit(size_index, chunk_index);
    checker_free_bit = checker_meta_get_bit(DFS_META_FREE_BITMAP, chunk_index);
    image_size_index_bit = lazylist_get_bit(size_index, chunk_index);
    image_free_bit = lazylist_get_bit(DFS_META_FREE_BITMAP, chunk_index);

    if (image_size_index_bit != checker_size_index_bit) {
        if (DB_MODE) {
            printf(YEL "Bitmap inconsistency! exp: %d, img: %d [SIdx: %d, CIdx: %d]\n" RESET, 
                          checker_size_index_bit, image_size_index_bit, size_index, chunk_index);
        }
        image_flip_bit(size_index, chunk_index);  
        bad_bit_cnt++;
    }
    
    if (image_free_bit != checker_free_bit) {
        if (DB_MODE) {
            printf(YEL "Free bitmap inconsistency! exp: %d, img: %d [CIdx: %d]\n" RESET, 
                                checker_free_bit, image_free_bit, chunk_index);
        }
        image_flip_bit(DFS_META_FREE_BITMAP, chunk_index);
        bad_bit_cnt++;
    }

    // This chunk should not be marked as used (1) in any other bitmap levels
    for (int i = 0; i < DFS_META_FREE_BITMAP; i++) {
        if (i == size_index)
            continue;   // skip the target level
        if (lazylist_get_bit(i, chunk_index) == 1) {
            if (DB_MODE) {
                printf(YEL "Bitmap size index inconsistency! [SIdx: %d, CIdx: %d]\n" RESET, 
                                                   size_index, chunk_index);
            }
            image_flip_bit(i, chunk_index); 
            bad_bit_cnt++;
        }
    }

    return bad_bit_cnt;
}

/* 
 * Push the checker's own lazy list records (chunk capacity records, 
 * bitmap, etc.) onto the image.
 */
static void conform_lazy_list()
{
    printf(":: Conforming image meta-metadata...\n");

    check_lazylist_locks();     /* No chunk head should be locked */

    /* Go through every chunk. */
    int bad_bit_cnt = 0, ret;
    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        /* Update chunk capacity record on image. */
        if (lazylist_get_capacity(i) != meta_chunk_get_capacity(i)) {
            printf(" Chunk #%d capacity: %lu -> %lu.\n", i, 
                        meta_chunk_get_capacity(i), lazylist_get_capacity(i));
            meta_chunk_set_capacity(i, lazylist_get_capacity(i));
        }
        
        /* Fix image bitmaps if inconsistent. */
        ret = meta_chunk_verify_bit(i);
        bad_bit_cnt += ret;
    }

    printf("  Total bad bits: %d.\n", bad_bit_cnt);
}

/* Initialise checker data structures. */
static int dfsck_init()
{
    dentries = malloc(ALLOC_SZ * sizeof(struct dentry_item));
    if (!dentries)
        return -1;
    dirs = malloc(ALLOC_SZ * sizeof(struct inode_item));
    if (!dirs)
        return -1;
    files = malloc(ALLOC_SZ * sizeof(struct inode_item));
    if (!files)
        return -1;
    datachunks = malloc(ALLOC_SZ * sizeof(struct datachunk_item));
    if (!datachunks)
        return -1;
    lost_files = stack_init();
    if (!lost_files)
        return -1;
    corrupt_datachunks = stack_init();
    if (!corrupt_datachunks)
        return -1;
    bad_datachunks = stack_init();
    if (!bad_datachunks)
        return -1;
    corrupt_files = stack_init();
    if (!corrupt_files)
        return -1;
    good_files = stack_init();
    if (!good_files)
        return -1;

    return 0;
}

/* 
 * Initialise metadata bitmaps (including all lazy lists and headers, etc.)
 * and data bitmap (unchanged from original densefs)
 */
static int dfsck_init_bitmaps() 
{
    // Initialise checker's own meta bitmap
    size_t chunk_area_bytes = (size_t)((void *)datachunk - (void *)chunks);
    size_t chunk_area_units = DIV_ROUND_UP(chunk_area_bytes, DFS_META_SIZE_GRANULARITY);
    checker_bitmap_num_bytes = DIV_ROUND_UP(chunk_area_units, BITS_PER_BYTE);
    checker_meta_bitmap = malloc(checker_bitmap_num_bytes);
    if (!checker_meta_bitmap)
        return -1;
    memset(checker_meta_bitmap, 0x0, checker_bitmap_num_bytes);

    // Initialise lazy list bitmaps
    img_meta_bitmaps = (struct chunk_bitmap *)mem;
    meta_bitmaps = calloc(DFS_META_FREE_BITMAP + 1, sizeof(struct chunk_bitmap));
    if (!meta_bitmaps) 
        return -1;
    // set all bits in the free bitmap to 1's.
    memset(&meta_bitmaps[DFS_META_FREE_BITMAP], 0xff, DFS_META_NUM_CHUNKS / BITS_PER_BYTE);

    // Initialise capacity array (for lazy list)
    meta_chunk_capacity = calloc((size_t)((void *)sb->chunks - (void *)sb->heads) 
                    / sizeof(struct lazy_list_head), sizeof(struct lazy_list_head));
    if (!meta_chunk_capacity)
        return -1;

    // Initialise all chunk records
    chunk_records = malloc(sizeof(struct list *) * DFS_META_NUM_CHUNKS);
    if (!chunk_records)
        return -1;
    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        chunk_records[i] = NULL;
    }

    // Initialise data bitmap
    img_data_bitmap = (unsigned long *)((void *)datachunk + sizeof(struct gen_pool_chunk));
    size_t dbitmap_bits = DIV_ROUND_UP(8 * (data_size - sizeof(struct gen_pool_chunk)),
                                                    (8 * (DFS_DATA_ALLOCUNIT)) + 1);
    data_bm_bytes = BITS_TO_LONGS(dbitmap_bits) * sizeof(long);
    data_bitmap = calloc(DIV_ROUND_UP(data_bm_bytes, UL_SZ), UL_SZ);
    if (!data_bitmap) 
        return -1;

    return 0;
}

/* Free all data structures used by the checker and exit the program. */
static void dfsck_exit()
{
    free(dentries);
    free(dirs);
    free(files);
    free(datachunks);
    free(checker_meta_bitmap);
    free(meta_bitmaps);
    free(meta_chunk_capacity);
    free(data_bitmap);

    stack_free(lost_files);
    stack_free(corrupt_datachunks);
    stack_free(bad_datachunks);
    stack_free(corrupt_files);
    stack_free(good_files);

    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        list_free(chunk_records[i]);
    }
    free(chunk_records);

    if (DB_MODE)
        printf("========================= DFSCK 2.0 =========================\n");
    exit(0);
}

/* Function: print_results
 * Print out the error counts.
 */
static void print_results() 
{
    if (DB_MODE) {
        printf("Bad intervals count: %d.\n", bad_interval_cnt);
        printf("Corrupted datachunks: (Total: %ld)\n", corrupt_datachunks->size);
        stack_print_all(corrupt_datachunks);

        printf("\n");
    }

    static unsigned long expected_total_bytes = 0x28e5000;
    unsigned long total_bytes = total_good_file_bytes + total_bad_file_bytes;
    unsigned long lost_bytes = expected_total_bytes - total_bytes;

    if (DB_MODE)
        SET_CLR(GRN);
    printf("Number of files:           %d.\n", file_count);
    printf("Number of directories:     %d.\n", dir_count);
    printf("Good file data bytes:      0x%lx.\n", total_good_file_bytes);
    printf("Bad file recovered bytes:  0x%lx.\n", total_bad_file_bytes);
    printf("Total bytes:               0x%lx.\n", total_bytes);
    printf("Total lost bytes:          0x%lx.\n", lost_bytes);
    printf("Total lost kilobytes:      %lu.\n", lost_bytes / 0x1000);
    printf("  (NOTE: expected_total_bytes (=0x%lx) is a hardcoded value!)\n", expected_total_bytes);
    if (DB_MODE)
        SET_CLR(RESET);
}

/* 
 * Load the image given its file path. Returns file system size.
 */
static unsigned long load_image(char *img_filename)
{
    int fd = open(img_filename, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: failed to open image.\n");
        exit(1);
    }

    struct stat st;
    if (stat(img_filename, &st) != 0) {
        fprintf(stderr, "Error: failed to read image.\n");
        exit(1);
    }

    mem = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (!mem) {
        fprintf(stderr, "Error: failed to map image to memory.\n");
        exit(1);
    }

    close(fd);
    return st.st_size;
}

int main(int argc, char *argv[]) 
{
    if (argc != 2) {
        fprintf(stderr, "Error: no image.\n");
        exit(1);
    }

    unsigned long fs_size = load_image(argv[1]);

    if (dfsck_init() != 0) {
        fprintf(stderr, "Error: failed to allocate memory for data structures.\n");
        exit(1);
    }

    if (DB_MODE)
        printf("\n========================= DFSCK 2.0 =========================\n");
    /* This is where the fun begins. --Darth Vader */
    clock_t begin = clock();

    load_superblock(fs_size);

    if (dfsck_init_bitmaps() != 0) {
        fprintf(stderr, "Error: failed to allocate memory for bitmaps.\n");
        dfsck_exit();
    }

    // check_metametadata();
    check_metadata();

    struct dfs_dentry *lostnfound;
    int lostnfound_index = -1;
    lostnfound = find_lostnfound_dir(map_inode(sb->rootdir.inode));
    if (lostnfound == NULL) {
        if (DB_MODE)
            printf(YEL "  No lost+found folder found. Creating...\n" RESET);
        lostnfound = create_lostnfound_dir(map_inode(sb->rootdir.inode));
        lostnfound_index = dir_count;
        insert_dir_inode(map_inode(lostnfound->inode), 0);
    } else {
        for (int i = 0; i < dir_count; i++) {
            if (dirs[i].inode == map_inode(lostnfound->inode)) {
                lostnfound_index = i;
                break;
            }
        }
    }

    recover_orphaned_files(lostnfound_index);
    recover_orphaned_datachunks(lostnfound_index);
    // add entire directory to checker record
    // FIXME: fucks up if lost+found already exists and new stuff is added to it
    recover_data();
    repair_files();
    check_nlinks();
    conform_lazy_list();

    // print the runtime
    clock_t end = clock();
    double runtime_main = (double)(end - begin) / (CLOCKS_PER_SEC / 1000);
    printf("Total runtime: %.3fms.\n", runtime_main);

    print_results();

    if (DB_MODE) {
        // DEBUG: compare img bitmaps and checker bitmaps
        char yesno[4];
        printf("\nWould you like to see meta-metadata comparisons? (yes/no) ");
        scanf("%s", yesno);
        if (strcmp(yesno, "y") == 0 || strcmp(yesno, "yes") == 0)
            DB_print_bitmaps();

        printf("\nWould you like to see a summary of all data structures? (yes/no) ");
        scanf("%s", yesno);
        if (strcmp(yesno, "y") == 0 || strcmp(yesno, "yes") == 0) {
            print_metadata();
        }
    }

    dfsck_exit();
}

static void DB_print_meta_bitmap(struct chunk_bitmap *bitmap)
{
    for (int i = 0; i < DFS_META_FREE_BITMAP + 1; i++) {
        for (int j = 0; j < DFS_META_NUM_CHUNKS / BITS_PER_UINT; j++) {
            printf("%x ", *((unsigned int *)(bitmap + i) + j));
        }
        printf("\n");
    }
    printf("\n");
}

static void DB_print_data_bitmap(unsigned long *bitmap)
{
    char *bm = (char *)bitmap;
    for (int i = 0; i < data_bm_bytes; i++) {
        printf("%hhx", (unsigned char)*(bm + i));
        if ((i + 1) % 8 == 0)
            if (i != 0) printf(" ");
        if ((i + 1) % 64 == 0) 
            if (i != 0) printf("\n");
    }
    printf("\n\n");
}

static void DB_print_check_meta_bitmap()
{
    for (int i = 0; i < checker_bitmap_num_bytes / sizeof(unsigned long); i++) {
        printf("%lx", checker_meta_bitmap[i]);
        if ((i + 1) % 8 == 0)
            if (i != 0) printf(" ");
        if ((i + 1) % 64 == 0) 
            if (i != 0) printf("\n");
    }
    printf("\n");
}

/*
 * Print out the number of data structures occupying each chunk as recorded
 * in the checker and the image. (Omits empty chunks.)
 *
 * Format:
 * ID   Image   DFSCK   Limit    Content
 * 0    12      12      125      FILE INO    OK    [DB]...
 * 1    223     223     223      DATACHUNK   OK    [DB]...
 * 2    15      19      125      DENTRY 64   ERR   [DB]...
 * ...
 */
static void DB_compare_capacity()
{
    printf("Chunks capacity record comparisons:\n");
    printf("ID   Image  DFSCK  Limit   Content\n");
    size_t img_cnt, dfsck_cnt, size_index;
    unsigned long limit;
    for (int i = 0; i < DFS_META_NUM_CHUNKS; i++) {
        img_cnt = meta_chunk_get_capacity(i);
        dfsck_cnt = lazylist_get_capacity(i);
        size_index = meta_chunk_get_size_index(i);
        limit = chunk_capacity_limit[size_index];
        if (dfsck_cnt != 0 || img_cnt != 0) {
            printf("%-4d %-6ld %-6ld %-6lu  ", i, img_cnt, dfsck_cnt, limit);
            print_size_index_name(size_index);
            printf("  ");
            if (img_cnt == dfsck_cnt) {
                printf(GRN "OK  " RESET);
            } else {
                printf(RED "ERR!" RESET);
            }
            // DEBUG: capacity value img[bit|free bit] dfsck[bit|free bit]
            printf("  [DB] %16lx img[%d|%d] dfsck[%d|%d]\n", llist_heads[i].capacity,
                       lazylist_get_bit(size_index, i), lazylist_get_bit(DFS_META_FREE_BITMAP, i),
                       checker_meta_get_bit(size_index, i), checker_meta_get_bit(DFS_META_FREE_BITMAP, i));
                                        
        }
    }
    printf("(unused)...\n");
}

static void DB_print_data_region(unsigned long *bitmap)
{
    for (int i = 0; i < data_bm_bytes * BITS_PER_BYTE; i++) {
        printf("%d", get_data_block_status((char *)bitmap, i));
        if ((i + 1) % 8 == 0)
            if (i != 0) printf(" ");
        if ((i + 1) % 64 == 0) 
            if (i != 0) printf("\n");
    }
}

static void DB_print_bitmaps()
{
    // printf("Image lazy list bitmap: \n");
    // DB_print_meta_bitmap(img_meta_bitmaps);
    // printf("\nChecker maintained lazy list bitmap: \n");
    // DB_print_meta_bitmap(meta_bitmaps);

    DB_compare_capacity(); 
}
