#ifndef DFSCK_UTIL_H
#define DFSCK_UTIL_H

#include <string.h>
#include "dfs.h"

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYA   "\x1B[36m"
#define RESET "\x1B[0m"
#define SET_CLR(x)  printf(x)

#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define LMS_SIZE_MASK GENMASK(LMS_METAIDX_POS - 1, 0)

/* 
 * Macros to verify and fix different types of data, as well as 
 * printing out error messages and incrementing counters (if any is provided.)
 */
#define check_ptr(img, expected, name, counter) \
    if ((void *)(img) != (void *)(expected)) {  \
        if (strcmp(name, "") != 0) {  \
            printf(YEL "Corrupt: incorrect %s pointer.\n" RESET, name); \
            printf(YEL "    Expected: %p, Image: %p.\n" RESET, expected, img); \
            if (counter != NO_COUNTER) {  \
                ++*counter;  \
            }   \
        } \
        img = expected;     \
    }

#define check_val(img, expected, name, counter) \
    if (img != expected) {  \
        if (strcmp(name, "") != 0) {  \
            printf(YEL "Corrupt: incorrect %s value.\n" RESET, name);  \
            printf(YEL "    Expected: %ld, Image: %ld.\n" RESET,  \
                    (unsigned long)expected, (unsigned long)img); \
            if (counter != NO_COUNTER) {  \
                ++*counter;  \
            }   \
        }  \
        img = expected;  \
    }

#define check_str(img, expected, name, counter) \
    if (strcmp(img, expected) != 0) {  \
        if (strcmp(name, "") != 0) {  \
            printf(YEL "Corrupt: incorrect %s.\n" RESET, name);  \
            printf(YEL "    Expected: %s, Image: %s.\n" RESET, expected, img);  \
            if (counter != NO_COUNTER) {  \
                ++*counter;  \
            }   \
        }  \
        strcpy(img, expected);  \
    }

void *img_to_mem(void *addr);
void *mem_to_img(void *addr);

struct dfs_inode *map_inode(struct dfs_inode *inode);
struct dfs_inode *unmap_inode(struct dfs_inode *inode);
struct dfs_dentry *map_dentry(struct dfs_dentry *dentry);
struct dfs_dentry *unmap_dentry(struct dfs_dentry *dentry);
struct dfs_datachunk *map_datachunk(struct dfs_datachunk *dc);
struct dfs_datachunk *unmap_datachunk(struct dfs_datachunk *dc);

void *check_capacity(void *addr, unsigned long *curr_sz, int cnt, unsigned long sz);
size_t dfs_dentry_size(const struct dfs_dentry *dent);
bool isdir(const struct dfs_inode *inode);
bool isreg(const struct dfs_inode *inode);

size_t dfs_inode_get_size(struct dfs_inode *inode);
void dfs_inode_set_size(struct dfs_inode *inode, unsigned long newsz);

unsigned int crc32b(unsigned char *message, int message_size);

struct dfs_dentry *get_first_dentry(struct dfs_inode *dir_inode);
struct dfs_datachunk *get_root_datachunk(struct dfs_inode *file_inode);
struct dfs_datachunk *get_left_datachunk(struct dfs_datachunk *dc);
struct dfs_datachunk *get_right_datachunk(struct dfs_datachunk *dc);
struct dfs_datachunk *get_datachunk_parent(struct dfs_datachunk *dc);
void *get_datachunk_data_pointer(struct dfs_datachunk *dc);

void print_all_intervals(struct dfs_inode *file);
void print_interval_tree(struct dfs_inode *file);

#endif // DFSCK_UTIL_H
