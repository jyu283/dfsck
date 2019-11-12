#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "include/dfsck_util.h" 
#include "include/dfsck.h"
#include "include/interval_tree_util.h"

extern void *image_mem;
extern struct dfs_fs *sb;

/* Convert image address to mmap'd address in memory. */
void *img_to_mem(void *addr) 
{
    if (addr == NULL)
        return NULL;
    unsigned long off = (unsigned long)(addr - image_mem);
    return (void *)mem + off;
}

/* Convert mmap'd address in memory to image address. */
void *mem_to_img(void *addr) 
{
    if (addr == NULL)
        return NULL;
    unsigned long off = (unsigned long)(addr - mem);
    return image_mem + off;
}

struct dfs_inode *map_inode(struct dfs_inode *inode)
{
    return (struct dfs_inode *)img_to_mem(inode);
}

struct dfs_inode *unmap_inode(struct dfs_inode *inode)
{
    return (struct dfs_inode *)mem_to_img(inode);
}

struct dfs_dentry *map_dentry(struct dfs_dentry *dentry)
{
    return (struct dfs_dentry *)img_to_mem(dentry);
}

struct dfs_dentry *unmap_dentry(struct dfs_dentry *dentry)
{
    return (struct dfs_dentry *)mem_to_img(dentry);
}

struct dfs_datachunk *map_datachunk(struct dfs_datachunk *dc)
{
    return (struct dfs_datachunk *)img_to_mem(dc);
}

struct dfs_datachunk *unmap_datachunk(struct dfs_datachunk *dc)
{
    return (struct dfs_datachunk *)mem_to_img(dc);
}

static size_t dfs_dentry_size_for_len(size_t namelen)
{
	size_t extra;
	if ((namelen + 1) <= DFS_DENTRY_INLINE_LEN)
		extra = 0;
	else
		extra = namelen + 1 - DFS_DENTRY_INLINE_LEN;
	return sizeof(struct dfs_dentry) + extra;
}

size_t dfs_dentry_size(const struct dfs_dentry *dent)
{
	return dfs_dentry_size_for_len(dent->namelen);
}

/*
 * Checks if a container has enough space to accomodate more items
 * If not, reallocate more space for the container.
 */
void *check_capacity(void *addr, unsigned long *curr_sz, int cnt, unsigned long sz) 
{
    if (cnt >= *curr_sz - 1) {
        *curr_sz = *curr_sz * 2;
        return realloc(addr, *curr_sz * sz);
    }
    return addr;
}

static inline metaidx_t dfs_inode_get_meta_idx(const struct dfs_inode* inode)
{
    return (inode->__lock_metaidx_size & LMS_METAIDX_MASK) >> LMS_METAIDX_POS;
}

static void read_imeta(metaidx_t idx, kuid_t* uid, kgid_t* gid, umode_t* mode)
{
	struct imeta* p;
	p = &(sb->imeta.arr[idx / DFS_IMETA_PER_LIST_NODE].imeta[idx % DFS_IMETA_PER_LIST_NODE]);
    p = img_to_mem(p);
	if (uid)
		*uid = p->uid;
	if (gid)
		*gid = p->gid;
	if (mode)
		*mode = p->mode;
}

static umode_t inode_mode(const struct dfs_inode* inode)
{
    umode_t mode;
    read_imeta(dfs_inode_get_meta_idx(inode), NULL, NULL, &mode);
    return mode;
}

bool isdir(const struct dfs_inode* inode)
{
    return S_ISDIR(inode_mode(inode));
}

bool isreg(const struct dfs_inode* inode)
{
    return S_ISREG(inode_mode(inode));
}

size_t dfs_inode_get_size(struct dfs_inode *inode)
{
    return inode->__lock_metaidx_size & LMS_SIZE_MASK;
}

// Copied from hackerdelight.org(Free to use), small modification
unsigned int crc32b(unsigned char *message, int message_size) {
   int i, j;
   unsigned int byte, crc, mask;

   i = 0;
   crc = 0xFFFFFFFF;
   while (i < message_size) {
      byte = message[i];            // Get next byte.
      crc = crc ^ byte;
      for (j = 7; j >= 0; j--) {    // Do eight times.
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
      i = i + 1;
   }
   return ~crc;
}

struct dfs_dentry *get_first_dentry(struct dfs_inode *dir_inode)
{
    return img_to_mem(dir_inode->data.dirents.next);
}

struct dfs_datachunk *get_root_datachunk(struct dfs_inode *file_inode)
{
    return img_to_mem(file_inode->data.chunks.rb_node);
}

struct dfs_datachunk *get_left_datachunk(struct dfs_datachunk *dc)
{
    return img_to_mem(dc->it.rb.rb_left);
}

struct dfs_datachunk *get_right_datachunk(struct dfs_datachunk *dc)
{
    return img_to_mem(dc->it.rb.rb_right);
}

struct dfs_datachunk *get_datachunk_parent(struct dfs_datachunk *dc)
{
    unsigned long parent = dc->it.rb.__rb_parent_color & (~3);
    return map_datachunk((struct dfs_datachunk *)parent);
}

void *get_datachunk_data_pointer(struct dfs_datachunk *dc)
{
    return (void *)(dc->data_initialized & (~1UL));
}

static void in_order_print_intervals(struct dfs_datachunk *dc)
{
    if (dc == NULL)
        return;

    in_order_print_intervals(get_left_datachunk(dc));
    printf("[%lx, %lx] ", dc->it.start, dc->it.last);
    in_order_print_intervals(get_right_datachunk(dc));

}

void print_all_intervals(struct dfs_inode *file)
{
    struct dfs_datachunk *dc = get_root_datachunk(file);
    in_order_print_intervals(dc);
    printf("\n");
}

static void in_order_print_tree(struct dfs_datachunk *dc)
{
    if (dc == NULL)
        return;
    in_order_print_tree(get_left_datachunk(dc));
    printf("%p: [%lx, %lx]\t L: %p, R: %p, P_C: %lx. S_L: %lx\n", unmap_datachunk(dc),
            dc->it.start, dc->it.last, dc->it.rb.rb_left, dc->it.rb.rb_right, 
            dc->it.rb.__rb_parent_color, dc->it.__subtree_last);
    in_order_print_tree(get_right_datachunk(dc));
}

void print_interval_tree(struct dfs_inode *file)
{
    printf("Total node count: %d.\n", get_node_count(file));
    struct dfs_datachunk *dc = get_root_datachunk(file);
    in_order_print_tree(dc);
}
