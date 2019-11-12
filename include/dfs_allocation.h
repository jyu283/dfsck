#ifndef DFS_ALLOCATION_H
#define DFS_ALLOCATION_H

#include "dfs.h"

void *dfs_meta_alloc(size_t sz, int sz_index);
void dfs_meta_free(void *ptr, int sz_index);

struct dfs_dentry *dfs_alloc_dentry(size_t name_len);
struct dfs_inode *dfs_alloc_dir_inode();
struct dfs_inode *dfs_alloc_file_inode();

void dfs_free_datachunk(struct dfs_datachunk *dc);
void dfs_free_dentry(struct dfs_dentry *dentry);
void dfs_free_dir_inode(struct dfs_inode *inode);
void dfs_free_file_inode(struct dfs_inode *inode);
void dfs_free_datachunk(struct dfs_datachunk *dc);

void init_dentry(struct dfs_dentry *dent, const char *name, struct dfs_inode *inode);
struct dfs_inode *create_dir_inode(struct dfs_inode *dir_parent);
struct dfs_inode *create_file_inode();

#endif // __DFS_ALLOCATION_H__
