#ifndef INTERVAL_TREE_UTIL_H
#define INTERVAL_TREE_UTIL_H

#include "dfs.h"
#include "stack.h"

#define RB_BLACK            1
#define RB_RED              0

int rb_get_color(struct rb_node *node);
int rb_is_red(struct rb_node *node);
int rb_is_black(struct rb_node *node);

void rb_set_parent(struct rb_node *rb, struct rb_node *parent);

int check_interval_tree_structure(struct dfs_datachunk *root_dc);
int check_rb_property(struct dfs_inode *file);
int check_intervals(struct dfs_inode *file);
int get_node_count(struct dfs_inode *file);
void construct_interval_tree(struct stack *chunks);

void dc_flip_color(struct dfs_datachunk *dc);
void dc_set_rbparent(struct dfs_datachunk *dc, struct dfs_datachunk *p);
void dc_set_subtree_last(struct dfs_datachunk *dc);

#endif // __INTERVAL_TREE_UTIL_H__
