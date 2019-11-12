/*
 * NOTE: This utility library is meant to be used on a mmap'd image of a 
 * DenseFS file system. Therefore it is important that address conversion
 * (included in dfsck_util library) is performed whenever necessary.
 *
 * Red-Black tree rules (according to Linux kernel documentations):
 *   - A node is either RED or BLACK
 *   - The root is black
 *   - All leaves (NULL) are BLACK
 *   - Both chlidren of every RED node are BLACK
 *   - Every simple path from root to leaves contain 
 *     the same number of BLACK nodes.
 *
 * Additional rules for the DenseFS file interval tree:
 *   - a node's start = left child's __subtree_last + 1
 *   - a node's last = right child's subtree first (wrote function for that)
 *   - a node's __subtree_last = right child's __subtree_last
 *
 * NOTE TO READER
 *   If you are reading this, I'm no longer on this project. But I'd like to tell
 * you a few things --
 *   Interval trees are a menace to the fundation of modern civilisation and all 
 * basic human decency. And to place them in the Linux kernel ... Dear reader, 
 * can you contemplate such utter evil without horror?
 *   If, by some great misfortune, you have come upon the dreaful mess I have
 * begotten, please do accept my sincere apology; I hope you can sympathise with
 * my pain and anguish.            
 * 
 *   Jerry Yu
 *   13 August 2019
 */

#include <stdio.h>

#include "include/interval_tree_util.h"
#include "include/dfsck_util.h"

static struct dfs_datachunk *first_chunk, *last_chunk;
static int total_black_count;
static unsigned long last_addr;

/* Ignore these */
static int no_counter = 0, *NO_COUNTER = &no_counter;

int rb_get_color(struct rb_node *rb)
{
    if (rb == NULL)
        return RB_BLACK;
    return (rb->__rb_parent_color & 3UL);
}

int rb_is_red(struct rb_node *rb)
{
    return (rb_get_color(rb) ? 0 : 1);
}

int rb_is_black(struct rb_node *rb)
{
    return rb_get_color(rb);
}

static inline int dc_is_red(struct dfs_datachunk *dc)
{
    return (rb_is_red(&dc->it.rb));
}

static inline int dc_is_black(struct dfs_datachunk *dc)
{
    return (rb_is_black(&dc->it.rb));
}

static inline void rb_set_black(struct rb_node *rb)
{
    rb->__rb_parent_color |= RB_BLACK;
}

static inline void rb_set_red(struct rb_node *rb)
{
    rb->__rb_parent_color &= ~1UL;
}

static int rb_get_black_count(struct rb_node *curr) {
    int count = 0;
    while (curr != NULL) {
        if (rb_is_black(curr))
            count++;
        curr = img_to_mem(curr->rb_left);   // FIXME: img_to_mem
    }
    
    return count;
}

static inline unsigned long get_inode_final_block_last(struct dfs_inode *inode)
{
    size_t inode_size = dfs_inode_get_size(inode);
    return (round_up(inode_size, PGSIZE) - 1);
}

static int get_node_count_traverse(struct dfs_datachunk *dc)
{
    int count = 1;
    struct dfs_datachunk *left = img_to_mem(dc->it.rb.rb_left);
    struct dfs_datachunk *right = img_to_mem(dc->it.rb.rb_right);

    if (left != NULL)
        count += get_node_count_traverse(left);
    if (right != NULL)
        count += get_node_count_traverse(right);

    return count;
}

int get_node_count(struct dfs_inode *file)
{
    struct dfs_datachunk *root_dc = img_to_mem(file->data.chunks.rb_node);
    int count = 0;
    if (root_dc != NULL)
        count = get_node_count_traverse(root_dc);
    return count;
}

static struct dfs_datachunk *find_subtree_first_chunk(struct dfs_datachunk *root_dc)
{
    struct dfs_datachunk *curr = root_dc;
    while (curr->it.rb.rb_left != NULL) {
        curr = img_to_mem(curr->it.rb.rb_left);
    }
    return curr;
}

static struct dfs_datachunk *find_subtree_last_chunk(struct dfs_datachunk *root_dc)
{
    struct dfs_datachunk *curr = root_dc;
    while (curr->it.rb.rb_right != NULL) {
        curr = img_to_mem(curr->it.rb.rb_right);
    }
    return curr;
}

static inline unsigned long it_get_subtree_start(struct interval_tree_node *it)
{
    struct dfs_datachunk *it_root = (struct dfs_datachunk *)it;
    return find_subtree_first_chunk(it_root)->it.start;
}

/* 
 * Checks the RB properties of a tree.
 */
static int check_rb_correctness(struct dfs_datachunk *dc, int curr_black_cnt)
{
    if (dc == NULL) {
        if (curr_black_cnt != total_black_count) {
            printf(YEL "Warning: RB imbalance detected (exp: %d, img: %d).\n" RESET,
                                                    curr_black_cnt, total_black_count);
            return 1;
        } else
            return 0;
    }

    int ret = 0;

    struct dfs_datachunk *left = get_left_datachunk(dc);
    struct dfs_datachunk *right = get_right_datachunk(dc);

    if (dc_is_red(dc)) {
        /* Red nodes should not have red children. */
        if (dc_is_red(left) || dc_is_red(right)) {
            printf(YEL "Warning: RB imbalance detected: red node has red child(ren)." RESET);
            ret++;
        }
    } else {
        curr_black_cnt++;
    }

    ret += check_rb_correctness(left, curr_black_cnt);
    ret += check_rb_correctness(right, curr_black_cnt);

    return ret;
}

int check_rb_property(struct dfs_inode *file)
{
    struct dfs_datachunk *root_dc = get_root_datachunk(file);
    struct rb_node *rb_root = &root_dc->it.rb;
    total_black_count = rb_get_black_count(rb_root);

    if (check_rb_correctness(root_dc, 0) != 0) 
        return -1;
    else 
        return 0;
}

static inline bool interval_is_aligned(unsigned long interval)
{
    return ((interval & 0xfffUL) == 0xfff);
}

static inline bool dc_is_left_child(struct dfs_datachunk *dc) 
{
    struct dfs_datachunk *parent = get_datachunk_parent(dc);
    return (dc == get_left_datachunk(parent));
}

static inline bool dc_is_right_child(struct dfs_datachunk *dc)
{
    struct dfs_datachunk *parent = get_datachunk_parent(dc);
    return (dc == get_right_datachunk(parent));
}

static int check_intervals_traverse(struct dfs_datachunk *dc)
{
    static unsigned long expected_start;
    int ret = 0;

    if (dc == NULL)
        return ret;

    if (dc == first_chunk) {
        // printf(GRN "Starting new tree!\n" RESET);
        expected_start = 0;
    }

    struct dfs_datachunk *left = get_left_datachunk(dc);
    struct dfs_datachunk *right = get_right_datachunk(dc);

    ret += check_intervals_traverse(left);
    
    // printf(":: Interval start: %lx, expected: %lx.\n", dc->it.start, expected_start);
    /* Check interval start */
    if (dc->it.start != expected_start) {
        printf(GRN "  Fixed interval start: %lx -> %lx.\n" RESET, dc->it.start, expected_start);
        dc->it.start = expected_start;
        ret++;
    }

    /* Check interval end */
    unsigned long expected_last;
    struct dfs_datachunk *parent = get_datachunk_parent(dc);
    if (parent != NULL) {
        if (dc_is_left_child(dc)) {
            if (right != NULL) {
                expected_last = it_get_subtree_start(&right->it) - 1;
            } else {
                expected_last = parent->it.start - 1;
            }
        } else {    
            if (right != NULL) {
                expected_last = it_get_subtree_start(&right->it) - 1; 
            } else {
                expected_last = dc->it.__subtree_last;
            }
        }
    } else {
        if (right != NULL) {
            expected_last = it_get_subtree_start(&right->it) - 1;
        } else {
            expected_last = dc->it.__subtree_last;
        }
    }
    // printf(":: Interval last: %lx, expected: %lx.\n", dc->it.last, expected_last);

    if (dc->it.last != expected_last) {
        if (!interval_is_aligned(dc->it.last)) {
            printf(GRN "  Fixed interval last:  %lx -> %lx.\n" RESET, dc->it.last, expected_last);
            dc->it.last = expected_last;
        }
    }

    expected_start = dc->it.last + 1;

    ret += check_intervals_traverse(right);

    return ret;
}

int check_intervals(struct dfs_inode *file)
{
    struct dfs_datachunk *root_dc = get_root_datachunk(file);
    first_chunk = find_subtree_first_chunk(root_dc);
    last_chunk = find_subtree_last_chunk(root_dc);
    return check_intervals_traverse(root_dc);
}

void rb_set_parent(struct rb_node *rb, struct rb_node *parent)
{
    rb->__rb_parent_color &= 3UL;
    rb->__rb_parent_color |= (unsigned long)parent;
}

void dc_set_rbparent(struct dfs_datachunk *dc, struct dfs_datachunk *p)
{
    if (dc) {
        dc->it.rb.__rb_parent_color &= 3UL;
        dc->it.rb.__rb_parent_color |= (unsigned long)p;
    }
}

void dc_flip_color(struct dfs_datachunk *dc)
{
    struct rb_node *rb = &dc->it.rb;
    if (rb_is_red(rb)) {
        rb_set_black(rb);
    } else {
        rb_set_red(rb);
    }
}

static unsigned long dc_find_subtree_last(struct dfs_datachunk *dc)
{
    while (get_right_datachunk(dc) != NULL) {
        dc = get_right_datachunk(dc);
    }
    return dc->it.last;
}

void dc_set_subtree_last(struct dfs_datachunk *dc)
{
    dc->it.__subtree_last = dc_find_subtree_last(dc);
}

int check_interval_tree_structure(struct dfs_datachunk *root_dc)
{
    int ret = 0;
    struct rb_node *rb_root = &root_dc->it.rb;
    first_chunk = find_subtree_first_chunk(root_dc);
    last_chunk = find_subtree_last_chunk(root_dc);
    total_black_count = rb_get_black_count(rb_root);
    // printf("  Total black count: %d.\n", total_black_count);

    if (check_rb_correctness(root_dc, 0) != 0) {
        return -1;
    }

    // If the tree's structure is intact (no missing nodes)
    // then proceed to verify all the intervals
    
    return ret;
}

