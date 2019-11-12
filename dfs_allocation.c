#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <sys/stat.h>

#include "include/dfs_allocation.h"
#include "include/dfs.h"
#include "include/dfsck.h"
#include "include/dfsck_util.h"

/* NOTICE: All functions in this file take and return MMAP addresses. */

static inline size_t dfs_get_chunk_capacity(struct lazy_list_head *head)
{
    return head->capacity << 6 >> 6;
}

/*
 * Allocate metadata.
 * Copied from densefs.c with minor modifications to work with checker.
 * Removed kernel-only function calls.
 * NOTE: When using addresses contained within a structure, need to convert
 * it to an image address before using the pointer.
 */
void *dfs_meta_alloc(size_t sz, int sz_index)
{
    struct lazy_list_head *head;
    struct lazy_list_node *chunk, *next;
    struct chunk_bitmap *bm;
    struct chunk_bitmap *bm2;
    void *ret;
    int group, i, bit;
    bm2 = bm = sb->chunk_bitmaps + sz_index;

start:
    // Search chunk bitmap
	for (i = 0; i < DFS_META_NUM_CHUNKS / BITS_PER_UINT; i++){
		if (bm2->ints[i] > 0){
			bit = ffs(bm2->ints[i]) - 1;
			if (bm2 == sb->chunk_bitmaps + DFS_META_FREE_BITMAP) {
				// found bit in free list; allocate new chunk
				bm2->ints[i] &= ~(1 << bit);
				bm->ints[i] |= 1 << bit;
			}
			group = i;
			goto found_chunk;
		}
	}
	if (bm2 == sb->chunk_bitmaps + DFS_META_FREE_BITMAP) {
		return NULL; // No chunk found in free list; fail
	}
	bm2 = sb->chunk_bitmaps + DFS_META_FREE_BITMAP; // No chunk found; go to free list
	goto start;
	
found_chunk:
	head = llist_heads + bit + group * BITS_PER_UINT;
	chunk = (struct lazy_list_node*)(chunks + (bit + group * BITS_PER_UINT) * sb->chunk_size);
	
	ret = img_to_mem(head->head); 
    
    if (dfs_get_chunk_capacity(head) + 1 >= sb->chunk_size / sz) {
        bm->ints[group] &= ~(1 << bit);
    }

	head->capacity++;

    unsigned long reset_mask = ~((unsigned long)0xF << LAZY_LIST_HEAD_INDEX_START_BIT);
    head->capacity &= reset_mask;
    head->capacity |= ((unsigned long)sz_index) << LAZY_LIST_HEAD_INDEX_START_BIT;
	
	if (!DFS_META_CHUNK_BIT(head)){
		// In first run of list; advance head to adjacent node
		next = (struct lazy_list_node *)(img_to_mem(head->head) + sz);
		next->next = ((struct lazy_list_node *)img_to_mem(head->head))->next;
		head->head = mem_to_img(next);
		
		//pr_crit("next: %p, sz: %d, chunk: %p, chunk size: %lu\n", next, sz, chunk, dfs->chunk_size);
		if ((char*)next + sz * 2 > (char *)chunk + sb->chunk_size){
            // If next adjacent node is outside chunk, 
            // set bit to indicate that the first run is over
			head->capacity |= 1UL << LAZY_LIST_HEAD_CHUNK_BIT; 		
        }
	}
	else{
		head->head = ((struct lazy_list_node *)img_to_mem(head->head))->next; // Pop off the head
	}
	memset(ret, 0, sz); // Clear new allocation space
	return ret;
}

// FIXME: Addressing
/* TAKES MMAP'D MEMORY ADDRESSES */
void dfs_meta_free(void *ptr, int sz_index)
{
	struct lazy_list_head *head;
	struct lazy_list_node *addr;
	int chunk_index, group, bit;
	addr = (struct lazy_list_node *)ptr;
	chunk_index = ((char*)ptr - chunks) / sb->chunk_size;
	head = llist_heads + chunk_index;
	group = chunk_index / BITS_PER_UINT;
	bit = chunk_index % BITS_PER_UINT;
	
    if (dfs_get_chunk_capacity(head) - 1 < chunk_capacity_limit[sz_index]) {
    // if (DFS_META_CHUNK_UNFULL(sb, head, DFS_META_INDEX_TO_SIZE(sz_index))){
        // Check if chunk is about to become unfull
		sb->chunk_bitmaps[sz_index].ints[group] |= 1 << bit; // Set bit in chunk bitmap for this sigma
	} else if (DFS_META_CHUNK_EMPTY(head)) { 
        // Check if chunk is about to become empty
		// deallocate chunk
		sb->chunk_bitmaps[sz_index].ints[group] &= ~(1 << bit); // Unset bit in chunk bitmap for this sigma
		sb->chunk_bitmaps[DFS_META_FREE_BITMAP].ints[group] |= 1 << bit; // Set bit in free list
		head->head = (struct lazy_list_node *)(sb->chunks + chunk_index * sb->chunk_size); // Set head to base
		((struct lazy_list_node *)img_to_mem(head->head))->next = NULL; // Detach list
		head->capacity = 0;
		return;
	}
	
	head->capacity--;
	if (!DFS_META_CHUNK_BIT(head)) {
		// In first run of list; place after head node	
		addr->next = ((struct lazy_list_node *)img_to_mem(head->head))->next;
		((struct lazy_list_node *)img_to_mem(head->head))->next = mem_to_img(addr);
	} else {
		// Place as head node
		addr->next = head->head;
		head->head = mem_to_img(addr);
	}
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

struct dfs_dentry *dfs_alloc_dentry(size_t name_len)
{
	size_t alloc_sz, dentry_sz;
	struct dfs_dentry* dent;
	dentry_sz = dfs_dentry_size_for_len(name_len);
    alloc_sz = (dentry_sz + DFS_META_SIZE_GRANULARITY - 1) & ~(DFS_META_SIZE_GRANULARITY - 1);
	dent = dfs_meta_alloc(alloc_sz, DFS_META_DENTRY_BITMAP(dentry_sz));
	if (!dent)
		return NULL;
	return dent;
}

struct dfs_inode *dfs_alloc_dir_inode()
{
    struct dfs_inode *inode;
    inode = dfs_meta_alloc(DIR_INODE_SZ, DFS_META_DIR_INODE_BITMAP);
    return inode;
}

struct dfs_inode *dfs_alloc_file_inode()
{
    struct dfs_inode *inode;
    inode = dfs_meta_alloc(FILE_INODE_SZ, DFS_META_FILE_INODE_BITMAP);
    return inode;
}

void init_dentry(struct dfs_dentry *dent, const char *name, struct dfs_inode *inode)
{
    dent->list.next = NULL;
    dent->inode = mem_to_img(inode);
    inode->nlink += 1;
    dent->refs.refcount.refs.counter = 1;
    dent->namelen = strlen(name);
    strcpy(dent->name, name);
}

// TODO: Many fields are not initialised yet.
// dir_parent is an mmap'd memory address
struct dfs_inode *create_dir_inode(struct dfs_inode *dir_parent)
{
    struct dfs_inode *inode;

    inode = dfs_alloc_dir_inode();
    if (!inode)
        return NULL;

    // FIXME: This is definitely not good.
    inode->__lock_metaidx_size = 0x3ce000000000000;
        
    inode->extra->parent = unmap_inode(dir_parent);
    inode->data.dirents.next = NULL;
    inode->pincount.refs.counter = 0;

    return inode;
}

struct dfs_inode *create_file_inode()
{
    struct dfs_inode *inode;

    inode = dfs_alloc_file_inode();
    if (!inode)
        return NULL;

    inode->__lock_metaidx_size = 0x786000000000000;    // TODO
    inode->data.chunks.rb_node = NULL;
    inode->pincount.refs.counter = 0;

    return inode;
}

void dfs_free_file_inode(struct dfs_inode *inode)
{
    dfs_meta_free(inode, DFS_META_FILE_INODE_BITMAP);
}

void dfs_free_dentry(struct dfs_dentry *dentry)
{
    dfs_meta_free(dentry, DFS_META_DENTRY_BITMAP(dfs_dentry_size(dentry)));
}

void dfs_free_datachunk(struct dfs_datachunk *dc)
{
    dfs_meta_free(dc, DFS_META_DATACHUNK_BITMAP);
}
