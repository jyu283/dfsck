
/* The cmp function operates between nodes (void *N)-s.
 * These must store L, R (void *)-s at N + coff.    // ours are right first then left, im changing this accordingly and hopefully that fixes any issue
 * The black (0) / red (1) bit is used at // this is also the opposite for us, so we should traverse the tree in the end and flip all the bits
 * the masked bit of N+boff.
 NOTE: THERE IS NO PARENT POINTER, WILL HAVE TO BE ADDED AFTER THE ENTIRE TREE IS CONSTRUCTED.
 boff = color bit offset
 coff = children offset
 */

#ifndef RBTREE_H
#define RBTREE_H

// This structure basically holds information about this tree and 
// it gets passed around to other functions
typedef struct {
    int (*cmp)(const void *, const void *);
    unsigned int coff, boff;
    unsigned char mask; // contains a one where red/black bit is set.
    void *nil;
} rbop_t;

// Only keeping the ones we would be needing
void new_tree(void *N, const rbop_t *o);
void *add_node(void **N, void *A, const rbop_t *o);

// returns mask or 0
unsigned char get_mask(const void *N, const rbop_t *o);

#endif // RBTREE_H
