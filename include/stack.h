#ifndef STACK_H
#define STACK_H

struct stack_node {
    struct stack_node *next;
    void *data;
};

struct stack {
    struct stack_node *first;
    unsigned long size;
};

struct stack *stack_init();
struct stack_node *stack_new_node(void *data);
void stack_push(struct stack_node *new_node, struct stack *stack);
struct stack_node *stack_pop(struct stack *stack);
struct stack_node *stack_peek(struct stack *stack);
void stack_remove(void *data, struct stack *stack);
void stack_free(struct stack *stack);
void stack_clear(struct stack *stack);
int stack_find(void *data, struct stack *stack);
void stack_print_all(struct stack *list);

#endif // STACK_H
