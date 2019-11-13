#include <stdlib.h>
#include <stdio.h>

#include "stack.h"

struct stack *stack_init()
{
    struct stack *stack = malloc(sizeof(struct stack));
    stack->first = NULL;
    stack->size = 0;
    return stack;
}

struct stack_node *stack_new_node(void *data)
{
    struct stack_node *new_node = malloc(sizeof(struct stack_node));
    new_node->data = data;
    return new_node;
}

void stack_push(struct stack_node *new_node, struct stack *stack)
{
    if (new_node == NULL || stack == NULL)
        return;
    new_node->next = stack->first;
    stack->first = new_node;
    stack->size++;
}

struct stack_node *stack_pop(struct stack *stack)
{
    if (stack->first == NULL)
        return NULL;
    struct stack_node *popped = stack->first;
    stack->first = stack->first->next;
    stack->size--;
    return popped;
}

struct stack_node *stack_peek(struct stack *stack)
{
    return stack->first;
}

void stack_free(struct stack *stack)
{
    if (stack == NULL)
        return;
    struct stack_node *curr;
    while (stack->first != NULL) {
        curr = stack->first;
        stack->first = stack->first->next;
        free(curr);
    }
    free(stack);
}

int stack_find(void *data, struct stack *stack)
{
    if (stack == NULL)
        return 0;
    struct stack_node *curr = stack->first;
    while (curr != NULL) {
        if (curr->data == data) {
            return 1;
        } else {
            curr = curr->next;
        }
    }
    return 0;
}

void stack_remove(void *data, struct stack *stack)
{
    if (stack == NULL)
        return;

    struct stack_node *curr = stack->first;
    if (curr->data == data) {   /* first node is target */
        stack->first = curr->next;
        free(curr);
        stack->size--;
        return;
    }

    struct stack_node *prev = curr;
    curr = curr->next;

    while (curr != NULL) {
        if (curr->data == data) {
            prev->next = curr->next;
            free(curr);
            stack->size--;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

void stack_clear(struct stack *stack)
{
    if (stack == NULL)
        return;

    struct stack_node *curr;
    while (stack->first != NULL) {
        curr = stack->first;
        stack->first = stack->first->next;
        free(curr);
    }

    stack->first = NULL;
    stack->size = 0;
}

void stack_print_all(struct stack *list)
{
    int new_line_cnt = 0;
    int lines = 0;
    if (list == NULL)
        printf("Invalid list.\n");
    if (list->first == NULL)
        printf("Empty.\n");
    struct stack_node *curr = list->first;
    while (curr != NULL) {
        printf("%p | ", curr->data);
        if (new_line_cnt++ == 4) {
            printf("\n");
            new_line_cnt = 0;
            lines++;
            if (lines > 5) {
                printf(" ... \n");
                return;
            }
        }
        curr = curr->next;
    }
    if (new_line_cnt != 0)
        printf("\n");
}

