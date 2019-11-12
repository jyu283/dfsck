/* A small sorted list library. */

#include <stdlib.h>
#include <stdio.h>

#include "include/list.h"

struct list *list_init()
{
    struct list *list = malloc(sizeof(struct list));
    list->head = NULL;
    list->size = 0;
    return list;
}

void list_free(struct list *list)
{
    if (list == NULL)
        return;
    struct list_node *curr;
    while (list->head != NULL) {
        curr = list->head;
        list->head = list->head->next;
        free(curr);
    }
    free(list);
}

struct list_node *list_new_node(void *data)
{
    struct list_node *new_node = malloc(sizeof(struct list_node));
    new_node->data = data;
    return new_node;
}

// Return -1 if address already exists in the list
int list_insert(struct list_node *new_node, struct list *list)
{
    if (list == NULL)
        return -1;
    if (list->head == NULL || list->head->data > new_node->data) {
        new_node->next = list->head;
        list->head = new_node;
        list->size++;
        return 0;
    }
    struct list_node *curr = list->head;
    while (curr->next != NULL && curr->next->data < new_node->data) {
        curr = curr->next;
    }
    if (curr->next != NULL && curr->next->data == new_node->next) {
        return -1;
    }
    new_node->next = curr->next;
    curr->next = new_node;
    list->size++;
    return 0;
}

int list_remove_by_value(void *data, struct list *list) 
{
    if (list == NULL || list->head == NULL) {
        return -1;
    }
    struct list_node *deleted = NULL;
    if (list->head->data == data) {
        deleted = list->head;
        list->head = list->head->next;
        free(deleted);
        list->size--;
        return 0;
    }
    struct list_node *curr = list->head;
    while (curr->next != NULL && curr->next->data != data) {
        curr = curr->next;
    }
    if (curr->next == NULL) {   // target not found
        return -1;
    } else {
        deleted = curr->next;
        curr->next = curr->next->next;
        free(deleted);
        list->size--;
        return 0;
    }
}

int list_find(void *data, struct list *list)
{
    if (list == NULL)
        return 0;
    struct list_node *curr = list->head;
    while (curr != NULL) {
        if (curr->data == data) {
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

void list_print_all(struct list *list)
{
    int new_line_cnt = 0;
    int lines = 0;
    if (list == NULL)
        printf("Invalid list.\n");
    if (list->head == NULL)
        printf("Empty.\n");
    struct list_node *curr = list->head;
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

