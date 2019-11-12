#ifndef LIST_H
#define LIST_H

struct list_node {
    struct list_node *next;
    void *data;
};

struct list {
    struct list_node *head;
    unsigned long size;
};

struct list *list_init();
struct list_node *list_new_node(void *data);
int list_insert(struct list_node *new_node, struct list *list);
int list_remove_by_value(void *data, struct list *list);
int list_find(void *data, struct list *list);
void list_free(struct list *list);
void list_print_all(struct list *list);

#endif // __LIST_H__
