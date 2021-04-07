/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/list.h }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef __FORX_LIST_H
#define __FORX_LIST_H

#include <forx/stddef.h>
#include <forx/container_of.h>

/**
 * Very similar to the Linux kernel list.h header (GPLv2).
 * Doubly-linked circular linked list.
 *
 * The design of this is such that the `head` of a linked list, and a
 * `node` area actually the same thing.
 *
 * The `head` is simply an entry in the list like all the rest. When
 * doing a loop or movement that involves the head, we simply take a
 * pointer to the `head` node in the list, and then check the rest of
 * them against that reference node.
 *
 * There are still separate `ListNode` and `ListHead` types that are
 * equivalent, for making it easier to recognize when a node is being
 * used as the head of a list versus being an entry in a list. The
 * types themselves are equivalent.
**/
typedef struct ListNodeSt ListNode;
typedef struct ListNodeSt ListHead;

struct ListNodeSt {
    ListNode *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) \
    ListHead name = LIST_HEAD_INIT(name)

#define LIST_NODE_INIT(name) LIST_HEAD_INIT(name)
#define list_node_init(node) list_head_init(node)

static inline void
list_head_init(ListHead *head)
{
    *head = (ListHead)LIST_HEAD_INIT(*head);
}

static inline void
__list_add(ListNode *new, ListNode *prev, ListNode *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void
list_add(ListHead *head, ListNode *new)
{
    __list_add(new, head, head->next);
}

static inline void
list_add_tail(ListHead *head, ListNode *new)
{
    __list_add(new, head->prev, head);
}

#define list_attach(head, node) \
    list_add_tail(node, head)

#define list_add_after(node1, node2) \
    list_add((node1), (node2))

#define list_add_before(node1, node2) \
    list_add_tail((node1), (node2))

static inline void
__list_del(ListNode *prev, ListNode *next)
{
    next->prev = prev;
    prev->next = next;
}

static inline void
__list_del_entry(ListNode *entry)
{
    __list_del(entry->prev, entry->next);
}

// Adds the list `list_to_add` between prev and next //
static inline void
__list_splice(ListNode *prev, ListNode *next, ListHead *list_to_add)
{
    ListNode *first = list_to_add->next;
    ListNode *last = list_to_add->prev;

    first->prev = prev;
    prev->next = first;
    last->next = next;
    next->prev = last;
}

static inline void
list_del(ListNode *entry)
{
    __list_del_entry(entry);
    list_node_init(entry);
}

static inline void
list_replace(ListNode *old, ListNode *new)
{
    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;
}

static inline void
list_replace_init(ListNode *old, ListNode *new)
{
    list_replace(old, new);
    list_head_init(old);
}

static inline void
list_move(ListHead *head, ListNode *entry)
{
    __list_del_entry(entry);
    list_add(head, entry);
}

static inline void
list_move_tail(ListHead *head, ListNode *entry)
{
    __list_del_entry(entry);
    list_add_tail(head, entry);
}

static inline int
list_is_last(const ListHead *head, const ListNode *entry)
{
    return entry->next == head;
}

static inline int
list_empty(const ListHead *head)
{
    return head == head->next;
}

#define list_node_is_in_list(node) !list_empty(node)

static inline void
list_rotate_left(ListHead *head)
{
    if (!list_empty(head))
        list_move_tail(head, head->next);
}

static inline void
list_rotate_right(ListHead *head)
{
    if (!list_empty(head))
        list_move(head, head->prev);
}

static inline void
list_splice(ListHead *head, ListHead *old_list)
{
    if (!list_empty(old_list))
        __list_splice(head, head->next, old_list);
}

static inline void
list_splice_tail(ListHead *head, ListHead *old_list)
{
    if (!list_empty(old_list))
        __list_splice(head->prev, head, old_list);
}

static inline void
list_splice_init(ListHead *head, ListHead *old_list)
{
    if (!list_empty(old_list)) {
        __list_splice(head, head->next, old_list);
        list_head_init(old_list);
    }
}

static inline void
list_splice_tail_init(ListHead *head, ListHead *old_list)
{
    if (!list_empty(old_list)) {
        __list_splice(head->prev, head, old_list);
        list_head_init(old_list);
    }
}

/**
 * Moves `first`, which is already in list `head`, to the position of
 * the first entry in `head`, by rotating the list.
 *
 * The `new_first` and `new_last` can be though of as doing multiple
 * rotations at once, as you could do that to achieve the same result,
 * but it would be much less optimal.
**/
static inline void
list_new_first(ListHead *head, ListNode *new_first)
{
    ListNode *last = head->prev;
    ListNode *first = head->next;
    ListNode *new_last = new_first->prev;

    if (first == new_first)
        return;

    // Connect first and last list node together //
    last->next = first;
    first->prev = last;

    // Make `new_last` and `new_first` the first and last nodes of the list //
    new_last->next = head;
    new_first->prev = head;
    head->prev = new_last;
    head->next = new_first;
}

static inline void
list_new_last(ListHead *head, ListNode *new_last)
{
    ListNode *last = head->prev;
    ListNode *first = head->next;
    ListNode *new_first = new_last->next;

    if (last == new_last)
        return;

    last->next = first;
    first->prev = last;
    new_last->next = head;
    new_first->prev = head;

    head->prev = new_last;
    head->next = new_first;
}

static inline ListNode *
__list_first(ListHead *head)
{
    return head->next;
}

#define list_first(head, type, member) \
    container_of(__list_first(head), type, member)

static inline ListNode *
__list_last(ListHead *head)
{
    return head->prev;
}

#define list_last(head, type, member) \
    container_of(__list_last(head), type, member)

static inline ListNode *
__list_take_first(ListHead *head)
{
    ListNode *node = __list_first(head);
    list_del(node);

    return node;
}

#define list_take_first(head, type, member) \
    container_of(__list_take_first(head), type, member)

static inline ListNode *
__list_take_last(ListHead *head)
{
    ListNode *node = __list_last(head);
    list_del(node);

    return node;
}

#define list_take_last(head, type, member) \
    container_of(__list_take_last(head), type, member)

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
    list_entry((ptr)->prev, type, member)

#define list_first_entry_or_null(ptr, type, member) \
    (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
    list_entry((pos)->member.prev, typeof(*(pos)), member)

#define list_foreach(head, pos) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_foreach_prev(head, pos) \
    for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define list_foreach_entry(head, pos, member) \
    for (pos = list_first_entry(head, typeof(*pos), member); \
        &pos->member != (head); \
        pos = list_next_entry(pos, member))

#define list_foreach_entry_safe(head, pos, nxt, member) \
    for (pos = list_first_entry(head, typeof(*pos), member), \
        nxt = list_next_entry(pos, member); \
        &pos->member != (head); \
        pos = nxt, nxt = list_next_entry(nxt, member))

#define list_foreach_entry_reverse(head, pos, member) \
    for (pos = list_last_entry(head, typeof(*pos), member); \
        &pos->member != (head); \
        pos = list_prev_entry(pos, member))

#define list_foreach_take_entry(head, pos, member) \
    for (pos = list_empty(head) ? NULL : list_take_first(head, typeof(*pos), member); \
        pos;
        pos = list_empty(head) ? NULL : list_take_first(head, typeof(*pos), member))
        
#define list_foreach_take_entry_reverse(head, pos, member) \
    for (pos = list_empty(head) ? NULL : list_take_last(head, typeof(*pos), member); \
        &(pos)->member != NULL;
        pos = list_empty(head) ? NULL : list_take_last(head, typeof(*pos), member))

#define list_ptr_is_head(head, ptr) \
    ((ptr) == (head))

#endif
