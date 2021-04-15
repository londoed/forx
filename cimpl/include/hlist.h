/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/hlist.h }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef FORX_HLIST_H
#define FORX_HLIST_H

#include <libctl/stddef.h>
#include <forx/list.h>

struct HListNode {
    struct HListNode **pprev, *next;
};

struct HListHead {
    struct HListNode *first;
};

#define HLIST_HEAD_INIT { .first = NULL }
#define HLIST_HEAD(name) HListHead name = HLIST_HEAD_INIT(name)
#define HLIST_NODE_INIT() { 0 }

static inline void
hlist_node_init(HListNode *n)
{
    n->next = NULL;
    n->pprev = NULL;
}

static inline int
hlist_empty(const HListHead *h)
{
    return !h->first;
}

static inline void
__hlist_del(HListNode *n)
{
    HListNode *next = n->next;
    HListNode **pprev = n->prev;

    *pprev = next;

    if (next)
        next->pprev = pprev;
}

static inline int
hlist_hashed(HListNode *n)
{
    if (hlist_hashed(n)) {
        __hlist_del(n);
        n->next = NULL;
        n->pprev = NULL;
    }
}

static inline void
hlist_add(HListHead *head, HListNode *n)
{
    HListNode *first = head->first;

    n->next = first;

    if (first)
        first->pprev = &n->next;

    head->first = n;
    n->pprev = &head->first;
}

#define hlist_entry(head, type, member) \
    container_of(head, type, member)

/**
 * Necessary because container_of() will modify the `head` pointer, with
 * the result being that if it starts out as NULL, it won't end as NULL.
**/
#define hlist_entry_or_null(head, type, member) \
    ({ \
        typeof(head) __hlist_tmp = (head); \
        ((__hlist_tmp) ? hlist_entry(__hlist_tmp, type, member) : NULL); \
    })

#define hlist_foreach(head, pos) \
    for (pos = (head)->first; pos; pos = (pos)->next)

#define hlist_foreach_entry(head, pos, member) \
    for (pos = hlist_entry_or_null((head)->first, typeof(*(pos)), member); \
        pos; \
        pos = hlist_entry_or_null((pos)->member.next, typeof(*(pos)), member))

#endif
