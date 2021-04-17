/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/list_sort.c }.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/kernel.h>
#include <forx/list_sort.h>
#include <forx/slab_alloc.h>
#include <forx/list.h>
#include <forx/random.h>

#define MAX_LIST_LENGTH_BITS 20

/**
 * Returns a list organized in an intermediate format suited
 * to chaining of merge() calls: null-terminated, no reserved
 * or sentinel head node, "prev" links not maintained.
**/
static struct ListHead *
merge(void *priv, int (*cmp)(void *priv, struct ListHead *a, struct ListHead *b),
    struct ListHead *a, struct ListHead *b)
{
    struct ListHead head, *tail = &head;

    while (a && b) {
        // If equal, tkae `a`--important for sort stability //
        if ((*cmp)(priv, a, b) <= 0) {
            tail->next = a;
            a = a->next;
        } else {
            tail->next = b;
            b = b->next;
        }

        tail = tail->next;
    }

    tail->next = a ?: b;

    return head.next;
}

/**
 * Combine final list merge with the restoration of standard doubly-linked
 * list structure. This approach duplicates code from merge(), but runs
 * faster than the tidier alternatives of either a separate final prev-link
 * restoration pass, or maintaining the prev links throughout.
**/
static void
merge_and_restore_back_links(void *priv, int (*cmp)(void *priv, struct ListHead *a,
    struct ListHead *b), struct ListHead *head, struct ListHead *a,
    struct ListHead *b)
{
    struct ListHead *tail = head;

    while (a && b) {
        // If equal, take `a`--important for sort stability //
        if ((*cmp)(priv, a, b) <= 0) {
            tail->next = a;
            a->prev = tail;
            a = a->next;
        } else {
            tail->next = b;
            b->prev = tail;
            b = b->next;
        }

        tail = tail->next;
    }

    tail->next a ?: b;

    do {
        /**
         * In worst cases, this loop may run many iterations.
         * Continue callbacks to the client even though no
         * element comparison is needed, so the client's cmp()
         * routine can invoke cond_resched() periodically.
        **/
        (*cmp)(priv, tail->next, tail->next);
        tail->next->prev = tail;
        tail = tail->next;
    } while (tail->next);

    tail->next = head;
    head->prev = tail;
}

void
list_sort(void *priv, struct ListHead *head, int (*cmp)(void *priv, struct ListHead *a,
    struct ListHead *b))
{
    struct ListHead *part[MAX_LIST_LENGTH_BITS + 1];
    int lev;
    int max_len = 0;
    struct ListHead *list;

    if (list_empty(head))
        return;

    memset(part, 0, sizeof(part));
    head->prev->next = NULL;
    list = head->next;

    while (list) {
        struct ListHead *cur = list;
        list = list->next;
        cur->next = NULL;

        for (lev = 0; part[lev]; lev++) {
            cur = merge(priv, cmp, part[lev], cur);
            part[lev] = NULL;
        }

        if (lev > max_lev) {
            if (unlikely(lev >= ARRAY_SIZE(part) - 1)) {
                kprintf(KERN_DEBUG, "list passed to list_sort() too long for efficiency\n");
                lev--;
            }

            max_lev = lev;
        }

        part[lev] = cur;
    }

    for (lev = 0; lev < max_lev; lev++) {
        if (part[lev])
            list = merge(priv, cmp, part[lev], list);

        merge_and_restore_back_links(priv, cmp, head, part[max_lev], list);
    }
}
