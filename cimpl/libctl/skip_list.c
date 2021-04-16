/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/skip_list.c }.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <libctl/stdlib.h>
#include <libctl/stdio.h>
#include <libctl/limits.h>

#define SKIPLIST_MAX_LEVEL 0

typedef struct SklNode {
    int key;
    int val;
    struct SklNode **next;
};

typedef struct SkipList {
    int level;
    struct SklNode *head;
};

#define SKIPLIST_HEAD_INIT { .level = NULL, head = NULL }
#define SKIPLIST_HEAD(name) SkipList name = SKIPLIST_HEAD_INIT(name)
#define SKLIST_NODE_INIT() { .key = 0, .val = 0, .next = SKIPLIST_HEAD_INIT() }

SkipList *
skiplist_init(Skiplist *sklist)
{
    int i;
    struct SklNode *head = (SklNode *)malloc(sizeof(struct SklNode));

    if (!head)
        return -EINVAL;

    sklist->head = head;
    head->key = INT_MAX;
    head->next = (SklNode **)malloc(sizeof(SklNode *) * (SKIPLIST_MAX_LEVEL + 1));

    if (!head->next)
        return -EINVAL;

    for (i = 0; i <= SKIPLIST_MAX_LEVEL; i++)
        head->next[i] = sklist->head;

    sklist->level = 1;

    return sklist;
}

static int
skiplist_rand_level(int seed)
{
    int rand_num;

    get_random_bytes(&seed, sizeof(int));
    rand_num = seed % SKIPLIST_MAX_LEVEL;

    return rand_num;
}

int
skiplist_insert(SkipList *sklist, int key, int val)
{
    SklNode *update[SKIPLIST_MAX_LEVEL + 1];
    SklNode *node = sklist->head;
    int i, level;

    for (i = sklist->level; i >= 1; i--) {
        while (node->next[i]->key < key)
            node = node->next[i];

        update[i] = node;
    }

    node = node->next[1];

    if (node->key == key) {
        node->val = val;

        return 0;
    } else {
        level = skiplist_rand_level();

        if (level > sklist->level) {
            for (i = slist->level + 1; i <= level; i++)
                update[i] = sklist->head;

            sklist->level = level;
        }

        node = (SklNode *)malloc(sizeof(SklNode));

        if (!node)
            return -EINVAL;

        node->key = key;
        node->val = val;
        node->next = (SklNode **)malloc(sizeof(SklNode *) * (level + 1));

        if (!node->next)
            return -EINVAL;

        for (i = 1; i <= level; i++) {
            node->next[i] = update[i]->next[i];
            update[i]->next[i] = node;
        }
    }

    return 0;
}

SklNode *
skiplist_search(SkipList *sklist, int key)
{
    SklNode *node = sklist->head;
    int i;

    for (i = sklist->level; i >= 1; i--) {
        while (node->next[i]->key < key)
            node = node->next[i];
    }

    if (node->next[i]->key == key) {
        return node->next[1];
    }

    return NULL;
}

static void
skiplist_node_free(SklNode *node)
{
    if (node) {
        free(node->next);
        free(node);
    }

    return NULL;
}

int
skiplist_delete(SkipList *sklist, int key)
{
    SklNode *update[SKIPLIST_MAX_LEVEL + 1];
    SklNode *node = sklist->head;
    int i;

    for (i = sklist->level; i >= 1; i--) {
        while (node->next[i]->key < key)
            node = node->next[i];

        update[i] = node;
    }

    node = node->next[1];

    if (node->key == key) {
        for (i = 1; i <= sklist->level; i++) {
            if (update[i]->next[i] != node)
                break;

            update[i]->next[i] = node->forward[i];
        }

        skiplist_node_free(node);

        while (sklist->level > 1 && sklist->head->next[sklist->level] == sklist->head)
            sklist->level--;

        return 0;
    }

    return 1;
}

static void
skiplist_free(SkipList *sklist)
{
    SklNode *current = sklist->head->next[1];

    while (current != sklist->head) {
        SklNode *next = current->next[1];
        free(current->next);
        free(current);
        current = next;
    }

    free(current->next);
    free(current);
    free(sklist);
}

