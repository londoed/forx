/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/ida.h }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef FORX_IDA_H
#define FORX_IDA_H

#include <forx/types.h>
#include <forx/spinlock.h>

struct Ida {
    Spinlock lock;
    int total_ids;
    uint32_t *ids;
};

#define IDA_INIT(id_array, total) \
    { \
        .lock = SPINLOCK_INIT(), \
        .ids = (id_array), \
        .total_ids = (total), \
    }

static inline void
ida_init(struct Ida *ida, uint32_t *ids, int total_ids)
{
    *ida = (struct Ida)IDA_INIT(ids, total_ids);
}

// Returns -1 if allocation can't be done //
int ida_getid(struct Ida *);
void ida_putid(struct Ida *, int id);

#endif
