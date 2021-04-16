/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/ida.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/bits.h>
#include <forx/mm/page_table.h>
#include <forx/ida.h>

int
ida_getid(struct Ida *ida)
{
    using_spinlock(&ida->lock) {
        int id = bit_find_first_zero(ida->ids, ALIGN_2(ida->total_ids, 4));

        if (id == -1 || id >= ida->total_ids)
            return -1;

        bit_set(ida->ids, id);

        return id;
    }
}

void
ida_putid(struct Ida *ida, int id)
{
    using_spinlock(&ida->lock)
        bit_clear(ida->ids, id);
}
