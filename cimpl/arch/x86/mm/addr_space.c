/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x86/mm/addr_space.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/vm.h>
#include <forx/sched.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>

#include <forx/arch/paging.h>
#include <forx/arch/page_table.h>

PageDir *
page_table_new(void)
{
    PageDir *pgd = page_alloc_va(0, PAL_KERNEL);
    memcpy(pgd, &kernel_dir, PAGE_SIZE);

    return pgd;
}

void
page_table_free(PageDir *table)
{
    PageDirEntry *pde;
    PhysAddr pa;

    pgd_foreach_pde(table, pde) {
        if (!pde_exists(pde))
            continue;

        if (!pde_is_user(pde))
            continue;

        pa = pde_get_pa(pde);

        if (pa)
            page_free_pa(pa, 0);
    }

    page_free_va(table, 0);
}

void
page_table_change(PageDir *new)
{
    set_current_page_dir(V2P(new));
}
