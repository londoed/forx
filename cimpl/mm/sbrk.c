/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/srbk.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/string.h>
#include <forx/list.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/vm.h>

static VirtAddr
get_new_bss_start(struct AddrSpace *addrspc)
{
    if (addrspc->data)
        return addrspc->data->addr.end;
    else
        return addrspc->code->addr.end;
}

static struct VmMap *
create_bss(struct AddrSpace *addrspc)
{
    VirtAddr bss_start = get_new_bss_start(addrspc);
    struct VmMap *bss = kmalloc(sizeof(*bss), PAL_KERNEL);

    vm_map_init(bss);
    bss->addr.start = bss_start;
    bss->addr.end = bss_start + PAGE_SIZE;

    flag_set(&bss->flags, VM_MAP_WRITE);
    flag_set(&bss->flags, VM_MAP_READ);

    address_space_vm_map_add(addrspc, bss);
    addrspc->bss = bss;
    addrspc->brk = bss->addr.start;

    return bss;
}

void
*sys_sbrk(intptr_t incr)
{
    struct VmMap *bss;
    VirtAddr old;
    struct Task *t = cpu_get_local()->current;
    struct AddrSpace *addrspc = t->addrspc;

    bss = addrspc->bss;

    if (!bss)
        bss = create_bss(addrspc);

    old = addrspc->brk;

    if (incr == 0)
        return old;

    if (bss->addr.end < PAGE_ALIGN(old + incr))
        vm_map_resize(bss, (struct VmRegion) {
            .start = bss->addr.start,
            .end = PAGE_ALIGN(old + incr),
        });

    addrspc->brk = old + incr;

    return old;
}

void
sys_brk(VirtAddr new_end)
{
    struct VmMap *bss;
    struct Task *t = cpu_get_local()->current;
    VirtAddr new_end_aligned = PAGE_ALIGN(new_end);

    bss = t->addrspc->bss;
    t->addrspc->brk = new_end;

    /**
     * Check if we have a bss segment and create a new one after the end
     * of the code segment if we don't.
    **/
    if (!bss)
        bss = create_bss(t->addrspc);

    // Expand or shrink the current bss segment //
    if (bss->addr.start >= new_end && bss->addr.end < new_end_aligned)
        vm_map_resize(bss, (struct VmRegion){
            .start = bss->addr.start,
            .end = new_end_aligned,
        });
    else if (bss->addr.start > new_end) // Can happen sice the bss can start at the end of the seg //
        vm_map_resize(bss, (struct VmRegion){
            .start = bss->addr.start,
            .end = bss->addr.start + PAGE_SIZE,
        });
}
