/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/vm.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/string.h>
#include <forx/list.h>
#include <forx/libctl/snprintf.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/vm.h>
#include <forx/mm/page_table.h>
#include <forx/fs/vfs.h>

static int
mmap_private_fill_page(struct VmMap *map, VirtAddr addr)
{
    struct Page *p = page_zalloc(0, PAL_KERNEL);

    if (!p)
        return -ENOSPC;

    page_table_map_entry(map->owner->page_dir, addr, page_to_pa(p),
        map->flags, PCM_CACHED);

    return 0;
}

int
address_space_handle_pagefault(struct AddrSpace *addrspc, VirtAddr addr)
{
    struct VmMap *map;

    list_foreach_entry(&addrspc->vm_maps, map, addr_space_entry) {
        if (addr >= map->addr.start && addr < map->addr.end) {
            if (map->ops && map->ops->fill_page)
                return (map->ops->fill_page)(map, addr);
            else
                return mmap_private_fill_page(map, addr);
        }
    }

    kprintf(KERN_TRACE, "addrspc: No handler for fault: %p\n", addr);

    return -EFAULT;
}

void
address_space_change(struct AddrSpace *new)
{
    struct Task *current = cpu_get_local()->current;
    struct AddrSpace *old = current->addrspc;

    current->addrspc = new;
    page_table_change(new->page_dir);
    address_space_clear(old);
    kfree(old);
}

void
address_space_clear(struct AddrSpace *addrspc)
{
    struct VmMap *map;

    list_foreach_take_entry(&addrspc->vm_maps, map, addr_spc_entry) {
        int page_count = (map->addr.end - map->addr.start) / PAGE_SIZE;

        if (flag_test(&map->flags, VM_MAP_IGNORE))
            page_table_zap_range(addrspc->page_dir, map->addr.start, page_count);
        else
            page_table_free_range(addrspc->page_dir, map->addr.start, page_count);

        if (map->filp)
            vfs_close(map->filp);

        kfree(map);
    }

    page_table_free(addrspc->page_dir);
    addrspc->page_dir = NULL;
}

static struct VmMap *
vm_map_copy(struct AddrSpace *new, struct AddrSpace *old, struct VmMap *old_map)
{
    if (flag_test(&old_map->flags, VM_MAP_NOFORK))
        return NULL;

    struct VmMap *new_map = kmalloc(sizeof(*new_map), PAL_KERNEL);
    vm_map_init(new_map);

    new_map->addr = old_map->addr;
    new_map->flags = old_map->flags;
    int pages = (uintptr_t)(old_map->addr.end - old_map->addr.start) / PAGE_SIZE;

    if (!flag_test(&old_map->flags, VM_MAP_IGNORE)) {
        /**
         * We can reply on the page fault handler to fault in pages for a
         * read-only file mapping. If we don't have that though, then we need
         * to just duplicate all backing pages.
        **/
        if (flag_test(&old_map->flags, VM_MAP_WRITE) || !old_map->filp)
            page_table_copy_range(new->page_dir, old->page_dir, old_map->add.start, pages);
    } else {
        /**
         * If the mapping is marked VM_MAP_IGNORE, then we simply copy the PTEs
         * rather than create new backing pages.
        **/
        page_table_clone_range(new->page_dir, old->page_dir, old_map->addr.start, pages);
    }

    if (old_map->filp) {
        new_map->filp = file_dup(old_map->filp);
        new_map->file_page_offset = old_map->file_page_offset;
    }

    new_map->ops = old_map->ops;

    return new_map;
}

void
address_space_copy(struct AddrSpace *new, struct AddrSpace *old)
{
    struct VmMap *map;
    struct VmMap *new_map;

    // Make copy of every map //
    list_foreach_entry(&old->vm_maps, map, addr_space_entry) {
        new_map = vm_map_copy(new, old, map);

        if (!new_map)
            continue;

        if (old->code == map)
            new->code = new_map;
        else if (old->data == map)
            new->data = new_map;
        else if (old->stack == map)
            new->stack = new_map;
        else if (old->bss == map)
            new->bss = new_map;

        address_space_vm_map_add(new, new_map);
    }
}

void
address_space_vm_map_add(struct AddrSpace *addrspc, struct VmMap *map)
{
    list_add(&addrspc->vm_map, &map->addr_space_entry);
    map->owner = addrspc;
}

void
address_space_vm_map_remove(struct AddrSpace *addrspc, struct VmMap *map)
{
    list_del(&map->addr_space_entry);
    map->owner = NULL;
}

static void
vm_map_resize_start(struct VmMap *map, VirtAddr new_start)
{
    PageDir *pgd = map->owner->page_dir;

    if (map->addr.start <= new_start) {
        int old_pages = (new_start - map->addr.start) / PAGE_SIZE;
        VirtAddr new_addr = map->addr.start;
        page_table_free_range(pgd, new_addr, old_pages);
    }

    map->addr.start = new_start;
}

static void
vm_map_resize_end(struct VmMap *map, VirtAddr new_end)
{
    PageDir *pgd = map->owner->page_dir;

    if (new_end <= map->addr.end) {
        int old_pages = (map->addr.end - new_end) / PAGE_SIZE;

        if (old_pages)
            page_table_free_range(pgd, map->addr.end - old_pages * PAGE_SIZE,
                old_pages);
    }

    map->addr.end = new_end;
}

void
vm_map_resize(struct VmMap *map, struct VmRegion new_size)
{
    if (map->addr.start != new_size.start)
        vm_map_resize_start(map, new_size.start);

    if (map->addr.end != new_size.end)
        vm_map_resize_end(map, new_size.end);
}

#define MMAP_START_ADDRS (VirtAddr)0x80000000

int
address_space_find_region(struct AddrSpace *addrspc, size_t size, struct VmRegion *region)
{
    struct VmMap *prev = NULL;
    struct VmMap *map;

    size = ALIGN_2(size, PAGE_SIZE);

    list_foreach_entry(&addrspc->vm_maps, map, addr_space_entry) {
        if (map->addr.start > MMAP_START_ADDRS)
            break;

        prev = map;
    }

    VirtAddr bottom;

    if (prev)
        bottom = ((MMAP_START_ADDRS < prev->addr.end) ? prev->addr.end : MMAP_START_ADDRS);
    else
        bottom = MMAP_START_ADDRS;

    // Calculate the amount of space we have in the intended MMAP location //
    size_t space_after_addr = (map->addr.start - bottom);

    if (space_after_addrs >= size) {
        region->start = bottom;
        region->end = region->start + size;

        return 0;
    }

    return -ENOMEM;
}
