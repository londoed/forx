/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/vm_area.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <libctl/snprintf.h>
#include <forx/task.h>
#include <forx/mutex.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/vm.h>
#include <forx/mm/vm_area.h>
#include <forx/mm/kmmap.h>

// A lock covering VmAreaList and VmAreaMappings //
static Mutex vm_area_list_lock = MUTEX_INIT(vm_area_list_lock);

// VmAreaList is a list of all currently free VmArea's, sorted by size //
static ListHead vm_area_list = LIST_HEAD_INIT(vm_area_list);

/**
 * An array that represents which pages of virtual memory are currently
 * used by what `VmArea`s.
 *
 * This allows us to quickly take an address and find it's associated `VmArea`,
 * and also take a VmArea and quickly check the nearest VmAreas to it for
 * combining into larger areas.
 *
 * NOTE: This uses a __lot__ of memory, with the default config its 256KB. This
 * is too much for a feature we don't actually use all that much, and we can
 * definitely represent the mappings in a more efficient way.
**/
static struct VmArea *vm_area_mappings[KMAP_PAGES];

static int
vm_area_to_index(void *p)
{
    p -= CONFIG_KERNEL_KMAP_START;

    return (uintptr_t)p >> PAGE_SHIFT;
}

static void
__vm_area_add(struct VmArea *area)
{
    struct VmArea *vm;

    list_foreach_entry(&vm_area_list, vm, vm_area_entry) {
        if (vm->page_count > area->page_count) {
            list_add_tail(&vm->vm_area_entry, &area->vm_area_entry);

            return;
        }
    }

    list_add_tail(&vm_area_list, &area->vm_area_entry);
}

/**
 * Takes a VmArea with a page_count larger then `new_pages`, and splits
 * it into two VmAreas, one with a page_count of `new_pages`, and one
 * with the rest, and returns the VmArea with a page_count of `new_pages`.
**/
static struct VmArea *
__vm_area_split(struct VmArea *area, int new_pages)
{
    int i, start_index;
    struct VmArea *alloced_area = kzalloc(sizeof(*alloced_area), PAL_KERNEL);
    struct VmArea *new_area = alloced_area;

    vm_area_init(new_area);

    /**
     * We choose to use the newly allocated VmArea as the area with the
     * free or the used pages depending on which requires us to modify
     * the least number of `VmAreaMapping`s entries.
     *
     * This is simply a matter of finding which VmArea will end-up with
     * less pages.
    **/
    if (area->page_count / 2 >= new_pages) {
        new_area->area = area->area + PAGE_SIZE * new_pages;
        new_area->page_count = area->page_count - new_pages;
        flag_set(&new_area->flags, VM_AREA_FREE);
        area->page_count = new_pages;
    } else {
        struct VmArea *tmp;
        new_area->area = area->area;
        new_area->page_count = new_pages;

        area->area = new_area->area + PAGE_SIZE * new_pages;
        area->page_count = area->page_count - new_pages;
        flag_set(&area->flags, VM_AREA_FREE);

        tmp = new_area;
        new_area = area;
        area = tmp;
    }

    start_index = vm_area_to_index(alloced_area->area);

    for (i = 0; i < alloced_area->page_count; i++)
        vm_area_mappings[i + start_index] = alloced_area;

    __vm_area_add(new_area);

    return area;
}

static struct VmArea *
__vm_area_combine(struct VmArea *area)
{
    int again = 0;

    do {
        int i, index = vm_area_to_index(area->area);
        struct VmArea *before = vm_area_mappings[index - 1];
        struct VmArea *after = vm_area_mappings[index + area->page_count];
        again = 0;

        if (index > 0 && flag_test(&before->flags, VM_AREA_FREE)) {
            int start_index;
            list_del(&before->vm_area_entry);

            /**
             * Fancy swapping is to reduce the number of VmAreaMappings
             * we have to modify down below.
            **/
            if (before->page_count < area->page_count) {
                area->area = before->area;
                area->page_count += before->page_count;
            } else {
                struct VmArea *tmp;
                before->page_count += area->page_count;

                tmp = area;
                area = before;
                before = tmp;
            }

            start_index = vm_area_to_index(before->area);

            for (i = 0; i < before->page_count; i++)
                vm_area_mappings[i + start_index] = area;

            kfree(before);
            again = 1;
        }

        if (index + area->page_count < KMAP_PAGES && flag_test(&after->flags, VM_AREA_FREE)) {
            int start_index;
            list_del(&after->vm_area_entry);

            /**
             * Fancy swapping here is to reduce the number of VmAreaMappings
             * we have to modify down below.
            **/
            if (area->page_count < after->page_count) {
                area->page_count += after->page_count;
            } else {
                struct VmArea *tmp;
                after->area = area->area;
                after->page_count += area->page_count;

                tmp = area;
                area = after;
                after = tmp;
            }

            start_index = vm_area_to_index(after->area);

            for (i = 0; i < after->page_count; i++)
                vm_area_mappings[i + start_index] = area;

            kfree(after);
            again = 1;
        }
    } while (again);

    return area;
}

struct VmArea *
vm_area_alloc(int pages)
{
    struct VmArea *area;

    using_mutex(&vm_area_list_lock) {
        list_foreach_entry(&vm_area_list, area, vm_area_entry) {
            if (area->page_count >= pages)
                break;
        }

        if (list_ptr_is_head(&vm_area_list, &area->vm_area_entry))
            return NULL;

        list_del(&area->vm_area_entry);

        if (area->page_count > pages)
            area = __vm_area_split(area, pages);

        flag_clear(&area->flags, VM_AREA_FREE);
    }

    return area;
}

void
vm_area_free(struct VmArea *area)
{
    using_mutex(&vm_area_list_lock) {
        flag_set(&area->flags, VM_AREA_FREE);
        list_del(&area->vm_area_entry);

        area = __vm_area_combine(area);
        __vm_area_add(area);
    }
}

static void
vm_area_allocator_init(void)
{
    int i;
    struct VmArea *area = kmalloc(sizeof(*area), PAL_KERNEL);

    area->area = (void *)CONFIG_KERNEL_KMAP_START;
    area->page_count = KMAP_PAGES;
    flag_set(&area->flags, VM_AREA_FREE);

    list_add(&vm_area_list, &area->vm_area_entry);

    for (i = 0; i < KMAP_PAGES; i++)
        vm_area_mappings[i] = area;
}

initcall_core(VmArea, vm_area_allocator_init);

void *
kmmap_pcm(PhysAddr addr, size_t len, Flags vm_flags, int pcm)
{
    size_t addr_offset = addr % PAGE_SIZE;
    PhysAddr pg_addr = addr & ~PAGE_SIZE;
    int pages = PAGE_ALIGN(len + addr_offset) >> PAGE_SHIFT;
    struct VmArea *area;
    int i;

    kprintf(KERN_NORM, "mem_map: %d pages, %p:%d\n", pages, (void *)addr, len);
    area = vm_area_alloc(pages);

    for (i = 0; i < pages; i++)
        vm_area_map(area->area + i * PAGE_SIZE, pg_addr + i * PAGE_SIZE, vm_flags, pcm);

    return area->area + addr_offset;
}

void *
kmmap(PhysAddr addr, size_t len, Flags vm_flags)
{
    return kmmap_pcm(addr, len, vm_flags, PCM_UNCACHED_WEAK);
}

void
kmunmap(void *p)
{
    int index = vm_area_to_index(p);
    struct VmArea *area;
    int i;

    using_mutex(&vm_area_list_lock)
        area = vm_area_mappings[index];

    kprintf(KERN_NORM, "mem_unmap: %p, %p:%d\n", p, area->area, area->page_count);

    for (i = 0; i < area->page_count; i++)
        vm_area_unmap(area->area + i * PAGE_SIZE);

    vm_area_free(area);
}
