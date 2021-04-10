/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/bootmem.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/libctl/string.h>
#include <forx/libctl/snprintf.h>
#include <forx/debug.h>
#include <forx/bits.h>
#include <forx/libctl/limits.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/page_alloc.h>
#include <forx/backtrace.c>
#include <forx/kparam.h>
#include <forx/mm/bootmem.h>

struct BootmemRegion {
    PhysAddr start;
    PhysAddr end;
};

// Max number of memory regions that bootmem can handle //
static struct BootmemRegion mem_regions[64];
static PageNum highest_page;
extern char kern_end, kern_start;

static void *kern_end_addr = &kern_end;
static void *kern_start_addr = &kern_start;

int
bootmem_add(PhysAddr start, PhysAddr end)
{
    int i = 0;
    start = PAGE_ALIGN(start);
    end = PAGE_ALIGN_DOWN(end);
    size_t size = end - start;

    // Skip the zero page, we don't allow allocating PA 0 even if it's valid mem //
    if (start == 0) {
        start = PAGE_SIZE;

        if (start >= end)
            return 0;
    }

    /**
     * Keep track of the highest page of physical memory. page_malloc() needs
     * this to know how big to make the Page array.
    **/
    PageNum last_page = __PA_TO_PN(end);

    if (last_page > hightest_page)
        hightest_page = last_page;

    PhysAddr kern_pg_start = PG_ALIGN_DOWN(V2P(kern_start_addr));
    PhysAddr kern_pg_end = PG_ALIGN(V2P(kern_end_addr));

    // If the entire region is within the kernel's location, skip it //
    if (start >= kern_pg_start && end < kern_pg_end)
        return 0;

    /**
     * Check if this region overlaps with the kernel's physical location.
     * If so, split into two separate regions and exclude the kernel.
    **/
    if ((start < kern_pg_end && end >= kern_pg_end) ||
        (start <= kern_pg_start && end > kern_pg_start)) {

        if (start < kern_pg_start)
            bootmem_add(start, kern_pg_start);

        if (end > kern_pg_end)
            bootmem_add(kern_pg_end, end);

        return 0;
    }

    kprintf(KERN_NORMAL, "bootmem: Registering region 0x%08-0x%08x, %dMB\n",
        start, end, size / 1024 / 1024);

    for (; i < ARRAY_SIZE(mem_regions); i++) {
        if (mem_regions[i].start == 0) {
            mem_regions[i].start = start;
            mem_regions[i].end = end;

            return 0;
        }
    }

    kprintf(KERN_WARN, "bootmem: Ran out of regions, discarded region 0x%08x-0x%08x\n",
        start, end);

    return -ENOMEM;
}

void *
bootmem_alloc_nopanic(size_t length, size_t alignment)
{
    struct BootmemRegion *region = mem_regions;

    for (; region != mem_regions + ARRAY_SIZE(mem_regions); region++) {
        PhysAddr first_addr = ALIGN_2(region->start, alignment);
        PhysAddr end_addr = ALIGN_2_DOWN(region->end, alignment);

        if (first_addr < end_addr && end_addr - first_addr >= length) {
            region->start = first_addr + length;

            return P2V(first_addr);
        }
    }

    return NULL;
}

void *
bootmem_alloc(size_t len, size_t align)
{
    void *ret = bootmem_alloc_nopanic(len, align);

    if (!ret)
        panic("Ran out of bootmem() memory\n");

    return ret;
}

void
bootmem_setup_page_alloc(void)
{
    page_alloc_init(highest_page);
    int i = 0;

    for (; i < ARRAY_SIZE(mem_regions); i++) {
        if (!mem_regions[i].start)
            continue;

        PhysAddr first_page = PAGE_ALIGN(mem_regions[i].start);
        PhysAddr last_page = PAGE_ALIGN_DOWN(mem_regions[i].end);

        for (; first_page < last_page; first_page += PAGE_SIZE) {
            struct Page *p = page_from_pa(first_page);
            bit_clear(&p->flags, PG_INVALID);

            if (first_page >= V2P(CONFIG_KERNEL_KMAP_START)) {
                kprintf(KERN_WARN, "High memory not supported, memory past %p is not "
                    "usable\n", (void *)first_page);
                break;
            }

            __mark_page_free(first_page);
        }
    }
}

#ifdef CONFIG_KERNEL_TESTS
#include "bootmem_test.c"
#endif
