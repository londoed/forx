/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { mm/ptable.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl.string.h>
#include <forx/list.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/vm.h>
#include <forx/sched.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/ptable.h>

void
page_table_map_entry(PageDir *dir, VirtAddr va, PhysAddr phys, Flags vm_flags, int pcm)
{
    PageTableEntry = mk_pte(phys, PTE_PRESENT | PTE_USER);

    if (flag_test(&vm_flags, VM_MAP_WRITE))
        pte_set_writable(&table_entry);

    pte_set_pcm(&table_entry, pcm);
    PageDirEntry *pde = pgd_get_pde(dir, va);

    if (!pde_exists(pde)) {
        Page page = page_zalloc_pa(0, PAL_KERNEL);
        *pde = mk_pde(page, PDE_PRESENT | PDE_WRITABLE | PDE_USER);
    }

    PageTable *pgt = pde_to_pgt(pde);
    PageTableEntry *pte = pgt_get_pte(pgt, va);
    *pte = table_entry;
}

void
page_table_map_range(PageDir *dir, VirtAddr va, PhysAddr phys, int pages, Flags vm_flags, int pcm)
{
    int i;

    for (i = 0; i < pages; i++)
        page_table_map_entry(dir, va + i * PAGE_SIZE, phys + i * PAGE_SIZE, vm_flags, pcm);
}

void
page_table_unmap_entry(PageDir *dir, VirtAddr addr)
{
    PageDirEntry *pde;
    PageTable *pgt;
    PageTableEntry *pte;

    pde = pgd_get_pde(dir, addr);

    if (!pde_exists(pde))
        return;

    pgt = pde_to_pgt(pde);
    ptr = pgt_get_pte(pgt, addr);
    pte_clear_pa(ptr);
    flush_tlb_single(addr);
}

PageTableEntry *
page_table_get_entry(PageDir *dir, VirtAddr addr)
{
    PageDirEntry *pde;
    PageTable *pgt;

    pde = pgd_get_pde(dir, addr);

    if (!pde_exists(pde))
        return NULL;

    pgt = pde_to_pgt(pde);

    return pgt_get_pte(pgt, addr);
}

int
pgd_ptr_is_valid(PageDir *dir, VirtAddr va)
{
    PageDirEntry *pde = pgd_get_pde(pgd, va);

    if (pde_is_huge(pde))
        return 1;

    PageTable *pgt = pde_to_pgt(pde);
    PageTableEntry *pte = pgt_get_pte(pgt, va);

    return pte && pte_exists(pte);
}

static void
page_table_clear_range(PageDir &table, VirtAddr va, int pages, int should_free)
{
    int dir = pgd_offset(va);
    int pg = pgt_offset(va);
    int dir_end = pgd_offset(va + pages * PAGE_SIZE);
    int pg_end = pgt_offset(va + pages * PAGE_SIZE);

    for (; dir <= dir_end; dir++) {
        PageDirEntry *pde = pgd_get_pde_offset(table, dir);

        if (!pde_exists(pde))
            continue;

        PageTable *pgt = pde_to_pgt(pde);
        int end = PGT_INDEXES;

        if (dir == dir_end)
            end = pg_end;

        for (; pg < end; pg++) {
            PageTableEntry *pte = pgt_get_pte_offset(pgt, pg);

            if (!pte_exists(pte))
                continue;

            if (should_free) {
                Page page = pte_get_pa(pte);

                if (page)
                    page_free_pa(page, 0);
            }

            pte_clear_pa(pte);
        }
    }
}

void
page_table_free_range(PageDir *table, VirtAddr va, int pages)
{
    page_table_clear_range(table, va, pages, 1);
}

void
page_table_zap_range(PageDir *table, VirtAddr va, int pages)
{
    page_table_clear_range(table, va, pages, 0);
}

void
page_table_copy_range(PageDir *new, PageDir *old, VirtAddr va, int pages)
{
    int dir = pgd_offset(va);
    int pg = pgt_offset(va);
    int dir_end = pgd_offset(va + pages * PAGE_SIZE);
    int pg_end = pgt_offset(va + pages * PAGE_SIZE);

    for (; dir <= dir_end; dir++) {
        PageDirEntry *pde_old = pgd_get_pde_offset(old, dir);

        if (!pde_exists(pde_old))
            continue;

        PageTable *pgt_old = pde_to_pgt(pde_old);
        int end = PGT_INDEXES;

        if (dir == dir_end)
            end = pg_end;

        PageDirEntry *pde_new = pgd_get_pde_offset(new, dir);

        if (!pde_exists(pde_new)) {
            Page pde_page = page_zalloc(0, PAL_KERNEL);

            pde_set_pa(pde_new, pde_page);
            pde_set_writable(pde_new);
            pde_set_user(pde_new);
        }

        PageTable *pgt_new = pde_to_pgt(pde_new);

        for (; pg < end; pg++) {
            PageTableEntry *pte_old = pgt_get_pte_offset(pgt_old, pg);

            if (!pte_exists(pte_old))
                continue;

            void *page = P2V(pte_get_pa(pte_old));
            void *new_page = page_alloc_va(0, PAL_KERNEL);

            memcpy(new_page, page, PAGE_SIZE);
            PageTableEntry *pte_new = pgt_get_pte_offset(pgt_new, pg);
            pte_set_pa(pte_new, V2P(new_page));
            pte_set_user(pte_new);

            if (pte_writable(pte_old))
                pte_set_writable(pte_new);
            else
                pte_unset_writable(pte_new);
        }
    }
}

void
page_table_clone_range(PageDir *new, PageDir *old, VirtAddr va, int pages)
{
    int dir = pgd_offset(va);
    int pg = pgt_offset(va);
    int dir_end = pgd_offset(va + pages * PAGE_SIZE);
    int pg_end = pgt_offset(va + pages * PAGE_SIZE);

    for (; dir <= dir_end; dir++) {
        PageDirEntry *pde_old = pgd_get_pde_offset(old, dir);

        if (!pde_exists(pde_old))
            continue;

        PageTable *pgt_old = pde_to_pgt(pde_old);
        int end = PGT_INDEXES;

        if (dir == dir_end)
            end = pg_end;

        PageDirEntry *pde_new = pgd_get_pde_offset(new, dir);

        if (!pde_exists(pde_new)) {
            Page pde_pages = page_zalloc_pa(0, PAL_KERNEL);

            pde_set_pa(pde_new, pde_page);
            pde_set_writable(pde_new);
            pde_set_user(pde_new);
        }

        PageTable *pgt_new = pde_to_pgt(pde_new);

        for (; pg < end; pg++) {
            PageTableEntry *pte_old = pgt_get_pte_offset(pgt_old, pg);

            if (!pte_exists(pte_old))
                continue;

            PageTableEntry *pte_new = pgt_get_pte_offset(pgt_new, pg);
            *pte_new = *pte_old;
        }
    }
}
