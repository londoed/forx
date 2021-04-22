/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x96/kernel/backtrace.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/compiler.h>
#include <forx/symbols.h>
#include <forx/mm/page_table.h>
#include <forx/arch/memlayout.h>

#include <forx/arch/backtrace.h>

void
dump_stack_ptr(void *start, int log_level)
{
    struct StackFrame *stack = start;
    int frame = 0;

    PhysAddr page_dir = get_current_page_directory();
    PageDir *pgd = p_to_v(page_dir);

    for (frame = 1; stack != 0; stack = stack->caller_stackframe, frame++) {
        if (!pgd_ptr_is_valid(pgd, stack)) {
            kprintf(log_level, "  Stack is invalid past this point, was: %p\n", stack);

            return;
        }

        const struct Symbol *sym = ksym_lookup(stack->return_addr);

        if (sym)
            kprintf(log_level, "  [%d][0x%08x] %s\n", frame, stack->return_addr, sym->name);
        else
            kprintf(log_level, "  [%d][0x%08x]\n", frame, stack->return_addr);
    }
}

void
dump_stack(int log_level)
{
    dump_stack_ptr(read_ebp(), log_level);
}
