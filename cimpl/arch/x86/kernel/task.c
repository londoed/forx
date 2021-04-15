/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/kernel/task.h }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <libctl/snprintf.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/user_check.h>
#include <forx/mm/vm.h>
#include <forx/dump_mem.h>
#include <forx/sched.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>
#include <forx/fs/inode.h>
#include <forx/fs/file.h>
#include <forx/fs/fs.h>
#include <forx/fs/sys.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/fake_task.h>
#include <forx/arch/kernel_task.h>
#include <forx/arch/context.h>
#include <forx/arch/backtrace.h>
#include <forx/arch/gdt.h>
#include <forx/irq.h>
#include <forx/idt.h>

#include "irq_handler.h"

#include <forx/arch/paging.h>
#include <forx/arch/asm.h>
#include <forx/arch/cpu.h>
#include <forx/arch/task.h>

void
arch_task_switch(Context *old, struct Task *new)
{
    cpu_set_kernel_stack(cpu_get_local(), new->kstack_top);

    if (flag_test(&new->flags, TASK_FLAG_KERNEL))
        set_current_page_directory(V2P(&kernel_dir));
    else
        set_current_page_directory(V2P(new->addrspc->page_dir));

    arch_context_switch(&new->context, old);
}

static char *
setup_sched_entry(struct Task *t, char *ksp)
{
    ksp -= sizeof(*t->context.esp);
    t->context.esp = (struct x86Regs *)ksp;

    memset(t->context.esp, 0, sizeof(*t->context.esp));
    t->context.esp->eip = (uintptr_t)sched_task_entry;

    return ksp;
}

void
arch_task_setup_stack_user_with_exec(struct Task *t, const char *exec)
{
    char *ksp = t->kstack_top;

    ksp -= sizeof(*t->context.frame);
    t->context.frame = (struct IrqFrame *)ksp;
    memset(t->context.frame, 0, sizeof(*t->context.frame));

    ksp -= sizeof(uintptr_t);
    *(uintptr_t *)ksp = (uintptr_t)irq_handler_end;

    if (exec) {
        /**
         * NOTE: This code depends on the code at arch_user_task_entry.
         * Notably, we push the arguments for sys_execve() onto the
         * stack here, and arch_task_user_entry pops them off.
        **/
        ksp -= sizeof(struct IrqFrame *);
        *(struct IrqFrame **)ksp = t->context.frame;

        // envp //
        ksp -= sizeof(struct UserBuffer);
        *(struct UserBuffer *)ksp = make_user_buffer(NULL);

        // argv //
        ksp -= sizeof(struct UserBuffer);
        *(struct UserBuffer *)ksp = make_user_buffer(NULL);

        // exe //
        ksp -= sizeof(struct UserBuffer);
        *(struct UserBuffer *)ksp = make_kernel_buffer(exec);

        ksp -= sizeof(uintptr_t);
        *(uintptr_t *)ksp = arch_task_user_entry_addr;
    }

    ksp = setup_sched_entry(t, ksp);
}

void
arch_task_setup_stack_user(struct Task *t)
{
    arch_task_setup_stack_user_with_exec(t, NULL);
}

void
arch_task_setup_stack_kernel(struct Task *t, int (*kernel_task)(void *), void *ptr)
{
    char *ksp = t->kstack_top;

    /**
     * Push ptr onto stack to use as argument for `kernel_task`. Then, push
     * address of `kernel_task` to run. The function is run when `task_entry`
     * pops the address of `kernel_task` off of the stack when it returns.
    **/
    ksp -= sizeof(*ptr);
    *(void **)ksp = ptr;

    ksp -= sizeof(kernel_task);
    *(void **)ksp = kernel_task;

    /**
     * Entry point for kernel tasks. We push this address below the
     * `SchedEntry`, so that when that function returns, it will
     * "return" to the task_entry function.
    **/
    ksp -= sizeof(uintptr_t);
    *(uintptr_t *)ksp = (uintptr_t)kernel_task_entry_addr;
    ksp = setup_sched_entry(t, ksp);
}

void
arch_task_change_address_space(struct AddrSpace *addrspc)
{
    struct Task *current = cpu_get_local()->current;
    struct AddrSpace *old = current->addrspc;

    current->addrspc = addrspc;
    set_current_page_directory(V2P(addrspc->page_dir));

    address_space_clear(old);
    kfree(old);
}

void
arch_task_init(struct Task *t)
{
    arch_task_info_init(&t->arch_info);
}
