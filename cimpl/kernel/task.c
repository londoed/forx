/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/task.c }.
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
#include <forx/drivers/tty.h>
#include <forx/dump_mem.h>
#include <forx/sched.h>
#include <forx/task.h>
#include <forx/mm/page_alloc.h>
#include <forx/fs/inode.h>
#include <forx/fs/file.h>
#include <forx/fs/fs.h>
#include <forx/wait.h>
#include <forx/signal.h>
#include <forx/task_api.h>

#include <forx/arch/spinlock.h>
#include <forx/arch/fake_task.h>
#include <forx/arch/kernel_task.h>
#include <forx/arch/idle_tash.h>
#include <forx/arch/context.h>
#include <forx/arch/backtrace.h>
#include <forx/arch/gdt.h>
#include <forx/arch/idt.h>
#include <forx/arch/paging.h>
#include <forx/arch/asm.h>
#include <forx/arch/cpu.h>
#include <forx/arch/task.h>

#define KERNEL_STACK_PAGES 2

static Atomic total_tasks = ATOMIC_INIT(0);

const char *task_states[] = {
    [TASK_NONE] = "no state",
    [TASK_SLEEPING] = "sleep",
    [TASK_INTR_SLEEPING] = "isleep",
    [TASK_RUNNING] = "running",
    [TASK_ZOMBIE] = "zombie",
    [TASK_TERMINATED] = "dead",
};

void
task_print(char *buf, size_t size, struct Task *task)
{
    snprintf(buf, size, "Task:%s\nPid: %d\nParent: %d\nState: %s\nKilled: %d\n",
        task->name, task->pid, task->parent->pid, task_states[task->state],
        flag_test(&task->flags, TASK_FLAG_KILLED));
}

void
task_init(struct Task *task)
{
    memset(task, 0, sizeof(*task));

    list_node_init(&task->task_list_node);
    list_node_init(&task->task_sibling_list);
    list_node_init(&task->task_children);
    wait_queue_node_init(&task->wait);
    work_init_task(&task->wait.on_complete, task);

    spinlock_init(&task->children_list_lock);
    task->addrspc = kmalloc(sizeof(*task->addrspc), PAL_KERNEL);
    address_space_init(task->addrspc);

    task->pid = sched_next_pid();
    task->state = TASK_RUNNING;
    task->kstack_bot = page_alloc_va(log2(KERNEL_STACK_PAGES), PAL_KERNEL);
    task->kstack_top = task->kstack_bot + PAGE_SIZE * KERNEL_STACK_PAGES - 1;

    credentials_init(&task->creds);
    arch_task_init(task);
    kprintf(KERN_TRACE, "Created task %d\n", task->pid);
}

// Initiailizes a new allocated task //
struct Task *
task_new(void)
{
    struct Task *task;

    if (atomic_get(&total_tasks) >= CONFIG_TASK_MAX) {
        kprintf(KERN_WARN, "Max tasks reached, task_new() refused\n");

        return NULL;
    }

    atomic_inc(&total_tasks);
    task = kmalloc(sizeof(*task), PAL_KERNEL);
    kprintf(KERN_TRACE, "Task kmalloc: %p\n", task);

    if (!task)
        return NULL;

    task_init(task);

    return task;
}

void
task_kernel_init(struct Task *t, const char *name, int (*kernel_task)(void *), void *ptr)
{
    flag_set(&t->flags, TASK_FLAG_KERNEL);
    strcpy(t->name, name);

    // We never exit to user mode, so we have no frame //
    t->context.frame = NULL;
    arch_task_setup_stack_kernel(t, kernel_task, ptr);
}

struct Task *
task_kernel_new(const char *name, int (*kernel_task)(void *), void *ptr)
{
    struct Task *t = task_new();

    if (!t)
        return NULL;

    task_kernel_init(t, name, kernel_task, ptr);

    return t;
}

struct Task *
task_user_new_exec(const char *exe)
{
    struct Task *t = task_new();

    if (!t)
        return NULL;

    strncpy(t->name, exe, sizeof(t->name) - 1);
    t->name[sizeof(t->name) - 1] = '\0';

    arch_task_setup_user_with_exec(t, exe);
    t->cwd = inode_dup(ino_root);

    return t;
}

struct Task *
task_user_new(void)
{
    struct Task *t = task_new();

    if (!t)
        return NULL;

    arch_task_setup_stack_user(t);

    return t;
}

/**
 * Creates a new process that is a copy of `parent`.
 * NOTE: The userspace code/data/etc. is copied, but not the kernel
 * space stuff, like the kernel stack.
**/
struct Task *
task_fork(struct Task *parent)
{
    int i;
    struct Task *new = task_new();

    if (!new)
        return NULL;

    strcpy(new->name, parent->name);
    arch_task_setup_stack_user(new);
    address_space_copy(new->addrspc, parent->addrspc);
    new->cwd = inode_dup(parent->cwd);

    for (i = 0; i < NOFILE; i++) {
        if (parent->files[i])
            new->files[i] = file_dup(parent->files[i]);
    }

    new->tty = parent->tty;
    new->pgid = parent->pgid;
    new->session_id = parent->session_id;
    new->close_on_exec = parent->close_on_exec;
    new->sig_blocked = parent->sig_blocked;
    new->umask = parent->umask;

    using_creds(&parent->creds) {
        new->creds.uid = parent->creds.uid;
        new->creds.euid = parent->creds.euid;
        new->creds.suid = parent->creds.suid;

        new->creds.gid = parent->creds.gid;
        new->creds.egid = parent->creds.egid;
        new->creds.sgid = parent->creds.sgid;

        memcpy(&new->creds.sup_groups, &parent->creds.sup_groups, sizeof(new->creds.sup_groups));
    }

    new->parent = parent;
    memcpy(new->context.frame, parent->context.frame, sizeof(*new->context.frame));

    return new;
}

void
task_free(struct Task *t)
{
    atomic_dev(&total_tasks);

    // If this task wasn't yet killed, then we do it now //
    if (!flag_test(&t->flags, TASK_FLAG_KILLED))
        task_make_zombie(t);

    page_free_va(t->kstack_bot, log2(KERNEL_STACK_PAGES));
    kfree(t);
}

void
task_make_zombie(struct Task *t)
{
    struct Task *child;
    int i;

    kprintf(KERN_TRACE, "zombie: %d\n", t->pid);
    flag_set(&t->flags, TASK_FLAG_KILLED);

    /**
     * If the session leader dies while controlling a tty, then we
     * remove tty from every process in this same session.
    **/
    if (flag_test(&t->flags, TASK_FLAG_SESSION_LEADER) && t->tty) {
        struct Tty *tty = t->tty;
        sched_task_clear_sid_tty(tty, t->session_id);

        using_mutex(&tty->lock) {
            tty->session_id = 0;
            tty->fg_pgrp = 0;
        }
    }

    // Children of zombies are inherited by PID1 //
    using_spinlock(&task->pid1->children_list_lock) {
        list_foreach_take_entry(&t->task_children, child, task_sibling_list) {
            /**
            * The atomic swap guarentees consistency of the child->parent
             * pointer.
             *
             * There is no actual race here, even without a lock on the
             * 'child->parent' field, because a task will always be set to
             * TASK_ZOMBIE *before* attempting to wake it's parent.
             *
             * The race would be if 'child' is in sys_exit() while we're making
             * it's current parent a zombie. It's not an issue because
             * sys_exit() always sets 'child->state' to TASK_ZOMBIE *before*
             * caling scheduler_task_wake(child->parent).
             *
             * Thus, by swaping in task_pid1 as the parent before checking for
             * TASK_ZOMBIE, we guarentee that we get the correct functionality:
             * If 'child->state' isn't TASK_ZOMBIE:
             *   There's no issue because even if they're in sys_exit(), they
             *   haven't attempted to wake up the parent yet.
             *
             * If 'child->state' is TASK_ZOMBIE:
             *   Then we call scheduler_task_wake(task_pid1) to ensure PID1
             *   gets the wake-up. The worst case here is that PID1 recieves
             *   two wake-ups - No big deal.
            **/
            atomic_ptr_swap(&child->parent, task_pid1);
            kprintf(KERN_TRACE, "init: Inheriting child %d\n", child->pid);
            list_move(&task->pid1->task_children, &child->task_sibling_list);

            if (child->state == TASK_ZOMBIE)
                sched_task_send_signal(1, SIGCHLD, 0);
        }
    }

    for (i = 0; i < NOFILE; i++) {
        if (t->files[i]) {
            kprintf(KERN_TRACE, "closing file %d\n", i);
            vfs_close(t->files[i]);
        }
    }

    if (t->cwd)
        inode_put(t->cwd);

    if (!flag_test(&t->flags, TASK_FLAG_KERNEL)) {
        address_space_clear(t->addrspc);
        kfree(t->addrspc);
    }

    t->state = TASK_ZOMBIE;

    if (t->parent)
        sched_task_end_signal(t->parent->pid, SIGCHLD, 0);

    kprintf(KERN_TRACE, "Task %s(%p): zombie\n", t->name, t);
}
