/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/sched_internal.h }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#ifndef SCHED_INTERNAL_H
#define SCHED_INTERNAL_H

/**
 * ktasks is the current list of tasks the scheduler is holding.
 * `list` is the current list of struct Task tasks that the scheduler
 * could schedule.
 * `dead` is a list of tasks that have been killed and need to be cleaned up.
 *    - The scheduler handles this because a task can't clean itself up
 *          from it's own task. For example, a task can't free it's own stack.
 * `next_pid` is the next pid to assign to a new struct Task.
 * `lock` is a Spinlock that needs to be held when you modify the list of tasks.
 *
 * NOTE: The locking is a little tricky to comprehend. In some cases, a
 * standard using_spinlock(), with the normal spinlock_acquire() and
 * spinlock_release() is perfectly fine. However, when the lock is going to
 * surround a context switch, it means that the lock itself is going to be
 * locked and unlocked in two different contexts. Thus, the eflags value that
 * is normally saved in the Spinlock would be perserved across the context,
 * corrupting the interrupt state.
 *
 * The solution is to save the contents of the eflags register into the
 * current task's context and then restore it on a context switch from the
 * saved value in the new task's context. Since we're saving the eflags
 * ourselves, it's necessary to call the `noirq` versions of Spinlock,
 * which do nothing to chagne the interrupt state.
**/
struct SchedTaskList {
    struct Spinlock lock;
    ListHead list;
    ListHead dead;
    Pid next_pid;
};

extern struct SchedTaskList ktasks;

#endif
