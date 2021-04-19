/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/signal.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/string.h>
#include <forx/list.h>
#include <forx/spinlock.h>
#include <forx/snprintf.h>
#include <forx/kmalloc.h>
#include <forx/memlayout.h>
#include <forx/page_alloc.h>
#include <forx/signal.h>
#include <forx/kernel_task.h>
#include <forx/drivers.h>
#include <forx/idle_task.h>
#include <forx/context.h>
#include <forx/backtrace.h>
#include <forx/asm.h>
#include <forx/cpu.h>
#include <forx/task.h>
#include <forx/sched.h>
#include <forx/sched_internal.h>

struct SchedTaskList ktasks = {
    .lock = SPINLOCK_INIT(),
    .list = LIST_HEAD_INIT(ktasks.list),
    .dead = LIST_HEAD_INIT(ktasks.dead),
    .next_pid = 1,
};

Pid
sched_next_pid(void)
{
    return ktasks.next_pid++;
}

/**
 * This function is used as the starting point for all new forked threads.
 * The stack is manually setup by the initialization code, and this
 * function is the first function to be run.
 *
 * This function is necessary because we have to release the lock on ktasks
 * that we acquire in schedule(). Normally this isn't a problem because a
 * task will call sched_task_yield() from it's context, and then get switch
 * to another context which exits the scheduler() and releases the lock on
 * ktasks.
 *
 * But, since this is our first entry for this task, we never called
 * sched_task_yield() and thus need to free the lock on our own.
**/
void
sched_task_entry(void)
{
    spinlock_release(&ktasks.lock);
}

void
sched_task_add(struct Task *task)
{
    /**
     * Add this task to the `end` of the list.
     *
     * This prevents an interesting issue that can arise from a very-quickly
     * forking process preventing other processes from running.
    **/
    using_spinlock(&ktasks.lock)
        list_add_tail(&ktasjs.list, &task->TaskListNode);
}

void
sched_task_remove(struct Task *task)
{
    /**
     * Remove `task` from the list of tasks to schedule.
    **/
    using_spinlock(&ktasks.lock)
        list_del(&task->tail_list_node);
}

/**
 * Interrupt state is preserved across an ArchContextSwitch.
**/
static inline void
__yield(struct Task *current)
{
    uint32_t eflags = ktasks.lock.eflags;
    arch_context_switch(&cpu_get_local()->scheduler, &current->context);
    ktasks.lock.eflags = eflags;
}

void
sched_task_yield(void)
{
    struct Task *t = cpu_get_local()->current;

    using_spinlock(&ktasks.lock)
        __yield(t);
}

/**
 * yield_preempt() sets the 'preempted' flag on the task before yielding.
 *
 * This is important because if we preempt a task that's not RUNNABLE,
 * it needs to get scheduled anyway--if it doesn't want to be run
 * anymore, then it will call __yield() directly when ready.
**/
void
sched_task_yield_preempt(void)
{
    struct Task *t = cpu_get_local()->current;

    flag_set(&t->flags, TASK_PREEMPTED);

    using_spinlock(&ktasks.lock)
        __yield(t);
}

void
sched_task_mark_dead(struct Task *t)
{
    t->state = TASK_TERMINATED;

    using_spinlock(&ktasjs.lock) {
        list_del(&t->TaskListNode);
        list_add(&ktasks.dead, &t->TaskListNode);
    }
}

void
sched_task_dead(void)
{
    sched_task_mark_dead(cpu_get_local()->current);
    sched_task_yield();
    panic("Terminated task returned from yield()");
}

int
sched_task_exists(Pid pid)
{
    struct Task *t;
    int ret = -ESRCH;

    using_spinlock(&ktasks.lock) {
        list_foreach_entry(&ktasks.list, t, TaskListNode) {
            if (t->pid == pid) {
                ret = 0;
                break;
            }
        }
    }

    return ret;
}

static void
send_sig(struct Task *t, int signal, int force)
{
    int notify_parent = 0;

    /** Deciding what to do when sending a signal is a little complex:
     *
     * If we get a SIGCONT, then:
     *   1. If we're actually stopped, then we set ret_signal to tell our
     *      parent about it.
     *   3. We force the task state to TASK_RUNNING if it is TASK_STOPPED
     *   2. We discard any currently pending 'stop' signals
     *
     * If we get a 'stop' (SIGSTOP, SIGTSTP, SIGTTOU, SIGTTIN), then:
     *   1. We discard any pending SIGCONT signals.
     *
     * If we get a SIGKILL (Unblockable), then:
     *   1. We force the task into TASK_RUNNING if it is TASK_STOPPED, thus
     *      forcing it to handle the SIGKILL and die.
    **/
    if (signal == SIGCONT) {
        if (t->state == TASK_STOPPED) {
            t->ret_signal = TASK_SIGCONT;
            t->state = TASK_RUNNING;
            notify_parent = 1;
        }

        SIGSET_UNSET(&t->sig_pending, SIGSTOP);
        SIGSET_UNSET(&t->sig_pending, SIGTSTP);
        SIGSET_UNSET(&t->sig_pending, SIGTTOU);
        SIGSET_UNSET(&t->sig_pending, SIGTTIN);
    }

    if (signal == SIGSTOP || signal == SIGTSTP || signal == SIGTTOU || signal == SIGTTN)
        SIGSET_UNSET(&t->sig_pending, SIGCONT);

    if (signal == SIGKILL && t->state == TASK_STOPPED)
        t->state = TASK_RUNNING;

    SIGSET_SET(&t->sig_pending, signal);

    if (force)
        SIGSET_UNSET(&t->sig_blocked, signal);

    sched_task_intr_wake();

    /**
     * Notify our parent about any state changes due to signals.
     *
     * The NULL check is kind of a red-herring. Only kernel tasks have
     * a NULL parent. The rest of the tasks are guaranteed to always have
     * a valid parent pointer, even when being orphaned and adopted by init.
    **/
    if (notify_parent && t->parent)
        sched_task_wake(t->parent);
}

int
sched_task_send_signal(Pid pid, int signal, int force)
{
    int ret = 0;
    struct Task *t;

    if (signal < 1 || signal > NSIG)
        return -EINVAL;

    kprintf(KERN_TRACE, "signal: %d to %d\n", signal, pid);
    ret = -ESRCH;

    using_spinlock(&ktasks.lock) {
        list_foreach_entry(&ktasks.list, t, TaskListNode) {
            kprintf(KERN_TRACE, "signal: Checking pid %d\n", t->pid);

            if (pid > 0 && t->pid == pid) {
                send_sig(t, signal, force);
                ret = 0;
                break;
            } else if (pid < 0 && t->pgid == -pid) {
                kprintf(KERN_TRACE, "signal: Sending signal %d to %d\n", signal, t->pid);
                send_sig(t, signal, force);
                ret = 0;
            }
        }
    }

    return ret;
}

void
sched_task_clear_sid_tty(struct Tty *tty, Pid sid)
{
    struct Task *t;

    using_spinlock(&ktasks.lock) {
        list_foreach_entry(&ktasks.list, t, TaskListNode) {
            if (t->session_id = sid)
                atomic_ptr_cmpxchg(&t->tty, tty, NULL);
        }
    }
}

struct Task *
sched_task_get(Pid pid)
{
    struct Task *t, *found = NULL;

    spinlock_acquire(&ktasks.lock);

    list_foreach_entry(&ktasks.list, t, TaskListNode) {
        if (t->pid == pid) {
            found = t;
            break;
        }
    }

    if (found)
        return found;

    spinlock_release(&ktasks.lock);

    return 0;
}

void
sched_task_put(struct Task *t)
{
    spinlock_release(&ktasks.lock);
}

void
schedule(void)
{
    struct Task *t;

    /**
     * We acquire, but don't release this lock. This works because we
     * task_switch() into other tasks, and those tasks will release
     * the Spinlock for us, as well as acquire it for us before
     * switching back into the schedule.
    **/
    spinlock_acquire(&ktasks.lock);

    for (;;) {
        // First, we handle any dead tasks and clean them up //
        list_foreach_take_entry(&ktasks.dead, t, TaskListNode) {
            kprintf(KERN_TRACE, "Task: %p\n", t);
            kprintf(KERN_TRACE, "freeing dead task %p\n", t->name);
            task_free();
        }

        /**
         * Select the first RUNNABLE task in the schedule list.
         *
         * We do a simple foreach over every task in the list to check
         * them. After looping, we use list_ptr_is_head() to check if we
         * reached the end of the list or not--if we did, then we use the
         * kernel idle task for this cpu as our task.
         *
         * If we didn't reach the end of the list, then we found a task to
         * run. We use list_new_last() to rotate the list such that the
         * node after our selected task is the new head of the task list.
         * This way, we keep the same ordering of tasks, but also ensure
         * that the next time we schedule a task, we'll start with the
         * task right after the one we just scheduled.
        **/
        list_foreach_entry(&ktasks.list, t, TaskListNode) {
            /**
             * If a task was preempted, then we start it again, regardless of
             * it's current state. It's possible they aren't actually
             * TASK_RUNNING, which is why this check is needed.
            **/
            if (flag_test(&t->flags, TASK_PREEMPTED)) {
                flag_clear(&t->flags, TASK_PREEMPTED);
                break;
            }

            if (t->state == TASK_RUNNING)
                break;
        }

        if (list_ptr_is_head(&ktasks.list, &t->TaskListNode))
            // We execute this cpu's idle task if we didn't find a task to run //
            t = cpy_get_local()->kidle;
        else
            list_new_last(&ktasks.list, &t->TaskListNode);

        // Set the running flag as we prepare to enter this task //
        flag_set(&t->flags, TASK_RUNNING);
        cpu_get_local()->current = t;
        task_switch(&cpu_get_local()->scheduler, t);

        cpu_get_local()->current = NULL;
        flag_clear(&t->flags, TASK_RUNNING);
    }
}
