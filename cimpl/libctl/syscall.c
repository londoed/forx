/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/syscall.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/string.h>
#include <forx/list.h>
#include <forx/snprintf.h>
#include <forx/kmalloc.h>
#include <forx/memlayout.h>
#include <forx/user_check.h>
#include <forx/dump.h>
#include <forx/sched.h>
#include <forx/task.h>
#include <forx/page_alloc.h>
#include <forx/inode.h>
#include <forx/file.h>
#include <forx/fs.h>
#include <forx/wait.h>
#include <forx/signal.h>

Pid __fork(struct Task *current, Pid pgrp)
{
    struct Task *new = task_fork(current);

    if (new)
        kprintf(KERN_TRACE, "new task: %d\n", new->pid);
    else
        kprintf(KERN_TRACE, "fork failed\n");

    if (new) {
        if (pgrp == 0)
            new->pgid = new->pid;
        else
            new->pgid = pgrp;

        kprintf(KERN_TRACE, "task %s: locking list of children\n", current->name);

        using_spinlock(&current->children_list_lock)
            list_add(&current->task_children, &new->task_sibling_list);

        kprintf(KERN_TRACE, "task %s: unlocking list of children: %d\n", current->name,
            list_empty(&current->task_children));

        irq_frame_set_syscall_ret(new->context.frame, 0);
        sched_task_add(new);
    }

    if (new)
        return new->pid;
    else
        return -1;
}

Pid
sys_fork(void)
{
    struct Task *t = cpu_get_local()->current;

    return __fork(t, -1);
}

Pid
sys_fork_pgrp(Pid pgrp)
{
    struct Task *t = cpu_get_local()->current;

    return __fork(t, pgrp);
}

Pid
sys_getpid(void)
{
    struct Task *t = cpu_get_local()->current;

    return t->pid;
}

Pid
sys_getppid(void)
{
    struct Task *t = cpu_get_local()->current;

    if (t->parent)
        return t->parent->pid;
    else
        return -1;
}

void
sys_exit(int code)
{
    struct Task *t = cpu_get_local()->current;

    t->ret_code = code;
    kprintf(KERN_TRACE, "exit: %s(%p, %d):%d\n", t->name, t->pid, code);

    /**
     * At this point, we have to disable interrupts to ensure we don't get
     * rescheduled. We're deleting the majority of our task information, and
     * a reschedule back to us may not work after that.
    **/
    irq_disable();

    if (t->pid == 1)
        panic("PID 1 exited\n");

    /**
     * We're going to delete our address space, including our page table,
     * so we need to switch to the kernel's to ensure we don't attempt to
     * keep using the deleted page table.
    **/
    arch_address_space_switch_to_kernel();
    task_make_zombie();

    /**
     * Compiler barrier guaruntee's that t->parent will not be read
     * `before` t->state is set to TASK_ZOMBIE. See details in
     * task_make_zombie().
    **/
    barrier();

    if (t->parent)
        sched_task_wake(t->parent);

    /**
     * If we're a kernel process, we will never be wait()'d on, so we mark
     * ourselves dead.
    **/
    if (flag_test(&t->flags, TASK_FLAG_KERNEL))
        sched_task_mark_dead(t);

    sched_task_yield();
    panic("sched_task_yield() returned after sys_exit()\n");
}

Pid
sys_wait(struct UserBuffer ret)
{
    return sys_waitpid(-1, ret, 0);
}

Pid
sys_waitpid(Pid childpid, struct UserBuffer wstatus, int options)
{
    int have_child = 0, have_no_children = 0;
    int kill_child = 0;
    struct Task *child = NULL;
    struct Task *t = cpu_get_local()->current;
    int ret_status = 0;
    Pid child_pid = -1;

    /**
     * We enter a `sleep loop` here. We sleep until we're woke up directly,
     * which is fine because we're waiting for any children to call sys_exit(),
     * which will wake us up.
    **/
sleep_again:
    sleep_intr {
        kprintf(KERN_TRACE, "task %s: locking child list for wait4\n", t->name);

        using_spinlock(&t->children_list_lock) {
            if (list_empty(&t->task_children)) {
                have_no_children = 1;
                break;
            }

            list_foreach_entry(&t->task_children, child, task_sibling_list) {
                kprintf(KERN_TRACE, "checking child %s(%p, %d)\n", child->name, child,
                    child->pid);

                if (child_pid == 0) {
                    if (child->pgid != t->pgid)
                        continue;
                } else if (child_pid > 0) {
                    if (child->pid != child_pid)
                        continue;
                } else if (child_pid < -1) {
                    if (child->pgid != -child_pid)
                        continue;
                }

                if (child->state == TASK_ZOMBIE) {
                    list_del(&child->task_sibling_list);
                    kprintf(KERN_TRACE, "found zombie child: %d\n", child->pid);

                    if (child->ret_signal)
                        ret_status = WSIGNALED_MAKE(child->ret_signal);
                    else
                        ret_status = WEXIT_MAKE(child->ret_code);

                    kill_child = 1;
                    have_child = 1;
                    child_pid = child->pid;
                    break;
                }

                if (!(options & WUNTRACED) && !(options & WCONTINUED))
                    continue;

                kprintf(KERN_TRACE, "checking %d for continue\n", child->pid);

                if ((child->ret_signal & TASK_SIGCONT) && (options & WCONTINUED)) {
                    kprintf(KERN_TRACE, "found continued child: %d\n", child->pid);
                    ret_status = WCONTINUED_MAKE();

                    child->ret_signal = 0;
                    have_child = 1;
                    child_pid = child->pid;
                    break;
                }

                kprintf(KERN_TRACE, "checking %d for stop\n", child->pid);

                if ((child->ret_signal & TASK_SIGSTOP) && (options & WUNTRACED)) {
                    int status = child->ret_signal & ~TASK_SIGSTOP;
                    kprintf(KERN_TRACE, "found stopped child: %d\n", child->pid);
                    ret_status = WSTOPPED_MAKE(status);

                    child->ret_signal = 0;
                    have_child = 1;
                    child_pid = child->pid;
                    break;
                }
            }
        }

        kprintf(KERN_TRACE, "task %s: unlocking child list for wait4\n", t->name);

        if (!have_no_children && !have_child && !(options & WNOHANG)) {
            sched_task_yield();

            if (has_pending_status(t))
                return -ERESTARTSYS;

            goto sleep_again;
        }
    }

    if (!have_child && options & WNOHANG)
        return 0;

    if (!have_child)
        return -ECHILD;

    if (kill_child)
        sched_task_mark_dead(child);

    if (!user_buffer_is_null(wstatus)) {
        int ret = user_copy_from_kernel(wstatus, ret_status);

        if (ret)
            return ret;
    }

    return child_pid;
}

int
sys_dup(int oldfd)
{
    struct Task *current = cpu_get_local()->current;
    struct File *filp = fd_get(oldfd);
    int newfd;
    int ret;

    ret = fd_get_checked(oldfd, &filp);

    if (ret)
        return ret;

    newfd = fd_get_empty();
    fd_assign(newfd, file_dup(filp));
    FD_CLR(newfd, &current->close_on_exec);

    return newfd;
}

int
sys_dup2(int oldfd, int newfd)
{
    struct Task *current = cpu_get_local()->current;
    struct File *old_filp, *new_filp;
    int ret;

    ret = rd_get_checked(oldfd, &old_filp);

    if (ret)
        return ret;

    if (newfd > NOFILE || newfd < 0)
        return -EBADF;

    new_filp = fd_get(newfd);

    if (new_filp)
        vfs_close(new_filp);

    fd_assign(newfd, file_dup(old_filp));
    FD_CLR(newfd, &current->close_on_exec);

    return newfd;
}

int
sys_setpgid(Pid pid, Pid pgid)
{
    struct Task *current = cpu_get_local()->current;

    if (pid) {
        struct Task *t = sched_task_get(pid);

        if (!t)
            return -ESRCH;

        if (!pgid)
            pgid = pid;

        t->pgid = pgid;
        sched_task_put(t);

        return 0;
    }

    if (!pgid)
        pgid = current->pid;

    current->pgid = pgid;

    return 0;
}

int
sys_getpgrp(struct UserBuffer pgrp)
{
    struct Task *current = cpu_get_local()->current;

    return user_copy_from_kernel(pgrp, current->pgid);
}

Pid
sys_setsid(void)
{
    struct Task *current = cpu_get_local()->current;

    kprintf(KERN_TRACE, "%d: setsid\n", current->pid);
    kprintf(KERN_TRACE, "%d: pgrp: %d, session_leader: %d\n", current->pid, current->pgid,
        flag_test(&current->flags, TASK_FLAG_SESSION_LEADER));

    if (flag_test(&current->flags, TASK_FLAG_SESSION_LEADER) || current->pid == current->pgid)
        return -EPERM;

    kprintf(KERN_TRACE, "setting setsid...\n");
    flag_set(&current->flags, TASK_FLAG_SESSION_LEADER);
    current->session_id = current->pgid = current->pid;
    current->tty = NULL;

    return current->pid;
}

Pid
sys_getsid(Pid pid)
{
    struct Task *current = cpu_get_local()->current;
    struct Task *t;
    int ret;

    kprintf(KERN_TRACE, "%d: getsid: %d\n", current->pid, pid);

    if (pid == 0)
        return current->session_id;

    if (pid < 0)
        return -ESRCH;

    t = sched_task_get(pid);

    if (t->session_id != current->session_id)
        ret = -EPERM;
    else
        ret = t->session_id;

    sched_task_put(t);

    return ret;
}
