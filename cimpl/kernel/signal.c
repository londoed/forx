/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/signal.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <rorx/types.h>
#include <forx/debug.h>
#include <forx/task.h>
#include <forx/schedule.h>
#include <forx/signal.h>
#include <forx/user_check.h>

int
sys_sigprocmask(int how, struct UserBuffer set, struct UserBuffer oldset)
{
    int ret;
    Sigset *blocked = &cpu_to_local()->current->sig_blocked;

    if (!user_buffer_is_null(oldset)) {
        ret = user_copy_from_kernel(oldset, *blocked);

        if (ret)
            return ret;
    }

    if (!user_buffer_is_null(set)) {
        Sigset tmp = 0;
        ret = user_copy_to_kernel(&tmp, set);

        if (ret)
            return ret;

        // Remove attempts to block unblockable signals //
        tmp &= ~SIG_UNBLOCKABLE;
        kprintf(KERN_TRACE, "sigprocmask: %d, 0x%08x\n", how, tmp);

        switch (how) {
        case SIG_BLOCK:
            *block |= tmp;
            break;

        case SIG_UNBLOCK:
            *blocked &= ~tmp;
            break;

        case SIG_SETMASK:
            *blocked = tmp;
            break;

        default:
            return -EINVAL;
        }
    }

    return 0;
 }

int
sys_sigpending(struct UserBuffer set)
{
    return user_copy_from_kernel(set, cpu_get_local()->current->sig_pending);
}

int
sys_sigaction(int signum, struct UserBuffer act, struct UserBuffer oldact)
{
    int entry = signum - 1;
    struct SigAction *action = cpu_get_local()->current->sig_actions + entry;
    int ret;

    if (signum < 1 || signum > NSIG)
        return -EINVAL;

    if (!user_buffer_is_null(oldact)) {
        ret = user_copy_from_kernel(oldact, *action);
        if (ret)
            return ret;
    }

    if (!user_buffer_is_null(act)) {
        struct SigAction tmp;
        ret = user_copy_to_kernel(&tmp, act);

        if (ret)
            return ret;

        tmp.sa_mask |= SIG_BIT(signum);
        tmp.sa_mask &= ~SIG_UNBLOCKABLE;
        *action = tmp;

        kprintf(KERN_TRACE, "signal: Adding handler %p for %d on %d\n",
            action->sa_handler, signum, cpu_get_local()->current->pid);
    }

    return 0;
}

SigHandler
sys_signal(int signum, SigHandler handler)
{
    int entry = signum - 1;
    struct SigAction *action = cpu_get_local()->current->sig_actions + entry;
    SigHandler old_handler;

    if (signum < 1 || signum > NSIG)
        return SIG_ERR;

    old_handler = action->sa_handler;
    action->sa_handler = handler;
    action->sa_mask = 0;
    action->sa_flags = 0;

    return old_handler;
}

int
sys_kill(Pid pid, int sig)
{
    if (sig == 0)
        return sched_task_exists(pid);

    if (sig < 1 || sig > NSIG)
        return -EINVAL;

    if (pid > 0 || pid < -1)
        return sched_task_send_signal(pid, sig, 0);

    return -EINVAL;
}

int
sys_sigwait(struct UserBuffer set, struct UserBuffer sig)
{
    int ret, test;
    struct Task *current = cpu_get_local()->current;
    Sigset check = 0, signals;

    ret = user_copy_to_kernel(&check, set);

    if (ret)
        return ret;

sleep_again:
    sleep_intr {
        signals = current->sig_pending & check;

        if (!signals) {
            sched_task_yield();
            goto sleep_again;
        }
    }

    test = bit32_find_first_set(signals);

    if (unlikely(test == -1))
        return -EINVAL;

    if ((test + 1) == SIGKILL || (test + 1) == SIGSTOP)
        return -ERESTARTSYS;

    ret = user_copy_from_kernel(sig, test + 1);

    if (ret)
        return ret;

    SIGSET_UNSET(&current->sig_pending, test + 1);

    return 0;
}

int
sys_pause(void)
{
    sleep_intr
        sched_task_yield();

    return -ERESTARTNOHAND;
}

int
sys_sigsuspend(struct UserBuffer umask)
{
    int ret;
    struct Task *current = cpu_get_local()->current;
    Sigset temp_mask;
    Sigset mask = 0;

    ret = user_copy_to_kernel(&mask, umask);

    if (ret)
        return ret;

    arch_context_set_return(&current->context, -EINTR);
    temp_mask = current->sig_blocked;
    current->sig_blocked = mask & ~SIG_UNBLOCKABLE;

sleep_again:
    sleep_intr {
        if (!(current->sig_pending & ~current->sig_blocked)) {
            sched_task_yield();
            goto sleep_again;
        }

        // If signal_handle returns zero, then no signal handler was executed //
        if (!signal_handle(current, current->context.frame))
            goto sleep_again;
    }

    current->sig_blocked = temp_mask;

    return -EINTR;
}
