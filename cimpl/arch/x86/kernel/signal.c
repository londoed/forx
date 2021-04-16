/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x86/kernel/signal.c }.
 * Copyright (C) 2016, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/task.h>
#include <forx/irq.h>
#include <forx/arch/paging.h>
#include <forx/sched.h>
#include <forx/signal.h>

// This is the contents of the stack--keep in mind, the stack grows down //
struct SignalContext {
    /**
     * Above here is where the return address from the sig handler will go.
     *
     * Argument to the sig handler.
    **/
    int signum;
    Sigset old_mask;

    // Below is where the trampoline code will be placed on stack //
    struct IrqFrame frame;
};

/**
 * Restart a syscall with the same parameters.
 *
 * Since syscalls do not modify the original contents of registers
 * besides `eax`, a restart is as simple as restoring the old value
 * of `eax` to the previous syscall number, and then decrementing
 * `eip` by 2, which is the length in bytes of an `int #imm8`
 * instruction.
 *
 * This effectively executes the original `int` instruction again.
**/
static void
signal_syscall_restart(struct IrqFrame *iframe, int prev_syscall)
{
    iframe->eax = prev_syscall;
    iframe->eip -= 2;
}

void
sys_sigreturn(struct IrqFrame *iframe)
{
    struct SignalContext context;
    struct Task *current = cpu_get_local()->current;
    char *stack = (char *)iframe->esp;

    context = *(struct SignalContext *)stack;
    *iframe = context.frame;
    current->sig_blocked = context.old_mask & ~SIG_UNBLOCKABLE;
}

static void
signal_setup_stack(struct Task *current, struct SigAction *action, int signum,
    struct IrqFrame *iframe)
{
    struct SignalContext context;
    char *stack, *signal_ret;

    context.frame = *iframe;
    context.old_mask = current->sig_blocked;
    context.signum = signum;

    stack = (char *)iframe->esp;
    kprintf(KERN_TRACE, "iframe->esp: %p\n", stack);
    stack = ALIGN_2_DOWN(stack, 4);

    stack -= x86_trampoline_len;
    memcpy(stack, x86_trampoline_code, x86_trampoline_len);
    signal_ret = stack;

    kprintf(KERN_TRACE, "signal_ret: %p\n", signal_ret);
    stack = ALIGN_2_DOWN(stack, 4);

    stack -= sizeof(context);
    *(struct SignalContext *)stack = context;

    stack -= sizeof(signal_ret);
    *(char **)stack = signal_ret;

    iframe->esp = (uint32_t)stack;
    iframe->eip = (uint32_t)action->sa_handler;
    kprintf(KERN_TRACE, "iframe->eip: %p\n", (void *)iframe->eip);
}

static void
signal_jump(struct Task *current, int signum, struct IrqFrame *iframe)
{
    struct SigAction *action = current->sig_actions + signum - 1;

    if (current->context.prev_syscall) {
        switch (iframe->eax) {
        case -ERESTARTSYS:
            if (action->sa_flags & SA_RESTART)
                signal_syscall_restart(iframe, current->context.prev_syscall);
            else
                iframe->eax = -EINTR;

            break;

        case -ERESTARTNOINTR:
            signal_syscall_restart(iframe, current->context.prev_syscall);
            break;

        case -ERESTARTNOHAND:
            iframe->eax = -EINTR;
            break;
        }
    }

    signal_setup_stack(current, action, signum, iframe);

    if (action->sa_flags & SA_ONESHOT)
        action->sa_handler = NULL;

    current->sig_blocked |= action->sa_mask;
}

static void
signal_default(struct Task *current, int signum)
{
    // Init ignores every signal //
    if (current->pid == 1)
        return;

    switch (signum) {
    case SIGCHLD:
    case SIGCONT:
    case SIGWINCH:
        // Ignore //
        break;

    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU:
        kprintf(KERN_TRACE, "task %d: Handling stop (%d)\n", current->pid, signum);
        current->ret_signal = TASK_SIGNAL_STOP | signum;
        current->state = TASK_STOPPED;

        if (current->parent)
            sched_task_wake(current->parent);

        sched_task_yield();
        break;

    default:
        current->ret_signal = signum;
        sys_exit(0);
    }
}

int
signal_handle(struct Task *current, struct IrqFrame *iframe)
{
    while (current->sig_pending & (~current->sig_blocked)) {
        int signum = bit32_find_first_set((current->sig_pending &
            (~current->sig_blocked)));
        struct SigAction *action = current->sig_actions + signum - 1;

        kprintf(KERN_TRACE, "signal: handling %d on %d\n", signum, current->pid);
        kprintf(KERN_TRACE, "signal: handler: %p\n", action->sa_handler);
        SIGSET_UNSET(&current->sig_pending, signum);

        if (action->sa_handler == SIG_IGN) {
            if (signum == SIGCHLD) {
                while (sys_waitpid(-1, make_kernel_buffer(NULL), WNOHANG) > 0)
                    ; // Reap children //
            }

            continue;
        } else if (action->sa_handler == SIG_DFL) {
            signal_default(current, signum);
        } else {
            signal_jump(current, signum, iframe);

            return 1;
        }
    }

    if (current->context.prev_syscall) {
        switch (iframe->eax) {
        case -ERESTARTSYS:
        case -ERESTARTNOINTR:
        case -ERESTARTNOHAND:
            signal_syscall_restart(iframe, current->context.prev_syscall);
            break;
        }
    }

    return 0;
}
