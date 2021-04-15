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
