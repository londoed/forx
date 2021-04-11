/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { block/bdflush.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/sched.h>
#include <forx/mm/kmalloc.h>
#include <forx/block/bcache.h>
#include <forx/kparam.h>
#include <forx/fs/sys.h>

static struct Task *bdflushd_thread;
static int bdflush_delay_secs = CONFIG_BDFLUSH_DELAY;
KPARAM("bdflush.delay", &bdflush_delay_secs, KPARAM_INT);

static __noreturn int
bdflushd_loop(void *ptr)
{
    for (;;) {
        task_sleep_ms(bdflush_delay_secs);
        sys_sync();
    }
}

static void
bdflush_init(void)
{
    bdflushd_thread = task_kernel_new("bdflushd", bdflushd_loop, NULL);
    sched_task_init(bdflushd_thread);
}

initcall_device(bdflush, bdflush_init)
