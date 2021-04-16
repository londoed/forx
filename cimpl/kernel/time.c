/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/time.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/snprintf.h>
#include <forx/atomic.h>
#include <forx/mm/vm.h>
#include <forx/mm/user_check.h>
#include <forx/fs/procfs.h>
#include <forx/arch/timer.h>
#include <forx/time.h>

Time current_uptime = 0;
Time boot_time = 0;

void
forx_uptime_inc(void)
{
    return atomic32_inc((Atomic32 *)&current_uptime);
}

Time
forx_uptime_get(void)
{
    return atomic32_get((Atomic32 *)&current_uptime);
}

void
forx_uptime_reset(void)
{
    atomic32_set((Atomic32 *)&current_uptime, 0);
}

void
forx_boot_time_set(Time t)
{
    boot_time = t;
}

Time
forx_boot_time_get(void)
{
    return boot_time;
}

Time
forx_current_time_get(void)
{
    return forx_uptime_get() + forx_boot_time_get();
}

uint32_t
forx_uptime_get_ms(void)
{
    return timer_get_ms();
}

static int
forx_uptime_read(void *page, size_t page_size, size_t *len)
{
    *len = snprintf(page, page_size, "%ld\n", forx_uptime_get());

    return 0;
}

static int
forx_boot_time_read(void *page, size_t page_size, size_t *len)
{
    *len = snprintf(page, page_size, "%ld\n", forx_boot_time_get());

    return 0;
}

static int
forx_current_time_read(void *page, size_t page_size, size_t *len)
{
    *len = snprintf(page, page_size, "%ld\n", forx_current_time_get());

    return 0;
}

struct ProcfsEntryOps uptime_ops = {
    .readpage = forx_uptime_read,
};

struct ProcfsEntryOps boot_time_ops = {
    .readpage = forx_boot_time_read,
};

struct ProcfsEntryOps current_time_ops = {
    .readpage = forx_current_time_read,
};

int
sys_time(struct UserBuffer t)
{
    return user_copy_from_kernel(t, forx_current_time_get());
}

int
sys_gettimeofday(struct UserBuffert tv, struct UserBuffer tz)
{
    uint32_t tick = timer_get_ticks();
    struct Timeval tmp;

    tmp.tv_sec = tick / TIMER_TICKS_PER_SEC;
    tmp.tv_usec = ((uint64_t)(tick % (TIMER_TICKS_PER_SEC)) * 1000000 / TIMER_TICKS_PER_SEC);

    return user_copy_from_kernel(tv, tmp);
}
