/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/sleep.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/string.h>
#include <forx/list.h>
#include <forx/arch/spinlock.h>
#include <forx/libctl/snprintf.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/mm/page_alloc.h>
#include <forx/signal.h>
#include <forx/time.h>
#include <forx/sched.h>

struct KTimerSleep {
    struct KTimer timer;
    struct Task *task;
};

static void
sleep_callback(struct KTimer *timer)
{
    struct KTimerSleep *sleep = container_of(timer, struct KTimerSleep, timer);

    if (!sleep->task)
        return;

    struct Task *t = sleep->task;
    sleep->task = NULL;
    sched_task_wake(t);
}

static int
sleep_inner_ms(int ms, int check_signals)
{
    struct Task *current = cpu_get_local()->current;
    struct KTimerSleep sleep = {
        .timer = KTIMER_CALLBACK_INIT(sleep.timer, sleep_callback),
        .task = current,
    };

    timer_add(&sleep.timer, ms);

    for (;;) {
        if (check_signals)
            sched_set_intr_sleeping();
        else
            sched_set_sleeping();

        int sig_pending = check_signals ? has_pending_signal(current) : 0;
        int timer_fired = timer_was_fired(&sleep.timer);

        if (sig_pending || timer_fired)
            break;

        sched_task_yield();
    }

    sched_set_running();
    timer_cancel(&sleep.timer);

    return sleep.task ? -EINTR : 0;
}

int
task_sleep_ms(int ms)
{
    return sleep_inner_ms(ms, 0);
}

int
task_sleep_intr_ms(int ms)
{
    return sleeper_inner_ms(ms, 1);
}

int
sys_sleep(int seconds)
{
    return task_sleep_intr_ms(seconds * 1000);
}

int
sys_usleep(useconds_t usecs)
{
    /**
     * This rounds up if the value is not an exact millisecond value.
     * This is necessary to ensure we sleep for __at least__ useconds.
    **/
    useconds_t ms = (usecs + 999) / 1000;

    return task_sleep_intr_ms(ms);
}
