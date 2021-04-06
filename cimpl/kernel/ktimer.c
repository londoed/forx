/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/ktimer.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/snprintf.h>
#include <forx/atomic.h>
#include <forx/vm.h>
#include <forx/procfs.h>
#include <forx/time.h>
#include <forx/pic8259_timer.h>
#include <forx/ktimer.h>

/**
 * Kernel Timers -- ktimer.
 *
 * Implemented as a sorted list of lists. The main list holds a sorted list
 * of timers, where the one soonest to go off is first.
 *
 * Each timer in that list hold its own list of timers who share the same
 * wake-up tick (if there are any).
 *
 * The above setup allows for very fast handling of timers each tick. Only
 * the first timer has to ever be checked, even if there are multiple
 * timers registered for that tick.
**/
static Spinlock timers_lock;
static ListHead timer_list = LIST_HEAD_INIT(timer_list);

/**
 * TODO: This should be per-CPU, since they can all trigger ktimers.
 *
 * NOTE: This __CANNOT__ be used to read the state of the current timer,
 * once we drop the lock in timer_handle_timers(), this thing could be
 * free'd at any time.
 *
 * What we can do, however, is do a direct pointer comparison against a
 * pointer provided to us in timer_cancel(). If they're equal, the timer
 * is __potentially__ still running, and we need to wait until they
 * don't equal.
**/
static struct KTimer *curr_running_timer;

void
timer_handle_timers(uint64_t tick)
{
    struct KTimer *timer;
    void (*callback)(struct KTimer *);

    for (;;) {
        using_spinlock(&timers_lock) {
            curr_running_timer = NULL;

            if (list_empty(&timer_list))
                return;

            timer = list_first_entry(&timer_list, struct KTimer, timer_entry);

            if (timer->wake_up_tick > tick)
                return;

            list_del(&timer->timer_entry);

            /**
             * Store callback because timer might be modified once we release
             * the lock.
            **/
            callback = timer->callback;
            curr_running_timer = timer;
        }

        (callback)(timer);
    }
}

int
timer_was_fired(struct KTimer *timer)
{
    using_spinlock(&timers_lock)
        return !list_node_is_in_list(&timer->timer_entry);
}

int
timer_add(struct KTimer *timer, uint64_t ms)
{
    struct KTimer *t;

    timer->wake_up_tick = timer_get_ticks() + ms * (TIMER_TICKS_PER_SEC / 1000);

    using_spinlock(&timer_lock) {
        // We're already scheduled, don't do anything //
        if (list_node_is_in_list(&timer->timer_entry))
            return -1;

        list_foreach_entry(&timer_list, t, timer_entry) {
            if (t->wake_up_ticks >= timer->wake_up_tick) {
                list_add_before(&t->timer_entry, &timer->timer_entry);
                break;
            }
        }

        if (!list_node_is_in_list(&timer->timer_entry))
            list_add_tail(&timer_list, &timer->timer_entry);

        return 0;
    }
}

int
timer_del(struct KTimer *timer)
{
    using_spinlock(&timers_lock) {
        if (!list_node_is_in_list(&timer->timer_entry))
            return -1;

        list_del(&timer->timer_entry);
    }

    return 0;
}

void
timer_cancel(struct KTimer *timer)
{
    int ret = timer_del(timer);

    // The easy case, timer wasn't yet run, just return //
    if (!ret)
        return;

    /**
     * Annoying case, timer might currently be running, keep checking
     * curr_running_timer and yielding. Timers are __supposed__ to
     * finish quickly, so this shouldn't last that long.
    **/
    for (;;) {
        using_spinlock(&timers_lock) {
            if (curr_running_timer != timer)
                return;
        }
    }

    sched_task_yield();
}
