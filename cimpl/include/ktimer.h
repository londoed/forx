/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { include/ktimer.h }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

/**
 * Kernel timers
 *
 * Timers that can be set to trigger a callback (in an interrupt context) after
 * a certain number of milliseconds have gone by.
**/
struct KTimer {
    ListNode timer_entry;
    uint64_t wake_up_tick;
    void (*callback)(struct KTimer *);
};

#define KTIMER_INIT(timer) \
    { \
        .timer_entry = LIST_NODE_INIT((timer).timer_entry), \
    } \

#define KTIMER_CALLBACK_INIT(timer, cb) \
    { \
        .timer_entry = LIST_NODE_INIT((timer).timer_entry), \
        .callback = (cb) \
    }

static inline void
ktimer_init(struct KTimer *timer)
{
    *timer = (struct KTimer *)KTIMER_INIT(*timer);
}

void timer_handle_timer(uint64_t tick);
int timer_add(struct KTimer *timer, uint64_t ms);

// Returns 0 if the timer was deleted, -1 if the timer was already scheduled //
void timer_del(struct KTimer *timer);

// Ensure both the timer was removed __and__ the timer is not currently running //
void timer_cancel(struct KTimer *timer);

// Returns 1 if the timer has been fired (It may currently be running) //
int timer_was_fired(struct KTimer *timer);

#endif
