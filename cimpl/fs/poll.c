/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/poll.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/string.h>
#include <forx/arch/spinlock.h>
#include <forx/sched.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/user_check.h>
#include <forx/task.h>

#include <forx/fs/file.h>
#include <forx/fs/poll.h>

/**
 * The poll_table situation is largely opaque to the outside world, only
 * offering a 'poll_table_add' function to add a wait_queue. The implementation
 * of it is defined in this file.
 *
 * Races/issues to keep in mind:
 *   Wake-ups can be recieved any time after we register for a wait-queue.
 *     - We also have to be registered for a wait-queue before we can
 *       accurately check a condition variable.
 *
 *   It is impossible to accurately 'catch' wake-ups across anything that may
 *     sleep, like locking a mutex. There is no indication of "where" a wake-up
 *     came from, so the wake-up will be lost if you're waiting in the mutex's
 *     wait-queue and recieve a different wait-queue's wake. The mutex code will
 *     just skip it, as will any other sleeping code. This is a problem since
 *     poll() functions may need to take a mutex.
 *
 * The biggest issues are due to the fact that the normal wait_queue
 * notifications are not sufficent for our needs here. The task state can
 * change in undesirable situations, and the wake-up's really can't be
 * accurately detected.
 *
 * The fix is to not sleep while calling the various poll() callbacks, and
 * instead use a callback in the wait_queue. The wait_queue's associated with a
 * poll() call are all given a callback that sets the 'event' variable in the
 * associated poll_table. In poll(), after calling the various poll() calls on
 * the fd's, we sleep and check 'event'.
 *
 * 'event' will only be set by one of our wait_queues so we use it as an
 * indication we were "woken-up" by a wait_queue and shouldn't sleep.
 *
 * If it is not set after we start sleeping, then it is clear we have not yet
 * been woken-up by one of our wait_queues and can safely suspend ourselves
 * until we recieve a wake-up.
 *
 * The optional timeout is handled by a similar mechanism - a ktimer is started
 * at the beginning of `poll()`. If it goes off, it sets the `timeout` flag in
 * the poll_table and wakes the polling task, causing it to exit the sleep early.
**/

struct PollTableEntry {
    struct WaitQueueNode wait_node;
    ListNode poll_table_node;
    struct PollTable *table;
};

struct PollTable {
    Spinlock event_lock;
    unsigned int event: 1;
    unsigned int timeout: 1;
    ListHead entries;
    struct Task *poll_task;
    struct KTimer timer;
};

static void poll_table_timer_callback(struct KTimer *);

#define POLL_TABLE_ENTRY_INIT(entry) \
    { \
        .wait_node = WAIT_QUEUE_NODE_INIT((entry).wait_node), \
        .poll_table_node = LIST_NODE_INIT((entry).poll_table_node), \
    }

#define POLL_TABLE_INIT(table) \
    { \
        .event_lock = SPINLOCK_INIT(), \
        .entries = LIST_HEAD_INIT((table).entries), \
        .timer = KTIMER_CALLBACK_INIT((table).timer, poll_table_timer_callback), \
    }

static inline void
poll_table_entry_init(struct PollTableEntry *entry)
{
    *entry = (struct PollTableEntry)POLL_TABLE_ENTRY_INIT(*entry);
}

static inline void
poll_table_init(struct PollTable *table)
{
    *table = (struct PollTable)POLL_TABLE_INIT(*table);
}

static void
poll_table_timer_callback(struct KTimer *timer)
{
    struct PollTable *table = container_of(timer, struct PollTable, timer);

    using_spinlock(&table->event_lock) {
        table->timeout = 1;
        sched_task_wake(table->poll_task);
    }
}

static void
poll_table_wait_queue_callback(struct Work *work)
{
    struct PollTableEntry *entry = container_of(work, struct PollTableEntry,
        wait_node.on_complete);
    struct PollTable *table = entry->table;

    using_spinlock(&table->event_lock) {
        table->event = 1;
        sched_task_wake(table->poll_task);
    }
}

void
poll_table_add(struct PollTable *table, struct WaitQueue *wq)
{
    struct PollTableEntry *entry = kmalloc(sizeof(*entry), PAL_KERNEL);

    poll_table_entry_init(entry);
    entry->table = table;

    work_init_callback(&entry->wait_node.on_complete, poll_table_wait_queue_callback);
    wait_queue_register(queue, &entry->wait_node);
    list_add_tail(&table->entries, &entries->poll_table_node);
}

static void
poll_table_unwait(struct PollTable *table)
{
    list_foreach_take_entry(&table->entries, entry, poll_table_node) {
        /**
         * This doesn't race with poll_table_wait_queue_callback because
         * that is called while holding the wait_queue's internal lock.
         *
         * Meaning, it is not possible for unregister to return and
         * pull_table_wait_queue_callback() to still be running or
         * __scheduled__ to run later.
        **/
        wait_queue_unregister(&entry->wait_node);
        kfree(entry);
    }
}

int
sys_poll(struct UserBuffer ufds, Nfds nfds, int timeout)
{
    struct PollTable table = POLL_TABLE_INIT(table);
    struct File **filps;
    struct Task *current = cpu_get_local()->current;
    struct PollFd *fds;
    unsigned int i;
    int ret, exit_poll = 0, event_count = 0;

    if (ndfs == 0 && timeout < 0)
        return -EINVAL;

    /**
     * NOTE: This is too low, but due to us making a copy into a single
     * allocated page below.
    **/
    if (ndfs > 512)
        return -ERANGE;

    filps = page_alloc_va(0, PAL_KERNEL);

    if (!filps)
        return -ENOMEM;

    fds = page_alloc_va(0, PAL_KERNEL);

    if (!fds) {
        ret = -ENOMEM;
        goto page_free_filps;
    }

    ret = user_memcpy_to_kernel(fds, ufds, nfds * sizeof(*fds));

    if (ret)
        goto page_free_fds;

    for (i = 0; i < ndfs; i++) {
        if (fds[i].fd <= -1) {
            filps[i] = NULL;
            continue;
        }

        ret = fd_get_checked(fds[i].fd, filps + i);

        if (ret)
            goto page_free_fds;
    }

    table.poll_task = cpu_get_local()->current;

    if (timeout > 0)
        timer_add(&table.timer, timeout);
    else if (timeout == 0)
        exit_poll = 1;

    do {
        table.event = 0;

        for (i = 0; i < ndfs; i++) {
            if (!filps[i])
                continue;

            if (filps[i]->ops->poll)
                fds[i].revents = (filps[i]->ops->poll)(fds[i], &table, fds[i].events) &
                    fd[i].events;
            else
                fds[i].revents = (POLLIN | POLLOUT) & fds[i].events;

            if (fds[i].revents) {
                event_count++;
                exit_poll = 1;
            }
        }

        if (!exit_poll) {
            using_spinlock(&table.event_lock)
                sleep_event_intr_spinlock(table.event || table.timeout, &table.event_lock);
        }

        poll_table_unwait(&table);
    } while (!exit_poll && !has_pending_signal(current) && !table.timeout);

    timer_cancel(&table.timer);

    if (event_count == 0 && has_pending_signal(current))
        event_count = -EINTR;

    ret = user_memcpy_from_kernel(ufds, fds, nfds * sizeof(*fds));

    if (!ret)
        ret = event_count;

page_free_fds:
    page_free_va(fds, 0);

page_free_filps:
    page_free_va(filps, 0);

    return ret;
}
