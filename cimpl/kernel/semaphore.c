/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/semaphore.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/snprintf.h>
#include <forx/semaphore.h>
#include <forx/sched.h>

static void
__sem_wake_if_waiting(struct Sempahore *sem)
{
    struct SemWaitEntry *ent;

    if (!list_empty(&sem->queue)) {
        ent = list_first_entry(&sem->queue, struct SemWaitEntry, next);
        sched_task_wake(ent->task);
    }
}

static void
__sem_down(struct Semaphore *sem)
{
    struct SemWaitEntry ent;

    sem_wait_entry_init(&ent);
    ent.task = cpu_get_local()->current;

    /**
     * 1. Add yourself at the end of the queue of tasks waiting on this semaphore.
     * 2. You wait until sem->count > 0 (sleeping and releasing sem->lock if necessary).
     * 3. You remove yourself from the list and decrement sem->count.
     * 4. We wake the next task if the semaphore still has space.
     *
     * The 4th step is probably the most interesting. sem_up() never modifies the
     * sem->queue, so if sem_up() is done twice before the first sleeping task
     * wakes up, then that task receives two wake-ups. This we may exit the
     * sleeping with sem->count > 1. When that happens we have to make sure we
     * wake up the next waiter (if there is one) to prevent a stall where
     * waiters wouldn't be woken-up immediately.
    **/
    list_add_tail(&sem->queue, &ent.next);
    sleep_event_spinlock(sem->count > 0, &sem->lock);
    list_del(&ent.next);
    sem->count--;

    if (sem->count > 0)
        __sem_wake_if_waiting(sem);
}

static int
__sem_try_down(struct Semaphore *sem)
{
    /**
     * We have the lock on the sem, so it's guaranteed sem->count won't
     * change this context.
    **/
    if (sem->count <= 0)
        return 0;

    /**
     * Since we held the lock, nobody can change sem->count, so we're fine to
     * decrement it and not check it.
    **/
    sem->count--;

    return 1;
}

static void
__sem_up(struct Semaphore *sem)
{
    sem->count++;
    __sem_wake_if_waiting(sem);
}

void
sem_down(struct Semaphore *sem)
{
    using_spinlock(&sem->lock)
        __sem_down(sem);
}

int
sem_try_down(struct Semaphore *sem)
{
    int ret;

    using_spinlock(&sem->lock)
        ret = __sem_try_down(sem);

    return ret;
}

void
sem_up(struct Semaphore *sem)
{
    using_spinlock(&sem->lock)
        __sem_up(sem);
}

int
sem_waiting(struct Semaphore *sem)
{
    int c;

    using_spinlock(&sem->lock)
        c = sem->count;

    return c;
}
