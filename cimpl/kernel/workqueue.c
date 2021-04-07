/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { kernel/workqueue.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
 **/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/string.h>
#include <forx/list.h>
#include <forx/page_alloc.h>
#include <forx/spinlock.h>
#include <forx/snprintf.h>
#include <forx/task.h>
#include <forx/schedule.h>
#include <forx/work.h>

static struct WorkQueue kwork = WORKQUEUE_INIT(kwork);

/**
 * `struct work` is designed such that a particular instance of it will only
 * ever be run on one workqueue thread at a time (if running on a workqueue).
 * However, we also have to ensure that if a `struct work` is scheduled while
 * already running, we don't lost that wake up.
 *
 * We achieve this via the `WORK_SCHEDULED` flag and the `work_running_list`.
 * `work_schedule` set this flag even when the work is already on a list
 * (either the `work_list` or the `work_running_list`). When the work is done
 * running, if the `WORK_SCHEDULED` flag is set, then we simply requeue the
 * work at the end of teh list.
**/
static int
workqueue_thread(void *q)
{
    struct WorkQueue *queue = q;
    struct Work *work = NULL;
    int clear_work = 0;

    for (;;) {
        using_spinlock(&queue->lock) {
            if (work) {
                list_del(&work->work_entry);

                if (flag_test(&work->flags, WORK_SCHEDULED))
                    list_add_tail(&queue->work_list, &work->work_entry);
            }

            sleep_event_spinlock(!list_empty(&queue->work_list), &queue->lock);
            work = list_take_first(&queue->work_list, struct Work, work_entry);
            clear_work = flag_test(&work->flags, WORK_ONESHOT);

            if (!clear_work)
                list_add_tail(&queue->work_running_list, &work->work_entry);

            // This is fine, since we're about to run it anyway //
            flag_clear(&work->flags, WORK_SCHEDULED);
        }

        (work->callback)(work);

        if (clear_work)
            work = NULL;
    }

    return 0;
}

void
workqueue_start_multiple(struct WorkQueue *queue, const char *thread_name, int thread_count)
{
    int i;
    struct Page *tmp_page = page_alloc(0, PAL_KERNEL);

    queue->thread_count = thread_count;

    for (i = 0; i < thread_count; i++) {
        snprintf(tmp_page->virt, PAGE_SIZE, "%s/%d", thread_name, i + 1);
        queue->work_threads[i] = task_kernel_new(tmp_page->virt, workqueue_thread, queue);
        scheduler_task_add(queue->work_threads[i]);
    }

    page_free(tmp_page, 0);
}

void
workqueue_start(struct WorkQueue *queue, const char *thread_name)
{
    workqueue_start_multiple(queue, thread_name, 1);
}

void
workqueue_add_work(struct WorkQueue *queue, struct Work *work)
{
    using_spinlock(&queue->lock) {
        flag_set(&work->flags, WORK_SCHEDULED);

        if (!list_node_is_in_list(&work->work_entry))
            list_add_tail(&queue->work_list, &work->work_entry);

        if (queue->thread_count) {
            scheduler_task_wake(queue->work_threads[queue->wake_next_thread]);
            queue->wake_next_thread = (queue->wake_next_thread + 1) % queue->thread_count;'
        }
    }
}

void
work_schedule(struct Work *work)
{
    switch (work->type) {
    case WORK_CALLBACK:
        (work->callback)(work);
        break;

    case WORK_KWORK:
        workqueue_add_work(&kwork, work);
        break;

    case WORK_TASK:
        scheduler_task_wake(work->task);
        break;

    case WORK_WORKQUEUE:
        workqueue_add_work(work->queue, work);
        break;

    case WORK_NONE:
        break;
    }
}

static void
kwork_delay_timer_callback(struct KTimer *timer)
{
    struct DelayWork *work = container_of(timer, struct DelayWork, timer);

    workqueue_add_work(&kwork, &work->work);
}

int
kwork_delay_schedule(struct DelayWork *work)
{
    return timer_del(&work->timer);
}

static void
kwork_init(void)
{
    workqueue_start_multiple(&work, "kwork", 4);
}

initcall_core(kwork, kwork_init);
