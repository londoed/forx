/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/event/event.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <forx/fs/char.h>
#include <forx/fs/file.h>
#include <forx/sched.h>
#include <forx/wait.h>
#include <forx/dev.h>
#include <forx/initcall.h>
#include <forx/mm/user_check.h>
#include <forx/event/device.h>
#include <forx/event/keyboard.h>
#include <forx/event/protocol.h>

static inline size_t
next(size_t val, size_t size)
{
    return (val + 1) % size;
}

static inline int
queue_full(struct EventQueue *queue)
{
    return next(queue->tail, queue->size) == queue->head;
}

static inline int
queue_empty(struct EventQueue *queue)
{
    return queue->tail == queue->head;
}

static void
event_queue_drop_reader(struct EventQueue *queue)
{
    using_spinlock(&queue->lock) {
        queue->open_readers--;

        if (queue->open_readers == 0 && !flag_test(&queue->flags, EQUEUE_FLAG_BUFFER_EVENTS))
            queue->tail = queue->head;
    }
}

void
event_queue_submit_event(struct EventQueue *queue, uint16_t type, uint16_t code, uint32_t value)
{
    using_spinlock(&queue->lock) {
        if ((queue->open_readers || flag_test(&queue->flags, EQUEUE_FLAG_BUFFER_EVENTS)) &&
            !queue_full(queue)) {

            queue->buffer[queue->tail].type = type;
            queue->buffer[queue->tail].code = code;
            queue->buffer[queue->tail].value = value;

            queue->tail = next(queue->tail, queue->size);
        }
    }

    wait_queue_wake(&queue->event_wait);
}

int
event_queue_open(struct File *filp, struct EventQueue *queue)
{
    filp->priv_data = queue;

    using_spinlock(&queue->lock)
        queue->open_readers++;

    return 0;
}

int
event_queue_read(struct File *filp, struct UserBuffer buf, size_t size)
{
    struct EventQueue *queue = filp->priv_data;
    int err = 0;
    size_t index = 0;
    size_t max_events = size / sizeof(struct KernEvent);
    int should_wait = !flag_test(&filp->flags, FILE_NONBLOCK);
    struct KernEvent tmp_event;

    if (max_events == 0)
        return -EINVAL;

again:
    spinlock_acquire(&queue->lock);

again_locked:
    if (index != max_events && !queue_empty(queue)) {
        tmp_event = queue->buffer[queue->head];
        queue->head = next(queue->head, queue->size);

        max_events--;
        should_wait = 0;

        spinlock_release(&queue->lock);
        err = user_copy_from_kernel_indexed(buf, tmp_event, index);

        if (err)
            return err;

        index++;
        goto again;
    } else if (should_wait) {
        err = wait_queue_event_intr_spinlock(&queue->event_wait, !queue_empty(queue), &queue->lock);

        if (err) {
            spinlock_release(&queue->lock);

            return err;
        }

        goto again_locked;
    }

    spinlock_release(&queue->lock);

    /**
     * We never return EOF, since the stream is infinite. The case of index == 0
     * only happens if FILE_NONBLOCK was set on the file.
    **/
    if (index == 0)
        return -EAGAIN;

    return index * sizeof(struct KernEvent);
}

int
event_queue_release(struct File *filp)
{
    struct EventQueue *queue = filp->priv_data;
    event_queue_drop_reader(queue);

    return 0;
}

int
event_open(struct Inode *ino, struct File *filp)
{
    Device minor = DEV_MINOR(ino->dev_no);

    switch (minor) {
    case EVENT_MINOR_KEYBOARD:
        filp->ops = &keyboard_event_file_ops;

        return (filp->ops->open)(ino, filp);
    }

    return -ENODEV;
}

struct FileOps event_file_ops = {
    .open = event_open,
};

static void
event_device_init(void)
{
    device_submit_char(KERN_EVENT_DEVICE_ADD, DEV_MAKE(CHAR_DEV_EVENT, EVENT_MINOR_KEYBOARD));
}

initcall_device(event_device, event_device_init);
