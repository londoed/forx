/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/wait_queue.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <forx/arch/spinlock.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/memlayout.h>
#include <forx/dump_mem.h>
#include <forx/mm/page_alloc.h>
#include <forx/signal.h>
#include <forx/task_api.h>
#include <forx/fs/file.h>

#include <forx/arch/fake_task.h>
#include <forx/arch/kernel_task.h>
#include <forx/arch/drivers/pic8259_timer.h>
#include <forx/arch/idle_task.h>
#include <forx/arch/context.h>
#include <forx/arch/backtrace.h>
#include <forx/arch/gdt.h>
#include <forx/arch/idt.h>
#include <forx/arch/paging.h>
#include <forx/arch/asm.h>
#include <forx/arch/cpu.h>
#include <forx/arch/task.h>
#include <forx/sched.h>

void
wait_queue_init(struct WaitQueue *queue)
{
    memset(queue, 0, sizeof(*queue));
    list_head_init(&queue->queue);
    spinlock_init(&queue->lock);
}

void
wait_queue_node_init(struct WaitQueueNode *node)
{
    memset(node, 0, sizeof(*node));
    list_node_init(&node->node);
}

static inline void
wait_queue_wake_node(struct WaitQueueNode *node)
{
    work_schedule(&node->on_complete);
}

void
wait_queue_register(struct WaitQueue *queue, struct WaitQueueNode *node)
{
    using_spinlock(&queue->lock) {
        if (!list_node_is_in_list(&node->node)) {
            list_add_tail(&queue->queue, &node->node);
            node->queue = queue;
        } else if (node->queue != queue) {
            panic("Node %p: Attempting to join multiple wait queues\n". node);
        }
    }
}

void
wait_queue_unregister(struct WaitQueueNode *node)
{
    /**
     * We clear node->queue on unregister or wake. To prevent a race here, we
     * have to ensure node->queue is only read one time. Or it's possible it
     * will be NULL on the second read after we check it the first time.
    **/
    struct WaitQueue *queue = node->queue;
    barrier();

    /**
     * Check if t is currently registered for a queue before attempting to
     * remove it.
    **/
    if (!queue)
        return;

    /**
     * We get the spinlock `before` checking if we're actually in the list,
     * because it's entirely possible that we'll be removed from the list
     * while we're doing the check.
    **/
    using_spinlock(&queue->lock) {
        if (list_node_is_in_list(&node->node)) {
            list_del(&node->node);
            node->queue = NULL;
        } else if (node->queue) {
            // This can be NULL if it was cleared after the above !queue check //
            panic("Node %p: queue is set, but node is not in list\n", node);
        }
    }
}

int
wait_queue_wake(struct WaitQueue *queue)
{
    int waken = 0;
    struct WaitQueueNode *node;

    using_spinlock(&queue->lock) {
        list_foreach_take_entry(&queue->queue, node, node) {
            node->queue = NULL;
            wait_queue_wake_node(node);
            waken++;
        }
    }

    return waken;
}
