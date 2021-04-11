/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/packet_queue.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <libctl/snprintf.h>
#include <forx/list.h>
#include <forx/work.h>
#include <forx/arch/asm.h>

#include <forx/fs/procfs.h>
#include <forx/drivers/pci.h>
#include <forx/drivers/pci_ids.h>
#include <forx/net/proto.h>
#include <forx/net/linklayer.h>
#include <forx/net.h>

static Atomic queue_count = ATOMIC_INIT(0);
static struct WorkQueue packet_queue = WORKQUEUE_INIT(packet_queue);

static void
packet_process(struct Work *work)
{
    struct Packet *packet = container_of(work, struct Packet, dwork.work);
    int count = atomic_dec_return(&queue_count);

    if (unlikely(count > 30))
        kprintf(KERN_WARNING, "Packet queue depth: %d\n", count);

    packet_linklayer_rx(packet);
}

void
net_packet_receive(struct Packet *packet)
{
    work_init_workqueue(&packet->dwork.work, packet_process, &packet_queue);
    flag_set(&packet->dwork.work.flags, WORK_ONESHOT);
    atomic_inc(&queue_count);
    work_schedule(&packet->dwork.work);
}

struct Packet *
__net_iface_tx_packet_pop(struct NetInterface *iface)
{
    if (list_empty(&iface->tx_packet_queue))
        return NULL;

    return list_take_first(&iface->tx_packet_queue, struct Packet, packet_entry);
}

void
net_packet_transmit(struct Packet *packet)
{
    struct NetInterface *iface = packet->iface_tx;

    if (flag_test(&iface->flags, NET_IFACE_UP)) {
        using_netdev_write(iface) {
            iface->metrics.tx_packets++;
            iface->metrics.tx_bytes += packet_len(packet);
        }

        using_spinlock(&iface->tx_lock)
            list_add_tail(&iface->tx_packet_queue, &packet->packet_entry);

        (iface->process_tx_queue)(iface);
    } else {
        packet_free(packet);
    }
}

static void
new_packet_queue_init(void)
{
    workqueue_start(&packet_queue, "packet-queue");
}

initcall_subsys(net_packet_queue, net_packet_queue_init);
