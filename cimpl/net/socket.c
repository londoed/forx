/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/socket.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additiional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <libctl/snprintf.h>
#include <forx/list.h>
#include <forx/arch/asm.h>

#include <forx/fs/procfs.h>
#include <forx/drivers/pci.h>
#include <forx/drivers/pci_ids.h>
#include <forx/net/socket.h>
#include <forx/net.h>

static Mutex socket_list_lock = MUTEX_INIT(socket_list_lock);
static Atomic open_sockets = ATOMIC_INIT(0);
static ListHead socket_list = LIST_HEAD_INIT(socket_list);

struct Socket *
socket_alloc(void)
{
    struct Socket *socket = kzalloc(sizeof(*socket), PAL_KERNEL);

    socket_init(socket);
    atomic_inc(&open_sockets);

    using_mutex(&socket_list_lock)
        list_add_tail(&socket_list, &socket->global_socket_entry);

    kprintf(KERN_NORM, "Allocate socket: %p\n", socket);

    return socket_dup(socket);
}

void
socket_free(struct Socket *socket)
{
    atomic_dec(&open_sockets);

    using_mutex(&socket_list_lock)
        list_del(&socket->global_socket_entry);

    // NOTE: Clear various queues and such //
    kprintf(KERN_NORM, "Freeing sockets: %p\n", socket);
    kfree(socket);
}

int
socket_last_error(struct Socket *socket)
{
    return xchg(&socket->last_err, 0);
}

void
socket_set_last_error(struct Socket *socket, int err)
{
    kprintf(KERN_NORM, "Socket: signalling last error: %d\n", err);
    xchg(&socket->last_err, err);
    wait_queue_wake(&socket->state_changed);
}

void
socket_state_change(struct Socket *socket, enum SocketState state)
{
    kprintf(KERN_NORM, "Socket: Signalling state change to %d\n", state);
    xchg(&socket->state, state);
    wait_queue_wake(&socket->state_changed);
}

enum SocketState
socket_state_cmpxchg(struct Socket *socket, enum SocketState cur, enum SocketState new)
{
    kprintf(KERN_NORM, "Socket: cmpxchg from %d to %d\n", cur, new);
    int ret = cmpxchg(&socket->state, cur, new);

    if (ret == new)
        wait_queue_wake(&socket->state_changed);

    return ret;
}

static const char *socket_state[] = {
    [SOCKET_UNCONNECTED] = "UNCONNECTED",
    [SOCKET_CONNECTING] = "CONNECTING",
    [SOCKET_CONNECTED] = "CONNECTED",
    [SOCKET_DISCONNECTING] = "DISCONNECTING",
};

static int
socket_seq_start(struct SeqFile *seq)
{
    mutex_lock(&socket_list_lock);

    return seq_list_start_header(seq, &socket_list);
}

static int
socket_seq_render(struct SeqFile *seq)
{
    struct Socket *s = seq_list_get_entry(seq, struct Socket, global_socket_entry);

    if (!s)
        return seq_printf(seq, "refs\taf\ttype\tproto\tstate\n");

    return seq_printf(seq, "%d\t%d\t%d\t%d\t%s\n", atomic_get(&s->refs),
        s->addr_family, s->sock_type, s->protocol, socket_state[atomic_get(&s->state)]);
}

static int
socket_seq_next(struct SeqFile *seq)
{
    return seq_list_next(seq, &socket_list);
}

static void
socket_seq_end(struct SeqFile *seq)
{
    mutex_unlock(&socket_list_lock);
}

const static struct SeqFileOps socket_seq_file_ops = {
    .start = socket_seq_start,
    .next = socket_seq_next,
    .render = socket_seq_render,
    .end = socket_seq_end,
};

static int
socket_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &socket_seq_file_ops);
}

struct FileOps socket_procfs_file_ops = {
    .open = socket_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
