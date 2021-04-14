/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/sys_file.c }.
 * Copyright (C) 2017, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <libctl/snprintf.h>
#include <forx/list.h>

#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/vfs.h>
#include <forx/net/ipv4/ip_route.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net/linklayer.h>
#include <forx/net/socket.h>
#include <forx/net/sys.h>
#include <forx/net.h>

#include "sys_common.h"

static int
socket_poll(struct File *filp, struct PollTable *table, int events)
{
    struct InodeSocket *ino;
    struct Socket *sock;
    int ret = 0;

    ino = container_of(filp->inode, struct InodeSocket, i);
    sock = ino->socket;

    if (events & POLLOUT)
        ret |= POLLOUT;

    using_mutex(&sock->recv_lock) {
        if (events & POLLIN) {
            if (!list_empty(&sock->recv_queue))
                ret |= POLLIN;
            else
                poll_table_add(table, &sock->recv_wait_queue);
        }
    }

    return ret;
}

static int
socket_file_release(struct File *filp)
{
    struct InodeSocket *ino;
    struct Socket *sock;
    int ret = 0;

    ino = container_of(filp->inode, struct InodeSocket, i);
    sock = ino->socket;

    if (events & POLLOUT)
        ret |= POLLOUT;

    using_mutex(&sock->recv_lock) {
        if (events & POLLIN) {
            if (!list_empty(&sock->recv_queue))
                ret |= POLLIN;
            else
                poll_table_add(table, &sock->recv_wait_queue);
        }
    }

    return ret;
}

static int
socket_file_release(struct File *filp)
{
    struct InodeSocket *ino;
    struct Socket *sock;

    ino = container_of(filp->inode, struct InodeSocket, i);
    sock = ino->socket;
    socket_release(sock);
    socket_put(sock);

    return 0;
}

static int
socket_read(struct File *filp, struct UserBuffer vptr, size_t len)
{
    return __sys_recvfrom(filp, vptr, len, 0, make_user_buffer(NULL), make_user_buffer(NULL));
}

static int
socket_write(struct File *filp, struct UserBuffer vptr, size_t len)
{
    return __sys_sendto(filp, vptr, len, 0, make_user_buffer(NULL), 0);
}

static int
socket_ioctl(struct File *filp, int cmd, struct UserBuffer arg)
{
    return -EINVAL;
}

struct FileOps socket_file_ops = {
    .poll = socket_poll,
    .release = socket_file_release,
    .read = socket_read,
    .write = socket_write,
    .ioctl = socket_ioctl,
};

