/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { net/sys.c }.
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
#include <forx/fs/super.h>
#include <forx/net/ipv4/ip_route.h>
#include <forx/net/ipv4/ipv4.h>
#include <forx/net/linklayer.h>
#include <forx/net/socket.h>
#include <forx/net/sys.h>
#include <forx/net.h>

#include "sys_common.h"

static int
socket_inode_dealloc(struct SuperBlock *socket_sb, struct Inode *ino)
{
    struct InodeSocket *ino_socket = container_of(ino, struct InodeSocket, i);

    kfree(ino_socket);

    return 0;
}

static struct Inode *
socket_inode_alloc(struct SuperBlock *socket_sb)
{
    struct InodeSocket *ino = kzalloc(sizeof(*ino), PAL_KERNEL);

    inode_init(&ino->i);

    return &ino->i;
}

static struct SuperBlockOps socket_fake_super_block_ops = {
    .inode_dealloc = socket_inode_dealloc,
    .inode_alloc = socket_inode_alloc,
};

static struct SuperBlock socket_fake_super_block = SUPER_BLOCK_INIT(socket_fake_super_block);
static ino_t next_socket_ino = 1;

static struct InodeSocket *
new_socket_inode(void)
{
    struct Inode *ino = inode_create(&socket_fake_super_block);

    ino->ino = next_socket_ino++;
    ino->mode = S_IFSOCK;

    return container_of(ino, struct InodeSocket, i);
}

static int
fd_get_socket(int sockfd, struct Socket **sock)
{
    int ret;
    struct File *filp;
    struct InodeSocket *inode;

    ret = fd_get_checked(sockfd, &filp);

    if (ret)
        return ret;

    if (!S_ISSOCK(filp->inode->mode))
        return -ENOTSOCK;

    return 0;
}

static int
user_read_sockaddr(struct SockAddr *addr, struct UserBuffer user, socklen_t len)
{
    if (len < 0 || sizeof(*addr) < len)
        return -EINVAL;

    if (len == 0)
        return 0;

    return user_memcpy_to_kernel(addr, user, len);
}

static int
user_write_sockaddr(struct SockAddr *addr, socklen_t len, struct UserBuffer user,
    struct UserBuffer user_socklen)
{
    socklen_t user_len = 0;
    int ret = user_copy_to_kernel(&user_len, user_socklen);

    if (ret)
        return ret;

    if (user_len < 0)
        return -EINVAL;

    if (user_len > len)
        user_len = len;

    if (user_len) {
        ret = user_memcpy_from_kernel(user, addr, user_len);

        if (ret)
            return ret;
    }

    return user_copy_from_kernel(user_socklen, len);
}

int
sys_bind(int sockfd, struct UserBuffer addr, socklen_t addr_len)
{
    struct SockAddr cpy;
    struct Socket *socket;
    int ret = user_read_sockaddr(&cpy, addr, addr_len);

    if (ret)
        return ret;

    ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    return socket_bind(socket, &cpy, addr_len);
}

int
sys_getsockname(int sockfd, struct UserBuffer user_addr, struct UserBuffer user_addrlen)
{
    struct SockAddr cpy;
    socklen_t len = sizeof(cpy);
    struct Socket *socket;
    int ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    ret = socket_getsockname(socket, &cpy, &len);

    if (ret)
        return ret;

    return user_write_sockaddr(&cpy, len, user_addr, user_addrlen);
}

int
sys_setsockopt(int sockfd, int level, int optname, struct UserBuffer optval, socklen_t optlen)
{
    struct Socket *socket;
    int ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    return socket_setsockopt(socket, level, optname, optval, optlen);
}

int
sys_getsockopt(int sockfd, int level, int optname, struct UserBuffer optval, struct UserBuffer optlen)
{
    struct Socket *socket;
    int ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    return socket_getsockopt(socket, level, optname, optval, optlen);
}

int
__sys_sendto(struct File *filp, struct UserBuffer buf, size_t buflen, int flags,
    struct UserBuffer dest, socklen_t addr_len)
{
    struct SockAddr cpy;
    struct InodeSocket *ino;
    struct Socket *socket;

    if (!S_ISSOCK(filp->inode->mode))
        return -ENOTSOCK;

    int ret = user_read_sockaddr(&cpy, dest, addr_len);

    if (ret)
        return ret;

    ino = container_of(filp->inode, struct InodeSocket, i);
    socket = ino->socket;

    struct SockAddr *sockbuf = &cpy;

    if (!addr_len)
        sockbuf = NULL;

    return socket_sendto(socket, buf, buflen, flags, sockbuf, addr_len,
        flag_test(&filp->flags, FILE_NONBLOCK));
}

int
sys_sendto(int sockfd, struct UserBuffer buf, size_t len, int flags, struct UserBuffer dest,
    socklen_t addr_len)
{
    struct File *filp;
    int ret;

    if (len > 1500)
        return -EMSGSIZE;

    ret = fd_get_checked(sockfd, &filp);

    if (ret)
        return ret;

    return __sys_sendto(filp, buf, len, flags, dest, addr_len);
}

int
sys_send(int sockfd, struct UserrBuffer buf, size_t len, int flags)
{
    return sys_sendto(sockfd, buf, len, flags, make_user_buffer(NULL), 0);
}

int
__sys_recvfrom(struct File *filp, struct UserBuffer buf, size_t len, int flags,
    struct UserBuffer addr, struct UserBuffer addr_len)
{
    struct SockAddr cpy;
    socklen_t cpylen = sizeof(cpy);
    struct InodeSocket *ino;
    struct Socket *socket;

    if (!S_ISSOCK(filp->inode->mode))
        return -ENOTSOCK;

    ino = container_of(filp->inode, struct InodeSocket, i);
    socket = ino->socket;
    int ret = socket_recvfrom(socket, but, len, flags, &cpy, &cpylen,
        flag_test(&filp->flags, FILE_NONBLOCK));

    if (ret < 0)
        return ret;

    if (addr.ptr && addr_len.ptr) {
        int err = user_write_sockaddr(&cpy, cpylen, addr, addr_len);

        if (err)
            return err;
    }

    return ret;
}

int
sys_recvfrom(int sockfd, struct UserBuffer buf, size_t len, int flags, struct UserBuffer addr,
    struct UserBuffer addr_len)
{
    struct File *filp;
    int ret = fd_get_checked(sockfd, &filp);

    if (ret)
        return ret;

    return __sys_recvfrom(filp, buf, len, flags, addr, addr_len);
}

int
sys_recv(int sockfd, struct UserBuffer buf, size_t len, int flags)
{
    return sys_recvfrom(sockfd, buf, len, flags, make_user_buffer(NULL),
        make_user_buffer(NULL));
}

int
sys_shutdown(int sockfd, int how)
{
    struct Socket *socket;
    int ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    return socket_shutdown(socket, how);
}

int
sys_accept(int sockfd, struct UserBuffer addr, struct UserBuffer addr_len)
{
    struct SockAddr copy;
    socklen_t cpylen = sizeof(cpy);
    struct Socket *socket, *new_socket = NULL;
    int ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    ret = socket_accept(socket, &cpy, &cpylen, &new_socket);

    if (ret)
        return ret;

    if (addr.ptr && addr_len.ptr) {
        // NOTE: Don't just leak the FD... //
        int err = user_write_sockaddr(&cpy, cpylen, addr, addr_len);

        if (err)
            return err;
    }

    // NOTE: Create a new struct file and fill it in with the created socket //
    return 0;
}

int
sys_connect(int sockfd, struct UserBuffer addr, socklen_t addr_len)
{
    struct SockAddr cpy;
    struct SockAddr *ptr = &cpy;
    struct Socket *socket;
    int ret;

    if (addr.ptr && addr_len) {
        ret = user_read_sockaddr(&cpy, addr, addr_len);

        if (ret)
            return ret;
    } else {
        ptr = NULL;
        addr_len = 0;
    }

    ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    return socket_connect(socket, ptr, addr_len);
}

int
sys_listen(int sockfd, int backlog)
{
    struct Socket *socket;
    int ret = fd_get_socket(sockfd, &socket);

    if (ret)
        return ret;

    return socket_listen(socket, backlog);
}

int
sys_socket(int af, int type, int protocol)
{
    int ret = 0;
    int fd;
    struct File *filp;
    struct InodeSocket *ino;
    struct Task *current = cpu_get_local()->current;

    ino = new_socket_inode();

    if (!ino)
        return -ENFILE;

    // We initialize the socket first //
    ret = socket_open(af, type & SOCK_MASK, protocol, &ino->socket);

    if (ret)
        goto release_inode;

    filp = kzalloc(sizeof(*filp), PAL_KERNEL);
    filp->inode = &inode->i;
    filp->flags = F(FILE_RD) | F(FILE_WR);
    filp->ops = &socket_file_ops;
    atomic_inc(&filp->ref);

    if (type & SOCK_NONBLOCK)
        flag_set(&filp->flags, FILE_NONBLOCK);

    fd = fd_assign_empty(filp);

    if (fd == -1) {
        ret = -ENFILE;
        goto release_flip;
    }

    if (type & SOCK_CLOEXEC)
        FD_SET(fd, &current->close_on_exec);
    else
        FD_CLR(fd, &current->close_on_exec);

    kprintf(KERN_NORM, "Created socket: "PRinode"\n", Pinode(&inode->i));

    return fd;

    fd_release(fd);

release_flip:
    kfree(filp);
    socket_put(ino->socket);

release_ino:
    inode_put(&ino->i);

    return ret;
}

static void
socket_subsystem_init(void)
{
    Device dev = block_dev_anon_get();

    socket_fake_super_block.bdev = block_dev_get(dev);
    socket_fake_super_block.ops = &socket_fake_super_block_ops;
}

initcall_subsys(socket_subsystem, socket_subsystem_init);
