/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/pipe.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/hlist.h>
#include <forx/string.h>
#include <forx/arch/spinlock.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/page_alloc.h>
#include <forx/mm/user_check.h>
#include <forx/initcall.h>
#include <forx/arch/task.h>

#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/vfs.h>
#include <forx/fs/pipe.h>

/**
 * The first step is setting up a `fake` SuperBlock for anonymous pipes
 * to reside in. This is necessary for pipes to be correctly entered into
 * the inode-table, since inode_put() will result in sb->ops->inode_dealloc()
 * being called.
**/
static int
pipe_inode_dealloc(struct SuperBlock *pipe_sb, struct Inode *pipe_ino)
{
    kfree(pipe_ino);

    return 0;
}

static Inode next_pipe_ino = 1;

static struct Inode *
pipe_inode_alloc(struct SuperBlock *pipe_sb)
{
    struct Inode *ino = kzalloc(sizeof(*ino), PAL_KERNEL);

    inode_init(ino);

    return ino;
}

static void
pipe_release_pages(struct PipeInfo *pipe)
{
    struct Page *page;

    list_foreach_take_entry(&pipe->free_pages, page, page_list_node)
        page_free(page, 0);

    list_foreach_take_entry(&pipe->bufs, page, page_list_node)
        page_free(page, 0);

    pipe->total_pages = 0;
}

static int
pipe_inode_delete(struct SuperBlock *pipe_sb, struct Inode *ino)
{
    kprintf(KERN_TRACE, "Deleting pipe "PRinode"\n", Pinode(ino));
    pipe_release_pages(&ino->pipe_info);

    return 0;
}

static struct SuperBlockOps pipe_fake_super_block_ops = {
    .inode_dealloc = pipe_inode_dealloc,
    .inode_alloc = pipe_inode_alloc,
    .inode_read = NULL,
    .inode_write = NULL,
    .inode_delete = pipe_inode_delete,
    .sb_write = NULL,
    .sb_put = NULL,
};

// This is initialized with the proper fields down the pipe_init() //
static struct SuperBlock pipe_fake_super_block = SUPER_BLOCK_INIT(pipe_fake_super_block);

/**
 * Indicates the read and write file-descriptor numbers in the fds[] array
 * passed to the syscall.
**/
#define P_READ 0
#define P_WRITE 1

static struct Inode *
new_pipe_inode(void)
{
    // struct Inode *inode = pipe_inode_alloc(&page_fake_super_block); //
    struct Inode *ino = pipe_fake_super_block.ops->inode_alloc(&pipe_fake_super_block);

    ino->ino = next_pipe_ino++;
    ino->sb = &pipe_fake_super_block;

    return ino;
}

int
inode_is_pipe(struct Inode *ino)
{
    return ino->sb == &pipe_fake_super_block;
}

/**
 * When a file is released, we decrease the number of readers or writers
 * of the corresponding pipe. When either number drops to zero, then we
 * wake up the corresponding WaitQueue, so that they can exit with an
 * error or EOF.
 *
 * In example, if a reader is waiting for data, and all the writers close,
 * then when the last writer closes we hit this code, which wakes up the
 * remaining readers. Those readers check if writers == 0, and if it does
 * then the read exits and returns zero.
**/
static int
pipe_release(struct File *filp, int reader, int writer)
{
    struct Inode *ino = filp->inode;
    struct PipeInfo *pinfo = &ino->pipe_info;

    using_mutex(&pinfo->pipe_buf_lock) {
        if (reader) {
            pinfo->readers--;

            if (pinfo->readers == 0)
                wait_queue_wake(&pinfo->write_queue);
        }

        if (writer) {
            pinfo->writers--;

            if (pinfo->writers == 0)
                wait_queue_wake(&pinfo->read_queue);
        }
    }

    return 0;
}

static int
pipe_read_release(struct File *filp)
{
    return pipe_release(filp, 1, 0);
}

static int
pipe_write_release(struct File *filp)
{
    return pipe_release(filp, 0, 1);
}

static int
pipe_rdwr_release(struct File *filp)
{
    return pipe_release(filp, 1, 1);
}

static int
pipe_read(struct File *filp, struct UserBuffer data, size_t size)
{
    size_t orig_size = size;
    struct PipeInfo *pinfo = &filp->inode->pipe_info;
    struct Page *p;
    int wake_writers = 0;
    int ret = 0;

    if (!size)
        return 0;

    using_mutex(&pinfo->pipe_buf_lock) {
        while (size == orig_size) {
            list_foreach_take_entry(&pinfo->bufs, p, page_list_node) {
                size_t cpysize = p->lenb > size ? size : p->lenb;
                int ret = user_memcpy_from_kernel(data, p->virt + p->startb,
                    cpysize);

                if (ret)
                    return ret;

                data = user_buffer_index(data, cpysize);
                size -= cpysize;
                p->startb += cpysize;
                p->lenb -= cpysize;

                /**
                 * Check if there is still data left.
                 *
                 * Adding to pinfo->bufs is okay, because if p->lenb is not
                 * zero, that means we're definitely done reading and
                 * size == 0.
                **/
                if (p->lenb) {
                    list_add(&pinfo->bufs, &p->page_list_node);
                } else {
                    list_add(&pinfo->free_pages, &p->page_list_node);
                    wake_writers = 1;
                }

                if (size == 0)
                    break;
            }

            /**
             * If there are no writers, then we just break early without
             * sleeping, returning anything we have. In the case of EOF,
             * we will end up reading no data and returning zero, the
             * intended behavior.
            **/
            if (pinfo->writers == 0)
                break;

            if (flag_test(&filp->flags, FILE_NONBLOCK)) {
                if (size == orig_size)
                    ret = -EAGAIN;

                break;
            }

            if (size == orig_size) {
                /**
                 * If we freed a page by reading data, then wake up any
                 * writers that may have been waiting.
                **/
                wake_writers = 0;

                // Sleep until more data //
                ret = wait_queue_event_intr_mutex(&pinfo->read_queue,
                    !list_empty(&pinfo->bufs), &pinfo->pipe_buf_lock);

                if (ret)
                    return ret;
            }
        }

        // If the buffer isn't empty, then wake next reader //
        if (!list_empty(&pinfo->bufs) || pinfo->writers == 0)
            wait_queue_wake(&pinfo->read_queue);

        if (wake_writers)
            wait_queue_wake(&pinfo->write_queue);
    }

    if (!ret)
        return orig_size - size;
    else
        return ret;
}

static int
pipe_write(struct File *filp, struct UserBuffer data, size_t size)
{
    struct PipeInfo *pinfo = &filp->inode->pipe_info;
    struct Page *p;
    struct Task *current = cpu_get_local()->current;
    size_t orig_size = size;
    int wake_readers = 0, ret = 0;

    if (!size)
        return 0;

    using_mutex(&pinfo->pipe_buf_lock) {
        while (size) {
            if (!pinfo->readers) {
                SIGSET_SET(&current->sig_pending, SIGPIPE);
                ret = -EPIPE;
                break;
            }

            list_foreach_take_entry(&pinfo->free_pages, p, page_list_node) {
                size_t cpysize = PAGE_SIZE > size ? size : PAGE_SIZE;
                int ret = user_memcpy_to_kernel(p->virt, data, cpysize);

                if (ret)
                    return ret;

                p->startb = 0;
                p->lenb = cpysize;
                data = user_buffer_index(data, cpysize);
                size -= cpysize;

                list_add_tail(&pinfo->bufs, &p->page_list_node);
                wake_readers = 1;

                if (size == 0)
                    break;
            }

            /**
             * This allows us to add more pages to our buffer if we're still
             * under the limit. If we still need more page and are at our
             * limit for our buffer size, then we many need to sleep.
            **/
            if (size && pinfo->total_pages < CONFIG_PIPE_MAX_PAGES) {
                size_t max_pages = size / PAGE_SIZE + 1 > (CONFIG_PIPE_MAX_PAGES -
                    pinfo->total_pages) ?
                    CONFIG_PIPE_MAX_PAGES - pinfo->total_pages :
                    size / PAGE_SIZE + 1;
                pinfo->total_pages += max_pages;

                for (; max_pages; max_pages--)
                    list_add(&pinfo->free_pages, &page_alloc(0, PAL_KERNEL)
                        ->page_list_node);

                continue;
            }

            if (flag_test(&filp->flags, FILE_NONBLOCK)) {
                if (size == orig_size)
                    ret = -EAGAIN;

                break;
            }

            /**
             * If there's no data and no readers, then we send a SIGPIPE to
             * ourselves and exit with -EPIPE.
            **/
            if (size) {
                if (wake_readers)
                    wait_queue_wake(&pinfo->read_queue);

                wake_readers = 0;
                ret = wait_queue_event_intr_mutex(&pinfo->write_queue,
                    !list_empty(&pinfo->free_pages), &pinfo->pipe_buf_lock);

                if (ret)
                    return ret;
            }
        }

        if (!list_empty(&pinfo->free_pages) || pinfo->readers == 0)
            wait_queue_wake(&pinfo->write_queue);

        if (wake_readers)
            wait_queue_wake(&pinfo->read_queue);
    }

    if (!ret)
        return orig_size - size;
    else
        return ret;
}

static int
pipe_poll(struct File *filp, struct PollTable *table, int events)
{
    struct PipeInfo *pinfo = &filp->inode->pipe_info;
    int ret = 0;

    using_mutex(&pinfo->pipe_buf_lock) {
        if (flag_test(&filp->flags, FILE_RD) && events & POLLIN) {
            if (!list_empty(&pinfo->bufs))
                ret |= POLLIN;
            else if (!pinfo->writers)
                ret |= POLLIN | POLLHUP;

            poll_table_add(table, &pinfo->read_queue);
        }

        if (flag_test(&filp->flags & FILE_WR) && events & POLLOUT) {
            if (!list_empty(&pinfo->free_pages) || pinfo->total_pages < CONFIG_PIPE_MAX_PAGES)
                ret |= POLLOUT;
            else if (!pinfo->readers)
                ret |= POLLOUT | POLLHUP;

            poll_table_add(table, &pinfo->write_queue);
        }
    }

    return ret;
}

static int
fifo_open(struct Inode *ino, struct File *filp)
{
    struct PipeInfo *pinfo = &filp->inode->pipe_info;
    int ret = 0;

    if (flag_test(&filp->flags, FILE_READABLE) && flag_test(&filp->flags, FILE_WR)) {
        using_mutex(&pinfo->pipe_buf_lock) {
            pinfo->readers++;
            pinfo->writers++;
            wait_queue_wake(&pinfo->read_queue);
            wait_queue_wake(&pinfo->write_queue);
        }

        flip->ops = &fifo_rdwr_file_ops;
    } else if (flag_test(&filp->flags, FILE_RD)) {
        // Wait for any readers on the associated pipe //
        using_mutex(&pinfo->pipe_buf_lock) {
            if (!(pinfo->readers++))
                wake_queue_wake(&pinfo->write_queue);

            // Opening a non-blocking fifo for read always succeeds //
            if (!flag_test(&filp->flags, FILE_NONBLOCK))
                ret = wait_queue_event_intr_mutex(&pinfo->read_queue,
                    pinfo->writers, &pinfo->pipe_buf_lock);

            if (ret == 0)
                wait_queue_wake(&pinfo->read_queue);
        }

        if (!ret)
            filp->ops = &fifo_read_file_ops;
    } else if (flag_test(&filp->flags, FILE_WR)) {
        // Wait for any readers on the associated pipe //
        using_mutex(&pinfo->pipe_buf_lock) {
            // Opening a non-blocking fifo fails if there are no readers //
            if (!pinfo->readers && flag_test(&filp->flags, FILE_NONBLOCK)) {
                ret = -ENXIO;
                break;
            }

            if (!(pinfo->writers++))
                wait_queue_wake(&pinfo->read_queue);

            ret = wait_queue_event_intr_mutex(&pinfo->write_queue, pinfo->readers,
                &pinfo->pipe_buf_lock);

            if (ret == 0)
                wait_queue_wake(&pinfo->write_queue);
        }

        if (!ret)
            filp->ops = &fifo_write_file_ops;
    } else {
        ret = -EINVAL;
    }

    return ret;
}

struct FileOps pipe_read_file_ops = {
    .open = NULL,
    .release = pipe_read_release,
    .read = pipe_read,
    .readdir = NULL,
    .read_dent = NULL,
    .lseek = NULL,
    .write = NULL,
    .poll = pipe_poll,
};

struct FileOps fifo_read_file_ops = {
    .read = pipe_read,
    .poll = pipe_poll,
    .release = pipe_read_release,
};

struct FileOps fifo_write_file_ops = {
    .write = pipe_write,
    .poll = pipe_poll,
    .release = pipe_write_release,
};

struct FileOps fifo_rdwr_file_ops = {
    .write = pipe_write,
    .read = pipe_read,
    .poll = pipe_poll,
    .release = pipe_rdwr_release,
};

struct FileOps pipe_default_file_ops = {

};

struct FileOps fifo_default_file_ops = {
    .open = fifo_open,
};

int
sys_pipe(struct UserBuffer fds)
{
    int fd_local[2];
    int ret = 0;
    struct File *filps[2];
    struct Inode *ino;
    struct Task *current = cpu_get_local()->current;

    ino = new_pipe_inode();

    if (!ino) {
        ret = -ENFILE;
        goto ret;
    }

    kprintf(KERN_NORM, "PIPE: inode %p: "PRinode"\n", ino, Pinode(ino));

    filps[0] = kzalloc(sizeof(struct File), PAL_KERNEL);
    filps[1] = kzalloc(sizeof(struct File), PAL_KERNEL);

    filps[P_READ]->inode = inode_dup(ino);
    filps[P_READ]->flags = F(FILE_RD);
    filps[P_READ]->ops = &pipe_read_file_ops;
    atomic_inc(&flips[P_READ]->ref);
    ino->pipe_info.readers++;

    filps[P_WRITE]->inode = inode_dup(ino);
    filps[P_WRITE]->flags = F(FILE_WR);
    filps[P_WRITE]->ops = &pipe_write_file_ops;
    atomic_inc(&filps[P_WRITE]->ref);
    ino->pipe_info.writers++;
    fd_local[0] = fd_assign_empty(filps[0]);

    if (fd_local[0] == -1) {
        ret = -ENFILE;
        goto release_filps;
    }

    fd_local[1] = fd_assign_empty(filps[1]);

    if (fd_local[1] == -1) {
        ret = -ENFILE;
        goto release_fd_0;
    }

    FD_CLR(fd_local[P_READ], &current->close_on_exec);
    FD_CLR(fd_local[P_WRITE], &current->close_on_exec);
    ret = user_memcpy_from_kernel(fds, fd_local, sizeof(fd_local));

    if (ret)
        goto release_fd_1;

    return 0;

release_fd_1:
    fd_release(fd_local[1]);

release_fd_0:
    fd_release(fd_local[0]);

release_filps:
    kfree(filps[0]);
    kfree(filps[1]);
    inode_dup(ino);
    inode_put(ino);

ret:
    return ret;
}

static void
pipe_init(void)
{
    Device dev = block_dev_anon_get();

    pipe_fake_sb.bdev = block_dev_get(dev);
    pipe_fake_sb.ops = &pipe_fake_sb_ops;
    kprintf(KERN_NORM, "Pipe dev: %d\n", pipe_fake_sb.bdev->dev);
}

initcall_device(pipe, pipe_init);
