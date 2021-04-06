/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/usetask.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/string.h>
#include <forx/list.h>
#include <forx/dev.h>
#include <forx/snprintf.h>
#include <forx/kmalloc.h>
#include <forx/user_check.h>
#include <forx/drivers.h>
#include <forx/procfs.h>
#include <forx/usetask.h>
#include <forx/file.h>
#include <forx/bdev.h>
#include <forx/task.h>
#include <forx/sched.h>
#include <forx/sched_internal.h>

static void
__fill_task_info(struct TaskInfo *tinfo, struct Task *task)
{
    memset(tinfo, 0, sizeof(*tinfo));
    tinfo->is_kernel = flag_test(&task->flags, TASK_FLAG_KERNEL);
    tinfo->pid = task->pid;

    if (task->parent)
        tinfo->ppid = task->parent->pid;
    else
        tinfo->ppid = 0;

    tinfo->pgid = task->pgid;
    tinfo->sid = task->session_id;
    struct Credentials *creds = &task->creds;

    using_creds(creds) {
        tinfo->uid = creds->uid;
        tinfo->gid = creds->gid;
    }

    if (task->tty) {
        tinfo->has_tty = 1;
        tinfo->tty_devno = task->tty->dev_no;
    }

    switck (task->state) {
    case TASK_RUNNING:
        tinfo->state = TASK_USE_RUNNING;
        break;

    case TASK_ZOMBIE:
        tinfo->state = TASK_USE_ZOMBIE;
        break;

    case TASK_SLEEPING:
        tinfo->state = TASK_USE_SLEEPING;
        break;

    case TASK_INTR_SLEEPING:
        tinfo->state = TASK_USE_INTR_SLEEPING;
        break;

    case TASK_STOPPED:
        tinfo->state = TASK_USE_STOPPED;
        break;

    case TASK_DEAD:
    case TASK_NONE:
        tinfo->state = TASK_USE_NONE;
        break;
    }

    memcpy(&tinfo->close_on_exec, &task->close_on_exec, sizeof(tinfo->close_on_exec));
    memcpy(&tinfo->sig_pending, &task->sig_pending, sizeof(tinfo->sig_pending));
    memcpy(&tinfo->sig_blocked, &task->sig_blocked, sizeof(tinfo->sig_blocked));
    memcpy(&tinfo->name, task->name, sizeof(tinfo->name));
}

static int
sched_task_use_read(struct File *filp, struct UserBuffer buf, size_t size)
{
    struct TaskInfo tinfo;
    struct Task *task, *found = NULL;
    Pid last_pid = filp->offset;
    Pid found_pid = -1;

    using_spinlock(&ktasks.lock) {
        list_foreach_entry(&ktasks.list, task, TaskListNode) {
            if (task->state == TASK_DEAD || task->state == TASK_NONE)
                continue;

            if (task->pid > last_pid && (found_pid == -1 || task->pid < found_pid)) {
                found = task;
                found_pid = task->pid;
            }
        }

        if (!found)
            break;

        __fill_task_info(&tinfo, found);
    }

    if (found) {
        filp->offset = found_pid;
        int ret;

        if (size > sizeof(tinfo))
            ret = user_memcpy_from_kernel(buf, &tinfo, sizeof(tinfo));
        else
            ret = user_memcpy_from_kernel(buf, &tinfo, size);

        if (ret)
            return ret;

        return size;
    } else {
        return 0;
    }
}

static int
task_fill_mem_info(struct TaskMemInfo *info)
{
    struct VmMap *map;
    struct Task *task;
    int region;

    task = sched_task_get(info->pid);

    if (!task)
        return -ESRCH;

    list_foreach_entry(&task->addr_space->vm_maps, map, AddrSpaceEntry) {
        region = info->region_count++;

        if (region > ARRAY_SIZE(info->regions))
            break;

        info->regions[region].start = (uintptr_t)map->addr.start;
        info->regions[region].end = (uintptr_t)mem->addr.end;
        info->regions[region].is_read = flag_test(&map->flags, VM_MAP_READ);
        info->regions[region].is_write = flag_test(&map->flags, VM_MAP_WRITE);
        info->regions[region].is_exec = flag_test(&map->flags, VM_MAP_EXE);
    }

    sched_task_put(task);

    return 0;
}

static int
task_fill_file_info(struct TaskFileInfo *info)
{
    int i;
    struct Task *task;

    task = sched_task_get(info->pid);

    if (!task)
        return -ESRCH;

    for (i = 0; i < NOFILE; i++) {
        struct File *filp = task_fd_get(task, i);

        if (!filp) {
            info->files[i].in_use = 0;
            continue;
        }

        info->files[i].in_use = 1;

        if (ino_is_pipe(filp->inode))
            info->files[i].is_pipe = 1;

        if (flag_test(&filp->flags, FILE_WR))
            info->files[i].is_writable = 1;

        if (flag_test(&filp->flags, FILE_RD))
            info->files[i].is_readable = 1;

        if (flag_test(&filp->flags, FILE_NONBLOCK))
            info->files[i].is_nonblock = 1;

        if (flag_test(&filp->flags, FILE_APPEND))
            info->files[i].is_append = 1;

        info->files[i].inode = filp->inode->ino;
        info->files[i].dev = filp->inode->sb->bdev->dev;
        info->files[i].mode = filp->inode->mode;
        info->files[i].offset = filp->offset;
        info->files[i].size = filp->inode->size;
    }

    sched_task_put(task);

    return 0;
}

static int
sched_task_ioctl(struct File *filp, int cmd, struct UserBuffer ptr)
{
    struct TaskMemInfo *mem_info = NULL;
    struct TaskFileInfo *file_info = NULL;
    int ret;

    switch (cmd) {
    case TASK_MEM_INFO:
        mem_info = kmalloc(sizeof(*mem_info), PAL_KERNEL);

        if (!mem_info)
            return -ENOMEM;

        ret = task_fill_mem_info(mem_info);

        if (ret) {
            kfree(mem_info);

            return ret;
        }

        ret = user_copy_from_kernel(ptr, *mem_info);
        kfree(mem_info);

        return ret;

    case TASK_FILE_INFO:
        file_info = kmalloc(sizeof(*file_info), PAL_KERNEL);

        if (!file_info)
            return -ENOMEM;

        ret = task_fill_file_info(file_info);

        if (ret) {
            kfree(file_info);

            return ret;
        }

        ret = user_copy_from_kernel(ptr, *file_info);
        kfree(file_info);

        return ret;
    }

    return -EINVAL;
}

struct ProcfsEntryOps task_use_ops = {
    .read = sched_task_read,
    .ioctl = sched_task_ioctl,
};
