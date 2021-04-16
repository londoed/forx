/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/task_procfs.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/list.h>
#include <forx/mm/kmalloc.h>
#include <forx/fs/procfs.h>
#include <forx/usetask.h>
#include <forx/fs/file.h>
#include <forx/seq_file.h>

#include <forx/task.h>
#include <forx/sched.h>

#include "sched_internal.h"

static int
task_seq_start(struct SeqFile *seq)
{
    spinlock_acquire(&ktasks.lock);

    return seq_list_start_header(seq, &ktasks.list);
}

static int
task_seq_render(struct SeqFile *seq)
{
    struct Task *t = seq_list_get_entry(seq, struct Task, task_list_node);

    if (!t)
        return seq_printf(seq, "Pid\tPPid\tPGid\tState\tKilled\tName\n");

        return seq_printf(seq, "%d\t%d\t%d\t%s\t%d\t`%s`\n",
            t->pid, (t->parent) ? t->parent->pid : 0,
            t->pgid, task_states[t->state],
            flag_test(&t->flags, TASK_FLAG_KILLED),
            t->name);
}

static int
task_seq_next(struct SeqFile *seq)
{
    return seq_list_next(seq, &ktasks.list);
}

static void
task_seq_end(struct SeqFile *seq)
{
    spinlock_release(&ktasks.lock);
}

const static struct SeqFileOps task_seq_file_ops = {
    .start = task_seq_start,
    .next = task_seq_next,
    .render = task_seq_render,
    .end = task_seq_end,
};

static int
task_file_seq_open(struct Inode *inode, struct File *filp)
{
    return seq_open(filp, &task_seq_file_ops);
}

struct FileOps task_file_ops = {
    .open = task_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
