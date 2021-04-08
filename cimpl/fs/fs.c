/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/fs.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/string.h>
#include <forx/libctl/snprintf.h>
#include <forx/list.h>

#include <forx/arch/spinlock.h>
#include <forx/fs/ext2.h>
#include <forx/fs/procfs.h>
#include <forx/fs/seq_file.h>
#include <forx/fs/elf.h>
#include <forx/fs/binfmt.h>
#include <forx/fs/fs.h>

struct SuperBlock *sb_root;
struct Inode *ino_root;

struct FileSystemList {
    Spinlock lock;
    ListHead list;
} file_system_list = {
    .lock = SPINLOCK_INIT(),
    .list = LIST_HEAD_INIT(file_system_list.list),
};

void
fs_register(struct FileSystem *fs)
{
    kprintf(KERN_NORM, "Registering file system: %s\n", fs->name);

    using_spinlock(&file_system_list.lock)
        list_add_tail(&file_system_list.list, &fs->fs_list_entry);
}

void
fs_unregister(const char *name)
{
    struct FileSystem *fs;

    kprintf(KERN_NORM, "Unregistering file system: %s\n", name);

    using_spinlock(&file_system_list.lock) {
        list_foreach_entry(&file_system_list.list, fs, fs_list_entry) {
            if (strcmp(fs->name, name) == 0) {
                list_del(&fs->fs_list_entry);
                break;
            }
        }
    }
}

struct FileSystem *
fs_lookup(const char *name)
{
    struct FileSystem *found = NULL, *fs;

    using_spinlock(&file_system_list.lock) {
        list_foreach_entry(&file_system_list.list, fs, fs_list_entry) {
            if (strcmp(fs->name, name) == 0) {
                found = fs;
                break;
            }
        }
    }

    return found;
}

static int
fs_seq_start(struct SeqFile *seq)
{
    spinlock_acquire(&file_system_list.lock);

    return seq_list_start(seq, &file_system_list.list);
}

static void
fs_seq_end(struct SeqFile *seq)
{
    spinlock_release(&file_system_list.lock);
}

static int
fs_seq_render(struct SeqFile *seq)
{
    struct FileSystem *fs = seq_list_get_entry(seq, struct FileSystem, fs_list_entry);

    return seq_printf("%s\n", fs->name);
}

static int
fs_seq_next(struct SeqFile *seq)
{
    return seq_list_next(seq, &fs->name);
}

const static struct SecFileOps fs_seq_file_ops = {
    .start = fs_seq_start,
    .end = fs_seq_end,
    .render = fs_seq_render,
    .next = fs_seq_next,
};

static int
fs_file_seq_open(struct Inode *ino, struct File *filp)
{
    return seq_open(filp, &fs_seq_file_ops);
}

const struct FileOps fs_file_ops = {
    .open = fs_file_seq_open,
    .lseek = seq_lseek,
    .read = seq_read,
    .release = seq_release,
};
