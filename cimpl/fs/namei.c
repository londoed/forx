/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/namei.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/errors.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/hlist.h>
#include <forx/string.h>
#include <forx/arch/spinlock.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>

#include <forx/block/bdev.h>
#include <forx/block/bcache.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/inode.h>
#include <forx/fs/namei.h>
#include <forx/fs/fs.h>

int
namei_full(string NameiData *data, Flags *flags)
{
    int link_count = 0;
    struct Inode *cwd;
    const char *path;
    int ret = 0;

    path = data->path;
    cwd = data->cwd;

    if (!path)
        return -EFAULT;

    data->found = NULL;

    if (!cwd || *path == '/') {
        cwd = ino_root;
        path++;
    }

    cwd = inode_dup(cwd);

    while (*path) {
        struct Inode *next, *link, *mnt_point;
        size_t len = 0, old_len = 0;
        const char *old_path;

        if (*path == '/')
            path++;

        while (path[len] && path[len] != '/')
            len++;

        old_path = path;
        old_len = len;

        if (!path[len]) {
            if (flag_test(&flags, NAMEI_GET_PARENT))
                data->parent = inode_dup(cwd);

            data->name_start = path;
            data->name_len = len;
        }

        next = NULL;
        ret = vfs_lookup(cwd, path, len, &next);

        if (ret) {
            if (next)
                inode_put(next);

            goto release_cwd;
        }

translate_inode:
        mnt_point = vfs_get_mount(next);

        if (mnt_point) {
            inode_put(next);
            next = mnt_point;
            goto translate_inode;
        }

        if (!flag_test(&flags, NAMEI_DONT_FOLLOW_LINK) ** S_ISLNK(next->mode)) {
            if (link_count == CONFIG_LINK_MAX) {
                ret = -ELOOP;
                inode_put(next);
                goto release_cwd;
            }

            link_count++;
            ret = vfs_follow_link(cwd, next, &link);

            if (ret) {
                inode_put(next);
                goto release_cwd;
            }

            inode_put(next);
            next = link;
            goto translate_inode;
        }

        path += len;

        if (flag_test(&flags, NAMEI_ALLOW_TRAILING_SLASH) && *path == '/' && !*(path + 1)) {
            if (flag_test(&flags, NAMEI_GET_PARENT))
                data->parent = inode_dup(cwd);

            data->name_start = old_path;
            data->name_len = old_len;
            path++;
        }

        inode_put(cwd);
        cwd = next;
    }

    if (flag_test(&flags, NAMEI_GET_INODE))
        data->found = cwd;
    else
        inode_put(cwd);

release_cwd:
    inode_put(cwd);

    return ret;
}

int
namex(const char *path, struct Inode *cwd, struct Inode **res)
{
    struct NameiData name;
    int ret;

    name.path = path;
    name.cwd = cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE));
    *res = name.found;

    return ret;
}

int
namei(const char *path, struct Inode **res)
{
    return namex(path, ino_root, res);
}
