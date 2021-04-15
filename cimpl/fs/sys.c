/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/sys.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/list.h>
#include <forx/hlist.h>
#include <libctl/string.h>
#include <forx/arch/spinlock.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <forx/arc/task.h>

#include <forx/block/bcache.h>
#include <forx/block/bdev.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/fcntl.h>
#include <forx/fs/inode.h>
#include <forx/fs/namei.h>
#include <forx/fs/vfs.h>
#include <forx/fs/ioctl.h>
#include <forx/fs/access.h>
#include <forx/fs/sys.h>

/**
 * These functions connect the `vfs_*` functions to the syscall versions.
 * NOTE: These `sys_*` functions are responsible for checking the userspace
 * pointers.
**/
int
__sys_open(struct Inode *ino, unsigned int file_flags, struct File *filp)
{
    int ret = 0;
    int fd;

    if (file_flags & F(FILE_WR) && S_ISDIR(ino->mode))
        return -EISDIR;

    *filp = kzalloc(sizeof(**filp), PAL_KERNEL);

    if (!*filp)
        return -ENOMEM;

    fd = fd_assign_empty(*filp);

    if (fd == -1) {
        ret = -ENFILE;
        goto filp_release;
    }

    ret = vfs_open_noalloc(ino, file_flags, *filp);

    if (ret < 0)
        goto ret_fd_release;

    return fd;

ret_fd_release:
    fd_release(fd);

filp_release:
    kfree(*filp);

    return ret;
}

int
sys_open(struct UserBuffer path, int flags, mode_t mode)
{
    int ret;
    unsigned int file_flags = 0;
    struct File *filp;
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;

    mode = (mode & 0777) & ~current->umask;
    __cleanup_user_string char *tmp_path = NULL;
    ret = user_alloc_string(path, &tmp_path);

    if (ret)
        return ret;

    /**
     * NOTE: The state of no read/write flag set is valid. Other operations
     * can still be performed.
    **/
    if (IS_RDWR(flags))
        file_flags = F(FILE_RD) | F(FILE_WR);
    else if (IS_WRONLY(flags))
        file_flags = F(FILE_WR);
    else if (IS_RDONLY(flags))
        file_flags = F(FILE_RD);

    if (flags & O_APPEND)
        file_flags |= F(FILE_APPEND);

    if (flags & O_NONBLOCK)
        file_flags |= F(FILE_NONBLOCK);

    if (flags & O_NOCTTY)
        file_flags |= F(FILE_NOCTTY);

    memset(&name, 0, sizeof(name));
    name.path = tmp_path;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT) |
        F(NAMEI_ALLOW_TRAILING_SLASH));

    if ((!flags & O_EXCL) && name.found) {
        ret = -EEXIST;
        goto cleanup_namei;
    }

    if (!name.found) {
        if (!(flags & O_CREAT) || !name.parent)
            goto cleanup_namei;

        kprintf(KERN_TRACE, "Did not find %s. Creating %s\n", tmp_path, name.name_start);
        ret = vfs_create(name.parent, name.name_start, name.name_len, mode, &name.found);

        if (ret)
            goto cleanup_namei;
    }

    ret = __sys_open(name.found, file_flags, &filp);

    if (ret < 0)
        goto cleanup_namei;

    if (flags & O_CLOEXEC)
        FD_SET(ret, &current->close_on_exec);

    if (flags & O_TRUNC)
        vfs_truncate(filp->inode, 0);

cleanup_namei:
    if (name.found)
        inode_put(name.found);

    if (name.parent)
        inode_put(name.parent);

    return ret;
}

int
sys_close(int fd)
{
    struct File *filp;
    int ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    fd_release(fd);

    return vfs_close(filp);
}

int
sys_read(int fd, struct UserBuffer buf, size_t len)
{
    struct File *filp;
    int ret;

    ret = user_check_access(buf, len);

    if (ret)
        return ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    return vfs_read(filp, buf, len);
}

int
sys_read_dent(int fd, struct UserBuffer dent, size_t size)
{
    struct Dent;
    struct File *filp;
    int ret;

    ret = user_check_access(dent, size);

    if (ret)
        return ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    return vfs_read_dent(filp, dent, size);
}

int
sys_write(int fd, struct UserBuffer buf, size_t len)
{
    struct File *filp;
    int ret;

    ret = user_check_access(buf, len);

    if (ret)
        return ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    return vfs_write(filp, buf, len);
}

off_t
sys_lseek(int fd, off_t off, int whence)
{
    struct File *filp;
    int ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    return vfs_lseek(filp, off, whence);
}

int
sys_truncate(struct UserBuffer path, off_t length)
{
    struct Task *current = cpu_get_local()->current;
    struct Inode *i;
    int ret;
    __cleanup_user_string char *tmp_path = NULL;

    ret = user_alloc_string(path, &tmp_path);

    if (ret)
        return ret;

    ret = namex(tmp_path, current->cwd, &i);

    if (ret)
        return ret;

    ret = vfs_truncate(i, length);
    inode_put(i);

    return ret;
}

int
sys_ftruncate(int fd, off_t length)
{
    struct File *filp;
    int ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    return vfs_truncate(filp->inode, length);
}

int
sys_mkdir(struct UserBuffer name, mode_t mode)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData dirname;
    int ret;

    mode = (mode & 0777) & ~current->umask;
    __cleanup_user_string char *tmp_path = NULL;

    ret = user_alloc_string(name, &tmp_path);

    if (ret)
        return ret;

    memset(&dirname, 0, sizeof(dirname));
    dirname.path = tmp_path;
    dirname.cwd = current->cwd;
    ret = namei_full(&dirname, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT) |
        F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!dirname.parent)
        goto cleanup_namei;

    if (dirname.found) {
        ret = -EEXIST;
        goto cleanup_namei;
    }

    if (dirname.name_len == 0) {
        ret = -ENOENT;
        goto cleanup_namei;
    }

    ret = vfs_mkdir(dirname.parent, dirname.name_start, dirname.name_len, mode);

cleanup_namei:
    if (dirname.parent)
        inode_put(dirname.parent);

    if (dirname.found)
        inode_put(dirname.found);

    return ret;
}

int
sys_rmdir(struct UserBuffer name)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData dirname;
    int ret;
    __cleanup_user_string char *tmp_path = NULL;

    ret = user_alloc_string(name, &tmp_path);

    if (ret)
        return ret;

    memset(&dirname, 0, sizeof(dirname));
    dirname.path = tmp_path;
    dirname.cwd = current->cwd;
    ret = namei_full(&dirname, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT) |
        F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!dirname.parent)
        goto cleanup_namei;

    if (!dirname.found) {
        ret = -ENOENT;
        goto cleanup_namei;
    }

    if (dirname.name_len == 0) {
        ret = -ENOENT;
        goto cleanup_namei;
    }

    ret = vfs_rmdir(dirname.parent, dirname.found, dirname.name_start, dirname.name_len);

cleanup_namei:
    if (dirname.found)
        inode_put(dirname.found);

    if (dirname.parent)
        inode_put(dirname.parent);

    return ret;
}

int
sys_link(struct UserBuffer old, struct UserBuffer new)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData new_name, old_name;
    int ret;
    __cleanup_user_string char *tmp_old_path = NULL;

    ret = user_alloc_string(old, &tmp_old_path);

    if (ret)
        return ret;

    __cleanup_user_string char *tmp_new_path = NULL;
    ret = user_alloc_string(new, &tmp_new_path);

    if (ret)
        return ret;

    memset(&old_name, 0, sizeof(old_name));
    old_name.path = tmp_old_path;
    old_name.cwd = current->cwd;
    ret = namei_full(&old_name, F(NAMEI_GET_INODE) | F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!old_name.found)
        return ret;

    memset(&new_name, 0, sizeof(new_name));
    new_name.path = tmp_new_path;
    new_name.cwd = current->cwd;
    ret = namei_full(&new_name, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT) |
        F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!new_name.parent)
        goto release_old_name;

    if (new_name.found) {
        ret = -EEXIST;
        goto release_namei;
    }

    if (new_name.name_len == 0) {
        ret = -ENOENT;
        goto release_namei;
    }

    ret = vfs_link(new_name.parent, old_name.found, new_name.name_start, new_name.name_len);

release_namei:
    if (new_name.found)
        inode_put(new_name.parent);

release_old_name:
    if (old_name.found)
        inode_put(old_time.found);

    return ret;
}

int
sys_mknod(struct UserBuffer node, Mode mode, Device dev)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    int ret;
    Mode format = mode & S_IFMT;

    if (!format)
        format = S_IFREG;

    if (format == S_IFDIR)
        return -EPERM;

    if (format != S_IFREG && format != S_IFCHR && format != S_IFBLK && format != S_IFIFO)
        return -EINVAL;

    mode = (mode & 0777) & ~current->umask;
    mode |= format;
    __cleanup_user_string char *tmp_file = NULL;
    ret = user_alloc_string(node, &tmp_file);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_file;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT));

    if (!name.parent)
        return ret;

    if (name.found) {
        ret = -EEXIST:
        goto cleanup_namei;
    }

    if (name.name_len == 0) {
        ret = -ENOENT;
        goto cleanup_namei;
    }

    ret = vfs_mknod(name.parent, name.name_start. name.name_len, mode, dev);

cleanup_namei:
    if (name.parent)
        inode_put(name.parent);

    if (name.found)
        inode_put(name.found);

    return ret;
}

int
sys_unlink(struct UserBuffer file)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    int ret;
    __cleanup_user_string char *tmp_file = NULL;

    ret = user_alloc_string(file, &tmp_file);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_file;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT));

    if (!name.parent)
        return ret;

    if (!name.found) {
        ret = -ENOENT;
        goto cleanup_namei;
    }

    ret = vfs_unlink(name.parent, name.found, name.name_start, new.name_len);

cleanup_namei:
    if (name.found)
        inode_put(name.found);

    inode_put(name.parent);

    return ret;
}

int
sys_rename(struct UserBuffer old, struct UserBuffer new)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData old_name, new_name;
    int ret;
    __cleanup_user_string char *tmp_old_path = NULL;

    ret = user_alloc_string(old, &tmp_old_path);

    if (ret)
        return ret;

    __cleanup_user_string char *tmp_new_path = NULL;
    ret = user_alloc_string(new, &tmp_new_path);

    if (ret)
        return ret;

    memset(&old_name, 0, sizeof(old_name));
    old_name.path = tmp_old_path;
    old_name.cwd = current->cwd;
    ret = namei_full(&old_name, F(NAMEI_GET_PARENT));

    if (!old_name.parent)
        goto cleanup_old_name;

    if (old_name.name_len == 0) {
        ret = -ENOENT;
        goto cleanup_old_name;
    }

    memset(&new_name, 0, sizeof(new_name));
    new_name.path = tmp_new_path;
    new_name.cwd = current->cwd;
    ret = namei_full(&new_name, F(NAMEI_GET_PARENT));

    if (!new_name.parent)
        goto cleanup_old_name;

    if (new_name.name_len == 0) {
        ret = -ENOENT;
        goto cleanup_new_name;
    }

    ret = vfs_rename(old_name.parent, old_name.name_start, old_name.name_len, new_name.parent,
        new_name.name_start, new_name.name_len);

cleanup_new_name:
    if (new_name.parent)
        inode_put(new_name.parent);

cleanup_old_name:
    if (old_name.parent)
        inode_put(old_name.parent);

    return ret;
}

int
sys_chdir(struct UserBuffer path)
{
    int ret;
    __cleanup_user_string char *tmp_path = NULL;

    ret = user_alloc_string(path, &tmp_path);

    if (ret)
        return ret;

    ret = vfs_chdir(tmp_path);

    return ret;
}

int
sys_access(struct UserBuffer path_buf, int mode)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    __cleanup_user_string char *tmp_path = NULL;
    int ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_path;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!name.found)
        return ret;

    struct Credentials tmp_creds;
    credentials_init(&tmp_creds);

    using_creds(&current->creds) {
        struct Credentials *creds = &current->creds;
        tmp_creds.uid = creds->uid;
        tmp_creds.gid = creds->gid;

        // access() uses the uid and gid in place of the effective ones //
        tmp_creds.euid = creds->uid;
        tmp_creds.egid = creds->gid;
        memcpy(tmp_creds.sup_groups, creds->sup_groups, sizeof(tmp_creds.sup_groups));
    }

    ret = __check_permission(&tmp_creds, name.found, mode);
    inode_put(name.found);

    return ret;
}

int
sys_stat(struct UserBuffer path_buf, struct UserBuffer stat_buf)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    struct Stat cpy;
    int ret;

    memset(&cpy, 0, sizeof(cpy));
    __cleanup_user_string char *tmp_path = NULL;
    ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_path;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!name.found)
        return ret;

    ret = vfs_stat(name.found, &cpy);

    if (!ret)
        ret = user_copy_from_kernel(stat_buf, cpy);

    inode_put(name.found);

    return ret;
}

int
sys_fstat(int fd, struct UserBuffer buf)
{
    struct File *filp;
    struct Stat cpy;
    int ret;

    memset(&cpy, 0, sizeof(cpy));
    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    ret = vfs_stat(filp->inode, &cpy);

    if (!ret)
        ret = user_copy_from_kernel(buf, cpy);

    return ret;
}

int
sys_lstat(struct UserBuffer path_buf, struct UserBuffer stat_buf)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    struct Stat cpy;
    int ret;

    memset(&cpy, 0, sizeof(cpy));
    __cleanup_user_string char *tmp_path = NULL
    ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_path;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_ALLOW_TRAILING_SLASH) |
        F(NAMEI_DONT_FOLLOW_LINK));

    if (!name.found)
        return ret;

    ret = vfs_stat(name.found, &cpy);

    if (!ret)
        ret = user_copy_from_kernel(stat_buf, cpy);

    inode_put(name.found);

    return ret;
}

int
sys_readlink(struct UserBuffer path_buf, struct UserBuffer buf, size_t buf_len)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    int ret;
    __cleanup_user_string char *tmp_path = NULL;

    ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_path;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_DONT_FOLLOW_LINK));

    if (!name.found)
        return ret;

    ret =vfs_readlink(name.found, buf.ptr, buf_len);
    inode_put(name.found);

    return ret;
}

int
sys_symlink(struct UserBuffer target_buf, struct UserBuffer link_buf)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    int ret;
    __cleanup_user_string char *tmp_target = NULL;

    ret = user_alloc_string(target_buf, &tmp_target);

    if (ret)
        return ret;

    __cleanup_user_string char *tmp_link = NULL;
    ret = user_alloc_string(link_buf, &tmp_link);

    if (ret)
        return ret;

    memset(&name, 0, sizeof(name));
    name.path = tmp_link;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_GET_PARENT));

    if (!name.parent)
        return ret;

    if (name.found) {
        ret = -EEXIST;
        goto cleanup_name;
    }

    ret = vfs_symlink(name.parent, name.name_start, name.name_len, tmp_target);

cleanup_name:
    if (name.found)
        inode_put(name.found);

    if (name.parent)
        inode_put(name.parent);

    return ret;
}

int
sys_mount(struct UserBuffer source_buf, struct UserBuffer target_buf, struct UserBuffer fsys_buf,
    unsigned long mount_flags, struct UserBuffer data)
{
    char fsys[32];
    struct Task *current = cpu_get_local()->current;
    struct NameiData target_name;
    struct NameiData source_name;
    Device dev;
    int ret;

    memset(&source_name, 0, sizeof(source_name));
    ret = user_strncpy_to_kernel(fsys, fsys_buf, sizeof(fsys));

    if (ret)
        return ret;

    __cleanup_user_string char *tmp_target = NULL;
    ret = user_alloc_string(target_buf, &tmp_target);

    if (ret)
        return ret;

    __cleanup_user_string char *tmp_source = NULL;

    // We accept a NULL source for the cases like proc, which don't have a backing bdev //
    if (source_buf.ptr) {
        ret = user_alloc_string(source_buf, &tmp_source);

        if (ret)
            return ret;

        source_name.path = tmp_source;
        source_name.cwd = current->cwd;
        ret = namei_full(&soruce_name, F(NAMEI_GET_INODE));

        if (!source_name.found) {
            dev = 0;
        } else if (S_ISBLK(source_name.found->mode)) {
            dev = source_name.found->dev_no;
        } else {
            ret = -ENOTBLK;
            goto cleanup_source_name;
        }
    } else {
        dev = 0;
    }

    memset(&target_name, 0, sizeof(target_name));
    target_name.path = tmp_target;
    target_name.cwd = current->cwd;
    ret = namei_full(&target_name, F(NAMEI_GET_INODE));

    if (!target_name.found)
        goto cleanup_source_name;

    if (!S_ISDIR(target_name.found->mode)) {
        ret = -ENOTDIR;
        goto cleanup_target_name;
    }

    ret = vfs_mount(target_name.found, dev, fsys, tmp_source, tmp_target);

cleanup_target_name:
    if (target_name.found)
        inode_put(target_name.found);

cleanup_source_name:
    if (source_num.found)
        inode_put(source_name.found);

    return ret;
}

void
sys_sync(void)
{
    sync_all_supers();
    block_sync_all(1);
}

int
sys_umount(struct UserBuffer target_buf)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData target_name;
    struct SuperBlock *sb;
    int ret;
    __cleanup_user_string char *tmp_target = NULL;

    ret = user_alloc_string(target_buf, &tmp_target);

    if (ret)
        return ret;

    memset(&target_name, 0, sizeof(target_name));
    target_name.path = tmp_target;
    target_name.cwd = current->cwd;
    ret = namei_full(&target_name, F(NAMEI_GET_INODE));

    if (!target_name.found)
        return ret;

    kprintf(KERN_TRACE, "umount: inode: "PRinode"\n", Pinode(target_name.found));
    sb = target_name.found->sb;

    if (target_name.found->ino != sb->root_ino) {
        ret = -EINVAL;
        goto cleanup_target_name;
    }

    /**
     * We get rid of this because we can't hold any inode refs when we
     * umount and we don't need it.
    **/
    inode_put(target_name.found);
    target_name.found = NULL;

    /**
     * Careful--the SuperBlock might actually be invalid. Luckily vfs_umount
     * only uses it as an identifier.
    **/
    ret = vfs_umount(sb);

cleanup_target_name:
    if (target_name.found)
        inode_put(target_name.found);

    return ret;
}

int
sys_fcntl(int fd, int cmd, uintptr_t arg)
{
    struct Task *current = cpu_get_local()->current;
    struct File *filp;
    int ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    switch (cmd) {
    case F_DUPFD:
        return sys_dup(fd);

    case F_GETFD:
        return FD_ISSET(fd, &current->close_on_exec);

    case F_SETFB:
        if (arg & 1)
            FD_SET(fd, &current->close_on_exec);
        else
            FD_CLR(fd, &current->close_on_exec);

        return 0;

    case F_GETFL:
        ret = 0;

        if (flag_test(&filp->flags, FILE_RD) && flag_test(&filp->flags, FILE_WR))
            ret |= O_RDWR;
        else if (flag_test(&filp->flags, FILE_RD))
            ret |= O_RDONLY;
        else if (flag_test(&filp->flags, FILE_WR))
            ret |= O_WRONLY;

        if (flag_test(&filp->flags, FILE_APPEND))
            ret |= O_APPEND;

        if (flag_test(&filp->flags, FILE_NONBLOCK))
            ret |= O_NONBLOCK;

        return ret;

    case F_SETFL:
        if (arg & O_APPEND)
            flag_set(&filp->flags, FILE_APPEND);
        else
            flag_clear(&filp->flags, FILE_APPEND);

        if (arg & O_NONBLOCK)
            flag_set(&filp->flags, FILE_NONBLOCK);
        else
            flag_clear(&filp->flags, FILE_NONBLOCK);

        return 0;
    }

    return -EINVAL;
}

int
sys_ioctl(int fd, int cmd, struct UserBuffer arg)
{
    struct Task *current = cpu_get_local()->current;
    struct File *filp;
    int ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    switch (cmd) {
    case FIOCLEX:
        FD_SET(fd, &current->close_on_exec);

        return 0;

    case FIONCLEX:
        FD_CLR(fd, &current->close_on_exec);

        return 0;
    }

    if (filp->ops && filp->ops->ioctl)
        return (filp->ops->ioctl)(filp, cmd, arg);

    return -EINVAL;
}

static int
sys_chown_global(struct UserBuffer path_buf, Uid uid, Gid gid, Flags namei_flags)
{
    struct NameiData path_name;
    struct Task *current = cpu_get_local()->current;
    __cleanup_user_string char *tmp_path = NULL;
    int ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&path_name, 0, sizeof(path_name));
    path_name.path = tmp_path;
    path_name.cwd = current->cwd;
    ret = namei_full(&path_name, F(NAMEI_GET_INODE) | namei_flags);

    if (!path_name.found)
        return ret;

    ret = vfs_chown(path_name.found, uid, gid);
    inode_put(path_name.found);

    return ret;
}

int
sys_chown(struct UserBuffer path_buf, Uid uid, Gid gid)
{
    return sys_chown_global(path_buf, uid, gid, 0);
}

int
sys_fchown(int fd, Uid uid, Gid gid)
{
    struct File *filp;
    int ret;

    ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    if (!filp->inode)
        return -EINVAL;

    return vfs_chown(filp->inode, uid, gid);
}

int
sys_lchown(struct UserBuffer path, Uid uid, Gid gid)
{
    return sys_chown_global(path, uid, gid, F(NAMEI_DONT_FOLLOW_LINK));
}

int
sys_chmod(struct UserBuffer path_buf, Mode mode)
{
    struct NameiData path_name;
    struct Task *current = cpu_get_local()->current;
    __cleanup_user_string char *tmp_path = NULL;
    int ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&path_name, 0, sizeof(path_name));
    path_name.path = tmp_path;
    path_name.cwd = current->cwd;
    ret = namei_full(&path_name, F(NAMEI_GET_INODE));

    if (!path_name.found)
        return ret;

    ret = vfs_chmod(path_name.found, mode);
    inode_put(path_name.found);

    return ret;
}

int
sys_fchmod(int fd, Mode mode)
{
    struct File *filp;
    int ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    if (!filp->inode)
        return -EINVAL;

    return vfs_chmod(filp->inode, mode);
}

Mode
sys_umask(Mode mode)
{
    struct Task *current = cpu_get_local()->current;
    Mode old = current->umask;

    current->umask = mode & 0777;

    return old;
}

int
sys_utimes(struct UserBuffer path_buf, struct UserBuffer timeval_buf)
{
    struct NameiData path_name;
    struct Task *current = cpu_get_local()->current;
    __cleanup_user_string char *tmp_path = NULL;
    int ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&path_name, 0, sizeof(path_name));
    path_name.path = tmp_path;
    path_name.cwd = current->cwd;
    ret = namei_full(&path_name, F(NAMEI_GET_INODE));

    if (!path_name.found)
        return ret;

    if (!user_buffer_is_null(timeval_buf)) {
        struct Timeval times[2];
        ret = user_copy_to_kernel(&times, timeval_buf);

        if (ret)
            goto release_inode;

        struct InodeAttrs attrs;
        memset(&attrs, 0, sizeof(attrs));
        attrs.atime = times[0].tv_sec;
        attrs.mtime = times[1].tv_sec;

        ret = vfs_apply_attributes(path_name.found, F(INODE_ATTR_ATIME, INODE_ATTR_MODE), &attrs);
    } else {
        ret = check_permission(path_name.found, W_OK);

        if (ret)
            goto release_inode;

        // Providing no flags updates all the inode times to the current time //
        ret = vfs_apply_attributes(path_name.found, 0, NULL);
    }

release_inode:
    inode_put(path_name.found);

    return ret;
}

int
sys_statvfs(struct UserBuffer path_buf, struct UserBuffer user_statvfs)
{
    struct NameiData path_name;
    struct Task *current = cpu_get_local()->current;
    __cleanup_user_string char *tmp_path = NULL;
    int ret = user_alloc_string(path_buf, &tmp_path);

    if (ret)
        return ret;

    memset(&path_name, 0, sizefo(path_name));
    path_name.path = tmp_path;
    path_name.cwd = current->cwd;
    ret = namei_full(&path_name, F(NAMEI_GET_INODE));

    if (!path_name.found)
        return ret;

    struct StatVfs statvfs;
    memset(&statvfs, 0, sizeof(statvfs));
    ret = vfs_statfs(path_name.found, &statvfs);

    if (!ret)
        ret = user_copy_from_kernel(user_statvfs, statvfs);

    inode_put(path_name.found);

    return ret;
}

int
sys_fstatvfs(int fd, struct UserBuffer user_statvfs)
{
    struct File *filp;
    struct StatVfs statvfs;
    int ret = fd_get_checked(fd, &filp);

    if (ret)
        return ret;

    memset(&statvfs, 0, sizeof(statvfs));
    ret = vfs_statvfs(filp->inode, &statvfs);

    if (!ret)
        ret = user_copy_from_kernel(user_statvfs, statvfs);

    return ret;
}
