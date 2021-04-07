/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/vfs.c }.
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
#include <forx/kparam.h>
#include <forx/arch/task.h>

#include <forx/block/bdev.h>
#include <forx/block/bcache.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/fcntl.h>
#include <forx/fs/inode.h>
#include <forx/fs/namei.h>
#include <forx/fs/sys.h>
#include <forx/fs/access.h>
#include <forx/fs/vfs.h>

static int VFS_MAX_LOG_LEVEL = CONFIG_VFS_LOG_LEVEL;
KPARAM("vfs.loglevel", &VFS_MAX_LOG_LEVEL, KPARAM_LOGLEVEL);

#define kp_vfs_check_level(lvl, str, ...) \
    kp_check_level((lvl), VFS_MAX_LOG_LEVEL, "vfs: " str, ##__VA_ARGS__)

#define kp_vfs_trace(str, ...) kp_vfs_check_level(KERN_TRACE, str, ##__VA_ARGS__)
#define kp_vfs_debug(str, ...) kp_vfs_check_level(KERN_DEBUG, str, ##__VA_ARGS__)
#define kp_vfs(str, ...)       kp_vfs_check_level(KERN_NORM, str, ##__VA_ARGS__)
#define kp_vfs_warning(str, ...) kp_vfs_check_level(KERN_WARN, str, ##__VA_ARGS__)
#define kp_vfs_error(str, ...) kp_vfs_check_level(KERN_ERROR, str, ##__VA_ARGS__)

int
vfs_open_noalloc(struct Inode *ino, unsigned int file_flags, struct File *filp)
{
    int ret = 0;
    int access = 0;

    if (flag_text(&file_flags, FILE_RD))
        access |= R_OK;

    if (flag_test(&file_flags), FILE_WR)
        access |= W_OK;

    ret = check_permissions(ino, access);

    if (ret)
        return ret;

    kp_vfs_debug("Allocated filp: %p\n", filp);
    filp->inode = inode_dup(ino);
    filp->offset = 0;
    filp->flags = file_flags;
    filp->ops = ino->default_fops;

    atomic_inc(&filp->ref);

    if (file_has_open(filp))
        ret = filp->ops->open(ino, filp);

    if (ret < 0)
        goto cleanup_filp;

    return ret;

cleanup_filp:
    inode_put(filp->inode);

    return ret;
}

int
vfs_open(struct Inode *ino, unsigned int file_flags, struct File **filp_ret)
{
    int ret = 0;
    struct File *filp;

    kp_vfs_debug("Opening file: %p, %d, %p\n", ino, file_flags, filp_ret);
    *filp_ret = NULL;
    filp = kzalloc(sizeof(*filp), PAL_KERNEL);
    ret = vfs_open_noalloc(ino, file_flags, filp);

    if (!ret)
        *filp_ret = filp;
    else
        kfree(filp);

    return ret;
}

int
vfs_close(struct File *filp)
{
    int ret = 0;

    kp_vfs_debug("closing file, inode: "PRinode", %d\n", Pinode(filp->inode),
        atomic_get(&filp->ref));

    if (!atomic_dec_and_test(&filp->ref))
        return 0;

    kp_vfs_debug("Releasing file with inode "PRinode"\n", Pinode(filp->inode));

    if (file_has_release(filp))
        ret = filp->ops->release(filp);

    inode_put(filp->inode);
    kp_vfs_debug("Freeing file %p\n", filp);
    kfree(filp);

    return ret;
}

int
vfs_read(struct File *filp, struct UserBuffer buf, size_t len)
{
    if (S_ISDIR(filp->inode->mode))
        return -EISDIR;

    if (file_has_read(filp))
        return filp->ops->read(filp, buf, len);
    else
        return -ENOTSUP;
}

int
vfs_pread(struct File *filp, struct UserBuffer buf, size_t len, off_t off)
{
    if (S_ISDIR(filp->inode->mode))
        return -EISDIR;

    if (file_has_pread(filp))
        return filp->ops->pread(filp, buf, len, off);
    else
        return -ENOTSUP;
}

int
vfs_read_dent(struct File *filp, struct UserBuffer dent, size_t size)
{
    if (!S_ISDIR(filp->inode->mode))
        return -ENOTDIR;

    if (file_has_read_dent(filp))
        return filp->ops->read_dent(filp, dent, size);
    else
        return -ENOTSUP;
}

int
vfs_write(struct File *filp, struct UserBuffer buf, size_t len)
{
    if (S_ISDIR(filp->inode->mode))
        return -EISDIR;

    if (file_has_write(filp)) {
        if (S_ISREG(filp->inode->mode)) {
            int ret = vfs_apply_attributes(filp->inode,
                F(INO_ATTR_RM_SGID, INO_ATTR_RM_SUID, INO_ATTR_FORCE), NULL);

            if (ret)
                return ret;
        }

        return filp->ops->write(filp, buf, len);
    } else {
        return -ENOTSUP;
    }
}

off_t
vfs_lseek(struct File *filp, off_t off, int whence)
{
    if (S_ISDIR(filp->inode->mode))
        return -EISDIR;

    if (file_has_lseek(filp))
        return filp->ops->lseek(filp, off, whence);
    else
        return -ENOTSUP;
}

int
vfs_lookup(struct Inode *ino, const char *name, size_t len, struct Inode **res)
{
    if (!S_ISDIR(ino->mode))
        return -ENOTDIR;

    int ret = check_permissions(inode, X_OK);

    if (ret)
        return ret;

    if (inode_has_lookup(ino))
        return ino->ops->lookup(ino, name, len, result);
    else
        return -ENOTSUP;
}

int
vfs_truncate(struct Inode *ino, off_t length)
{
    if (S_ISDIR(ino->mode))
        return -EISDIR;

    int ret = check_permissions(ino, W_OK);

    if (ret)
        return ret;

    if (inode_has_truncate(ino)) {
        if (S_ISREG(ino->mode)) {
            int ret = vfs_apply_attributes(ino,
                F(INO_ATTR_RM_SGID, INO_ATTR_RM_SUID, INO_ATTR_FORCE), NULL);

            if (ret)
                return ret;
        }

        return ino->ops->truncate(ino, length);
    } else {
        return -ENOTSUP;
    }
}

Sector
vfs_bmap(struct Inode *ino, Sector s)
{
    if (inode_has_bmap(ino))
        return ino->ops->bmap(ino, s);
    else
        return -ENOTSUP;
}

Sector
vfs_bmap_alloc(struct Inode *ino, Sector s)
{
    if (inode_has_bmap_alloc(ino))
        return ino->ops->bmap_alloc(ino, s);
    else
        return vfs_bmap(ino, s);
}

int
vfs_link(struct Inode *dir, struct Inode *old, const char *name, size_t len)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_link(dir))
        return dir->ops->link(dir, old, name, len);
    else
        return -ENOTSUP;
}

int
vfs_mknod(struct Inode *dir, const char *name, size_t len, Mode mode, Device dev)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_mknod(dir))
        return dir->ops->mknod(dir, name, len, mode, dev);
    else
        return -ENOTSUP;
}

int
vfs_unlink(struct Inode *dir, struct Inode *entity, const char *name, size_t len)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_unlink(dir))
        return dir->ops->unlink(dir, entity, name, len)
    else
        return -ENOTSUP;
}

int
vfs_chdir(const char *path)
{
    struct Task *current = cpu_get_local()->current;
    struct NameiData name;
    int ret;

    kp_vfs_debug("chdir: %s\n", path);
    memset(&name, 0, sizeof(name));

    name.path = path;
    name.cwd = current->cwd;
    ret = namei_full(&name, F(NAMEI_GET_INODE) | F(NAMEI_ALLOW_TRAILING_SLASH));

    if (!name.found)
        return ret;

    if (!S_ISDIR(name, found->mode)) {
        inode_put(name.found);

        return -ENOTDIR;
    }

    inode_put(current->cwd);
    current->cwd = name.found;

    return 0;
}

int
vfs_stat(struct Inode *ino, struct Stat *buf)
{
    buf->st_dev = ino->sb->bdev->dev;
    buf->st_ino = ino->ino;
    buf->st_mode = ino->mode;
    buf->st_nlink = atomic32_get(&ino->nlinks);
    buf->st_size = ino->size;
    buf->st_rdev = ino->dev_no;

    buf->st_uid = ino->uid;
    buf->st_gid = ino->gid;
    buf->st_atime = ino->atime;
    buf->st_mtime = ino->mtime;
    buf->st_blksize = ino->block_size;
    buf->st_blocks = ino->blocks;

    return 0;
}

static int
verify_apply_attribute_permissions(struct Inode *ino, Flags flags, struct InodeAttrs *attrs)
{
    struct Task *current = cpu_get_local()->current;

    if (flag_test(&flags, INO_ATTR_FORCE))
        return 0;

    using_creds(&current->creds) {
        struct Credentials *creds = &current->creds;

        if (flag_test(&flags, INO_ATTR_UID)) {
            // Changing UID is only allowed if you're root, or if the change is NO-OP //
            int is_valid = creds->euid == 0 || (creds->euid == ino->uid &&
                ino->uid == attrs->uid);

            if (!is_valid)
                return -EPERM;
        }

        if (flag_test(&flags, INO_ATTR_GID)) {
            /**
             * Changing GID is only allowed if you're root or if you own the file and
             * belong to the destination group.
            **/
            int is_valud = creds->euid == 0 || (creds->euid == inode->uid &&
                (__credentials_belong_to_gid(creds, attrs->gid) ||
                attrs->gid == ino->gid));

            if (!is_valid)
                return -EPERM;
        }

        if (flag_test(&flags, INO_ATTR_MODE)) {
            // UID must match or root for chmod to be allowed //
            if (creds->euid != 0 && creds->euid != ino->uid)
                return -EPERM;

            // Clear SGID bit if you do not belong to the target GID //
            Gid target = flag_test(&flags, INO_ATTR_GID) ? attrs->gid : ino->gid;

            if (creds->euid != 0 && !__credentials_belong_to_gid(creds, target))
                attrs->mode &= ~S_ISGID;
        }

        // You must own the file to manually change the time //
        if (flag_test(&flags, INO_ATTR_ATIME) || flag_test(&flags, INO_ATTR_MTIME) ||
            flag_test(&flags, INO_ATTR_CTIME)) {

            if (creds->euid != 0 || creds->euid != ino->uid)
                return -EPERM;
        }
    }

    return 0;
}

int
vfs_apply_attributes(struct Inode *ino, Flags flags, struct InodeAttrs *attrs)
{
    struct InodeAttrs tmp_attrs;

    if (!attrs) {
        memset(&tmp_attrs, 0, sizeof(tmp_attrs));
        attrs = &tmp_attrs;
    }

    using_inode_lock_write(ino) {
        if ((flag_test(&flags, INO_ATTR_RM_SGID) && flag_test(&flags, INO_ATTR_MODE)) ||
            (flag_test(&flags, INO_ATTR_RM_SUID) && flag_test(&flags, INO_ATTR_MODE))
                return -EINVAL;

        if (flag_test(&flags, INO_ATTR_RM_SUID) || flag_test(&flags, INO_ATTR_RM_SGID)) {
            attrs->mode = ino->mode;

            if (flag_test(&flags, INO_ATTR_RM_SUID))
                attrs->mode = attrs->mode & ~S_ISUID;

            if (flag_test(&flags, INO_ATTR_RM_SGID))
                attrs->mode = attrs->mode & ~S_ISGID;

            flag_set(&flags, INO_ATTR_MODE);
        }

        if (verify_apply_attribute_permissions(ino, flags, attrs))
            return -EPERM;

        if (flag_test(&flags, INO_ATTR_MODE))
            // Make sure to clear the non-relevant bits of the mode, just in case //
            ino->mode = (ino->mode & S_IFMT) | (attrs->mode & 07777);

        if (flag_test(&flags, INO_ATTR_UID))
            ino->uid = attrs->uid;

        if (flag_test(&flags, INO_ATTR_GID))
            ino->gid = attrs->gid;

        Time cur_time = get_current_time();

        if (flag_test(&flags, INO_ATTR_ATIME))
            ino->atime = attrs->atime;
        else
            ino->atime = cur_time;

        if (flag_test(&flags, INO_ATTR_CTIME))
            ino->ctime = attrs->ctime;
        else
            ino->ctime = cur_time;

        if (flag_test(&flags, INO_ATTR_MTIME))
            ino->mtime = attrs->mtime;
        else
            ino->mtime = cur_time;

        inode_set_dirty(ino);
    }

    return 0;
}

int
vfs_create(struct Inode *dir, const char *name, size_t len, Mode mode, struct Inode **res)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_create(dir))
        return dir->ops->create(dir, name, len, mode, res);
    else
        return -ENOTSUP;
}

int
vfs_mkdir(struct Inode *dir, const char *name, size_t len, Mode mode)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_mkdir(dir))
        return dir->ops->mkdir(dir, name, len, mode);
    else
        return -ENOTSUP;
}

int
vfs_rmdir(struct Inode *dir, struct Inode *del_dir, const char *name, size_t len)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_rmdir(dir))
        return dir->ops->rmdir(dir, del_dir, name, len);
    else
        return -ENOTSUP;
}

int
vfs_rename(struct Inode *old_dir, const char *name, size_t len, struct Inode *new_dir,
    const char *new_name, size_t new_len)
{
    if (!S_ISDIR(old_dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(old_dir, W_OK | X_OK);

    if (ret)
        return ret;

    ret = check_permissions(new_dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_rename(old_dir))
        return old_dir->ops->rename(old_dir, name, len, new_dir, new_name, new_len);
    else
        return -ENOTSUP;
}

int
vfs_follow_link(struct Inode *dir, struct Inode *symlink, struct Inode **res)
{
    if (inode_has_follow_link(symlink))
        return symlink->ops->follow_link(dir, symlink, res);
    else
        return -ENOTSUP;
}

int
vfs_readlink(struct Inode *symlink, char *buf, size_t buf_len)
{
    if (inode_has_readlink(symlink))
        return symlink->ops->readlink(symlink, buf, buf_len);
    else
        return -ENOTSUP;
}

int
vfs_symlink(struct Inode *dir, const char *name, size_t len, const char *symlink_target)
{
    if (!S_ISDIR(dir->mode))
        return -ENOTDIR;

    int ret = check_permissions(dir, W_OK | X_OK);

    if (ret)
        return ret;

    if (inode_has_symlink(dir))
        return dir->ops->symlink(dir, name, len, symlink_target);
    else
        return -ENOTSUP;
}

int
vfs_chowm(struct Inode *ino, Uid uid, Gid gid)
{
    struct InodeAttds attrs;

    memset(&attrs, 0, sizeof(attrs));
    Flags flags = 0;

    if (uid != (Uid)(-1)) {
        attrs.uid = uid;
        flag_set(&flags, INO_ATTR_UID);
    }

    if (gid != (Gid)(-1)) {
        attrs.gid = gid;
        flag_set(&flags, INO_ATTR_GID);
    }

    if (!S_ISDIR(ino->mode)) {
        flag_set(&flags, INO_ATTR_RM_SUID);
        flag_set(&flags, INO_ATTR_RM_SGID);
    }

    return vfs_apply_attributes(ino, flags, &attr);
}

int
vfs_chmod(struct Inode *ino, Mode mode)
{
    struct InodeAttrs attrs;

    memset(&attrs, 0, sizeof(attrs));
    attrs.mode = mode;

    return vfs_apply_attributes(ino, F(INO_ATTR_MODE), &attrs);
}
