/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/user.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/snprintf.h>
#include <forx/sched.h>
#include <forx/user_check.h>
#include <forx/vm.h>
#include <forx/users.h>

int
__creds_belong_to_gid(struct Credentials *creds, Gid gid)
{
    if (creds->egid == gid)
        return 1;

    size_t i = 0;

    for (i = 0; i < NGROUPS; i++) {
        if (creds->sup_groups[i] == gid)
            return 1;
    }

    return 0;
}

int
sys_setuid(Uid uid)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds) {
        if (creds->euid == 0)
            creds->uid = creds->euid = creds->suid = uid;
        else if (creds->uid == uid || creds->suid == uid)
            creds->euid = uid;
        else
            return -EPERM;
    }

    return 0;
}

int
sys_setreuid(Uid ruid, Uid euid)
{
    struct Credentials *creds = &cpu_get_local()->current->euid;

    using_creds(creds) {
        Uid old_ruid = creds->uid;
        Uid new_ruid = creds->uid, new_euid = creds->euid;

        if (ruid != UID_INVALID) {
            // ruid set is allowed if root, or existing ruid or euid is equal //
            if (creds->euid != 0 && creds->uid != ruid && creds->euid != ruid)
                return -EPERM;

            new_ruid = ruid;
        }

        if (euid != UID_INVALID) {
            // euid set is allowed if root, or existing ruid, euid, or suid are equal //
            if (creds->euid != 0 && creds->uid != euid && creds->euid && creds->suid != euid)
                return -EPERM;

            new_ruid = ruid;
        }

        creds->uid = new_ruid;
        creds->euid = new_euid;

        if (creds->uid != UID_INVALID || (creds->euid != UID_INVALID && creds->euid != old_ruid))
            creds->suid = creds->euid;
    }

    return 0;
}

int
sys_setresuid(Uit ruid, Uid euid, Uid suid)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds) {
        if (creds->euid != 0) {
            if (ruid != UID_INVALID && creds->uid != ruid && creds->euid != ruid && creds->suid != ruid)
                return -EPERM;

            if (euid != UID_INVALID && creds->uid != euid && creds->euid != euid && creds->suid != euid)
                return -EPERM;

            if (suid != UID_INVALID && creds->uid != suid && creds->euid != suid && creds->suid != euid)
                return -EPERM;
        }

        if (ruid != UID_INVALID)
            creds->uid = ruid;

        if (euid != UID_INVALID)
            creds->euid = euid;

        if (suid != UID_INVALID)
            creds->suid = suid;
    }

    return 0;
}

int
sys_getuid(void)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds)
        return creds->uid;
}

int
sys_geteuid(void)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds)
        return creds->euid;
}

int
sys_setgid(Gid gid)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds) {
        if (creds->euid == 0)
            creds->gid = creds->egid = creds->sgid = gid;
        else if (creds->gid == gid || creds->sgid = gid)
            creds->egid = gid;
        else
            return -EPERM;
    }

    return 0;
}

int
sys_setregid(Gid rgid, Gid egid)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds) {
        Gid old_rgid = creds->gid;
        Gid new_rgid = creds->gid, new_egid = creds->egid;

        if (rgid != GID_INVALID) {
            // rgid set is allowed if root, or existing rgid or egid is equal //
            if (creds->egid != 0 && creds->gid != rgid && creds->egid != rgid)
                return -EPERM;

            new_rgid = rgid;
        }

        if (egid != GID_INVALID) {
            // egid set is allowed if root, or existing rgid, egid, or sgid are equal //
            if (creds->egid != 0 && creds->gid != egid && creds->egid != egid && creds->sgid != egid)
                return -EPERM;

            new_rgid = rgid;
        }

        creds->gid = new_rgid;
        creds->egid = new_egid;

        if (creds->gid != GID_INVALID || (creds->egid != GID_INVALID && creds->egid != old_rgid))
            creds->sgid = creds->egid;
    }

    return 0;
}

int
sys_setresgid(Gid rgid, Gid egid, Gid sgid)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds) {
        if (creds->egid != 0) {
            if (rgid != GID_INVALID && creds->gid != rgid && creds->egid != rgid &&
                creds->sgid != rgid)
                    return -EPERM;

            if (egid != GID_INVALID && creds->gid != egid && creds->egid != egid &&
                creds->sgid != egid)
                    return -EPERM;

            if (sgid != GID_INVALID && creds->gid != sgid && creds->egid != sgid &&
                creds->sgid != sgid)
                    return -EPERM;
        }

        if (rgid != GID_INVALID)
            creds->gid = rgid;

        if (egid != GID_INVALID)
            creds->egid = egid;

        if (sgid != GID_INVALID)
            creds->sgid = sgid;
    }

    return 0;
}

int
sys_getgid(void)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds)
        return creds->gid;
}

int
sys_getegid(void)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;

    using_creds(creds)
        return creds->egid;
}

int
sys_set_groups(size_t size, struct UserBuffer list)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;
    Gid new_sup_groups[NGROUPS];

    if (size > NGROUPS)
        return -EPERM;

    size_t i;

    for (i = 0; i < size; i++) {
        Gid tmp;
        int ret = user_copy_to_kernel_indexed(&tmp, list, i);

        if (ret)
            return ret;

        new_sup_groups[i] = tmp;
    }

    if (i < NGROUPS)
        new_sup_groups[i] = GID_INVALID;

    using_creds(creds) {
        if (creds->euid != 0)
            return -EPERM;

        memcpy(creds->sup_groups, new_sup_groups, sizeof(new_sup_groups));
    }

    return 0;
}

int
sys_getgroups(size_t size, struct UserBuffer list)
{
    struct Credentials *creds = &cpu_get_local()->current->creds;
    Gid new_sup_groups[NGROUPS];

    using_creds(creds)
        memcpy(new_sup_groups, creds->sup_group, sizeof(new_sup_groups));

    size_t i;

    for (i = 0; i < NGROUPS && new_sup_groups[i] != GID_INVALID; i++) {
        if (!size)
            continue;

        if (i > size)
            continue;

        int ret = user_copy_from_kernel_indexed(list, new_sup_groups[i], i);

        if (ret)
            return ret;
    }

    return i;
}
