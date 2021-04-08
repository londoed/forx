/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/dev.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/list.h>
#include <forx/libctl/hlist.h>
#include <forx/libctl/string.h>
#include <forx/libctl/snprintf.h>
#include <forx/arch/spinlock.h>
#include <forx/mutex.h>
#include <forx/atomic.h>
#include <forx/mm/kmalloc.h>
#include <forx/mm/user_check.h>
#include <forx/signal.h>
#include <forx/arch/task.h>

#include <forx/block/bcache.h>
#include <forx/fs/super.h>
#include <forx/fs/file.h>
#include <forx/fs/stat.h>
#include <forx/fs/inode.h>
#include <forx/fs/namei.h>
#include <forx/fs/access.h>
#include <forx/fs/sys.h>
#include <forx/fs/vfs.h>
#include <forx/fs/binfmt.h>

static void
set_credentials(struct Inode *ino, struct Task *current)
{
    Uid new_euid;
    Gid new_egid;

    using_creds(&current->creds) {
        new_euid = current->creds.euid;
        new_egid = current->creds.egid;

        if (ino->mode & S_ISUID)
            new_euid = ino->uid;

        if (ino->mode & S_ISGID)
            new_egid = ino->gid;

        current->creds.euid = current->creds.suid = new_euid;
        current->creds.egid = current->creds.sgid = new_egid;
    }
}

static void
generate_task_name(char *name, size_t len, const char *file, struct UserBuffer argv_buf)
{
    size_t name_len = 0;
    struct UserBuffer arg;
    char *str = NULL;

    // This is the creation of the replacement name for the current task //
    name_len = snprintf(name, len, "%s", file);
    int err = user_copy_to_kernel(&str, argv_buf);

    if (err)
        return;

    if (!str)
        return;

    // We skip argv[0] as it should be the same as the file system above //
    for (arg = user_buffer_index(argv_buf, sizeof(char *));
        !user_buffer_is_null(arg);
        arg = user_buffer_index(arg, sizeof(char *))) {

        err = user_copy_to_kernel(&str, arg);

        if (err)
            break;

        if (!str)
            break;

        struct UserBuffer str_wrapped = user_buffer_make(str, arg.is_user);
        char arg_str[64];
        err = user_strncpy_to_kernel(arg_str, str_wrapped, sizeof(arg_str));

        if (err)
            break;

        name_len += snprintf(name + name_len, len - name_len, " %s", arg_str);
    }
}

static int execve(struct Inode *ino, const char *file, struct UserBuffer argv_buf
    struct UserBuffer envp_buf, struct IrqFrame *frame)
{
    struct File *filp;
    struct ExecParams params;
    int ret;
    char *sp, *user_stack_end;
    struct Task *current = cpu_get_local()->current;
    char new_name[128];
    const char *def_argv[] = { file, NULL };
    const char *def_envp[] = { NULL };

    exec_params_init(&params);
    strncpy(params.filename, file, sizeof(params.filename));
    params.filename[sizeof(params.filename) - 1] = '\0';

    if (user_buffer_is_null(argv_buf))
        argv_buf = make_kernel_buffer(def_argv);

    if (user_buffer_is_null(envp_buf))
        envp_buf = make_kernel_buffer(def_envp);

    generate_task_name(new_name, sizeof(new_name), file, argv_buf);
    ret = params_fill_from_user(&params, argv_buf, envp_buf);

    if (ret) {
        params_clear(&params);

        return ret;
    }

    ret = vfs_open(ino, F(FILE_RD), &filp);

    if (ret)
        return ret;

    params.exec = filp;
    ret = binary_load(&params, frame);
    kprintf(KERN_TRACE, "binary_load: %d\n", ret);

    if (ret)
        goto close_fd;

    /**
     * At this point, the pointers we were passed are now completely invalid
     * (besides frame and inode, which reside in the kernel).
    **/
    user_stack_end = cpu_get_local()->current->addr_spc->stack->addr.end;
    sp = params_copy_to_userspace(&params, user_stack_end);
    irq_frame_set_stack(frame, sp);
    int i;

    for (i = 0; i < NSIG; i++) {
        if (current->sig_actions[i].sa_handler != SIG_IGN)
            current->sig_actions[i].sa_handler = SIG_DFL;

        current->sig_actions[i].sa_mask = 0;
        current->sig_actions[i].sa_flags = 0;
    }

    for (i = 0; i < NOFILE; i++) {
        if (FD_ISSET(i, &current->close_on_exec)) {
            kprintf(KERN_TRACE, "Close on exec: %d\n", i);
            sys_close(i);
        }
    }

    strcpy(current->name, new_name);
    set_credentials(ino, current);

close_fd:
    params_clear(&params);
    vfs_close(filp);

    return ret;
}

int
sys_execve(struct UserBuffer file_buf, struct UserBuffer argv_buf, struct UserBuffer envp_buf,
    struct IrqFrame *frame)
{
    struct Inode *exec;
    struct Task *current = cpu_get_local()->current;
    int ret;

    __cleanup_user_string char *tmp_file = NULL;
    ret = user_alloc_string(file_buf, &tmp_file);

    if (ret)
        return ret;

    kprintf(KERN_TRACE, "Executing: %s\n", tmp_file);
    ret = namex(tmp_file, current->cwd, &exec);

    if (ret) {
        irq_frame_set_syscall_ret(frame, ret);

        return ret;
    }

    ret = check_permissions(exec, X_OK);

    if (ret) {
        inode_put(exec);
        irq_frame_set_syscall_ret(frame, ret);

        return ret;
    }

    ret = execve(exec, tmp_file, argv_buf, envp_buf, frame);
    inode_put(exec);
    kprintf(KERN_TRACE, "execve ret: %d\n", ret);

    if (ret)
        irq_frame_set_syscall_ret(frame, ret);

    return ret;
}
