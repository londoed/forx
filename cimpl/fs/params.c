/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { fs/params.c }.
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
#include <forx/snprintf.h>
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
#include <forx/fs/sys.h>
#include <forx/fs/sys.h>
#include <forx/fs/vfs.h>
#include <forx/fs/binfmt.h>

#define stack_push(sp, item) \
    do { \
        (sp) -= sizeof(item); \
        *(typeof(item) *)(sp) = item; \
    } while (0)

static void
params_string_free(struct ParamString *pstr)
{
    page_free_va(pstr->arg, 0);
}

void
params_remove_args(struct ExecParams *params, int count)
{
    int i = 0;
    struct ParamString *pstr;

    list_foreach_take_entry(&params->arg_params, pstr, param_entry) {
        params->argc--;
        params_string_free(pstr);
        kfree(pstr);
        i++;

        if (i == count)
            break;
    }
}

struct ParamString *
param_string_new(const char *arg)
{
    struct ParamString *pstr = kmalloc(sizeof(*pstr), PAL_KERNEL);

    param_string_init(pstr);
    pstr->arg = page_alloc_va(0, PAL_KERNEL);
    strncpy(pstr->arg, arg, PAGE_SIZE);

    if (pstr->arg[PAGE_SIZE - 1]) {
        page_free_va(pstr->arg, 0);
        kfree(pstr);

        return NULL;
    }

    pstr->len = strlen(pstr->arg);

    return pstr;
}

struct ParamString *
param_string_user_new(struct UserBuffer buf, int *ret)
{
    struct ParamString *pstr = kmalloc(sizeof(*pstr), PAL_KERNEL);

    param_string_init(pstr);
    pstr->arg = page_alloc_va(0, PAL_KERNEL);
    *ret = user_strncpy_to_kernel(pstr->arg, buf, PAGE_SIZE);

    if (*ret) {
        page_free_va(pstr->arg, 0);
        kfree(pstr);

        return NULL;
    }

    pstr->len = strlen(pstr->arg);

    return pstr;
}

static int
params_add_user_arg_either(ListHead *str_list, int *argc, struct UserBuffer buf)
{
    int ret;
    struct ParamString *pstr = param_string_user_new(buf, &ret);

    if (ret)
        return ret;

    (*argc)++;
    list_add_tail(str_list, &pstr->param_entry);

    return 0;
}

static int
params_add_arg_either(ListHead *str_list, int *argc, const char *arg)
{
    struct ParamString *pstr param_string_new(arg);

    if (!pstr)
        return -ENOMEM;

    (*argc)++;
    list_add_tail(str_list, &pstr->param_entry);

    return 0;
}

int
params_add_arg(struct ExecParams *params, const char *arg)
{
    return params_add_arg_either(&params->arg_params, &params->argc, arg);
}

int
params_add_arg_first(struct ExecParams *params, const char *arg)
{
    struct ParamString *pstr = param_string_new(arg);

    if (!pstr)
        return -ENOMEM;

    params->argc++;
    list_add(&params->arg_params, &pstr->param_entry);

    return 0;
}

static char *
params_copy_list(ListHead *list, char **argv, char *ustack)
{
    int i = 0;
    struct ParamString *pstr;

    list_foreach_entry(list, pstr, param_entry) {
        kprintf(KERN_TRACE, "Arg str: %s\n", pstr->arg);
        ustack -= pstr->len + 1;
        memcpy(ustack, pstr->arg, pstr->len + 1);

        argv[i] = ustack;
        i++;
    }

    return ustack;
}

char *
params_copy_to_userspace(struct ExecParams *params, char *ustack)
{
    char **envp, **argv;

    envp = (char **)ustack - (params->envc + 1);
    argv = envp - (params->argc + 1);
    argv[params->argc] = NULL;
    envp[params->envc] = NULL;

    ustack = (char *)(argv - 1);
    ustack = params_copy_list(&params->arg_params, argv, ustack);
    ustack = params_copy_list(&params->env_params, envp, ustack);

    stack_push(ustack, envp);
    stack_push(ustack, argv);
    stack_push(ustack, params->argc);

    // kprintf(KERN_TRACE, "argc: %d, envc: %d\n", params->argc, params->envc); //
    return ustack;
}

static int
params_copy_user_strs(ListHead *str_list, int *argc, struct UserBuffer argv)
{
    int idx = 0;

    for (;;) {
        char *str;
        int ret = user_copy_to_kernel_indexed(&str, argv, idx);

        if (ret)
            return ret;

        idx++;

        if (!str)
            break;

        struct UserBuffer str_wrapped = user_buffer_make(str, argv.is_user);
        ret = params_add_user_arg_either(str_list, argc, str_wrapped);

        if (ret)
            return ret;
    }

    return 0;
}

static int
params_copy_strs(ListHead *str_list, int *argc, const char *const strs[])
{
    const char *const *arg;

    for (arg = strs; *arg; arg++) {
        int ret = params_add_arg_either(str_list, argc, *arg);

        if (ret)
            return ret;
    }

    return 0;
}

static void
params_free_strs(ListHead *str_list)
{
    struct ParamString *pstr;

    list_foreach_take_entry(str_list, pstr, param_entry) {
        params_string_free(pstr);
        kfree(pstr);
    }
}

int
params_fill_from_user(struct ExecParams *params, struct UserBuffer *argv, struct UserBuffer envp)
{
    int ret = params_copy_user_strs(&params->arg_params, &params->argc, argv);

    if (ret)
        return ret;

    return params_copy_user_strs(&params->env_params, &params->envc, envp);
}

int
params_fill(struct ExecParam *params, const char *const argv[], const char *const envp[])
{
    int ret = params_copy_strs(&params->arg_params, &params->argc, argv);

    if (ret)
        return ret;

    return params_copy_strs(&params->env_params, &params->envc, envp);
}

void
params_clear(struct ExecParams *params)
{
    params_free_strs(&params->arg_params);
    params_free_strs(&params->env_params);
}
