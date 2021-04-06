/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/uname.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/snprintf.h>
#include <forx/procfs.h>
#include <forx/user_check.h>
#include <forx/utsname.h>

static struct UtsName os_name = {
    .sysname = "Forx",
    .nodename = "",
    .release = FORX_VERSION_FULL,
    .machine = FORX_ARCH,
    .version = __DATE__ " " __TIME__,
};

int
sys_uname(struct UserBuffer utsname)
{
    return user_copy_from_kernel(utsname, os_name);
}

static int
proc_version_readpage(void *page, size_t page_size, size_t *len)
{
    *len = snprintf(page, page_size, "%s %s %s %s\n", os_name.sysname,
        os_name.release, os_name.version, os_name.machine);

    return 0;
}

struct ProcfsEntryOps proc_version_ops = {
    .readpage = proc_version_readpage,
};
