/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { init/init.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/libctl/stddef.h>
#include <forx/libctl/string.h>
#include <forx/sched.h>
#include <forx/task.h>
#include <forx/mm/kmalloc.h>
#include <forx/arch/init.h>
#include <forx/arch/asm.h>
#include <forx/fs/fs.h>
#include <forx/fs/namei.h>
#include <forx/fs/vfs.h>
#include <forx/block/bdev.h>
#include <forx/drivers/console.h>
#include <forx/kparam.h>
#include <forx/ktest.h>
#include <forx/initcall.h>

// Initial user task //
struct Task *task_init;
int kern_booting = 1;
static int root_major = CONFIG_ROOT_MAJOR;
static int root_minor = CONFIG_ROOT_MINOR;
static const char *root_fstype = CONFIG_ROOT_FSTYPE;
static const char *init_prog = "/bin/init";

KPARAM("major", &root_major, KPARAM_INT);
KPARAM("minor", &root_minor, KPARAM_INT);
KPARAM("fstype", &root_fstype, KPARAM_STRING);
KPARAM("init", &init_prog, KPARAM_STRING);
KPARAM("reboot_on_panic", &reboot_on_panic, KPARAM_BOOL);

static int
start_user_init(void *unused)
{
    void (**ic)(void);

    for (ic = initcalls; *ic; ic++)
        (*ic)();

    kprintf(KERN_NORM, "Mounting root device %d:%d, fs type: %s\n", root_major,
        root_minor, root_fstype);

    // Mount the current IDE drive as an ext2 file system //
    int ret = mount_root(DEV_MAKE(root_major, root_minor), root_fstype);

    if (ret)
        panic("UNABLE TO MOUNT ROOT FILESYSTEM, (%d, %d): %s\n", root_major,
            root_minor, root_fstype);

#ifdef CONFIG_KERNEL_TESTS
    ktest_init();
#endif

    kprintf(KERN_NORM, "Kernel is done booting\n");
    kprintf(KERN_NORM, "Starting `%s`...\n", init_prog);

    task_init = task_user_new_exec(init_prog);
    task_init->pid = 1;
    sched_task_add(task_init);

    return 0;
}

/**
 * We want to get to a process context as soon as possible, as not being in
 * one complicates what we can and can't do (For example, cpu_get_local()->current
 * is NULL until we enter a process context, so we can't sleep and we can't
 * register for wait queues, take mutex's, etc...). This is similar to an
 * interrupt context.
**/
void
kmain(void)
{
    cpu_setup_idle();
    struct Task *t = kmalloc(sizeof(*t), PAL_KERNEL | PAL_ATOMIC);

    if (!t)
        panic("Unable to allocate kernel init task...\n");

    task_init();
    task_kernel_init(t, "Kernel init", start_user_init, NULL);
    sched_task_add();

    kprintf(KERN_NORMAL, "Starting scheduler\n");
    cpu_start_sched();
    panic("ERROR: cpu_start_sched() returned\n");

    for (;;) {
        hlt();
    }
}
