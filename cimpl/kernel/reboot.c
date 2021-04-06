/**
 * FORX: An open and collaborative operating system kernel for the research community.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/reboot.c }.
 * Copyright (C) 2019, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <forx/errors.h>
#include <forx/reboot.h>
#include <forx/arch/reset.h>

int
sys_reboot(int magica, int magicb, int cmd)
{
    if (magica != FORX_REBOOT_MAGICA || magicb != FORX_REBOOT_MAGICB)
        return -EINVAL;

    switch (cmd) {
    case FORX_REBOOT_RESTART:
        kprintf(KERN_WARN, "System is rebooting...");
        system_reboot();
        break;

    default:
        return -EINVAL;
    }
}
