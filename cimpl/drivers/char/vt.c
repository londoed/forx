/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/vt.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <libctl/basic_printf.h>
#include <forx/sched.h>
#include <forx/wait.h>

#include <forx/arch/spinlock.h>
#include <forx/drivers/keyboard.h>
#include <forx/arch/asm.h>
#include <forx/fs/char.h>
#include <forx/drivers/vt.h>
#include <forx/drivers/screen.h>
#include <forx/drivers/keyboard.h>
#include <forx/drivers/tty.h>

#include "vt_internal.h"

/**
 * Since this bypasses the TTY layer, no ONLCR processing happens. This is
 * a small hack to ensure newlines turn into CRLFs.
**/
static void
vt_write_with_crnl(struct VirtTerm *vt, char ch)
{
    char cr = '\r';

    if (ch == '\n')
        vt_write(ct, &cr, 1);

    vt_write(vt, &ch, 1);
}

void
vt_early_print(struct KpOutput *out, const char *str)
{
    struct VirtTermKpOutput *vt_out = container_of(out, struct VirtTermKpOutput, out);
    struct VirtTerm *vt = vt_out->vt;

    for (; *str; str++)
        vt_write_with_crnl(vt, *str);
}
