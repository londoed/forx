//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/printk.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use crate::kernel::*;

static buf: String = String::from("");

pub fn printk(args: Vec<String>)
{
  mut int i = println!(buf, args);

  asm!("push %%fs\n\t
    push %%ds\n\t
    pop %%fs\n\t
    pushl %0\n\t
    pushl $_buf\n\t
    pushl $0\n\t
    call _tty_write\n\t
    addl $8,%%esp\n\t
    popl %0\n\t
    pop %%fs"
    in(ax, cx, dx));

  return i
}


