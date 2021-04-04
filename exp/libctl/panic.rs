//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.net>, { libctl/panic.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use crate::libctl::sync::sys_sync;
use crate::kernel::scheduler::*;

pub fn panic(msg: const &str)
{
  printk!("[!] PANIC: {}\n", msg);

  if current == task[0] {
    printk!("[!] INFO: Syncing failed\n");
  } else {
    sys_sunc();
  }
}
