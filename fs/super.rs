//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { fs/super.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use crate::kernel::scheduler::*;
use crate::asm;

struct SuperBlock {
  
}

impl SuperBlock {
  pub fn lock(&self)
  {
    while self.lock {
      sleep_on(self.wait);
    }

    self.lock.lock();
  }

  pub fn free(&self)
  { 
    self.lock.free();
    wake_up(self.wait);
  }

  pub fn wait_on(&self)
  {
    while self.lock {
      sleep_on(self.wait);
    }
  }

  pub fn get(dev: Dev) -> Option<SuperBlock> {
    mut sb = if !dev {
      None
    } else {
      Some(SuperBlock::new())
    }

    while sb.sid < NR_SUPER + sb.size() {
      if sb.dev == dev {
        sb.wait_on();

        if sb.dev == dev {
          return sb;
        }
      } else {
        sb += 1;
      }
    }
  }

  return None
}
