//
  // FORK: An open and collaborative research operating system kernel.
  //
  // Copyright (C) Eric Londo <londoed@comcast.net>, { kernel/resource/pthread.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use libc::{self, pthread_t};

pub type Pthread = pthread_t;

#[inline]
pub fn pthread_self() -> Pthread
{
    unsafe {
        libc::pthread_self()
    }
}

pub struct PTable {
    lock: SpinLock,
    process: Vec<Process>,
}
