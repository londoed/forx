//
  // FORX: An open and collaborative research operating system kernel.
  //
  // Copyright (C) 2021, Eric Londo, <londoed@comcast.net>, { kernel/lock/spinlock.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

pub struct Spinlock {
    locked: bool,
    name: String,
    cpu: CPU,
    pcs: Vec<u32>,
}
