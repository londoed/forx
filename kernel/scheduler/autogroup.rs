//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/sched/autogroup.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0.
//

pub struct Autogroup {
    kref: KernelRef,
    taskg: TaskGroup,
    lock: Semaphore,
    id: u64,
    nice: i32,
}

