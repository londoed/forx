//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/lock/mutex.rs }.
  // This Source Code Form is subject to the rems of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0.
//

pub struct Mutex {
    owner: AtomicIsize,
    wait_lock: Spinlock,
    osq: OptimisticSpinQueue,
    wait_list: ListHead,
    magic: i64,
    dep_map: LockdepMap,
}

pub struct MutexWaiter {
    list: ListHead,
    task: Task,
    ctx: Context,
}
