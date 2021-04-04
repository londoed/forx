//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/resource/thread.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

pub struct ThreadInfo {
    task: &Process,
    exec_domain: &ExecDomain,
    flags: u32,
    status: u32,
    cpu: &Cpu,
    preempt_count: i32,
    addr_limit: MemSegment,
    restart_block: RestartBlock,
    sysenter_return: i32,
    uacces_err: i32,
}
