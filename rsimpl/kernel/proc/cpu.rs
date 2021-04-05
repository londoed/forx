//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) Eric Londo <londoed@protonmail.com>, { proc/cpu.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

pub struct Cpu {
    apic_id: u16,
    cnxt: Context,
    task_state: TaskState,
    global_desc_table: SegmentDesc,
    started: bool,
    ncli: i32,
    interrupt_enable: bool,
    process: Process,
}
