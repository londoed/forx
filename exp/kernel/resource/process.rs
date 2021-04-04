//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/resource/process.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

pub struct Process {
    size: u32,
    page_dir: PageTable,
    kstack: char,
    state: ProcState,
    pid: i32,
    parent: Process,
    trap_frame: TrapFrame,
    context: Context,
    sleeping_chan: bool,
    killed: bool,
    open_files: Vec<File>,
    cwd: Inode,
    name: String,
}

pub type ProcTable = Vec<Process>;

pub enum ProcState {
    PROC_RUNNING,
    PROC_READY,
    PROC_INTERRUPTIBLE,
    PROC_UNINTERRUPTIBLE,
    PROC_STOPPED,
    PROC_TRACED,
}

impl Process {
    pub fn set_state(&self, state: ProcState)
    {
        self.state = state;
    }
}


