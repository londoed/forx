//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/proc/task.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use crate::interrupt;
use crate::kernel::{execdata, syscall, wait, elf}
use crate::fs::{vfs, sysfs, pipe};
use crate::mem::{vmem, kmalloc, page_alloc};
use crate::proc::signal;
use crate::tty::term;

struct ElfLoadContext {
    virt_end: VirtAddr,
    interpreter: String,
    str_tab: VirtAddr,
}

struct Task {
    pid: Pid,
    uid: Uid,
    gid: Gid,
    euid: Euid,
    egid: Egid,
    name: &String,
    parent: &Task,
    state: StackFrame,
    next: &Task,
    prev: &Task,
    vmem_ctx: Context,
    entry: PageTableEntry,
    stack: Stack,
    stack_size: isize,
    kstack: i32,
    tty: Terminal,
    tstate: TaskState,
    exit_code: i32,
    env: &String,
    files: Vec<VfsFile>,
    sig_handlers: Vec<SigAction>,
    sig_mask: u32,
    wait_ctx: Context,
    cwd: String,
    bin_path: String,
    syscall_err: u32,
    interrupt_yield: bool,
    strace_obs: &Task,
    strace_fd: FileDescriptor,
    file: File,
}

enum TaskState {
    TERMINATED,
    ZOMBIE,
    REAPED,
    STOPPED,
    REPLACED,
    RUNNING,
    WAITING,
    SYSCALL,
    READY,
}

struct WaitContext {
    wait_for: u32,
    wait_res_pid: Pid,
    stat_loc: i32,
}

const KSTACK_SIZE: u32 = PAGE_SIZE * 4;
static const hi_pid: Pid = Pid{0};

impl Task {
    pub fn new(&self, parent: Task, pid: Pid, name: String, env: String) -> Task
    {
        return Task{
            pid: pid,
            parent: parent,
            name: name,parent.state
            env: parent.env,
            uid: parent.uid,
            gid: parent.gid,
            euid: parent.euid,
            egid: parent.egid,
            state: parent.state,
            next: parent.next,
            prev: parent,
            vmem_ctx: parent.vmem_ctx,
            entry: PageTableEntry::new(),
            stack: Stack::new(),
            stack_size: parent.stack_size,
            kstack: 0,
            tty: Terminal::new(),
            tstate: TaskState::Ready,
            exit_code: None,
            env: parent.env,

        }
    }
}
