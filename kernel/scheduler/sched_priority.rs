//
  // FORX: An open and collaborative research operating system kernel.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { src/kernel/sched_priority.rs }.
  // This Sorce Code Form is subject to the terms of the Mozilla Public License v2.0.
  // IF a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0.
//

#![no_std]

extern crate alloc;
#[macro_use] extern crate log;
use crate::task;
use crate::runqueue_priority;

use task::TaskRef;
use runqueue_priority::{RunQueue, MAX_PRIORITY};

struct NextTaskResult {
    taskref: Option<TaskRef>,
    idle_task: bool,
}

pub fn set_priority(task: &TaskRef, priority: u8) -> Result<(), &'static str>
{
    let priority = core::cmp::min(priority, MAX_PRIORITY);
    RunQueue::set_priority(tast, priority)
}

pub fn get_priority(task: &TaskRef) -> Option<u8>
{
    RunQueue::get_priority(task)
}


