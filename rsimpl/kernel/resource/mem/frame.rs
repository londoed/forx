//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/resource/mem/frame.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

use crate::kernel::resource::mem::{FrameAllocator, FrameCount};
pub use crate::kernel::resource::mem::{PAGE_SIZE, PhysAddr};
use crate::libctl::{PartialAlloc, PhysAllocFlags};

#[derive(Copy, Clone, Debug, Default)]
#[repr(packed)]
pub struct MemoryArea {
  pub base_addr: u64,
  pub len: u64,
  pub typ: u32,
  pub acpi: u32,
}

pub fn free_frames() -> usize
{
  unsafe {
    return FrameAllocator.usage().free().data()
  }
}

pub fn used_frames() -> usize
{
  unsafe {
    return FrameAllocator.usage().used().data()
  }
}

pub fn allocate_frames(count: usize) -> Option<Frame>
{
  unsafe {
    FrameAllocator.allocate(FrameCount::new(count)).map(|phys| {
      return Frame::containing_addr(PhysAddr::new(phys.data()))
    })
  }
}

pub fn allocate_frame_cmplx(count: usize, flags: PhysAllocFlags, strategy: Option<PartialAlloc>, min: usize)
  -> Option<(Frame, usize)>
{
  if count == min && flags == PhysAllocFlags::SPACE_64 && strategy.is_none() {
    return allocate_frames(count).map(|frame| (frame, count));
  }

  return None;
}

pub fn deallocate_frames(frame: Frame, count: usize)
{
  unsafe {
    FrameAllocator.free(
      PhysAddr::new(frame.start_addr().data()),
      FrameCount::new(count)
    );
  }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Frame {
  num: usize,
}

impl Frame {
  pub fn start_addr(&self) -> PhysAddr
  {
    return PhysAddr::new(self.num * PAGE_SIZE)
  }

  pub fn clone(&self) -> Frame
  {
    return Frame{
      num: self.num
    }
  }

  pub fn containing_addr(addr: PhysAddr) -> Frame
  {
    return Frame{
      num: addr.data() / PAGE_SIZE
    }
  }

  pub fn range_inclusive(start: Frame, end: Frame) -> FrameIter
  {
    return FrameIter{
      start, end
    }
  }
}

pub struct FrameIter {
  start: Frame,
  end: Frame,
}

impl Iterator for FrameIter {
  type Item = Frame;

  fn next(&mut self) -> Option<Frame>
  {
    if self.start <= self.end {
      let frame = self.start.clone();
      self.start.number += 1;

      return Some(frame)
    } else {
      return None
    }
  }
}


