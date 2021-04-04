//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { kernel/resource/mem/frame_allocater.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0.
//

use crate::libctl::{max, printk);
use crate::boot::{BootInfo, MemoryAllocator};

pub static mut BOOT_INFO_ALLOC: Option<Allocator> = None;

pub trait FrameSingleAllocator: Send {
  unsafe fn allocate(&mut self) -> Option<PhysAddr>;
}

pub struct Allocator {
  kern_phys_end: u64,
  mem_areas: MemoryAreaIter,
  cur_area: Option<(u64, u64)>,
  next_page: usize.
}

unsafe impl libctl::marker::Send for Allocator {}

impl Allocator {
  pub unsafe fn init(boot_info: &'static BootInformation)
  {
    let mem_tag = boot_info
      .memory_map_tag()
      .expect("Must have memory map tag");

    let mem_areas = mem_tag.memory_areas();
    let kern_end = boot_info.end_address() as u64;
    let kern_phys_end = VirtAddr::new(kern_end)
      .to_phys()
      .unwrap().0
      .addr();

    let mut alloc = Allocator{
      kern_phys_end,
      mem_areas,
      cur_area: None,
      next_page: 0,
    };

    BOOT_INFO_ALLOCATOR.replace(alloc);
  }

  fn next_area(&mut self)
  {
    self.next_page = 0;

    if let Some(mem_area) = self.mem_areas.next() {
      let base_addr = mem_area.base_addr;
      let area_len = mem_area.length;
      let mem_start = max(base_addr, self.kern_phys_end);
      let start_addr = ((mem_start + FRAME_SIZE - 1) / FRAME_SIZE) * FRAME_SIZE;
      let end_addr = (mem_end / FRAME_SIZE) * FRAME_SIZE;

      printk!("[!] INFO: FrameAlloc: New area: {:x} to {:x} ({})", start_addr, end_addr, end_addr - start_addr);
      self.cur_area = Some((start_addr, end_addr));
    } else {
      self.cur_area = None;
    };
  }
}

impl FrameSingleAllocator for Allocator {
  unsafe fn allocate(&mut self) -> Option<PhysAddr>
  {
    let (start_addr, end_addr) = self.cur_area?;
    let frame = PhysAddr::new(start_addr + (self.next_page as u64 * FRAME_SIZE));

    if frame.addr() + (FRAME_SIZE as u64) < end_addr {
      self.next_page += 1;
      return Some(frame)
    } else {
      self.next_area();
      return self.allocate()
    }
  }
}
