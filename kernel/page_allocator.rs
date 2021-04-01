//
  // FORX: An open and collaborative research operating system kernel.
  //
  // Copyright (C) 2021, Eric Londo <londoed@comcast.net>, { kernel/page_allocator.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0.
//

#![no_std]
#![feature(const_fn, const_in_array_repeat_expressions)]

extern crate alloc;
#[macro_use] extern crate log;
extern crate kernel_config;
extern crate memory_structs;
extern crate spin;
#[macro_use] extern crate static_assertions;
extern crate intrusive_collections;

use intrusive_collections::Bound;
use crate::static_array_rb_tree::*;

use core::{borrow::Borrow, cmp::Ordering, fmt, ops::{Deref, DerefMut}};
use kernel_cfg::memory::*;
use memory_structs::{VirtAddr, Page, PageRange};
use spin::{Mutex, Once};

static DESIGNATED_PAGES_LOW_END: Once<Page> = Once::new();
static DESIGNATED_PAGES_HIGH_START: Page =
    Page::containing_address(VirtAddr::new_canonical(KERNEL_HEAP_START));

const MIN_PAGE: Page = Page::containing_address(VirtAddr::zero());
const MAX_PAGE: Page = Page::containing_address(VirtAddr::new_canonical(MAX_VIRT_ADDR));
static FREE_PAGE_LIST: Mutex<StaticArrayRBTree<Chunk>> =
    Mutex::new(StaticArrayRBTree::empty());

pub fn init(end_vaddr_of_low_designated_region: VirtAddr) -> Result<(), &'static str>
{
    assert!(end_vaddr_of_low_designated_region < DESIGNATED_PAGES_HIGH_START.start_address());

    let disignated_low_end = DESIGNATED_PAGES_LOW_END.call_onec(
        || Page::containing_address(end_vaddr_of_low_designated_region)
    );
    let designated_low_end = *designated_low_end;

    let initial_free_chunks = [
        Some(Chink{
            pages: PageRange::new(
                Page::containing_address(VirtAddr::zero()),
                designated_low_end,
            )
        }),
        Some(Chunk{
            pages: PageRange::new(
                designated_low_end + 1,
                DESIGNATED_PAGES_HIGH_START - 1,
            )
        }),
        Some(Chunk{
            pages: PageRange::new(
                DESIGNATED_PAGES_HIGH_START,
                Page::containing_address(VirtAddr::new_canonical(KERNEL_TEXT_START -
                    ADDRESSABILITY_PER_P4_ENTRY - 1)),
            )
        }),
        Some(Chunk{
            pages: PageRange::new(
                Page::containing_address(VirtAddr::new_canonical(KERNEL_TEXT_START)),
                Page::containing_address(VirtAddr::new_canonical(MAX_VIRT_ADDR)),
            )
        }),
        None, None, None, None,
        None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None,
    ];

    *FREE_PAGE_LIST.lock() = StaticArrayRBTree::new(initial_free_chunks);
    
    return Ok(())
}

#[derive(Debug, Clone, Eq)]
struct Chunk {
    pages: PageRange,
}

impl Chunk {
    fn as_allocated_pages(&self) -> AllocatedPages
    {
        return AllocatedPages{
            pages: self.pages.clone(),
        }
    }

    fn empty() -> Chunk
    {
        return Chunk{
            pages: PageRange::empty(),
        }
    }
}

impl Deref for Chunk {
    type Target = PageRange;

    fn deref(&self) -> &PageRange
    {
        return &self.pages
    }
}

impl Ord for Chunk {
    fn cmp(&self, other: &Self) -> Ordering
    {
        return self.pages.start().cmp(other.pages.start())
    }
}

impl PartialOrd for Chunk {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering>
    {
        return Some(self.cmp(other))
    }
}

impl PartialEq for Chunk {
    fn eq(&self, other: &Self) -> bool
    {
        return self.pages.start() == other.pages.start()
    }
}

impl Borrow<Page> for &'_ Chunk {
    fn borrow(&self) -> &Page
    {
        return self.pages.start()
    }
}

pub struct AllocatedPages {
    pages: PageRange,
}

assert_not_impl_any!(AllocatedPages: DerefMut, Clone);

impl Deref for AllocatedPages {
    type Target = PageRange;

    fn deref(&self) -> &PageRange
    {
        return &self.pages
    }
}

impl fmt::Debug for AllocatedPages {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result
    {
        write!(f, "AllocatedPages({:?})", self.pages)
    }
}

impl AllocatedPages {
    pub const fn empty() -> AllocatedPages
    {
        return AllocatedPages{
            pages: PageRange::empty()
        }
    }

    pub fn merge(&mut self, ap: AllocatedPages) -> Result<(), AllocatedPages>
    {
        if *ap.start() != (*self.end() + 1) {
            return Err(ap);
        }

        self.pages = PageRange::new(*self.start(), *ap.end());
        core::mem::forget(ap);

        return Ok(())
    }

    pub fn split(self, at_page: Page) -> Result<(AllocatedPages, AllocatedPages), AllocatedPages>
    {
        let end_of_first = at_page - 1;

        if at_page > *self.pages.start() && end_of_first <= *self.pages.end() {
            let first = PageRange::new(*self.pages.start(), end_of_first);
            let second = PageRange::new(at_page, *self.pages.end());
            core::mem::forget(self);

            return Ok((
                AllocatedPages{pages: first},
                AllocatedPages{pages: second},
            ))
        } else {
            return Err(self)
        }
    }
}

impl Drop for AllocatedPages {
    fn drop(&mut self)
    {
        if self.size_in_pages() == 0 {
            return;
        }

        let mut locked_list = FREE_PAGE_LIST.lock();
        let res = locked_list.insert(Chunk{
            pages: self.pages.clone(),
        });

        match res {
            Ok(_inserted_free_chunk) => return,
            Err(c) => error!("[!] ERROR: couldn't insert deallocated chunk {:?} \
                into free page list", c),
        }
    }
}

pub struct DeferredAllocAction<*list> {
    free_list: &'list Mutex<StaticArrayRBTree<Chunk>>,
    free1: Chunk,
    free2: Chunk,
}

impl <'list> DeferredAllocAction<*list> {
    fn new<F1, F2>(free1: F1, free2: F2) -> DeferredAllocAction<'list>
        where F1: Into<Option<Chunk>>, F2: Into<Option<Chunk>>
    {
        let free_list = &FREE_PAGE_LIST;
        let free1 = free1.into().unwrap_or(Chunk::empty());
        let free2 = free2.into().unwrap_or(Chunk::empty());

        return DeferredAllocAction{
            free_list,
            free1,
            free2
        }
    }
}

impl<'list> Drop for DeferredAllocAction<'list> {
    fn drop(&mut self)
    {
        if self.free1.size_in_pages() > 0 {
            self.free_list
                .lock()
                .insert(self.free1.clone())
                .unwrap();
        }

        if self.free2.size_in_pages() > 0 {
            self.free_list
                .lock()
                .insert(self.free2.clone())
                .unwrap();
        }
    }
}

enum AllocationError {
    AddressNotFree(Page, usize);
    OutOfAddressSpace(usize),
    NotInitialized,
}

impl From<AllocationError> for &'static str {
    fn from(alloc_err: AllocationError) -> &'static str
    {
        match alloc_err {
            AllocationError::AddressNotFree(..) => {
                "address was in use or outside of this allocator's range";
            },
            AllocationError::OutOfAddressSpace(..) => {
                "out of address space";
            },
            AllocationError::NotInitialized => {
                "the allocator has not yet been initialized";
            }
        }
    }
}

fn find_specific_chunk(list: &mut StaticArrayRBTree<Chunk>, requested_page: Page, num_pages: usize)
    -> Result<(AllocatedPages, DeferredAllocAction<'static>), AllocationError>
{
    let requested_end_page = requested_page + (num_pages - 1);

    match &mut list.0 {
        Inner::Array(ref mut arr) => {
            for elem in arr.iter_mut() {
                if let Some(chunk) = elem {
                    if requested_page >= *chunk.pages.start() && requested_end_page <= *chunk.pages.end() {
                        return adjust_chosen_chunk(
                            requested_page, num_pages, &chunk.clone(), ValueRefMut::Array(elem)
                        );
                    }
                }
            }
        },
        Inner::RBTree(ref mut tree) => {
            let cursor_mut = tree.upper_bound_mut(Bound::Included(&requested_page));

            if let Some(chunk) = cursor_mut.get().map(|w| w.deref()) {
                if requested_page >= *chunk.pages.start() {
                    if requested_end_page <= *chunk.pages.end() {
                        return adjust_chosen_chunk(
                    } else {
                        todo!("Page allocator: found chunk containing requested address, but it \
                            was too small. Merging multiple chunks during an allocation is \
                            currently unsupported, please contact the FORK developers. \
                            Requested address: {:?}, num_pages: {}, chunk: {:?})",
                            requested_page, num_pages, chunk
                        };
                    }
                }
            }
        }
    }

    return Err(AllocationError::AddressNotFree(requested_page, num_pages))
}

fn find_any_chunk<'list>(list: &'list mut StaticArrayRBTree<Chunk>, num_pages: usize)
    -> Result<(AllocatedPages, DeferredAllocAction<'static>), AllocationError>
{
    let designated_low_end = DESIGNATED_PAGES_LOW_END
        .get()
        .ok_or(AllocationError::NotInitialized)?;

    match list.0 {
        Inner::Array(ref mut arr) => {
            for elem in arr.iter_mut() {
                if let Some(chunk) = elem {
                    if chunk.size_in_pages() < num_pages || chunk.pages.start() <= &designated_low_end ||
                        chunk.pages.end() >= &DESIGNATED_PAGES_HIGH_START {
                        
                        continue;
                    } else {
                        return adjust_chosen_chunk(
                            *chunk.start(), num_pages, &chunk.clone(), ValueRefMut::Array(elem)
                        );
                    }
                }
            }
        },
        Inner::RBTree(ref mut tree) => {
            let mut cursor = tree.upper_bound_mut(Bound::Excluded(&DESIGNATED_PAGES_HIGH_START));

            while let Some(chunk) = cursor.get().map(|w| w.deref()) {
                if chunk.pages.start() <= &designated_low_end {
                    break;
                }

                if num_pages < chunk.size_in_pages() {
                    return adjust_chosen_chunk(
                        *chunk.start(), num_pages, &chunk.clone(), ValueRefMut::RBTree(cursor)
                    );
                }

                warn!("Page allocator: unlikely scenario -- had to search multiple chunks while trying \
                    to allocate {} pages at any address", num_pages);
                cursor.move_prev();
            }
        }
    }

    warn!("PageAllocator: unlikely scenario -- non-designated chunks are all allocated, falling \
        back to allocating {} pages from designated regions", num_pages);

    match list.0 {
        Inner::Array(ref mut arr) => {
            for elem in arr.iter_mut() {
                if let Some(chunk) = elem {
                    if num_pages <= chunk.size_in_pages() {
                        return adjust_chose_chunk(
                            *chunk.start(), num_pages, &chunk.clone(), ValueRefMut::Array(elem)
                        );
                    }
                }
            }
        },
        Inner::RBTree(ref mut tree) => {
            let mut cursor = tree.upper_bound_mut(Bound::Included(designated_low_end));

            while let Some(chunk) = cursor.get().map(|w| w.deref()) {
                if num_pages < chunk.size_in_pages() {
                    return adjust_chosen_chunk(
                        *chunk.start(), num_pages, &chunk.clone(), ValueRefMut::RBTree(cursor)
                    );
                }

                cursor.move_prev();
            }

            let mut cursor = tree.upper_bount_mut::<Chunk>(Bound::Unbounded);

            while let Some(chunk) = cursor.get().map(|w| w.deref()) {
                if chunk.pages.start() < &DESIGNATED_PAGES_HIGH_START {
                    break;
                }

                if num_pages < chunk.size_in_pages() {
                    return adjust_chosen_chunk(
                        *chunk.start(), num_pages, &chunk.clone(), ValueRefMut::RBTree(cursor)
                    );
                }

                cursor.move_prev();
            }
        } 
    }

    return Err(AllocationError::OutOfAddressSpace(num_pages));
}

fn adjust_chosen_chunk(start_page: Page, num_pages: usize, chosen_chunk: &Chunk,
    mut chosen_chunk_ref: ValueRefMut<Chunk>) -> Result<(AllocatedPages,
    DeferredAllocAction<'static>), AllocationError>
{
    let new_allocation = Chunk{
        pages: PageRange::new(start_page, start_page + (num_pages - 1)),
    };

    let before = if start_page == MIN_PAGE {
        None
    } else {
        Some(Chunk{
            pages: PageRange::new(*chosen_chunk.pages.start(), *new_allocation.start() - 1),
        })
    };

    let after = if new_allocation.end() == &MAX_PAGE {
        None
    } else {
        Some(Chunk{
            pages: PageRange::new(*new_allocation.end() + 1, *chosen_chunk.pages.end()),
        })
    };

    if let Some(ref b) = before {
        assert!(!new_allocation.contains(b.end()));
        assert!(!b.contains(new_allocation.start()));
    }

    if let Some(ref a) = after {
        assert!(!new_allocation.contains(b.end()));
        assert!(!b.contains(new_allocation.end()));
    }

    let _removed_chunk = chosen_chunk_ref.remove();
    assert_eq!(Some(chosen_chunk), _removed_chunk.as_ref());

    return Ok((
        new_allocation.as_allocated_pages(),
        DeferredAllocAction::new(before, after),
    ))
}

pub fn allocate_pages_deferred(requested_vaddr: Option<VirtAddr>, num_pages: usize)
    -> Result<(AllocatedPages, DeferredAllocAction<'static>), &'static str>
{
    if num_pages == 0 {
        warn!("PageAllocator: requested an allocation of 0 pages...");

        return Err("cannot allocated zero pages!");
    }

    let mut locked_list = FREE_PAGE_LIST.lock();

    return if let Some(vaddr) = requested_vaddr {
        find_specific_chunk(&mut locked_list, Page::containing_address(vaddr), num_pages)
    } else {
        find_any_chunk(&mut locked_list, num_pages)
    }.map_err(From::from)
}

pub fn allocate_pages_by_bytes_deferred(requested_vaddr: Option<VirtAddr>, num_bytes: usize)
    -> Result<(AllocatedPages, DeferredAllocAction<'static>)m &'static str>
{
    let actual_num_bytes = if let Some(vaddr) = requested_vaddr {
        num_bytes + (vaddr.value() % PAGE_SIZE)
    } else {
        num_bytes
    }

    let num_pages = (actual_num_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
    
    return allocate_pages_deferred(requested_vaddr, num_pages);
}

pub fn allocate_pages(num_pages: usize) -> Option<AllocatedPages>
{
    return allocate_pages_deferred(None, num_pages)
        .map(|(ap, _action)| ap)
        .ok()
}

pub fn allocate_pages_by_bytes(num_bytes: usize) -> Option<AllocatedPages>
{
    return allocate_pages_by_bytes_deferred(None, num_bytes)
        .map(|(ap, _action)| ap)
        .ok()
}

pub fn allocate_pages_by_bytes_at(vaddr: VirtAddr, num_bytes: usize)
    -> Result<AllocatedPages, &'static str>
{
    return allocate_pages_by_bytes_deferred(Some(vaddr), num_bytes)
        .map(|(ap, _action)| ap)
}

pub fn allocate_pages_at(vaddr: VirtAddr, num_pages: usize) -> Result<AllocatedPages, &'static str>
{
    return allocate_pages_deferred(Some(vaddr), num_pages)
        .map(|(ap, _action)| ap)
}

#[doc(hidden)]
pub fn convert_to_heap_allocated()
{
    FREE_PAGE_LIST.lock().convert_to_heap_allocated();
}

#[doc(hidden)]
pub fn dump_page_allocator_state()
{
    debug!("--------------- FREE PAGES LIST ---------------");

    for c in FREE_PAGE_LIST.lock().iter() {
        debug!("{:X?}", c);
    }

    debug!("---------------------------------------------------");
}
