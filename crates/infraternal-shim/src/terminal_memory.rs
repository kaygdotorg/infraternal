//! Audited per-terminal allocation accounting and ownership for shared hosts [D270].
//!
//! Every native allocation is linked to its terminal, including screen pages.
//! Retiring a nontransactional resize releases allocations directly without
//! walking the potentially damaged native graph. Callbacks run synchronously
//! on the reactor thread; the boxed ABI and context never move while borrowed.
#![allow(unsafe_code)]
use nix::libc;
use std::{
    alloc::{Layout, alloc, dealloc},
    ffi::c_void,
    ptr::{self, NonNull},
};

#[repr(C)]
struct Vtable {
    alloc: unsafe extern "C" fn(*mut c_void, usize, u8, usize) -> *mut c_void,
    resize: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> bool,
    remap: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> *mut c_void,
    free: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize),
}
#[repr(C)]
struct Abi {
    context: *mut c_void,
    vtable: *const Vtable,
}
struct Block {
    previous: Option<NonNull<Block>>,
    next: Option<NonNull<Block>>,
    base: NonNull<u8>,
    layout: Layout,
    mapped: bool,
    encoded: bool,
}

pub(super) struct Memory {
    abi: Abi,
    // Native read-side operations may decompress history and allocate even
    // while Rust borrows the engine immutably. Only this single-threaded FFI
    // context has interior mutation; its counters never escape as references.
    state: std::cell::UnsafeCell<State>,
}
struct State {
    first: Option<NonNull<Block>>,
    used: usize,
    peak: usize,
    limit: usize,
    refused: bool,
    mapped_used: usize,
    encoded_used: usize,
    encoded_limit: usize,
    page_size: usize,
}
impl Memory {
    // Native allocator pointers borrow the ABI and context, so constructing
    // the final stable box here is required rather than moving a stack value.
    #[allow(clippy::unnecessary_box_returns)]
    #[cfg(any(test, not(feature = "compact-history")))]
    pub(super) fn new(limit: usize) -> Box<Self> {
        Self::with_history(limit, 0)
    }
    #[allow(clippy::unnecessary_box_returns)]
    pub(super) fn with_history(limit: usize, encoded_limit: usize) -> Box<Self> {
        let mut memory = Box::new(Self {
            abi: Abi {
                context: ptr::null_mut(),
                vtable: &raw const VTABLE,
            },
            state: std::cell::UnsafeCell::new(State {
                first: None,
                used: 0,
                peak: 0,
                limit,
                refused: false,
                mapped_used: 0,
                encoded_used: 0,
                encoded_limit,
                page_size: page_size(),
            }),
        });
        memory.abi.context = memory.state.get().cast();
        memory
    }
    pub(super) fn stats(&self) -> (usize, usize, bool) {
        // SAFETY: synchronous reactor calls never overlap native callbacks;
        // return copied scalars, not a borrow across a subsequent native call.
        let state = unsafe { &*self.state.get() };
        (state.used, state.peak, state.refused)
    }
    pub(super) fn allocation_classes(&self) -> (usize, usize, usize) {
        // SAFETY: the synchronous test inspects copied ownership metadata only,
        // between native calls; the list is never borrowed across a callback.
        let state = unsafe { &*self.state.get() };
        let mut block = state.first;
        let mut count = 0;
        while let Some(current) = block {
            block = unsafe { current.as_ref().next };
            count += 1;
        }
        (
            state.used - state.mapped_used - state.encoded_used,
            state.mapped_used,
            count,
        )
    }
    /// Inspect only this terminal's private mappings; mincore never faults in
    /// their contents. Ordinary heap blocks share allocator pages and are
    /// reported by requested bytes instead of falsely attributing whole pages.
    pub(super) fn resident_pages(&self) -> std::io::Result<usize> {
        // SAFETY: the reactor invokes this between native calls; every node
        // and mapping remains owned and no callback overlaps this traversal.
        let state = unsafe { &*self.state.get() };
        let mut block = state.first;
        let mut resident = 0;
        let mut residency = [0_u8; 256];
        while let Some(current) = block {
            let current = unsafe { current.as_ref() };
            block = current.next;
            if !current.mapped {
                continue;
            }
            let pages = current.layout.size() / state.page_size;
            let mut first = 0;
            while first < pages {
                let count = (pages - first).min(residency.len());
                // SAFETY: the aligned range lies entirely inside this owned
                // mapping; the vector has one writable byte per queried page.
                let result = unsafe {
                    libc::mincore(
                        current.base.as_ptr().add(first * state.page_size).cast(),
                        count * state.page_size,
                        residency.as_mut_ptr(),
                    )
                };
                if result == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                resident += residency[..count]
                    .iter()
                    .filter(|byte| **byte & 1 != 0)
                    .count()
                    * state.page_size;
                first += count;
            }
        }
        Ok(resident)
    }
    #[cfg(all(test, feature = "compact-history"))]
    pub(super) fn mapped_blocks(&self) -> usize {
        // SAFETY: copied list accounting between synchronous native calls.
        let mut block = unsafe { (*self.state.get()).first };
        let mut count = 0;
        while let Some(current) = block {
            let current = unsafe { current.as_ref() };
            count += usize::from(current.mapped);
            block = current.next;
        }
        count
    }
    #[cfg(all(test, feature = "compact-history"))]
    pub(super) fn encoded_bytes(&self) -> usize {
        // SAFETY: copied accounting between synchronous native calls.
        unsafe { (*self.state.get()).encoded_used }
    }
    #[cfg(test)]
    pub(super) fn refuse_new_allocations(&mut self) {
        let state = self.state.get_mut();
        state.limit = state.used;
    }
    pub(super) fn abi(&self) -> *const c_void {
        (&raw const self.abi).cast()
    }
}

fn page_size() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        // SAFETY: read-only system configuration, cached once per host. Linux
        // exposes a positive power-of-two page size on every supported target.
        let result = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(result)
            .ok()
            .filter(|n| n.is_power_of_two())
            .unwrap_or(4096)
    })
}

// Header alignment follows the rounded allocation offset, proved below.
#[allow(clippy::cast_ptr_alignment)]
unsafe extern "C" fn allocate(
    ctx: *mut c_void,
    len: usize,
    alignment: u8,
    return_address: usize,
) -> *mut c_void {
    // SAFETY: the C ABI points into a live, uniquely borrowed boxed context.
    let memory = unsafe { &mut *ctx.cast::<State>() };
    // Alignment is log2(bytes), as specified by the pinned native C ABI.
    let Some(align) = 1_usize.checked_shl(u32::from(alignment)) else {
        return ptr::null_mut();
    };
    let mapped = return_address == usize::MAX;
    let encoded = return_address == usize::MAX - 1;
    // The native adapter tags page-pool requests explicitly. Large untrusted
    // payloads cannot bypass the ordinary-data cap merely through their size.
    // Arena backing may request weaker alignment; stronger alignment is valid.
    let align = align.max(if mapped {
        memory.page_size
    } else {
        std::mem::align_of::<Block>()
    });
    let Some(offset) = std::mem::size_of::<Block>()
        .checked_add(align - 1)
        .map(|n| n & !(align - 1))
    else {
        return ptr::null_mut();
    };
    let Some(size) = len.max(1).checked_add(offset) else {
        return ptr::null_mut();
    };
    // Screen pools require page-aligned, zero-filled, lazily backed mappings.
    // The header occupies a separate prefix page and is charged to the budget.
    let size = if mapped {
        size.checked_add(memory.page_size - 1)
            .map(|n| n & !(memory.page_size - 1))
    } else {
        Some(size)
    };
    let Some(layout) = size.and_then(|size| Layout::from_size_align(size, align).ok()) else {
        return ptr::null_mut();
    };
    let ordinary = memory.used - memory.mapped_used - memory.encoded_used;
    if layout.size() > memory.limit.saturating_sub(memory.used)
        || (!mapped && !encoded && layout.size() > (256 * 1024_usize).saturating_sub(ordinary))
        || (encoded && layout.size() > memory.encoded_limit.saturating_sub(memory.encoded_used))
        || (mapped && align > memory.page_size)
    {
        // Encoded history is an optional copy of still-resident exact state.
        // Refusing that optimization leaves the source page unchanged and
        // must not taint the terminal's faithful-replay certificate.
        if !encoded {
            memory.refused = true;
        }
        return ptr::null_mut();
    }
    let base = if mapped {
        // SAFETY: anonymous private mapping; no file or foreign address is used.
        let raw = unsafe {
            libc::mmap(
                ptr::null_mut(),
                layout.size(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            ptr::null_mut()
        } else {
            raw.cast::<u8>()
        }
    } else {
        // SAFETY: validated nonzero layout; null is a recoverable refusal.
        unsafe { alloc(layout) }
    };
    let Some(base) = NonNull::new(base) else {
        if !encoded {
            memory.refused = true;
        }
        return ptr::null_mut();
    };
    // SAFETY: offset reserves aligned header space before the returned payload.
    let payload = unsafe { base.as_ptr().add(offset) };
    let block = unsafe { payload.sub(std::mem::size_of::<Block>()).cast::<Block>() };
    unsafe {
        block.write(Block {
            previous: None,
            next: memory.first,
            base,
            layout,
            mapped,
            encoded,
        });
    }
    if let Some(mut first) = memory.first {
        // SAFETY: every live list node is owned by this context.
        unsafe {
            first.as_mut().previous = NonNull::new(block);
        }
    }
    memory.first = NonNull::new(block);
    memory.used += layout.size();
    if mapped {
        memory.mapped_used += layout.size();
    }
    if encoded {
        memory.encoded_used += layout.size();
    }
    memory.peak = memory.peak.max(memory.used);
    payload.cast()
}
unsafe extern "C" fn resize(
    _: *mut c_void,
    _: *mut c_void,
    _: usize,
    _: u8,
    _: usize,
    _: usize,
) -> bool {
    false
}
unsafe extern "C" fn remap(
    _: *mut c_void,
    _: *mut c_void,
    _: usize,
    _: u8,
    _: usize,
    _: usize,
) -> *mut c_void {
    ptr::null_mut()
}
// Payload minus the aligned header width recovers its original live node.
#[allow(clippy::cast_ptr_alignment)]
unsafe extern "C" fn release(ctx: *mut c_void, payload: *mut c_void, _: usize, _: u8, _: usize) {
    // SAFETY: native ownership supplies exactly one live allocator payload.
    let memory = unsafe { &mut *ctx.cast::<State>() };
    let block = unsafe {
        payload
            .cast::<u8>()
            .sub(std::mem::size_of::<Block>())
            .cast::<Block>()
            .read()
    };
    if let Some(mut previous) = block.previous {
        unsafe {
            previous.as_mut().next = block.next;
        }
    } else {
        memory.first = block.next;
    }
    if let Some(mut next) = block.next {
        unsafe {
            next.as_mut().previous = block.previous;
        }
    }
    memory.used -= block.layout.size();
    if block.encoded {
        memory.encoded_used -= block.layout.size();
    }
    if block.mapped {
        memory.mapped_used -= block.layout.size();
        // SAFETY: base and length identify this context's entire owned mapping.
        unsafe {
            libc::munmap(block.base.as_ptr().cast(), block.layout.size());
        }
    } else {
        // SAFETY: original pointer/layout; header is no longer referenced.
        unsafe {
            dealloc(block.base.as_ptr(), block.layout);
        }
    }
}
static VTABLE: Vtable = Vtable {
    alloc: allocate,
    resize,
    remap,
    free: release,
};
impl Drop for Memory {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        while let Some(first) = state.first {
            // SAFETY: no native call can outlive this context. Unlink one
            // owned allocation without inspecting terminal graph or payload.
            let payload = unsafe {
                first
                    .as_ptr()
                    .cast::<u8>()
                    .add(std::mem::size_of::<Block>())
            };
            unsafe {
                release((&raw mut *state).cast(), payload.cast(), 0, 0, 0);
            }
        }
        debug_assert_eq!(state.used, 0);
    }
}

#[cfg(test)]
mod tests {
    //! Logical byte caps and allocation-list integrity, without timing assertions.
    use super::*;
    #[test]
    fn allocation_budget_includes_overhead_and_refusal_is_recoverable() {
        let memory = Memory::new(16384);
        let ctx = memory.state.get().cast();
        // SAFETY: tests keep the context alive and free each returned allocation once.
        unsafe {
            let first = allocate(ctx, 1024, 4, 0);
            assert!(!first.is_null());
            assert_eq!(first as usize % 16, 0);
            let used = memory.stats().0;
            assert!(used > 1024);
            assert!(allocate(ctx, 16384, 4, 0).is_null());
            assert_eq!(memory.stats().0, used);
            assert!(memory.stats().2);
            release(ctx, first, 1024, 4, 0);
            assert_eq!(memory.stats().0, 0);
            assert!(!allocate(ctx, 1024, 4, 0).is_null());
        }
        // The still-owned block is reclaimed by Memory::drop, independently
        // of any native handle. This is the resize-tombstone reclamation path.
    }
    #[test]
    fn screen_pages_are_zero_filled_and_page_aligned() {
        let mut memory = Memory::new(32768);
        let ctx = memory.state.get().cast();
        // SAFETY: unique test-owned mapping; requested slice remains live.
        unsafe {
            let page = allocate(ctx, 8192, 12, usize::MAX);
            assert!(!page.is_null());
            assert_eq!(page as usize % 4096, 0);
            assert!(
                std::slice::from_raw_parts(page.cast::<u8>(), 8192)
                    .iter()
                    .all(|byte| *byte == 0)
            );
            let small = allocate(ctx, 10, 0, 0);
            assert!(!small.is_null());
            release(ctx, page, 8192, 12, 0);
            release(ctx, small, 10, 0, 0);
            assert_eq!(memory.stats().0, 0);
            assert!(memory.state.get_mut().first.is_none());
        }
    }
}

#[cfg(test)]
mod payload_tests {
    //! Payload size can never masquerade as a page-pool allocation.
    use super::*;
    #[test]
    fn oversized_payload_is_refused_before_allocation_while_tagged_pool_is_allowed() {
        let memory = Memory::new(4 * 1024 * 1024);
        let ctx = memory.state.get().cast();
        // SAFETY: the callback context is stable; drop reclaims its tagged block.
        unsafe {
            assert!(allocate(ctx, 512 * 1024, 3, 0).is_null());
            assert_eq!(memory.stats().0, 0);
            assert!(!allocate(ctx, 512 * 1024, 3, usize::MAX).is_null());
            assert!(memory.stats().0 >= 512 * 1024);
        }
    }

    #[test]
    fn residency_query_observes_only_owned_page_mappings_without_faulting_payload() {
        let payload = 2 * page_size();
        let memory = Memory::new(8 * page_size());
        let ctx = memory.state.get().cast();
        assert_eq!(memory.resident_pages().unwrap(), 0);
        // SAFETY: both allocations borrow this stable context. The entire
        // payload is writable and release/drop reclaim only its owned blocks.
        unsafe {
            let ordinary = allocate(ctx, 1024, 4, 0);
            assert!(!ordinary.is_null());
            assert_eq!(memory.resident_pages().unwrap(), 0);
            let pages = allocate(ctx, payload, 12, usize::MAX);
            assert!(!pages.is_null());
            let before = memory.resident_pages().unwrap();
            assert_eq!(memory.resident_pages().unwrap(), before);
            pages.cast::<u8>().write_bytes(1, payload);
            assert_eq!(memory.resident_pages().unwrap(), before + payload);
            release(ctx, pages, payload, 12, 0);
            assert_eq!(memory.resident_pages().unwrap(), 0);
        }
    }
}

#[cfg(all(test, feature = "compact-history"))]
mod history_tests {
    //! Cold history cannot borrow the parser share or exceed its own limit.
    use super::*;
    #[test]
    fn encoded_history_has_a_separate_enforced_allocation_share() {
        let memory = Memory::with_history(2 * 1024 * 1024, 512 * 1024);
        let ctx = memory.state.get().cast();
        // SAFETY: callbacks borrow the stable test owner; drop releases all blocks.
        unsafe {
            let history = allocate(ctx, 400 * 1024, 3, usize::MAX - 1);
            assert!(!history.is_null());
            assert!(memory.encoded_bytes() > 400 * 1024);
            let parser = allocate(ctx, 128 * 1024, 3, 0);
            assert!(
                !parser.is_null(),
                "history must not consume parser capacity"
            );
            assert!(allocate(ctx, 128 * 1024, 3, usize::MAX - 1).is_null());
            assert!(
                !memory.stats().2,
                "opportunistic compression refusal must not invalidate exact terminal state"
            );
            assert!(allocate(ctx, 256 * 1024, 3, 0).is_null());
            release(ctx, history, 400 * 1024, 3, usize::MAX - 1);
            assert_eq!(memory.encoded_bytes(), 0);
            release(ctx, parser, 128 * 1024, 3, 0);
            assert_eq!(memory.stats().0, 0);
        }
    }
}
