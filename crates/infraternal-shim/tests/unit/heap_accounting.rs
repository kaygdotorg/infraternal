//! Test-only requested-byte accounting forwards unchanged layouts to the system allocator [D270].
//! Scopes are thread-local and retain no addresses or contents. This separates
//! per-session ownership from fixed image pages and allocator resident slack.
#![allow(unsafe_code)]
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct Delta {
    pub(crate) bytes: i64,
    pub(crate) blocks: i64,
}
thread_local! {
    static CURRENT: Cell<Option<Delta>> = const { Cell::new(None) };
}
struct Counter;
#[global_allocator]
static ALLOCATOR: Counter = Counter;

fn record(bytes: i64, blocks: i64) {
    let _ = CURRENT.try_with(|current| {
        if let Some(mut delta) = current.get() {
            delta.bytes += bytes;
            delta.blocks += blocks;
            current.set(Some(delta));
        }
    });
}
fn size(bytes: usize) -> i64 {
    // Layout sizes are at most isize::MAX on supported 64-bit targets.
    i64::try_from(bytes).unwrap_or(i64::MAX)
}
// SAFETY: every allocation and deallocation uses precisely the original
// System pointer/layout; the counters do not allocate or change ownership.
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(size(layout.size()), 1);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(size(layout.size()), 1);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record(-size(layout.size()), -1);
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, new_size) };
        if !result.is_null() {
            record(size(new_size) - size(layout.size()), 0);
        }
        result
    }
}

pub(crate) fn measure<T>(work: impl FnOnce() -> T) -> (T, Delta) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CURRENT.with(|current| current.set(None));
        }
    }
    CURRENT.with(|current| {
        assert!(current.get().is_none(), "nested allocation scope");
        current.set(Some(Delta::default()));
    });
    let reset = Reset;
    let result = work();
    let delta = CURRENT.with(|current| current.get().unwrap_or_default());
    drop(reset);
    (result, delta)
}

#[test]
fn accounting_keeps_exact_layouts_and_balances_reallocation() {
    let (mut bytes, allocated) = measure(|| Vec::<u8>::with_capacity(19));
    assert_eq!((allocated.bytes, allocated.blocks), (19, 1));
    let ((), growth) = measure(|| bytes.reserve_exact(40));
    assert_eq!(growth.bytes, i64::try_from(bytes.capacity()).unwrap() - 19);
    assert_eq!(growth.blocks, 0);
    let ((), released) = measure(|| drop(bytes));
    assert_eq!(allocated.bytes + growth.bytes + released.bytes, 0);
    assert_eq!(allocated.blocks + released.blocks, 0);
}
