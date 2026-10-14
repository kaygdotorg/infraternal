//! Audited libghostty-vt FFI ownership and bounded snapshot buffer boundary [40][94].
#![allow(unsafe_code)]
use std::{ffi::c_void, io, ptr::NonNull};
#[repr(C)]
struct Options {
    cols: u16,
    rows: u16,
    max_scrollback: usize,
}
unsafe extern "C" {
    fn ghostty_terminal_new(
        allocator: *const c_void,
        out: *mut *mut c_void,
        options: Options,
    ) -> i32;
    fn ghostty_terminal_free(terminal: *mut c_void);
    fn ghostty_terminal_vt_write(terminal: *mut c_void, data: *const u8, len: usize);
    fn ghostty_terminal_resize(
        terminal: *mut c_void,
        cols: u16,
        rows: u16,
        width: u32,
        height: u32,
    ) -> i32;
    #[cfg(test)]
    fn infraternal_vt_compare(a: *mut c_void, b: *mut c_void, strict: bool) -> usize;
    #[cfg(test)]
    fn ghostty_terminal_get(terminal: *mut c_void, tag: i32, out: *mut c_void) -> i32;
    fn infraternal_vt_approximate(terminal: *mut c_void, data: *mut u8, len: usize) -> usize;
    fn infraternal_vt_snapshot(
        terminal: *mut c_void,
        data: *mut u8,
        len: usize,
        tail: usize,
    ) -> usize;
}
// A failed resize can partially mutate Ghostty page ownership. None is a
// permanent tombstone: even destruction would inspect invalid native state.
// Default builds retain retired allocations until shim exit (#37). The
// shared host owns a separate allocation list and reclaims that list without
// traversing the retired graph; neither path revives an invalid handle.
pub(super) struct Engine(
    Option<NonNull<c_void>>,
    #[cfg(feature = "process-per-user")] Option<Box<crate::terminal_memory::Memory>>,
);
impl Engine {
    #[cfg(feature = "process-per-user")]
    pub fn bounded(cols: u16, rows: u16, bytes: usize) -> io::Result<Self> {
        Self::build(cols, rows, bytes, 8 * 1024 * 1024)
    }
    pub fn new(cols: u16, rows: u16, bytes: usize) -> io::Result<Self> {
        Self::build(
            cols,
            rows,
            bytes,
            8 * 1024 * 1024 + bytes.saturating_mul(2) + usize::from(cols) * usize::from(rows) * 32,
        )
    }
    fn build(cols: u16, rows: u16, bytes: usize, limit: usize) -> io::Result<Self> {
        #[cfg(not(feature = "process-per-user"))]
        let _ = limit;
        let mut raw = std::ptr::null_mut();
        #[cfg(feature = "process-per-user")]
        let memory = crate::terminal_memory::Memory::new(limit);
        #[cfg(not(feature = "process-per-user"))]
        let allocator = std::ptr::null();
        #[cfg(feature = "process-per-user")]
        let allocator = memory.abi();
        // SAFETY: null selects Ghostty's allocator. Options matches its C ABI;
        // out is writable and a successful call transfers unique ownership.
        let result = unsafe {
            ghostty_terminal_new(
                allocator,
                &raw mut raw,
                Options {
                    cols,
                    rows,
                    max_scrollback: bytes,
                },
            )
        };
        if result != 0 {
            return Err(io::Error::new(
                if result == -2 {
                    io::ErrorKind::InvalidInput
                } else {
                    io::ErrorKind::Other
                },
                format!("Ghostty initialization failed: {result}"),
            ));
        }
        NonNull::new(raw)
            .map(|handle| {
                Self(
                    Some(handle),
                    #[cfg(feature = "process-per-user")]
                    Some(memory),
                )
            })
            .ok_or_else(|| io::Error::other("Ghostty returned a null terminal"))
    }
    #[cfg(feature = "process-per-user")]
    pub fn memory(&self) -> (usize, usize, bool) {
        self.1.as_ref().map_or((0, 0, false), |m| m.stats())
    }
    #[cfg(feature = "process-per-user")]
    pub fn allocation_classes(&self) -> (usize, usize, usize) {
        self.1
            .as_ref()
            .map_or((0, 0, 0), |m| m.allocation_classes())
    }
    #[cfg(feature = "process-per-user")]
    pub fn resident_pages(&self) -> io::Result<usize> {
        self.1.as_ref().map_or(Ok(0), |m| m.resident_pages())
    }
    pub fn process(&mut self, data: &[u8]) {
        let Some(handle) = self.0 else { return };
        // SAFETY: uniquely owned terminal; Ghostty consumes the borrowed slice
        // synchronously and retains parser state, never the input pointer.
        unsafe { ghostty_terminal_vt_write(handle.as_ptr(), data.as_ptr(), data.len()) }
    }
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        // SAFETY: uniquely owned live terminal; zero pixel dimensions are valid.
        // Resize is not transactional in the pinned engine. Retire on every
        // native error without querying or freeing the potentially invalid handle.
        let handle = self
            .0
            .ok_or_else(|| io::Error::other("retired Ghostty engine"))?;
        let result = unsafe { ghostty_terminal_resize(handle.as_ptr(), cols, rows, 0, 0) };
        if result == 0 {
            Ok(())
        } else {
            self.0 = None;
            #[cfg(feature = "process-per-user")]
            {
                self.1 = None;
            }
            Err(io::Error::new(
                if result == -2 {
                    io::ErrorKind::InvalidInput
                } else {
                    io::ErrorKind::Other
                },
                format!("Ghostty resize failed: {result}"),
            ))
        }
    }
    #[cfg(test)]
    pub fn difference(&self, other: &Self) -> usize {
        let (Some(left), Some(right)) = (self.0, other.0) else {
            return usize::MAX;
        };
        // SAFETY: both uniquely owned live terminals are borrowed read-only for
        // the call. The oracle retains no references and does not mutate them.
        unsafe { infraternal_vt_compare(left.as_ptr(), right.as_ptr(), false) }
    }
    #[cfg(test)]
    pub fn state_difference(&self, other: &Self) -> usize {
        let (Some(left), Some(right)) = (self.0, other.0) else {
            return usize::MAX;
        };
        // SAFETY: read-only oracle borrows live handles synchronously and retains nothing.
        unsafe { infraternal_vt_compare(left.as_ptr(), right.as_ptr(), true) }
    }
    #[cfg(test)]
    pub fn history_rows(&self) -> usize {
        let Some(handle) = self.0 else { return 0 };
        let mut rows: usize = 0;
        // SAFETY: tag 15 in the pinned C ABI writes a usize to this valid out
        // pointer; the live terminal is borrowed for this synchronous query.
        unsafe {
            ghostty_terminal_get(handle.as_ptr(), 15, (&raw mut rows).cast());
        }
        rows
    }
    pub fn approximate_snapshot(&self, data: &mut [u8]) -> usize {
        let Some(handle) = self.0 else { return 0 };
        // SAFETY: read-only live handle and writable bounded slice remain valid
        // synchronously. The adapter rolls back complete cell operations on
        // clipping, reserves a footer, and retains neither pointer.
        let len =
            unsafe { infraternal_vt_approximate(handle.as_ptr(), data.as_mut_ptr(), data.len()) };
        if len <= data.len() { len } else { 0 }
    }
    pub fn try_snapshot(&self, data: &mut [u8], tail: usize) -> io::Result<Option<usize>> {
        let handle = self
            .0
            .ok_or_else(|| io::Error::other("retired Ghostty engine"))?;
        // SAFETY: live terminal and writable slice remain valid throughout the
        // synchronous call. The adapter uses Writer.fixed and returns at most
        // data.len(), zero on overflow, or usize::MAX for an unrepresentable
        // state. The sentinel is checked before using it as a slice length;
        // the adapter retains neither pointer.
        let len = unsafe {
            infraternal_vt_snapshot(handle.as_ptr(), data.as_mut_ptr(), data.len(), tail)
        };
        if len == usize::MAX {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Ghostty state is not representable by the bounded faithful Snapshot painter",
            ));
        }
        Ok((len != 0 && len <= data.len()).then_some(len))
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        let Some(handle) = self.0.take() else { return };
        // SAFETY: this is the unique owner; destruction runs exactly once and
        // there are no callbacks or outstanding grid references in Rust.
        unsafe { ghostty_terminal_free(handle.as_ptr()) }
    }
}

#[cfg(test)]
#[path = "../tests/unit/allocation.rs"]
pub(crate) mod allocation;

#[cfg(all(test, feature = "process-per-user"))]
mod owned_memory_tests {
    //! Resize refusal releases the allocation owner without traversing damaged state.
    use super::*;
    #[test]
    fn refused_resize_reclaims_every_owned_native_allocation() {
        let mut engine = Engine::new(80, 24, 65536).unwrap();
        engine.process(allocation::PREFIX);
        assert!(engine.memory().0 > 0);
        engine.1.as_mut().unwrap().refuse_new_allocations();
        assert!(engine.resize(20_000, 2).is_err());
        assert!(engine.0.is_none());
        assert!(engine.1.is_none());
        assert_eq!(engine.memory().0, 0);
        engine.process(b"later output");
    }
}
