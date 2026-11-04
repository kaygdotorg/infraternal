//! Audited libghostty-vt FFI ownership and bounded snapshot buffer boundary [40][94].
#![allow(unsafe_code)]
use std::{ffi::c_void, io, ptr::NonNull};
/// Creation options laid out as the native library's C structure expects.
/// `max_scrollback` is the history byte budget.
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
    #[cfg(all(test, feature = "process-per-user"))]
    fn ghostty_terminal_mode_get(terminal: *mut c_void, tag: u16, out: *mut bool) -> i32;
    #[cfg(any(test, feature = "process-per-user"))]
    fn ghostty_terminal_get(terminal: *mut c_void, tag: i32, out: *mut c_void) -> i32;
    /// Writes an approximate repaint into the buffer; returns its length, which the
    /// caller must check against the buffer size.
    fn infraternal_vt_approximate(terminal: *mut c_void, data: *mut u8, len: usize) -> usize;
    /// Writes a faithful repaint with `tail` rows of history; returns the length,
    /// 0 on overflow, or `usize::MAX` if the state is not representable.
    fn infraternal_vt_snapshot(
        terminal: *mut c_void,
        data: *mut u8,
        len: usize,
        tail: usize,
    ) -> usize;
    #[cfg(feature = "compact-history")]
    fn infraternal_vt_compact(terminal: *mut c_void, full: bool);
    /// Page count and page size in bytes for a screen of `cols` x `rows`. Pure
    /// arithmetic; creates no terminal.
    #[cfg(feature = "process-per-user")]
    fn infraternal_vt_screen_pages(cols: u16, rows: u16, page_len: *mut usize) -> usize;
}
/// Sizes a shared-host terminal's floor for one `cols` x `rows` screen, at
/// the page shape of the native build [#205].
#[cfg(feature = "process-per-user")]
fn reserve_screens(memory: &mut crate::terminal_memory::Memory, cols: u16, rows: u16) {
    let mut page_len = 0;
    // SAFETY: pure layout arithmetic over the pinned page shape; writes only
    // the provided local.
    let pages = unsafe { infraternal_vt_screen_pages(cols, rows, &raw mut page_len) };
    memory.reserve_screens(pages, page_len);
}
/// Computes and reserves the startup screen floor before its PTY is spawned.
#[cfg(feature = "process-per-user")]
pub(crate) fn floor_for_geometry(cols: u16, rows: u16, minimum: usize) -> usize {
    let mut page_len = 0;
    // SAFETY: this native helper performs layout arithmetic only and writes
    // one scalar to the provided local; it creates no terminal state.
    let pages = unsafe { infraternal_vt_screen_pages(cols, rows, &raw mut page_len) };
    crate::terminal_memory::Memory::screen_floor(pages, page_len, minimum)
}
// A failed resize can partially mutate Ghostty page ownership. None is a
// permanent tombstone: even destruction would inspect invalid native state.
// Default builds retain retired allocations until shim exit (#37). The
// shared host owns a separate allocation list and reclaims that list without
// traversing the retired graph; neither path revives an invalid handle.
/// Visible screens, parser/style state and reflow transients of one bounded
/// engine, beyond its history share [D270].
#[cfg(feature = "process-per-user")]
pub(super) const SCREEN_RESERVATION: usize = 8 * 1024 * 1024;
/// Each screen-pool item is charged one header page on top of the item that
/// native history accounting counts. Items are at least eight pages, so an
/// eighth of the share covers every header; a unit test pins the ratio.
/// Compact history reserves twice its share instead.
#[cfg(all(
    feature = "process-per-user",
    any(test, not(feature = "compact-history"))
))]
pub(super) const ITEM_HEADER_SHARE: usize = 8;
/// Owner of one native terminal. The first field is the native handle, or
/// `None` once retired; the second (shared-host builds only) is the memory
/// accountant whose allocator the native terminal uses.
///
/// Invariants: the handle is uniquely owned and only touched from one thread at
/// a time. After a failed resize the native state may be half rebuilt, so the
/// engine retires itself and never queries or frees that handle again. Default
/// builds keep retired allocations until the shim exits; the shared host frees
/// its own allocation list without walking the damaged state. A retired engine
/// ignores output and refuses snapshots and resizes.
pub(super) struct Engine(
    Option<NonNull<c_void>>,
    #[cfg(feature = "process-per-user")] Option<Box<crate::terminal_memory::Memory>>,
);
impl Engine {
    #[cfg(all(test, feature = "process-per-user"))]
    pub(super) fn synchronized_output(&self) -> io::Result<bool> {
        let handle = self.0.ok_or_else(|| io::Error::other("retired VT"))?;
        let mut value = false;
        // SAFETY: the live handle and bool output remain valid synchronously.
        // ModeTag is packed u16: low 15 bits are the mode, ANSI flag is clear.
        let result = unsafe { ghostty_terminal_mode_get(handle.as_ptr(), 2026, &raw mut value) };
        if result == 0 {
            Ok(value)
        } else {
            Err(io::Error::other("native mode query failed"))
        }
    }
    /// A shared-host engine whose reservation is derived from its history
    /// share: the share itself, one header page per screen-pool item, and a
    /// fixed allowance for the visible screens, parser state and the
    /// transient pages of a reflow. A history share therefore always fits,
    /// whatever share the host hands out. `host` adds the host-wide ceiling.
    #[cfg(feature = "process-per-user")]
    pub fn bounded(
        cols: u16,
        rows: u16,
        bytes: usize,
        host: Option<std::sync::Arc<crate::terminal_memory::HostBudget>>,
        floor_reservation: Option<std::sync::Arc<crate::terminal_memory::HostFloor>>,
    ) -> io::Result<Self> {
        #[cfg(not(feature = "compact-history"))]
        let limit = SCREEN_RESERVATION
            .saturating_add(bytes)
            .saturating_add(bytes / ITEM_HEADER_SHARE);
        // Cold pages retain virtual mappings for infallible exact restore.
        // Their encoded allocations still obey the configured history share.
        #[cfg(feature = "compact-history")]
        let limit = SCREEN_RESERVATION + bytes.saturating_mul(2);
        Self::build(cols, rows, bytes, limit, host, floor_reservation)
    }
    /// Creates an engine with `bytes` of history, not charged to any shared host.
    /// Fails if the native terminal cannot be made.
    pub fn new(cols: u16, rows: u16, bytes: usize) -> io::Result<Self> {
        Self::build(
            cols,
            rows,
            bytes,
            8 * 1024 * 1024 + bytes.saturating_mul(2) + usize::from(cols) * usize::from(rows) * 32,
            #[cfg(feature = "process-per-user")]
            None,
            #[cfg(feature = "process-per-user")]
            None,
        )
    }
    /// Creates the native terminal. `limit` is the memory cap for shared-host
    /// builds. Fails with `InvalidInput` for bad dimensions, otherwise with an
    /// error naming the native result code.
    fn build(
        cols: u16,
        rows: u16,
        bytes: usize,
        limit: usize,
        #[cfg(feature = "process-per-user")] host: Option<
            std::sync::Arc<crate::terminal_memory::HostBudget>,
        >,
        #[cfg(feature = "process-per-user")] floor_reservation: Option<
            std::sync::Arc<crate::terminal_memory::HostFloor>,
        >,
    ) -> io::Result<Self> {
        #[cfg(not(feature = "process-per-user"))]
        let _ = limit;
        let mut raw = std::ptr::null_mut();
        #[cfg(all(feature = "process-per-user", not(feature = "compact-history")))]
        let mut memory =
            crate::terminal_memory::Memory::with_host(limit, 0, host, floor_reservation);
        #[cfg(feature = "compact-history")]
        let mut memory =
            crate::terminal_memory::Memory::with_host(limit, bytes, host, floor_reservation);
        // The first screen comes from the floor, so it is sized first.
        #[cfg(feature = "process-per-user")]
        reserve_screens(&mut memory, cols, rows);
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
    /// (Shared host.) `(bytes in use, peak bytes, refused)` from the memory accountant:
    /// current native allocation, its high-water mark, and whether any allocation
    /// was ever refused. All zero or false when there is no accountant.
    #[cfg(feature = "process-per-user")]
    pub fn memory(&self) -> (usize, usize, bool) {
        self.1.as_ref().map_or((0, 0, false), |m| m.stats())
    }
    /// (Shared host.) Native memory split into `(ordinary bytes, page bytes, block
    /// count)`. Page bytes are the mapped history pages plus their page-list
    /// structure; ordinary is everything else except encoded data. Zeros without an
    /// accountant.
    #[cfg(feature = "process-per-user")]
    pub fn allocation_classes(&self) -> (usize, usize, usize) {
        self.1
            .as_ref()
            .map_or((0, 0, 0), |m| m.allocation_classes())
    }
    /// (Shared host.) Bytes of this terminal's mapped pages that are resident in
    /// memory right now, asked of the kernel without touching the pages. Fails if
    /// the kernel query fails.
    #[cfg(feature = "process-per-user")]
    pub fn resident_pages(&self) -> io::Result<usize> {
        self.1.as_ref().map_or(Ok(0), |m| m.resident_pages())
    }
    #[cfg(all(test, feature = "compact-history"))]
    pub(super) fn mapped_blocks(&self) -> usize {
        self.1.as_ref().map_or(0, |m| m.mapped_blocks())
    }
    /// This terminal's floor in its host budget, for accounting tests.
    #[cfg(all(test, feature = "process-per-user"))]
    pub(super) fn host_floor(&self) -> usize {
        self.1.as_ref().map_or(0, |m| m.floor())
    }
    /// (Shared host.) Bytes currently held in compressed (encoded) history form.
    #[cfg(feature = "process-per-user")]
    pub(super) fn encoded_bytes(&self) -> usize {
        self.1.as_ref().map_or(0, |m| m.encoded_bytes())
    }
    /// Feeds output bytes to the native parser. The native side keeps its parser
    /// state but not the pointer. Does nothing if the engine is retired.
    pub fn process(&mut self, data: &[u8]) {
        let Some(handle) = self.0 else { return };
        // SAFETY: uniquely owned terminal; Ghostty consumes the borrowed slice
        // synchronously and retains parser state, never the input pointer.
        unsafe { ghostty_terminal_vt_write(handle.as_ptr(), data.as_ptr(), data.len()) }
        #[cfg(feature = "compact-history")]
        if !data.is_empty() {
            self.compact(false);
        }
    }
    #[cfg(feature = "compact-history")]
    pub(super) fn compact(&self, full: bool) {
        if let Some(handle) = self.0 {
            // SAFETY: the reactor owns the terminal exclusively. Only its
            // internal cold-page representation changes; no input is emitted.
            unsafe { infraternal_vt_compact(handle.as_ptr(), full) }
        }
    }
    /// Resizes to `cols` x `rows` (pixel size is left at zero).
    ///
    /// The native resize is not transactional. On any native error the engine
    /// retires: the handle and its memory accounting are dropped without being
    /// touched, and the error is returned (`InvalidInput` for bad dimensions). On a
    /// shared host, space for the new screen is reserved from the terminal's own
    /// floor first.
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        // SAFETY: uniquely owned live terminal; zero pixel dimensions are valid.
        // Resize is not transactional in the pinned engine. Retire on every
        // native error without querying or freeing the potentially invalid handle.
        let handle = self
            .0
            .ok_or_else(|| io::Error::other("retired Ghostty engine"))?;
        // Floor first: the new screen's pages are this terminal's own, not
        // the pool's. A failed resize retires the engine and its memory.
        #[cfg(feature = "process-per-user")]
        if let Some(memory) = self.1.as_mut() {
            reserve_screens(memory, cols, rows);
        }
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
    /// Number of rows of scrollback currently retained, from native metadata only.
    /// Zero if retired.
    #[cfg(any(test, feature = "process-per-user"))]
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
    /// Writes a bounded, visible-screen-only repaint into `data` and returns its
    /// length, or 0 if retired or it does not fit. Clipped content is rolled back to
    /// complete cell operations and a footer is reserved.
    pub fn approximate_snapshot(&self, data: &mut [u8]) -> usize {
        let Some(handle) = self.0 else { return 0 };
        // SAFETY: read-only live handle and writable bounded slice remain valid
        // synchronously. The adapter rolls back complete cell operations on
        // clipping, reserves a footer, and retains neither pointer.
        let len =
            unsafe { infraternal_vt_approximate(handle.as_ptr(), data.as_mut_ptr(), data.len()) };
        if len <= data.len() { len } else { 0 }
    }
    /// Writes a faithful repaint of both screens into `data`, with up to `tail`
    /// rows of scrollback.
    ///
    /// Returns `Ok(Some(len))` on success and `Ok(None)` when it does not fit, so
    /// the caller can retry with a smaller `tail`. Fails with `Unsupported` if the
    /// state cannot be represented faithfully, or if the engine is retired.
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

    /// PPU-R3-1 (#205): a refusal in the middle of a widening reflow leaves
    /// the native page list half rebuilt, with the cursor still pinned to a
    /// page the reflow already freed. The engine must report the error
    /// without touching that page, so the caller can retire it; reading it
    /// decoded freed memory as a compressed page and wrote out of bounds.
    /// Refusal points step through the reflow, so several land mid-reflow.
    #[test]
    fn refusal_inside_reflow_never_touches_freed_pages() {
        let mut history = Vec::new();
        for n in 0..3000_usize {
            let line = match n % 3 {
                0 => format!("\x1b[3{}m{n:08} plain\x1b[0m\r\n", n % 7 + 1),
                1 => format!("{n:08} {}\r\n", "wrap-".repeat(30)),
                _ => format!("{n:08} 漢字かな{}\r\n", "é".repeat(20)),
            };
            history.extend_from_slice(line.as_bytes());
        }
        let mut failed = 0;
        for step in 0..24_usize {
            let mut engine = Engine::new(80, 24, 17 * 1024 * 1024).unwrap();
            engine.process(b"\x1bc");
            engine.process(&history);
            // A styled cursor makes the resize reload its style afterwards.
            engine.process(b"\x1b[1;4;35mstyled");
            engine.1.as_mut().unwrap().refuse_beyond(step * 32 * 1024);
            if engine.resize(133, 40).is_err() {
                failed += 1;
                assert!(engine.0.is_none() && engine.1.is_none());
                assert_eq!(engine.memory().0, 0);
            }
        }
        assert!(
            failed >= 8,
            "only {failed} refusal points landed in the reflow"
        );
    }
}
