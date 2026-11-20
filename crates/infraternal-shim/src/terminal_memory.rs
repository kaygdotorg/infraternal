//! Audited per-terminal allocation accounting and ownership for shared hosts [D270].
//!
//! Every native allocation is linked to its terminal, including screen pages.
//! Retiring a nontransactional resize releases allocations directly without
//! walking the potentially damaged native graph. Callbacks run synchronously
//! on the reactor thread; the boxed ABI and context never move while borrowed.
//! Terminals of one host share a [`HostBudget`], including reserved session
//! floors and the allocated replay rings, so screens and scrollback stay
//! inside one per-user byte cap.
#![allow(unsafe_code)]
use nix::libc;
use std::{
    alloc::{Layout, alloc, dealloc},
    ffi::c_void,
    ptr::{self, NonNull},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Resize-callback tag for a fit query on one more screen-pool item. The C
/// allocator ABI has no query entry; native growth asks before allocating so
/// it can recycle its oldest history page instead of being refused.
const FIT_QUERY: usize = usize::MAX - 2;
/// Allocation tag for page-list structure: one node per page, so it grows
/// with the page count that the history share already bounds. It is exact
/// state charged to the reservation, but not to the ordinary-data cap that
/// bounds parser, title and style data.
const STRUCTURE: usize = usize::MAX - 3;

/// Native bytes shared by every terminal of one host [D270, #205].
///
/// Floors, native allocations above those floors and allocated replay rings
/// all fit inside `limit`. A terminal's floor protects its current screens
/// and may grow with geometry up to [`MAX_FLOOR`], subject to the same cap.
/// Session shares are equal, and when native history reaches its share the
/// terminal recycles its oldest page before refusing other growth. The reactor
/// is single-threaded; atomics keep its shared owners `Send` without a lock.
pub(crate) struct HostBudget {
    /// Allocations above each terminal's protected screen floor, plus rings.
    used: AtomicUsize,
    /// Floors reserved by admitted sessions; these are part of `limit`.
    floors: AtomicUsize,
    limit: usize,
    floor: usize,
}
/// One admitted session's protected screen reservation, shared with its VT.
pub(crate) struct HostFloor {
    host: Arc<HostBudget>,
    bytes: AtomicUsize,
}
/// Per-session protected bytes stop at two 250x180 screens; larger geometry
/// uses the shared remainder, still inside the total user pool.
pub(crate) const MAX_FLOOR: usize = 2 * 1024 * 1024;
impl HostBudget {
    /// Creates a pool of `limit` bytes for one user's terminals. `floor` is the
    /// smallest protected screen reservation a session gets.
    pub(crate) fn new(limit: usize, floor: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            floors: AtomicUsize::new(0),
            limit,
            floor,
        })
    }
    /// Reserves the session floor before its PTY starts. The floor is inside
    /// the same hard cap as history and ring allocations.
    pub(crate) fn reserve_session(
        self: &Arc<Self>,
        requested_floor: usize,
    ) -> std::io::Result<Arc<HostFloor>> {
        let floor = requested_floor.clamp(self.floor, MAX_FLOOR.max(self.floor));
        let current = self.used.load(Ordering::Relaxed) + self.floors.load(Ordering::Relaxed);
        if floor > self.limit.saturating_sub(current) {
            return Err(self.full_error());
        }
        self.floors.fetch_add(floor, Ordering::Relaxed);
        Ok(Arc::new(HostFloor {
            host: self.clone(),
            bytes: AtomicUsize::new(floor),
        }))
    }
    /// The smallest per-session floor this pool grants.
    pub(crate) fn minimum_floor(&self) -> usize {
        self.floor
    }
    /// The `OutOfMemory` error returned when the pool has no room, worded for the
    /// user, with the pool size in MiB, KiB or bytes.
    fn full_error(&self) -> std::io::Error {
        let mib = 1024 * 1024;
        let kib = 1024;
        let capacity = if self.limit.is_multiple_of(mib) {
            format!("{} MiB", self.limit / mib)
        } else if self.limit.is_multiple_of(kib) {
            format!("{} KiB", self.limit / kib)
        } else {
            format!("{} bytes", self.limit)
        };
        std::io::Error::new(
            std::io::ErrorKind::OutOfMemory,
            format!("terminal memory for this user is full ({capacity}); close a session"),
        )
    }
    /// Total bytes committed against the user's pool, including idle floors.
    pub(crate) fn total_used(&self) -> usize {
        self.used.load(Ordering::Relaxed) + self.floors.load(Ordering::Relaxed)
    }
    /// The pool's hard cap in bytes.
    pub(crate) fn limit_bytes(&self) -> usize {
        self.limit
    }
    /// Takes `bytes` from the pool's shared remainder (above floors). Returns false,
    /// changing nothing, if that would pass the cap; zero always succeeds.
    pub(crate) fn try_charge(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        self.used
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|next| {
                    *next
                        <= self
                            .limit
                            .saturating_sub(self.floors.load(Ordering::Relaxed))
                })
            })
            .is_ok()
    }
    /// Gives back `bytes` taken by `try_charge`. Must not exceed what was charged.
    pub(crate) fn release_charge(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::Relaxed);
    }
    /// Pool bytes a terminal at `used` with `floor` needs to grow by `bytes`.
    fn excess(used: usize, bytes: usize, floor: usize) -> usize {
        used.saturating_add(bytes).saturating_sub(floor) - used.saturating_sub(floor)
    }
    /// Pool bytes charged above floors. The total cap also includes floors.
    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
    /// True if growing a terminal that holds `used` bytes by `bytes` would fit,
    /// given its `floor`. Charges nothing.
    fn fits(&self, used: usize, bytes: usize, floor: usize) -> bool {
        let extra = Self::excess(used, bytes, floor);
        extra <= self.limit.saturating_sub(self.total_used())
    }
    /// Charges the pool for growing a terminal from `used` by `bytes`. Growth that
    /// stays within the terminal's own `floor` costs the pool nothing. False if it
    /// does not fit.
    fn charge(&self, used: usize, bytes: usize, floor: usize) -> bool {
        self.try_charge(Self::excess(used, bytes, floor))
    }
    /// `used` is the terminal's charge after `bytes` were released.
    fn release(&self, used: usize, bytes: usize, floor: usize) {
        self.release_charge(Self::excess(used, bytes, floor));
    }
    /// Moves a terminal's existing bytes between its protected floor and the
    /// shared remainder. A floor increase is refused if it would exceed the
    /// total cap; native allocation accounting then stays unchanged.
    fn refloor(&self, used: usize, from: usize, to: usize) -> bool {
        let (before, after) = (used.saturating_sub(from), used.saturating_sub(to));
        let total_before = self.total_used();
        let total_after = total_before
            .saturating_sub(from)
            .saturating_sub(before)
            .saturating_add(to)
            .saturating_add(after);
        if total_after > self.limit {
            return false;
        }
        if to > from {
            if before > after {
                self.used.fetch_sub(before - after, Ordering::Relaxed);
            }
            self.floors.fetch_add(to - from, Ordering::Relaxed);
        } else {
            self.floors.fetch_sub(from - to, Ordering::Relaxed);
            if after > before {
                self.used.fetch_add(after - before, Ordering::Relaxed);
            }
        }
        true
    }
}
impl HostFloor {
    /// Changes this session's floor to `to`, moving the terminal's existing `used`
    /// bytes between its protected floor and the shared remainder. Returns false and
    /// changes nothing if the larger floor would pass the pool's cap.
    fn resize(&self, used: usize, to: usize) -> bool {
        let from = self.bytes.load(Ordering::Relaxed);
        if !self.host.refloor(used, from, to) {
            return false;
        }
        self.bytes.store(to, Ordering::Relaxed);
        true
    }
    /// The session's current floor in bytes.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}
impl Drop for HostFloor {
    fn drop(&mut self) {
        self.host
            .floors
            .fetch_sub(self.bytes.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// The allocator function table in libghostty-vt 1.0's stable C layout. The
/// four callbacks are followed by four reserved pointers, which must stay null.
#[repr(C)]
struct Vtable {
    alloc: unsafe extern "C" fn(*mut c_void, usize, u8, usize) -> *mut c_void,
    resize: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> bool,
    remap: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> *mut c_void,
    free: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize),
    /// Reserved by the stable C ABI; null slots keep the table forward-compatible.
    reserved: [*mut c_void; 4],
}
/// The shared table is immutable, and all reserved pointer slots are null.
unsafe impl Sync for Vtable {}
/// The allocator handle passed to the native library: a context pointer and the
/// function table. It is boxed with the `Memory` so the pointers stay valid.
#[repr(C)]
struct Abi {
    context: *mut c_void,
    vtable: *const Vtable,
}
/// Header written in front of every native allocation. Blocks form a doubly
/// linked list per terminal, which lets the whole terminal's memory be freed
/// without looking at what the native side built. The flags record the class:
/// `mapped` for page-aligned history pages, `encoded` for compressed history,
/// `structure` for page-list nodes.
struct Block {
    previous: Option<NonNull<Block>>,
    next: Option<NonNull<Block>>,
    base: NonNull<u8>,
    layout: Layout,
    mapped: bool,
    encoded: bool,
    structure: bool,
}

/// Allocation accounting and ownership for one native terminal.
///
/// Gives the native library an allocator that charges every request against the
/// terminal's limit, per-class caps and the user's shared pool, and links it to
/// this terminal. Dropping `Memory` frees everything still allocated, without
/// touching the native state; that is how a terminal whose resize failed is
/// cleaned up safely. Everything runs on the reactor thread, inside synchronous
/// native calls.
pub(super) struct Memory {
    abi: Abi,
    // Native read-side operations may decompress history and allocate even
    // while Rust borrows the engine immutably. Only this single-threaded FFI
    // context has interior mutation; its counters never escape as references.
    state: std::cell::UnsafeCell<State>,
}
/// The mutable counters and block list behind `Memory`. `used`, `peak` and the
/// class counters are in bytes including headers. `refused` is set when a
/// request (other than optional compressed history) is turned down. `floor` is
/// this terminal's protected share of the pool.
struct State {
    first: Option<NonNull<Block>>,
    used: usize,
    peak: usize,
    limit: usize,
    refused: bool,
    mapped_used: usize,
    structure_used: usize,
    encoded_used: usize,
    encoded_limit: usize,
    page_size: usize,
    host: Option<Arc<HostBudget>>,
    floor_reservation: Option<Arc<HostFloor>>,
    /// This terminal's share of `host` that no neighbour can take.
    floor: usize,
}
impl Memory {
    // Native allocator pointers borrow the ABI and context, so constructing
    // the final stable box here is required rather than moving a stack value.
    /// Test constructor: a standalone `Memory` with `limit` bytes and no pool.
    #[allow(clippy::unnecessary_box_returns)]
    #[cfg(test)]
    pub(super) fn new(limit: usize) -> Box<Self> {
        Self::with_host(limit, 0, None, None)
    }
    /// Test constructor: like `new`, also with an `encoded_limit` for compressed
    /// history.
    #[allow(clippy::unnecessary_box_returns)]
    #[cfg(all(test, feature = "compact-history"))]
    pub(super) fn with_history(limit: usize, encoded_limit: usize) -> Box<Self> {
        Self::with_host(limit, encoded_limit, None, None)
    }
    /// Creates the accounting for one terminal. `limit` is its total cap and
    /// `encoded_limit` the cap for compressed history. `host` is the user's pool and
    /// `floor_reservation` the floor reserved for this session; both are optional.
    /// Returned boxed because the native side keeps pointers into it.
    #[allow(clippy::unnecessary_box_returns)]
    pub(super) fn with_host(
        limit: usize,
        encoded_limit: usize,
        host: Option<Arc<HostBudget>>,
        floor_reservation: Option<Arc<HostFloor>>,
    ) -> Box<Self> {
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
                structure_used: 0,
                encoded_used: 0,
                encoded_limit,
                page_size: page_size(),
                floor: floor_reservation.as_ref().map_or(0, |floor| floor.bytes()),
                host,
                floor_reservation,
            }),
        });
        memory.abi.context = memory.state.get().cast();
        memory
    }
    /// `(bytes in use, peak bytes, refused)`.
    pub(super) fn stats(&self) -> (usize, usize, bool) {
        // SAFETY: synchronous reactor calls never overlap native callbacks;
        // return copied scalars, not a borrow across a subsequent native call.
        let state = unsafe { &*self.state.get() };
        (state.used, state.peak, state.refused)
    }
    /// `(ordinary bytes, page bytes, block count)`. Page bytes are mapped history
    /// pages plus page-list structure; ordinary excludes those and compressed data.
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
            state.used - state.mapped_used - state.structure_used - state.encoded_used,
            // Page-list nodes scale with the pages they describe.
            state.mapped_used + state.structure_used,
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
    /// Bytes held in compressed history form.
    pub(super) fn encoded_bytes(&self) -> usize {
        // SAFETY: copied accounting between synchronous native calls.
        unsafe { (*self.state.get()).encoded_used }
    }
    /// Test helper: refuse every further allocation.
    #[cfg(test)]
    pub(super) fn refuse_new_allocations(&mut self) {
        self.refuse_beyond(0);
    }
    /// Lets `headroom` more bytes through, then refuses: places a refusal
    /// at a chosen point inside a multi-allocation native operation.
    #[cfg(test)]
    pub(super) fn refuse_beyond(&mut self, headroom: usize) {
        let state = self.state.get_mut();
        state.limit = state.used.saturating_add(headroom);
    }
    /// Sizes this terminal's floor for `pages` screen pages of `page_len`
    /// payload bytes each (one screen at its geometry) [#205]. Both screens
    /// and two pages to recycle history are covered, so a full-screen
    /// program or a resize never waits on the pool; the host's base floor
    /// still covers parser and style data of an idle terminal.
    pub(super) fn reserve_screens(&mut self, pages: usize, page_len: usize) {
        let state = self.state.get_mut();
        let Some(floor_reservation) = &state.floor_reservation else {
            return;
        };
        let floor = Self::screen_floor(pages, page_len, floor_reservation.host.floor);
        if floor_reservation.resize(state.used, floor) {
            state.floor = floor;
        }
    }
    /// The floor for a screen made of `pages` pages of `page_len` bytes: both
    /// screens plus two pages to recycle, charged as page-aligned mappings, plus
    /// fixed overhead, clamped between `minimum` and `MAX_FLOOR` (or `minimum` if
    /// that is larger).
    pub(crate) fn screen_floor(pages: usize, page_len: usize, minimum: usize) -> usize {
        let charge = mapping_charge(page_len, page_size());
        pages
            .saturating_mul(2)
            .saturating_add(2)
            .saturating_mul(charge)
            .saturating_add(SCREEN_OVERHEAD)
            .clamp(minimum, MAX_FLOOR.max(minimum))
    }
    /// Test helper: this terminal's current floor.
    #[cfg(test)]
    pub(super) fn floor(&self) -> usize {
        // SAFETY: copied scalar between synchronous native calls.
        unsafe { (*self.state.get()).floor }
    }
    /// The pointer to hand to the native library as its allocator. Valid as long as
    /// this `Memory` lives and is not moved (it is boxed).
    pub(super) fn abi(&self) -> *const c_void {
        (&raw const self.abi).cast()
    }
}

impl State {
    /// The terminal reservation and the cap of the request's class: ordinary
    /// data (parser, titles, styles) has its own 256 KiB cap; encoded history
    /// has its share; page memory and page structure only the reservation.
    fn class_admits(&self, size: usize, mapped: bool, encoded: bool, structure: bool) -> bool {
        let ordinary = self.used - self.mapped_used - self.structure_used - self.encoded_used;
        size <= self.limit.saturating_sub(self.used)
            && (mapped
                || encoded
                || structure
                || size <= (256 * 1024_usize).saturating_sub(ordinary))
            && (!encoded || size <= self.encoded_limit.saturating_sub(self.encoded_used))
    }
    /// Adds an admitted allocation of `size` bytes to the counters and the peak.
    fn count(&mut self, size: usize, mapped: bool, encoded: bool, structure: bool) {
        self.used += size;
        if mapped {
            self.mapped_used += size;
        }
        if structure {
            self.structure_used += size;
        }
        if encoded {
            self.encoded_used += size;
        }
        self.peak = self.peak.max(self.used);
    }
}

/// Parser, style and page-list data of an idle terminal beside its pages.
const SCREEN_OVERHEAD: usize = 64 * 1024;

/// Bytes a page-aligned mapping of `len` payload bytes is charged: the
/// payload rounded to whole pages plus the header's prefix page.
fn mapping_charge(len: usize, page: usize) -> usize {
    len.max(1)
        .saturating_add(std::mem::size_of::<Block>().next_multiple_of(page))
        .next_multiple_of(page)
}

/// The system page size, read once; 4096 if the system reports something
/// unusable.
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
/// Native allocator entry. Returns null (a refusal) unless the request fits the
/// terminal's limit, its class cap and the pool; a refusal other than for
/// compressed history marks the terminal as refused.
///
/// `return_address` carries a class tag from the native adapter: `usize::MAX`
/// for a page-aligned, zero-filled history mapping, `usize::MAX - 1` for
/// compressed history, `STRUCTURE` for page-list nodes, anything else ordinary.
/// `alignment` is log2 of the alignment in bytes. The block header is placed
/// before the returned payload and added to the terminal's list.
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
    let structure = return_address == STRUCTURE;
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
    if !memory.class_admits(layout.size(), mapped, encoded, structure)
        || (mapped && align > memory.page_size)
        // Charged last: the host pool takes bytes only for an admitted request.
        || memory
            .host
            .as_ref()
            .is_some_and(|host| !host.charge(memory.used, layout.size(), memory.floor))
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
            // Sparse pools restore and decommit individual pages. Avoid
            // faulting untouched arena tails through a huge-page mapping.
            // SAFETY: this entire private mapping is page-aligned and live;
            // the advice changes residency, not bytes or pointer identity.
            let _ = unsafe { libc::madvise(raw, layout.size(), libc::MADV_NOHUGEPAGE) };
            raw.cast::<u8>()
        }
    } else {
        // SAFETY: validated nonzero layout; null is a recoverable refusal.
        unsafe { alloc(layout) }
    };
    let Some(base) = NonNull::new(base) else {
        if let Some(host) = &memory.host {
            host.release(memory.used, layout.size(), memory.floor);
        }
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
            structure,
        });
    }
    if let Some(mut first) = memory.first {
        // SAFETY: every live list node is owned by this context.
        unsafe {
            first.as_mut().previous = NonNull::new(block);
        }
    }
    memory.first = NonNull::new(block);
    memory.count(layout.size(), mapped, encoded, structure);
    payload.cast()
}
/// Native buffers never grow in place. The one exception to `false` is the
/// tagged fit query: whether a screen-pool item of `len` bytes would be
/// charged successfully right now. It allocates nothing and never marks the
/// terminal refused.
unsafe extern "C" fn resize(
    ctx: *mut c_void,
    _: *mut c_void,
    _: usize,
    _: u8,
    len: usize,
    return_address: usize,
) -> bool {
    if return_address != FIT_QUERY {
        return false;
    }
    // SAFETY: the C ABI points into the live boxed context; read-only here.
    let memory = unsafe { &*ctx.cast::<State>() };
    // Same charge as a page-aligned mapping: a header prefix page plus the
    // payload, rounded to whole pages.
    let page = memory.page_size;
    let Some(size) = len
        .max(1)
        .checked_add(std::mem::size_of::<Block>().next_multiple_of(page))
        .and_then(|n| n.checked_next_multiple_of(page))
    else {
        return false;
    };
    size <= memory.limit.saturating_sub(memory.used)
        && memory
            .host
            .as_ref()
            .is_none_or(|host| host.fits(memory.used, size, memory.floor))
}
/// Native allocator entry for in-place remapping. Always refuses.
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
/// Native allocator entry that frees one payload: unlinks its block, returns the
/// bytes to the counters and the pool, and unmaps or deallocates it. Also used
/// by `Memory::drop` to free whatever is left.
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
    if let Some(host) = &memory.host {
        host.release(memory.used, block.layout.size(), memory.floor);
    }
    if block.encoded {
        memory.encoded_used -= block.layout.size();
    }
    if block.structure {
        memory.structure_used -= block.layout.size();
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
/// The allocator table handed to every native terminal.
static VTABLE: Vtable = Vtable {
    alloc: allocate,
    resize,
    remap,
    free: release,
    reserved: [std::ptr::null_mut(); 4],
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

    /// The 1.0 allocator ABI reserves four trailing pointers for future hooks.
    #[test]
    fn allocator_vtable_includes_stable_reserved_slots() {
        assert_eq!(
            std::mem::size_of::<Vtable>(),
            8 * std::mem::size_of::<usize>()
        );
        assert!(VTABLE.reserved.iter().all(|slot| slot.is_null()));
    }

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
