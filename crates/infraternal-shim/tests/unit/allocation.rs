//! Real C allocator-refusal continuation checks for the resize ownership boundary [40].
use super::*;
use nix::libc;

#[repr(C)]
/// C callback table used by the allocation-refusal test engine.
struct Vtable {
    alloc: unsafe extern "C" fn(*mut c_void, usize, u8, usize) -> *mut c_void,
    resize: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> bool,
    remap: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> *mut c_void,
    free: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize),
    /// Reserved by the stable C ABI; all four slots must stay null.
    reserved: [*mut c_void; 4],
}
/// The allocator table is immutable and its reserved slots are null.
unsafe impl Sync for Vtable {}
#[repr(C)]
struct Allocator {
    context: *mut Context,
    vtable: *const Vtable,
}
struct Context {
    remaining: usize,
    refusing: bool,
}
unsafe extern "C" fn allocate(
    ctx: *mut c_void,
    len: usize,
    alignment: u8,
    return_address: usize,
) -> *mut c_void {
    // SAFETY: the boxed fixture context outlives every synchronous engine call.
    let context = unsafe { &mut *ctx.cast::<Context>() };
    if context.refusing {
        if context.remaining == 0 {
            return std::ptr::null_mut();
        }
        context.remaining -= 1;
    }
    let mut out = std::ptr::null_mut();
    // SAFETY: POSIX writes one pointer; alignment is a power of two from the C ABI.
    if unsafe {
        libc::posix_memalign(
            &raw mut out,
            (1_usize << alignment).max(std::mem::size_of::<usize>()),
            len,
        )
    } == 0
    {
        if return_address == usize::MAX {
            // Page pools rely on fresh zero-filled storage, including arena
            // backing whose requested alignment is less than a page.
            unsafe {
                out.cast::<u8>().write_bytes(0, len);
            }
        }
        out
    } else {
        std::ptr::null_mut()
    }
}
unsafe extern "C" fn resize_memory(
    _: *mut c_void,
    _: *mut c_void,
    _: usize,
    _: u8,
    _: usize,
    _: usize,
) -> bool {
    false
}
unsafe extern "C" fn remap_memory(
    _: *mut c_void,
    _: *mut c_void,
    _: usize,
    _: u8,
    _: usize,
    _: usize,
) -> *mut c_void {
    std::ptr::null_mut()
}
unsafe extern "C" fn free_memory(_: *mut c_void, memory: *mut c_void, _: usize, _: u8, _: usize) {
    // SAFETY: pointer was uniquely allocated by posix_memalign and released once.
    unsafe {
        libc::free(memory);
    }
}
/// Stable callbacks shared by native terminals created in these unit tests.
static VTABLE: Vtable = Vtable {
    alloc: allocate,
    resize: resize_memory,
    remap: remap_memory,
    free: free_memory,
    reserved: [std::ptr::null_mut(); 4],
};

// The context outlives the closure and every valid native handle. Refusal is
// enabled only after both retained screens have been constructed.
pub(crate) const PREFIX: &[u8] = b"\x1bcPRIMARY\x1b[?47hALT\x1b[?47l";
/// Builds a populated native terminal, then refuses its `step`th later allocation.
/// Runs `run` with the engine while the allocator context and callback table live.
pub(crate) fn with_refusing_engine(step: usize, run: impl FnOnce(Engine)) {
    let mut context = Box::new(Context {
        remaining: 0,
        refusing: false,
    });
    let allocator = Allocator {
        context: &raw mut *context,
        vtable: &raw const VTABLE,
    };
    let mut raw = std::ptr::null_mut();
    // SAFETY: allocator, vtable and boxed context outlive the synchronous closure.
    assert_eq!(
        unsafe { ghostty_terminal_new((&raw const allocator).cast(), &raw mut raw, 80, 24,) },
        0
    );
    // libghostty-vt 1.0 sets the history cap after creating its opaque handle.
    // SAFETY: successful creation returned a uniquely owned terminal, and the
    // scalar option value remains live for this synchronous call.
    let max_scrollback = 17 * 1024 * 1024_usize;
    let result = unsafe {
        ghostty_terminal_set(
            raw,
            TERMINAL_OPT_SCROLLBACK_MAX_BYTES,
            (&raw const max_scrollback).cast(),
        )
    };
    if result != 0 {
        // SAFETY: creation succeeded and this fixture still owns the handle.
        unsafe { ghostty_terminal_free(raw) };
        panic!("native scrollback option failed: {result}");
    }
    let mut engine = Engine(
        Some(NonNull::new(raw).unwrap()),
        #[cfg(feature = "process-per-user")]
        None,
    );
    engine.process(PREFIX);
    context.refusing = true;
    context.remaining = step;
    run(engine);
}

/// After a failed native resize, later reads observe a retired terminal.
#[test]
fn resize_allocation_refusal_retires_native_handle() {
    let step = std::env::var("VT_ALLOCATION_STEP").map_or(2, |value| value.parse().unwrap());
    with_refusing_engine(step, |mut engine| {
        if engine.resize(20_000, 2).is_err() {
            let mut buffer = vec![0; 1024 * 1024];
            assert!(engine.try_snapshot(&mut buffer, 0).is_err());
            engine.process(b"later output");
            assert_eq!(engine.approximate_snapshot(&mut buffer), 0);
            assert_eq!(engine.history_rows().unwrap(), 0);
            assert_eq!(engine.state_difference(&engine), usize::MAX);
            assert_eq!(engine.difference(&engine), usize::MAX);
            assert!(engine.resize(80, 24).is_err());
        }
    });
}
