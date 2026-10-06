//! Real C allocator-refusal continuation checks for the resize ownership boundary [40].
use super::*;
use nix::libc;

#[repr(C)]
struct Vtable {
    alloc: unsafe extern "C" fn(*mut c_void, usize, u8, usize) -> *mut c_void,
    resize: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> bool,
    remap: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize, usize) -> *mut c_void,
    free: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, u8, usize),
}
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
    _: usize,
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
            usize::from(alignment).max(std::mem::size_of::<usize>()),
            len,
        )
    } == 0
    {
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
static VTABLE: Vtable = Vtable {
    alloc: allocate,
    resize: resize_memory,
    remap: remap_memory,
    free: free_memory,
};

// The context outlives the closure and every valid native handle. Refusal is
// enabled only after both retained screens have been constructed.
pub(crate) const PREFIX: &[u8] = b"\x1bcPRIMARY\x1b[?47hALT\x1b[?47l";
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
        unsafe {
            ghostty_terminal_new(
                (&raw const allocator).cast(),
                &raw mut raw,
                Options {
                    cols: 80,
                    rows: 24,
                    max_scrollback: 17 * 1024 * 1024,
                },
            )
        },
        0
    );
    let mut engine = Engine(Some(NonNull::new(raw).unwrap()));
    engine.process(PREFIX);
    context.refusing = true;
    context.remaining = step;
    run(engine);
}

#[test]
fn resize_allocation_refusal_retires_native_handle() {
    let step = std::env::var("VT_ALLOCATION_STEP").map_or(2, |value| value.parse().unwrap());
    with_refusing_engine(step, |mut engine| {
        if engine.resize(20_000, 2).is_err() {
            let mut buffer = vec![0; 1024 * 1024];
            assert!(engine.try_snapshot(&mut buffer, 0).is_err());
            engine.process(b"later output");
            assert_eq!(engine.approximate_snapshot(&mut buffer), 0);
            assert_eq!(engine.history_rows(), 0);
            assert_eq!(engine.state_difference(&engine), usize::MAX);
            assert_eq!(engine.difference(&engine), usize::MAX);
            assert!(engine.resize(80, 24).is_err());
        }
    });
}
