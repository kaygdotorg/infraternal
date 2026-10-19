//! Coverage-guided production VT stream/fragmentation harness, absent from product builds [D270].
#![no_main]
#![allow(dead_code)]
// Source inclusion instruments the actual Rust carry parser without introducing
// a public product API or a release fault hook. The pinned native engine remains
// linked by the shim's existing build; native C/Zig coverage is not claimed.
pub use infraternal_shim::{frame, ring};
#[path = "../../crates/infraternal-shim/src/terminal.rs"]
mod terminal;
#[path = "../../crates/infraternal-shim/src/terminal_limits.rs"]
mod terminal_limits;
#[path = "../../crates/infraternal-shim/src/terminal_memory.rs"]
mod terminal_memory;
#[path = "../../crates/infraternal-shim/src/terminal_native.rs"]
mod terminal_native;
use libfuzzer_sys::fuzz_target;

const MARKER: &[u8] = b"ppu-fuzz-after-resize";
#[derive(Default)]
struct PrintedMarker {
    matched: usize,
    seen: bool,
}
impl vte::Perform for PrintedMarker {
    fn print(&mut self, value: char) {
        if self.seen {
            return;
        }
        self.matched = if value == char::from(MARKER[self.matched]) {
            self.matched + 1
        } else {
            usize::from(value == char::from(MARKER[0]))
        };
        self.seen = self.matched == MARKER.len();
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 131_072 {
        return;
    }
    let mut state = terminal::Terminal::with_history_budget(80, 24, 65536).unwrap();
    let chunk = usize::from(data.first().copied().unwrap_or(0)) + 1;
    for part in data.chunks(chunk) {
        state.process(part);
    }
    if let Ok(snapshot) = state.snapshot() {
        assert!(snapshot.len() <= frame::MAX_FRAME);
    }
    assert!(state.approximate_snapshot().len() <= frame::MAX_FRAME);
    // Consume unterminated OSC/CSI and malformed UTF-8 carry before proving
    // that an ordinary marker is accepted after cancel/reset and resize.
    state.process(b"\x18\x1bcppu-fuzz-marker\r\n");
    let _ = state.resize(81, 25);
    state.process(b"\x18\x1bcppu-fuzz-after-resize\r\n");
    assert!(state.memory().0 <= 8 * 1024 * 1024);
    let repaint = state.approximate_snapshot();
    // The bounded painter can put attributes/cursor controls between printed
    // cells. Inspect print actions rather than requiring contiguous wire bytes.
    let mut printed = PrintedMarker::default();
    vte::Parser::new().advance(&mut printed, &repaint);
    assert!(printed.seen);
    if let Ok(snapshot) = state.snapshot() {
        assert!(snapshot.windows(MARKER.len()).any(|s| s == MARKER));
    }
});
