//! Regression checks for shared-host history preservation during geometry changes [#205].
use super::*;
use crate::terminal_memory::HostBudget;

const FLOOR: usize = 256 * 1024;
const POOL: usize = 80 * 1024 * 1024;

/// Seed the same reset state used by the real login terminal.
fn bounded_terminal(history: usize, host: &std::sync::Arc<HostBudget>) -> Terminal {
    let mut terminal = Terminal::with_host_budget(80, 24, history, Some(host.clone())).unwrap();
    terminal.process(b"\x1bc");
    terminal
}

/// Preserves history rows that a taller, wider resize moves onto the screen.
#[test]
fn taller_widening_keeps_history_rows_that_move_onto_the_screen() {
    const HISTORY: usize = 64 * 1024;
    const COLS: u16 = 133;
    const ROWS: u16 = 40;
    let host = HostBudget::new(POOL, FLOOR);
    let mut bounded = bounded_terminal(HISTORY, &host);
    let mut reference = Terminal::with_history_budget(80, 24, 48 * 1024 * 1024).unwrap();
    reference.process(b"\x1bc");

    let mut stream = Vec::new();
    for line in 0..3000_usize {
        stream.extend_from_slice(format!("{line:08} {}\r\n", "p".repeat(61)).as_bytes());
    }
    stream.extend_from_slice(b"$ ");
    for chunk in stream.chunks(8192) {
        bounded.process(chunk);
        reference.process(chunk);
    }

    let available_history = bounded.retained_history_rows().unwrap();
    let needed_history = usize::from(ROWS - 24);
    assert!(
        available_history >= needed_history,
        "fixture holds {available_history} history rows, needs {needed_history}"
    );

    bounded.resize(COLS, ROWS).unwrap();
    reference.resize(COLS, ROWS).unwrap();
    assert_eq!(
        bounded.engine.difference(&reference.engine),
        0,
        "taller widening dropped rows needed by the new screen (history {available_history})"
    );
}
