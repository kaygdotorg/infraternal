//! Break-it review r3 (#205): the same mixed stream and reflow, built in the
//! default and the shared-host configuration, so a native abort can be
//! attributed to the build that patches the engine.
use super::*;

/// Mixed styled, wrapped, wide, combining and hyperlinked lines.
pub(super) fn mixed_stream(lines: usize) -> Vec<u8> {
    let mut stream = Vec::new();
    for n in 0..lines {
        let color = 31 + n % 7;
        let body = match n % 5 {
            0 => format!("\x1b[{color}m{n:08} plain\x1b[0m"),
            1 => format!("{n:08} {}", "wrap-".repeat(30)),
            2 => format!("{n:08} 漢字かな{}", "é".repeat(20)),
            3 => format!("\x1b[1;4;{color}m{n:08}\x1b[0m e\u{301}\u{1f468}\u{200d}\u{1f469}"),
            _ => format!("\x1b]8;;https://example.invalid/{n}\x1b\\{n:08} link\x1b]8;;\x1b\\"),
        };
        stream.extend_from_slice(body.as_bytes());
        stream.extend_from_slice(b"\r\n");
    }
    stream
}

/// A per-session terminal with full default scrollback reflows a long mixed
/// history without aborting the process.
#[test]
fn review_r3_default_terminal_reflows_long_mixed_history() {
    let mut terminal = Terminal::new(80, 24).unwrap();
    terminal.process(b"\x1bc");
    for chunk in mixed_stream(20_000).chunks(4096) {
        terminal.process(chunk);
    }
    for (cols, rows) in [(50, 20), (133, 40), (80, 24)] {
        terminal.resize(cols, rows).unwrap();
    }
    assert!(terminal.snapshot().is_ok());
}
