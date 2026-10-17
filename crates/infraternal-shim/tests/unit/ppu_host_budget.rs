//! Shared-host native memory follows live pages and fits its budgets [D270, #205].
//!
//! The history share must be reachable without allocation refusal, memory
//! must return after history or geometry shrinks, and terminals sharing a
//! host budget recycle their own history instead of exceeding it.
use super::*;
use crate::terminal_memory::HostBudget;
use crate::terminal_native::{ITEM_HEADER_SHARE, SCREEN_RESERVATION};

fn lines(terminal: &mut Terminal, bytes: usize) {
    let mut line = [b'h'; 81];
    line[79] = b'\r';
    line[80] = b'\n';
    let chunk = line.repeat(200);
    let mut written = 0;
    while written < bytes {
        terminal.process(&chunk);
        written += chunk.len();
    }
}

/// Every share the host can hand out fills completely and then recycles,
/// with page headers inside the eighth the reservation adds for them.
#[test]
fn every_history_share_fills_and_recycles_inside_its_reservation() {
    for history in [17 * 1024 * 1024, 7 * 1024 * 1024, 1024 * 1024, 65536] {
        let mut terminal = Terminal::with_history_budget(80, 24, history).unwrap();
        // RIS makes the state certifiable for a faithful snapshot.
        terminal.process(b"\x1bc");
        lines(&mut terminal, 3 * history + 400_000);
        let (used, peak, refused) = terminal.memory();
        let (_, pages, _) = terminal.engine.allocation_classes();
        assert!(
            !refused,
            "share {history}: refused (used {used}, peak {peak})"
        );
        assert!(
            terminal.snapshot().is_ok(),
            "share {history}: exact snapshot lost"
        );
        assert!(
            pages <= history + history / ITEM_HEADER_SHARE + SCREEN_RESERVATION / 8,
            "share {history}: page mappings {pages} exceed the share and its headers"
        );
        // The share is used, not merely bounded: recycling starts only
        // once the pages reach it.
        if history >= 1024 * 1024 {
            assert!(
                pages >= history * 9 / 10,
                "share {history}: recycling began at {pages} B of pages"
            );
        }
    }
}

/// Erasing history, a full reset and a wide geometry all give their pages back.
#[test]
fn erased_history_reset_and_geometry_return_native_memory() {
    let mut terminal = Terminal::with_history_budget(80, 24, 2 * 1024 * 1024).unwrap();
    terminal.process(b"\x1bc");
    let baseline = terminal.memory().0;
    lines(&mut terminal, 4 * 1024 * 1024);
    let full = terminal.memory().0;
    assert!(full > baseline + 1024 * 1024);
    terminal.process(b"\x1b[3J");
    let erased = terminal.memory().0;
    assert!(
        erased <= baseline + 256 * 1024,
        "erased history kept {erased} B (baseline {baseline}, full {full})"
    );
    lines(&mut terminal, 4 * 1024 * 1024);
    terminal.process(b"\x1bc");
    let reset = terminal.memory().0;
    assert!(
        reset <= baseline + 256 * 1024,
        "reset kept {reset} B (baseline {baseline})"
    );
    terminal.resize(400, 160).unwrap();
    lines(&mut terminal, 200_000);
    terminal.resize(80, 24).unwrap();
    terminal.process(b"\x1b[3J");
    let (used, _, refused) = terminal.memory();
    assert!(!refused);
    assert!(
        used <= baseline + 256 * 1024,
        "wide geometry kept {used} B (baseline {baseline})"
    );
}

/// Terminals sharing a host pool smaller than the sum of their shares stay
/// exact: growth recycles their own oldest history instead of being refused,
/// and the host total never passes its floors plus the pool.
#[test]
fn shared_host_budget_bounds_the_sum_and_keeps_every_terminal_exact() {
    const TERMINALS: usize = 8;
    const FLOOR: usize = 256 * 1024;
    let history = 2 * 1024 * 1024;
    // Half of one share for all eight terminals together.
    let limit = history / 2;
    let host = HostBudget::new(limit, FLOOR);
    let mut terminals: Vec<_> = (0..TERMINALS)
        .map(|_| {
            let mut terminal =
                Terminal::with_host_budget(80, 24, history, Some(host.clone())).unwrap();
            terminal.process(b"\x1bc");
            terminal
        })
        .collect();
    let mut peak = 0;
    for round in 0..6 {
        for terminal in &mut terminals {
            lines(terminal, history / 2);
            terminal.process(format!("round {round}\r\n").as_bytes());
            peak = peak.max(host.used());
        }
    }
    assert!(
        peak <= limit,
        "host pool use {peak} passed its limit {limit}"
    );
    // The pool binds: together the terminals wanted far more than it holds.
    assert!(
        peak + 64 * 1024 > limit,
        "host pool {limit} never bound (peak {peak})"
    );
    let excess: usize = terminals
        .iter()
        .map(|t| t.memory().0.saturating_sub(FLOOR))
        .sum();
    assert_eq!(
        host.used(),
        excess,
        "host accounting differs from its terminals"
    );
    let total: usize = terminals.iter().map(|t| t.memory().0).sum();
    assert!(total <= TERMINALS * FLOOR + limit);
    for (index, terminal) in terminals.iter().enumerate() {
        assert!(!terminal.memory().2, "terminal {index} reached refusal");
        assert!(
            terminal.snapshot().is_ok(),
            "terminal {index} lost exact state"
        );
    }
    drop(terminals);
    assert_eq!(host.used(), 0, "dropped terminals left host charges");
}

/// Receipt for #205: idle size, the r2 resize scenarios and a full share.
/// Run with `--nocapture`; the assertions above are the gates.
#[test]
fn report_native_memory_numbers() {
    let mut idle = Terminal::with_history_budget(80, 24, 65536).unwrap();
    idle.process(b"\x1bc");
    let (ordinary, pages, blocks) = idle.engine.allocation_classes();
    eprintln!(
        "idle 80x24: used {} ordinary {ordinary} pages {pages} blocks {blocks}",
        idle.memory().0
    );
    let mut one = Terminal::with_history_budget(80, 24, 65536).unwrap();
    one.process(b"\x1bc");
    one.process(&b"storm line\r\n".repeat(500));
    let baseline = one.memory().0;
    one.resize(400, 200).unwrap();
    one.resize(80, 24).unwrap();
    lines(&mut one, 5000 * 81);
    eprintln!(
        "64 KiB share: baseline {baseline}, one 400x200 resize and 5000 lines {}",
        one.memory().0
    );
    let mut storm = Terminal::with_history_budget(80, 24, 65536).unwrap();
    storm.process(b"\x1bc");
    storm.process(&b"storm line\r\n".repeat(500));
    for round in 0..400_u16 {
        let cols = 20 + (round * 37) % 400;
        let rows = 5 + (round * 13) % 400;
        let cols = if usize::from(cols) * usize::from(rows) > 200_000 {
            80
        } else {
            cols
        };
        let _ = storm.resize(cols, rows);
        storm.process(b"x\r\n");
    }
    storm.resize(80, 24).unwrap();
    eprintln!("64 KiB share: 400-resize storm {}", storm.memory().0);
    let mut full = Terminal::with_history_budget(80, 24, 17 * 1024 * 1024).unwrap();
    full.process(b"\x1bc");
    lines(&mut full, 40 * 1024 * 1024);
    let (used, peak, refused) = full.memory();
    eprintln!("17 MiB share after 40 MB: used {used} peak {peak} refused {refused}");
}
