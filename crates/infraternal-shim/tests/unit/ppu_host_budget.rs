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
/// and the host total, including protected floors, stays inside the pool.
#[test]
fn shared_host_budget_bounds_the_sum_and_keeps_every_terminal_exact() {
    const TERMINALS: usize = 8;
    const FLOOR: usize = 256 * 1024;
    let history = 2 * 1024 * 1024;
    // One quarter of one share for all eight terminals together, plus their
    // protected floors, all inside the total host cap.
    let extra_limit = history / 4;
    let limit = extra_limit + TERMINALS * FLOOR;
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
        peak <= extra_limit,
        "host pool use {peak} passed its limit {limit}"
    );
    // Whole native page-pool items can leave an unused tail at the cap. The
    // shared limit must still see sustained pressure across these terminals.
    assert!(
        peak >= extra_limit * 2 / 3,
        "shared host pool use {peak} did not reach two thirds of {extra_limit}"
    );
    let excess: usize = terminals
        .iter()
        .map(|t| t.memory().0.saturating_sub(t.engine.host_floor()))
        .sum();
    assert_eq!(
        host.used(),
        excess,
        "host accounting differs from its terminals"
    );
    let total: usize = terminals.iter().map(|t| t.memory().0).sum();
    let floors: usize = terminals.iter().map(|t| t.engine.host_floor()).sum();
    assert!(floors <= limit);
    assert!(total <= limit);
    assert!(host.total_used() <= limit);
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

/// PPU-R3-1 (#205): page-list nodes grow with the page count, and 80x32
/// pages make a full 17 MiB share hundreds of nodes; a reflow briefly holds
/// both lists. They are page structure, charged to the reservation, not the
/// 256 KiB ordinary-data cap for parser, title and style data, which they
/// once exhausted mid-reflow.
#[test]
fn page_nodes_never_fill_the_ordinary_data_cap() {
    let history = 17 * 1024 * 1024;
    let mut terminal = Terminal::with_history_budget(80, 24, history).unwrap();
    terminal.process(b"\x1bc");
    let mut short = Vec::new();
    for n in 0..200_000_usize {
        short.extend_from_slice(format!("{n:08}\r\n").as_bytes());
    }
    terminal.process(&short);
    for (cols, rows) in [(50, 20), (80, 24), (60, 30), (80, 24)] {
        terminal.resize(cols, rows).unwrap();
        let (ordinary, pages, _) = terminal.engine.allocation_classes();
        eprintln!("{cols}x{rows}: ordinary {ordinary} pages+nodes {pages}");
        assert!(!terminal.memory().2, "{cols}x{rows}: refused");
        assert!(
            ordinary < 128 * 1024,
            "{cols}x{rows}: ordinary data {ordinary}"
        );
    }
}

/// PPU-R3-1 (#205): a row wider than the 80x32 standard page fits fewer
/// rows per page, so widening a full history needs more bytes than the
/// share (about 1.7x at 133 columns, 5x at 400) and the resize allocated
/// all of it before any prune. Widening now keeps the newest history that
/// fits the share at the new width, with and without reflow.
#[test]
fn widening_a_full_history_stays_inside_its_share() {
    let history = 17 * 1024 * 1024;
    let stream = super::review_r3_default::mixed_stream(40_000);
    for wraparound in [true, false] {
        let mut terminal = Terminal::with_history_budget(80, 24, history).unwrap();
        terminal.process(b"\x1bc");
        if !wraparound {
            terminal.process(b"\x1b[?7l");
        }
        for chunk in stream.chunks(4096) {
            terminal.process(chunk);
        }
        for (cols, rows) in [(133, 40), (400, 100), (80, 24), (400, 160), (200, 50)] {
            terminal.resize(cols, rows).unwrap();
            let (used, peak, refused) = terminal.memory();
            let kept = terminal.retained_history_rows().unwrap();
            eprintln!(
                "wraparound {wraparound} {cols}x{rows}: used {used} peak {peak} history rows {kept}"
            );
            assert!(!refused, "{cols}x{rows}: refused");
            assert!(kept > 1000, "{cols}x{rows}: kept only {kept} history rows");
            let limit = SCREEN_RESERVATION + history + history / ITEM_HEADER_SHARE;
            assert!(peak <= limit, "{cols}x{rows}: peak {peak} over {limit}");
        }
        terminal.process(b"after widening\r\n");
        assert!(!terminal.memory().2);
    }
}

/// D310: laptop-sized screen floors and history remain inside the maximum
/// pool; admission does not rely on floors living outside the user cap.
#[test]
fn laptop_screens_come_from_their_floors_not_the_pool() {
    const SESSIONS: usize = 300;
    const HISTORY: usize = 64 * 1024 * 1024;
    let pool = 512 * 1024 * 1024;
    let share = HISTORY / SESSIONS;
    let host = HostBudget::new(pool, 256 * 1024);
    let mut terminals: Vec<_> = (0..SESSIONS)
        .map(|_| {
            let mut terminal =
                Terminal::with_host_budget(200, 50, share, Some(host.clone())).unwrap();
            terminal.process(b"\x1bc");
            terminal
        })
        .collect();
    let line = format!("{}\r\n", "x".repeat(199));
    for terminal in &mut terminals {
        terminal.process(&line.repeat(3 * share / 200).into_bytes());
    }
    let after_history = host.used();
    let mut screen = b"\x1b[?1049h\x1b[2J".to_vec();
    for row in 1..=55 {
        screen.extend_from_slice(format!("\x1b[{row};1H\x1b[7m{}", "A".repeat(210)).as_bytes());
    }
    for terminal in &mut terminals {
        terminal.resize(210, 55).unwrap();
        terminal.process(&screen);
    }
    let refused = terminals.iter().filter(|t| t.memory().2).count();
    let floors: usize = terminals.iter().map(|t| t.engine.host_floor()).sum();
    eprintln!(
        "{SESSIONS} sessions at 210x55: pool {after_history} after history, {} after \
         full-screen + resize (limit {pool}); floor {} each, {floors} total; refused {refused}",
        host.used(),
        terminals[0].engine.host_floor()
    );
    assert_eq!(
        refused,
        0,
        "{refused} sessions refused (pool {}/{pool})",
        host.used()
    );
}
