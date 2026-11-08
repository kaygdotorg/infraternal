//! Break-it review r3 (#205, D270): the host-wide native pool must stay fair
//! and exact for every session of one host, and its accounting must balance.
//!
//! Host constants mirror `user_host.rs`: each session reserves its 256 KiB
//! floor inside the maximum 512 MiB pool. Shares follow
//! `HOST_HISTORY_BYTES / sessions`, capped at 17 MiB.
use super::*;
use crate::terminal_memory::HostBudget;

const FLOOR: usize = 256 * 1024;
const HISTORY: usize = 64 * 1024 * 1024;
const POOL: usize = 512 * 1024 * 1024;

fn share(sessions: usize) -> usize {
    (HISTORY / sessions).min(17 * 1024 * 1024)
}

fn host_terminal(
    cols: u16,
    rows: u16,
    sessions: usize,
    host: &std::sync::Arc<HostBudget>,
) -> Terminal {
    let mut terminal =
        Terminal::with_host_budget(cols, rows, share(sessions), Some(host.clone())).unwrap();
    // RIS only so a faithful snapshot is representable at all (see r3-RIS).
    terminal.process(b"\x1bc");
    terminal
}

fn numbered(terminal: &mut Terminal, tag: usize, from: usize, count: usize, width: usize) {
    let mut out = Vec::with_capacity(count * (width + 2));
    for n in from..from + count {
        let head = format!("{tag:04}:{n:08} ");
        out.extend_from_slice(head.as_bytes());
        out.resize(out.len() + width.saturating_sub(head.len()), b'.');
        out.extend_from_slice(b"\r\n");
        if out.len() > 64 * 1024 {
            terminal.process(&out);
            out.clear();
        }
    }
    terminal.process(&out);
}

fn excess(terminals: &[Terminal]) -> usize {
    terminals
        .iter()
        .map(|t| t.memory().0.saturating_sub(t.engine.host_floor()))
        .sum()
}

fn verdicts(terminals: &[Terminal]) -> (Vec<usize>, Vec<usize>) {
    let refused = terminals
        .iter()
        .enumerate()
        .filter(|(_, t)| t.memory().2)
        .map(|(i, _)| i)
        .collect();
    let inexact = terminals
        .iter()
        .enumerate()
        .filter(|(_, t)| t.snapshot().is_err())
        .map(|(i, _)| i)
        .collect();
    (refused, inexact)
}

/// r3-RIS: the 49083d3b8 edit seeds RIS before the r2 history-share test.
/// The memory claim must hold for a terminal that never sees RIS, which is
/// every real login shell: refusal latches approximation regardless of RIS.
#[test]
fn review_r3_history_share_without_ris_never_refuses() {
    for sessions in [1_usize, 4, 10] {
        let history = share(sessions);
        let mut terminal = Terminal::with_history_budget(80, 24, history).unwrap();
        numbered(&mut terminal, 0, 0, 500_000, 79);
        let (used, peak, refused) = terminal.memory();
        assert!(
            !refused,
            "{sessions} session(s), share {history}: refused without RIS (used {used}, peak {peak})"
        );
    }
}

/// Four sessions (16 MiB shares). One noisy session takes a large geometry
/// with an alternate screen and floods; three quiet sessions fill their
/// history. A quiet session that then opens a full-screen program (alternate
/// screen) or resizes must keep exact state: its own share is not the
/// neighbour's to take.
#[test]
fn review_r3_noisy_neighbour_does_not_make_quiet_sessions_approximate() {
    const SESSIONS: usize = 4;
    let host = HostBudget::new(POOL, FLOOR);
    let mut terminals: Vec<_> = (0..SESSIONS)
        .map(|_| host_terminal(80, 24, SESSIONS, &host))
        .collect();
    // Noisy: the widest geometry the cell limit allows, alternate screen
    // painted, then back to primary and a flood that fills its share.
    terminals[0].resize(400, 160).unwrap();
    terminals[0].process(b"\x1b[?1049h");
    for row in 0..160 {
        terminals[0].process(format!("\x1b[{};1H{}", row + 1, "N".repeat(400)).as_bytes());
    }
    terminals[0].process(b"\x1b[?1049l");
    numbered(&mut terminals[0], 0, 0, 80_000, 399);
    for (index, terminal) in terminals.iter_mut().enumerate().skip(1) {
        numbered(terminal, index, 0, 300_000, 79);
    }
    let before = host.used();
    // Quiet session 3 opens a full-screen program, and session 2 resizes.
    terminals[3].process(b"\x1b[?1049h\x1b[2J\x1b[Hvim");
    // Taller, not wider: widening with this much history aborts (PPU-R3-1).
    terminals[2].resize(80, 40).unwrap_or(());
    numbered(&mut terminals[1], 1, 300_000, 1000, 79);
    let (refused, inexact) = verdicts(&terminals);
    eprintln!(
        "noisy: pool {before}/{POOL} before quiet actions, {} after; per-session used {:?}",
        host.used(),
        terminals.iter().map(|t| t.memory().0).collect::<Vec<_>>()
    );
    assert!(
        refused.is_empty() && inexact.is_empty(),
        "quiet sessions lost exact state to a noisy neighbour: refused {refused:?}, \
         inexact {inexact:?} (pool {}/{POOL})",
        host.used()
    );
}

/// 100 sessions at an ordinary laptop geometry (200x50) fill their shares,
/// then each opens a full-screen program and resizes a little. Their floors
/// and all history remain accounted inside the D310 maximum pool.
#[test]
fn review_r3_hundred_laptop_sessions_keep_exact_state() {
    const SESSIONS: usize = 100;
    let host = HostBudget::new(POOL, FLOOR);
    let mut terminals: Vec<_> = (0..SESSIONS)
        .map(|_| host_terminal(200, 50, SESSIONS, &host))
        .collect();
    for (index, terminal) in terminals.iter_mut().enumerate() {
        numbered(terminal, index, 0, 3 * share(SESSIONS) / 200, 199);
    }
    let filled = host.used();
    for terminal in &mut terminals {
        terminal.process(b"\x1b[?1049h\x1b[2J\x1b[Hfull screen");
        let _ = terminal.resize(210, 55);
    }
    let (refused, inexact) = verdicts(&terminals);
    eprintln!(
        "laptop x100: pool {filled}/{POOL} after history, {} after full-screen + resize; \
         refused {} inexact {}",
        host.used(),
        refused.len(),
        inexact.len()
    );
    assert!(
        refused.is_empty() && inexact.is_empty(),
        "{} of {SESSIONS} sessions refused, {} inexact (pool {}/{POOL}); first refused {:?}",
        refused.len(),
        inexact.len(),
        host.used(),
        refused.iter().take(8).collect::<Vec<_>>()
    );
}

/// 1,000 idle 80x24 sessions plus one flooding session: the flood stays in
/// its share, and every idle session can still print and resize exactly.
#[test]
fn review_r3_thousand_sessions_and_one_flood() {
    const SESSIONS: usize = 1000;
    let host = HostBudget::new(POOL, FLOOR);
    let mut terminals: Vec<_> = (0..SESSIONS)
        .map(|_| host_terminal(80, 24, SESSIONS, &host))
        .collect();
    for (index, terminal) in terminals.iter_mut().enumerate() {
        numbered(terminal, index, 0, 30, 40);
    }
    let idle = host.used();
    let idle_used = terminals[1].memory().0;
    numbered(&mut terminals[0], 0, 0, 1_000_000, 79);
    let flood = terminals[0].memory().0;
    for (index, terminal) in terminals.iter_mut().enumerate().skip(1) {
        numbered(terminal, index, 30, 200, 79);
        let _ = terminal.resize(100, 30);
    }
    let (refused, inexact) = verdicts(&terminals);
    eprintln!(
        "1000+flood: idle session used {idle_used}, pool {idle} idle, flood session {flood}, \
         pool {} after; refused {} inexact {}",
        host.used(),
        refused.len(),
        inexact.len()
    );
    assert!(flood <= share(SESSIONS) + share(SESSIONS) / 8 + 8 * 1024 * 1024);
    assert!(
        refused.is_empty() && inexact.is_empty(),
        "{} of {SESSIONS} refused, {} inexact (pool {}/{POOL})",
        refused.len(),
        inexact.len(),
        host.used()
    );
    assert_eq!(host.used(), excess(&terminals));
}

/// Pool charges equal the sum of each terminal's bytes above its floor through
/// refusal, failed resize recovery, RIS, erase and drop. A leak here
/// permanently shrinks every other session's pool.
#[test]
fn review_r3_host_accounting_balances_through_recovery() {
    const SESSIONS: usize = 4;
    // A small pool so refusals and failed resizes really happen.
    let host = HostBudget::new(6 * 1024 * 1024, FLOOR);
    let mut terminals: Vec<_> = (0..SESSIONS)
        .map(|_| host_terminal(80, 24, SESSIONS, &host))
        .collect();
    let mut failures = 0;
    for round in 0..12_usize {
        for (index, terminal) in terminals.iter_mut().enumerate() {
            numbered(terminal, index, round * 10_000, 10_000, 79);
            let (cols, rows) = match (round + index) % 4 {
                0 => (300, 120),
                1 => (80, 24),
                2 => (160, 60),
                _ => (40, 10),
            };
            if terminal.resize(cols, rows).is_err() {
                failures += 1;
            }
            match round % 5 {
                1 => terminal.process(b"\x1b[3J"),
                2 => terminal.process(b"\x1bc"),
                3 => terminal.process(b"\x1b[?1049h\x1b[2Jalt"),
                4 => terminal.process(b"\x1b[?1049l"),
                _ => {}
            }
        }
        assert_eq!(
            host.used(),
            excess(&terminals),
            "round {round}: pool charge differs from terminals above floor"
        );
    }
    eprintln!(
        "accounting: {failures} failed resizes, pool {}",
        host.used()
    );
    drop(terminals);
    assert_eq!(host.used(), 0, "dropped terminals left pool charges");
}

/// Recycling the oldest page keeps every retained row exact: the retained
/// tail (256 rows, the snapshot contract), the visible screen, and the reflow
/// of both across a narrowing and widening resize equal an unbounded
/// reference fed the same stream. Lines wrap, carry styles, wide and
/// combining characters so heap-owned and pool pages both recycle.
#[test]
fn review_r3_recycled_history_matches_unbounded_reference() {
    for history in [64 * 1024, 655 * 1024, 1024 * 1024] {
        let host = HostBudget::new(POOL, FLOOR);
        let mut bounded = Terminal::with_host_budget(80, 24, history, Some(host.clone())).unwrap();
        // The per-session engine aborts on widening in this build (r3-1),
        // so the reference is a bounded terminal with a larger share.
        let mut reference =
            Terminal::with_history_budget(80, 24, (history * 4).min(6 * 1024 * 1024)).unwrap();
        for terminal in [&mut bounded, &mut reference] {
            terminal.process(b"\x1bc");
        }
        let mut stream = Vec::new();
        for n in 0..(6 * history / 100).max(20_000) {
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
        for chunk in stream.chunks(4096) {
            bounded.process(chunk);
            reference.process(chunk);
        }
        let check = |stage: &str, bounded: &Terminal, reference: &Terminal| {
            assert!(!bounded.memory().2, "share {history} {stage}: refused");
            let difference = reference.research_state_difference(bounded);
            assert_eq!(
                difference,
                0,
                "share {history} {stage}: recycled terminal differs from reference \
                 (code {difference}, history rows {} vs {})",
                bounded.retained_history_rows().unwrap(),
                reference.retained_history_rows().unwrap()
            );
            // The faithful painter refuses some wrap states in every build;
            // recycling must not refuse a state the reference can paint.
            let Ok(snapshot) = bounded.snapshot() else {
                assert!(
                    reference.snapshot().is_err(),
                    "share {history} {stage}: reference paints exactly, recycled terminal cannot"
                );
                return;
            };
            let mut replay = Terminal::new(bounded.dimensions.0, bounded.dimensions.1).unwrap();
            replay.process(b"\x1bc");
            replay.process(&snapshot);
            assert_eq!(
                bounded.research_state_difference(&replay),
                0,
                "share {history} {stage}: snapshot replay differs"
            );
        };
        check("after recycling", &bounded, &reference);
        for (cols, rows) in [(50, 20), (133, 40), (80, 24)] {
            bounded.resize(cols, rows).unwrap();
            reference.resize(cols, rows).unwrap();
            check(
                &format!("after reflow to {cols}x{rows}"),
                &bounded,
                &reference,
            );
        }
    }
}

/// The shared-host path itself: bounded terminals at the shares a host hands
/// out reflow the same long mixed history without aborting the process. An
/// abort ends every session of the person's host at once.
#[test]
fn review_r3_bounded_terminal_reflows_long_mixed_history() {
    let stream = super::review_r3_default::mixed_stream(20_000);
    for sessions in [1_usize, 4, 10, 100, 1000] {
        let host = HostBudget::new(POOL, FLOOR);
        let mut terminal = host_terminal(80, 24, sessions, &host);
        for chunk in stream.chunks(4096) {
            terminal.process(chunk);
        }
        eprintln!("bounded share {}: fed, resizing", share(sessions));
        for (cols, rows) in [(50, 20), (133, 40), (80, 24)] {
            terminal.resize(cols, rows).unwrap();
        }
        assert!(!terminal.memory().2);
        assert!(terminal.snapshot().is_ok());
    }
}

/// Recycling at the smallest host share keeps a faithful snapshot after
/// every line (lines that do not soft-wrap; wrapped rows are refused by the
/// painter in every build).
#[test]
fn review_r3_recycled_unwrapped_history_keeps_exact_snapshot() {
    let host = HostBudget::new(POOL, FLOOR);
    let mut terminal = host_terminal(80, 24, 1000, &host);
    for n in 0..4000_usize {
        terminal.process(format!("{n:08} {}\r\n", "u".repeat(60)).as_bytes());
        if n >= 100 {
            assert!(terminal.snapshot().is_ok(), "line {n}: snapshot inexact");
        }
    }
}

/// 400 sessions at 200x50 each print ordinary output within the maximum user
/// pool. Screen floors, history and output replay all share that hard cap.
#[test]
fn review_r3_four_hundred_laptop_screens_fit_the_host() {
    const SESSIONS: usize = 400;
    let host = HostBudget::new(POOL, FLOOR);
    let mut terminals: Vec<_> = (0..SESSIONS)
        .map(|_| host_terminal(200, 50, SESSIONS, &host))
        .collect();
    for (index, terminal) in terminals.iter_mut().enumerate() {
        numbered(terminal, index, 0, 200, 199);
    }
    let (refused, inexact) = verdicts(&terminals);
    eprintln!(
        "laptop x400: pool {}/{POOL}; one session uses {} B; refused {} (first {:?}), inexact {}",
        host.used(),
        terminals[0].memory().0,
        refused.len(),
        refused.first(),
        inexact.len()
    );
    assert!(
        refused.is_empty() && inexact.is_empty(),
        "{} of {SESSIONS} sessions refused ordinary output, first {:?}; {} inexact (pool {}/{POOL})",
        refused.len(),
        refused.first(),
        inexact.len(),
        host.used()
    );
}
