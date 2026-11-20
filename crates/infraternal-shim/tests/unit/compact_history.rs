//! Exact retained history and perf-VM memory proof for the experimental codec [D270].
use super::*;
use std::io::{Read, Write};

struct Prints(String);
impl vte::Perform for Prints {
    fn print(&mut self, value: char) {
        self.0.push(value);
    }
}

fn filled() -> Terminal {
    filled_with_body(&"x".repeat(65))
}

fn filled_with_body(body: &str) -> Terminal {
    assert_eq!(body.len(), 65);
    let mut terminal = Terminal::with_history_budget(80, 24, 17 * 1024 * 1024).unwrap();
    terminal.process(b"\x1bc");
    for number in 1..=10_000 {
        let line = format!("{number:06} {body}\r\n");
        assert_eq!(line.len(), 74);
        terminal.process(line.as_bytes());
    }
    terminal.engine.compact(true);
    terminal
}

#[test]
fn all_numbered_lines_survive_compression_and_full_replay() {
    assert_numbered_replay(&"x".repeat(65));
}

#[test]
fn all_decimal_lines_survive_compression_and_full_replay() {
    assert_numbered_replay(&("0123456789".repeat(6) + "01234"));
}

/// Verifies compressed numbered history restores the same rows and screen state.
fn assert_numbered_replay(body: &str) {
    let mut terminal = filled_with_body(body);
    assert!(terminal.engine.history_rows().unwrap() >= 9977);
    assert!(
        terminal.engine.encoded_bytes() > 0,
        "fixture must compress cold pages"
    );
    assert!(
        !terminal.memory().2,
        "normal history must not hit its allocator cap"
    );
    let mut snapshot = vec![0; 2 * 1024 * 1024];
    let length = terminal
        .engine
        .try_snapshot(&mut snapshot, 10_000)
        .unwrap()
        .unwrap();
    snapshot.truncate(length);
    // Observe real printed characters independently of snapshot control bytes.
    let mut parser = vte::Parser::new();
    let mut prints = Prints(String::new());
    parser.advance(&mut prints, &snapshot);
    let line = |number| format!("{number:06} {body}");
    let mut end = 0;
    for number in 1..=10_000 {
        let found = prints.0[end..]
            .find(&line(number))
            .unwrap_or_else(|| panic!("missing retained line {number}"));
        end += found + 72;
        assert_eq!(
            prints.0.match_indices(&line(number)).count(),
            1,
            "duplicated retained line {number}"
        );
    }
    let mut replayed = Terminal::with_history_budget(80, 24, 17 * 1024 * 1024).unwrap();
    replayed.process(&snapshot);
    assert_eq!(terminal.research_state_difference(&replayed), 0);
    let mut second = vec![0; 2 * 1024 * 1024];
    let second_length = replayed
        .engine
        .try_snapshot(&mut second, 10_000)
        .unwrap()
        .unwrap();
    let mut replay_prints = Prints(String::new());
    parser.advance(&mut replay_prints, &second[..second_length]);
    for number in [1, 4321, 6543, 10_000] {
        let needle = line(number);
        let before = prints.0.find(&needle).unwrap();
        let after = replay_prints.0.find(&needle).unwrap();
        // Text search and selection operate on reconstructed terminal rows.
        // Include both the numbered prefix and its filler in this span.
        assert_eq!(
            &prints.0[before..before + 72],
            &replay_prints.0[after..after + 72]
        );
    }
    // Reflow restores every cold page; compress again and verify every row
    // remains serializable after wider and narrower geometry transitions.
    replayed.resize(40, 24).unwrap();
    replayed.resize(80, 24).unwrap();
    replayed.engine.compact(true);
    terminal.resize(40, 24).unwrap();
    terminal.resize(80, 24).unwrap();
    assert_eq!(terminal.research_state_difference(&replayed), 0);
    assert!(replayed.engine.history_rows().unwrap() >= 9977);
}

#[test]
#[ignore = "perf VM only: paired resident increment for exact 10,000 x 72 history"]
fn numbered_history_resident_increment() {
    measured_history_increment(&"x".repeat(65), "repeated-x");
}

#[test]
#[ignore = "perf VM only: decimal-body 10,000 x 72 history for workload comparison"]
fn decimal_history_resident_increment() {
    measured_history_increment(&("0123456789".repeat(6) + "01234"), "decimal");
}

/// Measures memory growth as decimal history fills 50 terminal instances.
#[test]
#[ignore = "perf VM only: distinguish fixed code residency from history slope at scale"]
fn decimal_history_resident_slope() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    // All empty terminals exist before any fill. Subsequent increments charge
    // only added history; the first row still exposes cold image/stack faults.
    let mut terminals: Vec<_> = (0..50)
        .map(|_| {
            let mut terminal = Terminal::with_history_budget(80, 24, 17 * 1024 * 1024).unwrap();
            terminal.process(b"\x1bcseed\r\n");
            terminal
        })
        .collect();
    let body = "0123456789".repeat(6) + "01234";
    let mut previous = pss();
    let mut filled = 0;
    for count in [1, 10, 50] {
        for terminal in &mut terminals[filled..count] {
            for number in 1..=10_000 {
                terminal.process(format!("{number:06} {body}\r\n").as_bytes());
            }
            terminal.engine.compact(true);
            // The unchanged seed row precedes the 10,000 numbered rows.
            assert_eq!(terminal.retained_history_rows().unwrap(), 9978);
            assert!(!terminal.memory().2);
        }
        let resident = pss();
        let ordinary: usize = terminals
            .iter()
            .map(|t| t.engine.allocation_classes().0)
            .sum();
        let mapped: usize = terminals
            .iter()
            .map(|t| t.engine.resident_pages().unwrap())
            .sum();
        let encoded: usize = terminals.iter().map(|t| t.engine.encoded_bytes()).sum();
        let huge = memory_kib("AnonHugePages:");
        println!(
            "COMPACT_HISTORY_SLOPE filled={count} empty={} pss_kib={resident} increment_kib={} added={} ordinary_bytes={ordinary} mapped_resident_bytes={mapped} encoded_bytes={encoded} anon_huge_kib={huge} columns=72 lines=10000 body=decimal",
            50 - count,
            resident.saturating_sub(previous),
            count - filled
        );
        previous = resident;
        filled = count;
    }
}

/// Compares RSS and native page ownership before and after filling one history.
fn measured_history_increment(body: &str, label: &str) {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    assert_eq!(body.len(), 65);
    history_fence(label, "ready");
    // Use the same terminal instance and geometry for both measurements.
    let mut terminal = Terminal::with_history_budget(80, 24, 17 * 1024 * 1024).unwrap();
    terminal.process(b"\x1bcseed\r\n");
    terminal.engine.compact(true);
    let (empty_ordinary, _, _) = terminal.engine.allocation_classes();
    let empty_pages = terminal.engine.resident_pages().unwrap();
    let empty_encoded = terminal.engine.encoded_bytes();
    let empty_mappings = terminal.engine.mapped_blocks();
    // Fault in only the measurement code before the baseline. This does not
    // fill history or warm the codec, so cold engine costs remain charged.
    let _ = pss();
    let empty = pss();
    history_fence(label, "empty");
    for number in 1..=10_000 {
        terminal.process(format!("{number:06} {body}\r\n").as_bytes());
    }
    terminal.engine.compact(true);
    history_fence(label, "full");
    let full = pss();
    let (ordinary, reserved, blocks) = terminal.engine.allocation_classes();
    let resident = terminal.engine.resident_pages().unwrap();
    let encoded = terminal.engine.encoded_bytes();
    let mappings = terminal.engine.mapped_blocks();
    println!(
        "COMPACT_HISTORY body={label} lines=10000 columns=72 empty_pss_kib={empty} filled_pss_kib={full} increment_pss_kib={} empty_mapped_resident_bytes={empty_pages} mapped_resident_bytes={resident} empty_encoded_bytes={empty_encoded} encoded_bytes={encoded} empty_mappings={empty_mappings} mappings={mappings} empty_ordinary_bytes={empty_ordinary} ordinary_bytes={ordinary} reserved_bytes={reserved} blocks={blocks} reference_kib=407 ratio={:.6}",
        full.saturating_sub(empty),
        f64::from(u32::try_from(full.saturating_sub(empty)).unwrap()) / 407.0
    );
    assert!(!terminal.memory().2);
    assert!(terminal.engine.history_rows().unwrap() >= 9977);
}

/// An external observer can classify resident mappings without allocating a
/// smaps parser inside the measured process. The address is an IPC-only hint;
/// the driver removes it from receipts and never reads memory through it.
#[inline(never)]
fn history_fence(body: &str, phase: &str) {
    if std::env::var_os("PPU_HISTORY_FENCE").is_none() {
        return;
    }
    let marker = 0_u8;
    println!(
        "HISTORY_FENCE body={body} phase={phase} pid={} stack={:x}",
        std::process::id(),
        (&raw const marker) as usize
    );
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_exact(&mut [0]).unwrap();
}

#[test]
fn cold_unicode_styles_and_links_replay_with_exact_native_state() {
    let mut terminal = Terminal::with_history_budget(80, 24, 1024 * 1024).unwrap();
    terminal.process(b"\x1bc");
    for number in 0..320 {
        terminal.process(format!("\x1b[38;2;12;34;56;4:3m\x1b]8;id=retained;https://example.org\x1b\\{number:04} e\u{301}界🙂\x1b]8;;\x1b\\\x1b[0m\r\n").as_bytes());
    }
    terminal.engine.compact(true);
    assert!(terminal.engine.encoded_bytes() > 0);
    let mut snapshot = vec![0; 1024 * 1024];
    let length = terminal
        .engine
        .try_snapshot(&mut snapshot, 1000)
        .unwrap()
        .unwrap();
    let mut replayed = Terminal::with_history_budget(80, 24, 1024 * 1024).unwrap();
    replayed.process(&snapshot[..length]);
    assert_eq!(terminal.research_state_difference(&replayed), 0);
    terminal.process("\x1b[2b e\u{301}界🙂".as_bytes());
    replayed.process("\x1b[2b e\u{301}界🙂".as_bytes());
    assert_eq!(terminal.research_state_difference(&replayed), 0);
}

#[test]
fn ownership_receipt_accounts_encoded_history_separately() {
    let terminal = filled();
    let (ordinary, pages, resident, encoded, carry) = terminal.ownership().unwrap();
    assert_eq!(ordinary + pages + encoded, terminal.memory().0);
    assert!(encoded > 0, "retained history must appear in its own class");
    assert!(resident <= pages);
    assert_eq!(carry, terminal.pending.capacity());
}

fn pss() -> usize {
    memory_kib("Pss:")
}
fn memory_kib(key: &str) -> usize {
    std::fs::read_to_string("/proc/self/smaps_rollup")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// Confirms row-count metadata reads do not restore pages or change ownership.
#[test]
fn retained_row_receipt_neither_restores_pages_nor_changes_encoding() {
    let terminal = filled();
    let before = terminal.ownership().unwrap();
    assert_eq!(terminal.retained_history_rows().unwrap(), 9977);
    assert_eq!(terminal.ownership().unwrap(), before);
}
