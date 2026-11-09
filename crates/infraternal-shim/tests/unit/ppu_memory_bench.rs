//! Perf-VM-only native allocation and resident warm-up accounting for shared terminals [D270].
use super::*;

/// Checks small histories do not retain megabyte-sized native page quanta.
#[test]
#[ignore = "perf VM only: sparse history residency and native ownership"]
fn small_history_does_not_retain_megabyte_page_quanta() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    let mut terminal = Terminal::with_history_budget(80, 24, 65536).unwrap();
    terminal.process(b"\x1bcseed\r\n");
    terminal.resize(81, 24).unwrap();
    terminal.resize(80, 24).unwrap();
    for round in 0..32 {
        terminal.process(&b"light-history\r\n".repeat(256));
        let (ordinary, pages, blocks) = terminal.engine.allocation_classes();
        let (pss, anonymous) = resident();
        println!(
            "PPU_SPARSE lines={} ordinary_bytes={ordinary} page_bytes={pages} live_blocks={blocks} pss_kib={pss} anon_kib={anonymous} rows={}",
            (round + 1) * 256,
            terminal.engine.history_rows().unwrap()
        );
    }
    let (ordinary, pages, _) = terminal.engine.allocation_classes();
    // The configured history is 64 KiB. Screen and allocator metadata add
    // overhead, but native pooling must not multiply it into megabytes.
    assert!(
        ordinary + pages <= 512 * 1024,
        "small history retained {} bytes",
        ordinary + pages
    );
}

#[test]
#[ignore = "perf VM only: sparse resize ownership at 900 quiet sessions"]
fn quiet_resize_churn_does_not_keep_new_resident_pools() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    let mut terminals: Vec<_> = (0..900)
        .map(|_| Terminal::with_history_budget(80, 24, 65536).unwrap())
        .collect();
    for terminal in &mut terminals {
        terminal.process(b"init-quiet\r\n");
        terminal.resize(81, 24).unwrap();
        terminal.resize(80, 24).unwrap();
    }
    let mut rng = 270_205_u64;
    let mut settled = 0;
    for event in 0..2400 {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let terminal = &mut terminals[usize::try_from(rng % 900).unwrap()];
        terminal.resize(80 + event % 2, 24).unwrap();
        terminal.process(format!("churn-{event}\r\n").as_bytes());
        if (event + 1) % 200 == 0 {
            let reserved: usize = terminals.iter().map(|t| t.memory().0).sum();
            let (pss, anon) = resident();
            println!(
                "PPU_CHURN events={} reserved_bytes={reserved} pss_kib={pss} anon_kib={anon}",
                event + 1
            );
            if event == 199 {
                settled = pss;
            }
            if event == 2399 {
                assert!(pss <= settled + 1024, "quiet native pools did not settle");
            }
        }
    }
}

fn resident() -> (usize, usize) {
    let text = std::fs::read_to_string("/proc/self/smaps_rollup").unwrap();
    let value = |key: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<usize>()
            .unwrap()
    };
    (value("Pss:"), value("Anonymous:"))
}

#[test]
#[ignore = "perf VM only: native heap/resident accounting; set PPU_VT_ACCOUNT_SESSIONS"]
fn native_session_allocations_settle_after_geometry_warmup() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    let count: usize = std::env::var("PPU_VT_ACCOUNT_SESSIONS")
        .unwrap()
        .parse()
        .unwrap();
    assert!([1, 10, 100, 1000].contains(&count));
    let initial = resident();
    println!(
        "PPU_HEAP count={count} phase=base pss_kib={} anon_kib={}",
        initial.0, initial.1
    );
    let mut terminals: Vec<_> = (0..count)
        .map(|_| Terminal::with_history_budget(80, 24, 65536).unwrap())
        .collect();
    for terminal in &mut terminals {
        terminal.process(b"\x1bcseed\r\n");
    }
    // Cross native page/scrollback rollover repeatedly, rather than measuring
    // only the first screen. This matches the soak's 1024-line burst producer.
    let burst = b"warmup\r\n".repeat(1024);
    let mut settled = 0;
    for round in 0..16 {
        for terminal in &mut terminals {
            terminal.resize(81, 24).unwrap();
            terminal.resize(80, 24).unwrap();
            terminal.process(&burst);
        }
        let (reserved, peaks, refusals) = terminals.iter().fold((0, 0, 0), |acc, terminal| {
            let memory = terminal.memory();
            (
                acc.0 + memory.0,
                acc.1 + memory.1,
                acc.2 + usize::from(memory.2),
            )
        });
        let row = resident();
        let classes = terminals.iter().fold((0, 0, 0), |acc, terminal| {
            let memory = terminal.engine.allocation_classes();
            (acc.0 + memory.0, acc.1 + memory.1, acc.2 + memory.2)
        });
        assert!(
            classes.1 > 0,
            "protected native pages must use the owned allocator"
        );
        println!(
            "PPU_HEAP count={count} round={round} reserved_bytes={reserved} peak_bytes={peaks} refusals={refusals} ordinary_bytes={} page_bytes={} live_blocks={} pss_kib={} anon_kib={}",
            classes.0, classes.1, classes.2, row.0, row.1
        );
        assert_eq!(
            refusals, 0,
            "ordinary geometry warm-up must not hit the session cap"
        );
        if round == 7 {
            settled = row.0;
        }
        if round == 15 {
            assert!(row.0 <= settled + 1024, "native warm-up did not settle");
        }
    }
}

#[test]
fn fresh_shell_filler_snapshot_gap_is_independent_of_allocator_refusal() {
    let mut terminal = Terminal::with_history_budget(80, 24, 64 * 1024 * 1024 / 50).unwrap();
    for number in 1..=10_000 {
        terminal
            .process(format!("{number:06} {}\r\n", "0123456789".repeat(6) + "01234").as_bytes());
    }
    assert!(
        !terminal.memory().2,
        "filler must not hit the per-session native allocation cap"
    );
    assert!(
        !terminal.requires_approximation(),
        "recovery provenance remains exact"
    );
    let error = terminal.snapshot().unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
}
