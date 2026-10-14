//! Perf-VM-only native allocation and resident warm-up accounting for shared terminals [D270].
use super::*;

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
