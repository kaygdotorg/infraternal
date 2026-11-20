//! Terminal performance measurements against contract §5 [5][41].
use super::*;

// A wire Snapshot begins with RIS. Keep faithful-repaint fixtures in that
// canonical context; fresh C initialization has a distinct redraw default,
// covered by an explicit rejection regression rather than normalized away.
fn reset_terminal(cols: u16, rows: u16) -> std::io::Result<Terminal> {
    let mut terminal = Terminal::new(cols, rows)?;
    terminal.process(b"\x1bc");
    Ok(terminal)
}

#[cfg(test)]
mod budgets {
    //! Exercises terminal invariants against real data and frozen expectations.
    use super::*;
    #[test]
    #[ignore = "performance measurement; run release on the perf host"]
    fn snapshot_200x60() {
        let mut terminal = reset_terminal(200, 60).unwrap();
        terminal.process(&b"\x1b[32m1234567890 abcdefghijklmnopqrstuvwxyz\r\n".repeat(10060));
        let mut times = Vec::new();
        let mut len = 0;
        for _ in 0..1000 {
            let start = std::time::Instant::now();
            let bytes = terminal.snapshot().unwrap();
            len = bytes.len();
            std::hint::black_box(bytes);
            times.push(start.elapsed());
        }
        times.sort_unstable();
        println!(
            "Snapshot 200x60 + 256-line tail: p50={:.3} ms p99={:.3} ms bytes={len}",
            times[500].as_secs_f64() * 1000.0,
            times[990].as_secs_f64() * 1000.0
        );
        assert!(times[990] < std::time::Duration::from_millis(2));
    }
}

#[cfg(test)]
mod throughput {
    //! Exercises terminal invariants against real data and frozen expectations.
    use super::*;
    /// Measures parser throughput on the production adapter's long VT stream.
    #[test]
    #[ignore = "VT observer and history throughput measurement"]
    fn measured_parser() {
        let data = b"1234567890 abcdefghijklmnopqrstuvwxyz\r\n".repeat(10060);
        let mut terminal = reset_terminal(200, 60).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            terminal.process(&data);
        }
        let rate = f64::from(u32::try_from(data.len()).unwrap()) * 100.0
            / start.elapsed().as_secs_f64()
            / 1e6;
        println!(
            "shim Ghostty VT including carry: {rate:.2} MB/s, {SCROLLBACK_BYTES}-byte history budget, {} retained rows",
            terminal.engine.history_rows().unwrap()
        );
        assert!(rate > 10.0);
    }
}

#[cfg(test)]
mod memory {
    //! Linux process RSS isolates native terminal storage from the PTY/ring.
    use super::*;

    fn resident_kib() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    }

    /// Measures RSS growth as one terminal fills its bounded history.
    #[test]
    #[ignore = "RSS measurement; run this filter alone in a fresh release process"]
    fn measured_terminal_rss() {
        // Allocate the input before the baseline: report terminal growth, not
        // a reusable emitter buffer. A fresh process avoids allocator residue
        // from unrelated tests and previous terminal instances.
        let data = b"1234567890 abcdefghijklmnopqrstuvwxyz\r\n".repeat(10060);
        std::hint::black_box(&data);
        let before = resident_kib();
        let mut terminal = reset_terminal(200, 60).unwrap();
        let idle = resident_kib();
        terminal.process(&data);
        let first_rows = terminal.engine.history_rows().unwrap();
        let first = resident_kib();
        for _ in 0..10 {
            terminal.process(&data);
        }
        let full = resident_kib();
        println!(
            "Ghostty terminal 200x60: baseline={before} KiB idle={idle} KiB first={first} KiB ({first_rows} rows) full={full} KiB ({} rows); first_delta={} KiB full_delta={} KiB budget={SCROLLBACK_BYTES} bytes",
            terminal.engine.history_rows().unwrap(),
            first.saturating_sub(before),
            full.saturating_sub(before)
        );
        assert!((5000..20000).contains(&terminal.engine.history_rows().unwrap()));
    }
}
