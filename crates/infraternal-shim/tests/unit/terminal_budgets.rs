//! Terminal performance measurements against contract §5 [5][41].
use super::*;
#[cfg(test)]
mod budgets {
    //! Exercises terminal invariants against real data and frozen expectations.
    use super::*;
    #[test]
    #[ignore = "performance measurement; run release on the perf host"]
    fn snapshot_200x60() {
        let mut terminal = Terminal::new(200, 60).unwrap();
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
    #[test]
    #[ignore = "VT observer and history throughput measurement"]
    fn measured_parser() {
        let data = b"1234567890 abcdefghijklmnopqrstuvwxyz\r\n".repeat(10060);
        let mut terminal = Terminal::new(200, 60).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            terminal.process(&data);
        }
        let rate = f64::from(u32::try_from(data.len()).unwrap()) * 100.0
            / start.elapsed().as_secs_f64()
            / 1e6;
        println!("shim VT including observer: {rate:.2} MB/s, 10,000-line retention");
        assert!(rate > 10.0);
    }
}
