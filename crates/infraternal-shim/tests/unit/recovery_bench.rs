//! Measure bounded full-ring reconstruction without accumulating retired allocations [41].
use super::*;

#[test]
#[ignore = "release reconstruction measurement; old healthy handles permit repeated cleanup"]
fn measured_full_ring_reconstruction() {
    let mut bytes = b"\x1bc\x1b[32m".to_vec();
    let row = b"1234567890 abcdefghijklmnopqrstuvwxyz\r\n";
    while bytes.len() + row.len() <= crate::ring::DEFAULT_CAPACITY {
        bytes.extend_from_slice(row);
    }
    let mut ring = Ring::new(crate::ring::DEFAULT_CAPACITY);
    ring.append(&bytes).unwrap();
    let mut terminal = Terminal::new(200, 60).unwrap();
    terminal.process(&bytes);
    let mut times = Vec::new();
    // Measure the same constructor/replay path. Keeping the old handle healthy
    // lets Drop reclaim it instead of retaining fifty full histories after
    // forced native errors; the actual refusal path has its separate probes.
    for _ in 0..50 {
        let start = std::time::Instant::now();
        terminal.recover(Some(&ring)).unwrap();
        times.push(start.elapsed().as_secs_f64() * 1000.0);
        assert!(!terminal.requires_approximation());
    }
    times.sort_by(f64::total_cmp);
    println!(
        "reconstruction 200x60: bytes={} n=50 p50_ms={:.3} p99_ms={:.3} aggregate_bytes_at_128={}",
        bytes.len(),
        times[25],
        times[49],
        bytes.len() * 128
    );
}
