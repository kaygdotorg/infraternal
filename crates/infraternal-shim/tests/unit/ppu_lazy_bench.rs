//! Perf-VM receipt for deferred reflow work at the first terminal snapshot [D270].
use super::*;

#[test]
#[ignore = "perf VM only: measure cold materialization after bounded geometry replay"]
fn geometry_replay_materialization_cost() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    for (cols, rows) in [(80_u16, 24_u16), (160, 60), (1000, 100)] {
        for events in [1, RESIZE_LIMIT] {
            for eager in [true, false] {
                for repeat in 0..3 {
                    let mut terminal = LazyTerminal::new(80, 24, 65536);
                    terminal.process(b"\x1bcseed\r\n").unwrap();
                    let start = Instant::now();
                    for event in 0..events {
                        let width = cols + u16::try_from(event % 2).unwrap();
                        terminal.resize(width, rows).unwrap();
                        if eager {
                            terminal.materialize().unwrap();
                        }
                    }
                    let prepare_us = start.elapsed().as_micros();
                    let native_before = terminal.state.borrow().terminal.is_some();
                    let start = Instant::now();
                    terminal.materialize().unwrap();
                    let materialize_us = start.elapsed().as_micros();
                    let start = Instant::now();
                    let snapshot = terminal.snapshot().unwrap();
                    let snapshot_us = start.elapsed().as_micros();
                    println!(
                        "PPU_GEOMETRY cols={cols} rows={rows} events={events} eager={eager} repeat={repeat} native_before={native_before} prepare_us={prepare_us} materialize_us={materialize_us} snapshot_us={snapshot_us} snapshot_bytes={}",
                        snapshot.len()
                    );
                }
            }
        }
    }
}
