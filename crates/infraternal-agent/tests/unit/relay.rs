//! Boundary and restart invariants independent of socket scheduling [41].
use super::{Error, Input, Output, STARVATION};
use std::time::{Duration, Instant};

fn funded_output(cursor: u64) -> Output {
    let mut output = Output::attach(cursor);
    output.grant(1024 * 1024).unwrap();
    output
}

#[test]
fn attachment_has_no_implicit_output_or_snapshot_credit() {
    let mut output = Output::attach(4);
    assert_eq!(output.suffix(4, 3), Ok(0..0));
    assert_eq!(output.forward(1), Err(Error::OutOfRange));
    assert_eq!(output.repaint(4, 1), Err(Error::OutOfRange));
    assert_eq!(output.cursor(), 4);
    output.grant(2).unwrap();
    assert_eq!(output.suffix(4, 3), Ok(0..2));
    output.forward(2).unwrap();
    assert_eq!(output.suffix(6, 1), Ok(0..0));
    assert_eq!(output.forward(1), Err(Error::OutOfRange));
}

#[test]
fn input_overlap_gap_and_restart_from_confirmed_offset() {
    let mut input = Input::resume(4);
    assert_eq!(input.suffix(0, 7), Ok(4..7));
    input.submit(7).unwrap();
    assert_eq!(input.acked(), 4); // Queueing is not a PTY acknowledgment.
    assert_eq!(input.suffix(4, 3), Ok(3..3));
    assert_eq!(input.suffix(8, 1), Err(Error::Gap));
    assert_eq!(input.acknowledge(8), Err(Error::OutOfRange));
    input.acknowledge(6).unwrap();
    assert_eq!(input.acknowledge(5), Err(Error::OutOfRange));
    let resumed = Input::resume(input.acked());
    assert_eq!(resumed.suffix(4, 3), Ok(2..3));
    assert_eq!(resumed.suffix(u64::MAX, 1), Err(Error::Overflow));
}

#[test]
fn output_partial_credit_and_dedup() {
    let mut output = funded_output(10);
    assert_eq!(output.suffix(8, 6), Ok(2..6));
    output.forward(4).unwrap();
    assert_eq!(output.cursor(), 14);
    assert_eq!(output.suffix(8, 6), Ok(6..6));
    assert_eq!(output.suffix(15, 1), Err(Error::Gap));
    output.forward(1024 * 1024 - 5).unwrap();
    assert_eq!(output.suffix(output.cursor(), 10), Ok(0..1));
    assert_eq!(output.forward(2), Err(Error::OutOfRange));
    output.forward(1).unwrap();
    output.grant(3).unwrap();
    assert_eq!(output.suffix(output.cursor(), 10), Ok(0..3));
}

#[test]
fn starvation_is_one_shot_and_snapshot_length_does_not_advance_sequence() {
    let mut output = funded_output(0);
    let now = Instant::now();
    assert_eq!(output.pending(now), None); // No timer for idle/credited streams.
    output.forward(1024 * 1024).unwrap();
    assert_eq!(output.pending(now), Some(now + STARVATION));
    assert_eq!(
        output.pending(now + Duration::from_millis(100)),
        Some(now + STARVATION)
    );
    assert!(!output.expire(now + Duration::from_millis(249)));
    assert!(output.expire(now + STARVATION));
    assert!(!output.needs_snapshot());
    output.grant(4096).unwrap();
    assert!(output.needs_snapshot());
    assert_eq!(output.forward(1), Err(Error::OutOfRange));
    assert_eq!(output.repaint(50_000_000, 4097), Err(Error::OutOfRange));
    output.repaint(50_000_000, 4096).unwrap();
    assert_eq!(output.cursor(), 50_000_000);
    assert!(!output.needs_snapshot());
    assert_eq!(output.suffix(50_000_000, 16), Ok(0..0));
}

#[test]
fn overflowing_ranges_never_mutate_cursors() {
    let mut output = funded_output(u64::MAX);
    assert_eq!(output.suffix(u64::MAX, 1), Err(Error::Overflow));
    assert_eq!(output.forward(1), Err(Error::Overflow));
    assert_eq!(output.cursor(), u64::MAX);
    assert_eq!(output.repaint(0, 0), Err(Error::OutOfRange));
}

#[test]
fn returned_credit_cancels_starvation_and_state_has_no_payload_buffer() {
    let mut output = funded_output(0);
    output.forward(1024 * 1024).unwrap();
    let now = Instant::now();
    output.pending(now);
    output.grant(1).unwrap();
    assert!(!output.expire(now + STARVATION));
    assert!(std::mem::size_of::<Output>() <= 64);
    assert!(std::mem::size_of::<Input>() <= 32);
}

#[test]
fn expired_credit_resumes_retained_bytes_at_the_same_cursor() {
    let mut output = funded_output(41);
    output.forward(1024 * 1024).unwrap();
    let cursor = output.cursor();
    let now = Instant::now();
    output.pending(now);
    assert!(output.expire(now + STARVATION));
    output.grant(100).unwrap();
    assert_eq!(output.cursor(), cursor);
    output.resume_replay();
    // After a retained ReadFrom response the relay must forward its unseen
    // suffix, rather than silently discard it while waiting for a repaint.
    assert_eq!(output.suffix(cursor, 100).unwrap(), 0..100);
}

#[test]
fn positive_insufficient_credit_arms_a_one_shot_deadline() {
    let mut output = funded_output(0);
    output.forward(1024 * 1024 - 1).unwrap();
    let cursor = output.cursor();
    assert_eq!(output.repaint(cursor + 100, 16_384), Err(Error::OutOfRange));
    let now = Instant::now();
    assert_eq!(output.pending(now), Some(now + STARVATION));
    assert_eq!(
        output.pending(now + Duration::from_millis(100)),
        Some(now + STARVATION)
    );
    output.grant(1).unwrap();
    assert_eq!(
        output.pending(now + Duration::from_millis(200)),
        Some(now + STARVATION)
    );
    assert!(output.expire(now + STARVATION));
    assert_eq!(output.cursor(), cursor);
    assert!(
        !output.needs_snapshot(),
        "unchanged credit must park repaint serialization"
    );
    output.grant(16_384).unwrap();
    assert!(output.needs_snapshot());
}

#[test]
#[ignore = "release ownership versus payload-copy measurement"]
fn output_payload_move_measurement() {
    use std::{hint::black_box, time::Instant};
    let n = 100_000;
    for (label, copy) in [("forward-clone", true), ("forward-move", false)] {
        let start = Instant::now();
        for _ in 0..n {
            // Both paths receive an owned shim payload. Only the old relay
            // allocates and copies it again when creating the writer message.
            let payload = vec![42; 16_384];
            if copy {
                black_box(payload.clone());
            } else {
                black_box(payload);
            }
        }
        println!(
            "{label}: n={n} ns/frame={:.1}",
            start.elapsed().as_secs_f64() * 1e9 / f64::from(n)
        );
    }
}
