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

/// Check partial credit, overlap trimming, cursor progression, and gap rejection.
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

/// Keep the whole ordinary bulk window while requiring repaint bytes to spend
/// only credit the client has actually granted.
#[test]
fn reserved_credit_preserves_the_bulk_window_and_cannot_be_overspent() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    assert_eq!(output.repaint_reserved(1, 1), Err(Error::OutOfRange));
    assert_eq!(output.repaint_reserved(1, 0), Err(Error::OutOfRange));
    output.grant(BULK_CREDIT + REPAINT_RESERVE).unwrap();
    assert_eq!(
        output.suffix(0, (BULK_CREDIT + REPAINT_RESERVE) as usize),
        Ok(0..BULK_CREDIT as usize),
        "bulk output must leave the reserved repaint credit untouched"
    );
    output.forward(BULK_CREDIT as usize).unwrap();
    assert!(output.bulk_starved());
    assert_eq!(output.suffix(u64::from(BULK_CREDIT), 1), Ok(0..0));
    assert_eq!(output.cursor(), u64::from(BULK_CREDIT));
    output
        .repaint_reserved(u64::from(BULK_CREDIT) + 1, REPAINT_RESERVE as usize)
        .unwrap();
    assert_eq!(output.reserved_credit(), 0);
    assert_eq!(
        output.repaint_reserved(u64::from(BULK_CREDIT) + 2, 1),
        Err(Error::OutOfRange)
    );
    output.grant(1).unwrap();
    assert_eq!(output.reserved_credit(), 1);
    output
        .repaint_reserved(u64::from(BULK_CREDIT) + 2, 1)
        .unwrap();
}

/// A fragmented opening grant must retain its repaint reserve through the 16 KiB priming credit.
#[test]
fn fragmented_initial_credit_activates_repaint_reserve_without_shrinking_bulk_window() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const SHADOW_CREDIT: usize = 16 * 1024;
    let shadow_credit = u32::try_from(SHADOW_CREDIT).unwrap();
    let bulk_credit = usize::try_from(BULK_CREDIT).unwrap();

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(shadow_credit).unwrap();
    assert_eq!(output.suffix(0, SHADOW_CREDIT), Ok(0..SHADOW_CREDIT));
    output.forward(SHADOW_CREDIT).unwrap();

    output
        .grant(BULK_CREDIT + REPAINT_RESERVE - shadow_credit)
        .unwrap();

    assert_eq!(output.reserved_credit(), u64::from(REPAINT_RESERVE));
    let rest_of_bulk = bulk_credit - SHADOW_CREDIT;
    assert_eq!(
        output.suffix(output.cursor(), BULK_CREDIT as usize),
        Ok(0..rest_of_bulk)
    );
    output.forward(rest_of_bulk).unwrap();
    assert!(output.bulk_starved());
    assert_eq!(output.reserved_credit(), u64::from(REPAINT_RESERVE));
}

/// Accumulate two opening Credit frames without confusing them with returned output credit.
#[test]
fn a_split_opening_credit_activates_the_repaint_reserve() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT).unwrap();
    output.grant(REPAINT_RESERVE).unwrap();

    assert_eq!(output.reserved_credit(), u64::from(REPAINT_RESERVE));
    assert_eq!(
        output.suffix(output.cursor(), BULK_CREDIT as usize),
        Ok(0..BULK_CREDIT as usize),
        "the later opening credit must preserve the full 1 MiB raw allowance"
    );
}

/// A client that granted only the legacy window never gets a key repaint (#477, J637).
///
/// Native clients grant 1 MiB without the repaint reserve and check every byte
/// exactly once. Funding a Snapshot from their in-flight raw bytes replaced
/// output they had to receive, so the reserve must be confirmed first.
#[test]
fn a_legacy_window_never_funds_a_key_repaint_from_raw_output() {
    const BULK_CREDIT: u32 = 1024 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT).unwrap();
    output.forward(BULK_CREDIT as usize).unwrap();

    assert_eq!(output.reserved_credit(), 0);
    assert_eq!(
        output.repaint_budget(),
        0,
        "raw bytes of an unconfirmed reserve cannot fund a repaint"
    );
    assert_eq!(
        output.repaint_reserved(u64::from(BULK_CREDIT) + 1, 1),
        Err(Error::OutOfRange),
        "a legacy-window client keeps exact raw delivery"
    );
    output.grant(BULK_CREDIT).unwrap();
    assert_eq!(
        output.repaint_budget(),
        0,
        "returned legacy credit does not confirm a reserve"
    );
}

/// A legacy client's later fresh grant is not a split opening grant (#477, J654).
///
/// `verify-agent-snapshot.py` grants 1 MiB, receives it without returning
/// credit, grants 1 byte to pause, then 1 MiB to catch up. That last grant
/// exceeds the bytes in flight and crosses 1 MiB + 64 KiB, which used to look
/// like the browser's opening remainder: the relay activated a reserve the
/// client never offered and withheld 64 KiB of granted credit, so the client
/// waited forever. Once a grant has returned raw credit the opening is over.
#[test]
fn a_returned_credit_ends_reserve_setup_for_a_legacy_window() {
    const BULK_CREDIT: u32 = 1024 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT).unwrap();
    output.forward(BULK_CREDIT as usize).unwrap();
    output.grant(1).unwrap();
    output.grant(BULK_CREDIT).unwrap();

    assert_eq!(
        output.reserved_credit(),
        0,
        "the client never offered a reserve"
    );
    assert_eq!(
        output.repaint_budget(),
        0,
        "a legacy window keeps exact raw delivery"
    );
    assert_eq!(
        output.suffix(output.cursor(), 2 * BULK_CREDIT as usize),
        Ok(0..BULK_CREDIT as usize + 1),
        "every granted byte must stay available to raw output"
    );
}

/// Once a split opening grant confirms the reserve, the repaint path engages.
///
/// Shadow priming can split the browser's opening grant around early raw
/// output. Until the remainder arrives no key repaints; after it, a repaint can
/// use the reserve and the raw bytes already sent from that same window.
#[test]
fn a_confirmed_split_reserve_engages_the_repaint_path() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const MAX_SNAPSHOT: usize = infraternal_shim::frame::MAX_FRAME - 9;
    const EARLY: u32 = 256 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(EARLY).unwrap();
    output.forward(EARLY as usize).unwrap();
    assert_eq!(output.repaint_budget(), 0, "the reserve is still pending");
    assert_eq!(
        output.repaint_reserved(u64::from(EARLY), 1),
        Err(Error::OutOfRange)
    );

    output.grant(BULK_CREDIT + REPAINT_RESERVE - EARLY).unwrap();
    assert_eq!(output.reserved_credit(), u64::from(REPAINT_RESERVE));
    output.forward((BULK_CREDIT - EARLY) as usize).unwrap();
    assert!(output.bulk_starved());
    assert!(output.repaint_budget() >= MAX_SNAPSHOT as u64);
    output
        .repaint_reserved(u64::from(BULK_CREDIT) + 1, MAX_SNAPSHOT)
        .expect("a confirmed reserve plus the replaced raw queue funds a frame-valid Snapshot");
    assert_eq!(output.repaint_budget(), 0);
    assert_eq!(
        output.repaint_reserved(u64::from(BULK_CREDIT) + 2, 1),
        Err(Error::OutOfRange),
        "one replaced raw byte cannot fund a second repaint"
    );
}

/// Keep an early key repaint from taking credit that raw output could still spend.
#[test]
fn key_repaint_does_not_reduce_unspent_bulk_credit() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const BACKLOG: usize = 16 * 1024;
    const SNAPSHOT: usize = 32 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT + REPAINT_RESERVE).unwrap();
    output.forward(BACKLOG).unwrap();
    let bulk_before = output
        .suffix(output.cursor(), BULK_CREDIT as usize)
        .unwrap()
        .len();

    output
        .repaint_reserved(output.cursor() + 1, SNAPSHOT)
        .unwrap();

    let bulk_after = output
        .suffix(output.cursor(), BULK_CREDIT as usize)
        .unwrap()
        .len();
    assert_eq!(
        bulk_after, bulk_before,
        "a key repaint must spend its reserve first"
    );
}

/// Borrow repaint bytes only from outstanding raw output and never from an earlier repaint.
#[test]
fn a_large_repaint_reclaims_only_the_bulk_output_it_replaces() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const MAX_REPAINT: usize = infraternal_shim::frame::MAX_FRAME - 9;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT + REPAINT_RESERVE).unwrap();
    output.forward(BULK_CREDIT as usize).unwrap();

    output
        .repaint_reserved(u64::from(BULK_CREDIT) + 1, MAX_REPAINT)
        .expect("the largest valid Snapshot can borrow the raw bytes it replaces");
    output.grant(BULK_CREDIT).unwrap(); // The client drops the old raw queue for the repaint.

    assert_eq!(
        output.repaint_reserved(u64::from(BULK_CREDIT) + 2, MAX_REPAINT,),
        Err(Error::OutOfRange),
        "a previous Snapshot cannot be borrowed as raw output credit"
    );
    assert_eq!(output.reserved_credit(), u64::from(REPAINT_RESERVE));
}

/// Fit the largest valid Snapshot using the real unused grant before borrowing any queued raw bytes.
#[test]
fn maximum_snapshot_can_spend_unused_bulk_credit() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const BACKLOG: usize = 16 * 1024;
    const MAX_REPAINT: usize = infraternal_shim::frame::MAX_FRAME - 9;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT + REPAINT_RESERVE).unwrap();
    output.forward(BACKLOG).unwrap();
    let budget = output.repaint_budget();
    assert!(budget >= MAX_REPAINT as u64);

    output
        .repaint_reserved(BACKLOG as u64 + 1, MAX_REPAINT)
        .expect("every frame-valid Snapshot fits one unspent browser grant");

    assert_eq!(output.reserved_credit(), 0);
    let remaining = u64::from(BULK_CREDIT + REPAINT_RESERVE) - BACKLOG as u64 - MAX_REPAINT as u64;
    assert_eq!(output.repaint_budget(), remaining);
    output
        .repaint_reserved(BACKLOG as u64 + 2, usize::try_from(remaining).unwrap())
        .expect("one more repaint may spend the exact remaining grant");
    assert_eq!(output.repaint_budget(), 0);
    assert!(output.bulk_starved());
    assert_eq!(
        output.repaint_reserved(BACKLOG as u64 + 3, 1),
        Err(Error::OutOfRange),
        "key spam cannot mint credit after the original grant is exhausted"
    );
}

/// Keep the full legacy window for clients that do not offer repaint credit.
#[test]
fn a_legacy_initial_credit_keeps_its_full_bulk_window() {
    const BULK_CREDIT: u32 = 1024 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT).unwrap();
    assert_eq!(output.reserved_credit(), 0);
    assert_eq!(output.repaint_budget(), 0);
    assert_eq!(
        output.suffix(0, BULK_CREDIT as usize),
        Ok(0..BULK_CREDIT as usize)
    );
    assert_eq!(
        output.repaint_reserved(u64::from(BULK_CREDIT), 1),
        Err(Error::OutOfRange)
    );
}

/// Returned credit from a legacy full window must not look like a repaint grant.
#[test]
fn a_legacy_credit_return_does_not_activate_the_repaint_reserve() {
    const BULK_CREDIT: u32 = 1024 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT).unwrap();
    output.forward(BULK_CREDIT as usize).unwrap();
    output.grant(BULK_CREDIT).unwrap();

    assert_eq!(output.reserved_credit(), 0);
    assert_eq!(
        output.suffix(output.cursor(), BULK_CREDIT as usize),
        Ok(0..BULK_CREDIT as usize),
        "a legacy 1 MiB window must retain its full raw allowance after refund"
    );
}

/// Keep the negotiated repaint floor after a trusted remote cursor rebase.
#[test]
fn remote_cursor_rebase_preserves_repaint_credit_semantics() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const STYLED_SNAPSHOT: usize = 128 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(BULK_CREDIT + REPAINT_RESERVE).unwrap();
    output.forward(BULK_CREDIT as usize).unwrap();
    let cursor = output.cursor();

    // The server reissues only currently available credit after this trusted
    // cursor; rebasing must preserve negotiated and outstanding-byte state.
    output.reset_cursor(cursor);
    output.grant(REPAINT_RESERVE).unwrap();
    assert_eq!(output.reserved_credit(), u64::from(REPAINT_RESERVE));
    assert!(
        output.bulk_starved(),
        "raw output must not spend the repaint floor"
    );
    assert_eq!(
        output.suffix(cursor, REPAINT_RESERVE as usize),
        Ok(0..0),
        "repaint credit stays unavailable to bulk output"
    );
    assert!(
        output.repaint_budget() >= STYLED_SNAPSHOT as u64,
        "the reserve plus still-replaceable flood bytes can fund the repaint"
    );
    output
        .repaint_reserved(cursor + 1, STYLED_SNAPSHOT)
        .expect("the cursor rebase preserves enough real credit for a styled repaint");
    assert_eq!(output.repaint_budget(), 0);
    assert_eq!(
        output.repaint_reserved(cursor + 2, 1),
        Err(Error::OutOfRange),
        "another cursor reset cannot mint credit for key spam"
    );
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

/// A plain 1 MiB window stays legacy when a Snapshot refund rides with raw refunds (#477, J693).
///
/// The attach Snapshot and 128 KiB of flood are charged, then one Credit
/// returns the Snapshot and part of the flood together (a client that batches
/// refunds, or two Credits summed in the command queue). That Credit crosses
/// the full opening window if read as fresh credit, but every byte of it can be
/// a refund, so it proves no reserve.
#[test]
fn a_legacy_window_stays_legacy_when_a_snapshot_refund_rides_with_raw_refunds() {
    const K: u32 = 1024;
    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(1024 * K).unwrap();
    output.repaint(4096, (100 * K) as usize).unwrap();
    output.forward((128 * K) as usize).unwrap();
    output.grant(180 * K).unwrap();
    assert_eq!(
        output.repaint_budget(),
        0,
        "legacy window latched ACTIVE: reserved={} unreturned={}",
        output.reserved_credit(),
        output.unreturned_output_credit()
    );
    assert_eq!(output.reserved_credit(), 0);
}

/// An opening remainder that arrives merged with a refund leaves no phantom raw bytes (#477, J693).
///
/// The excess over the opening shortfall is returned output, so the raw bytes
/// it repays must leave the in-flight count; otherwise the repaint budget
/// overstates what the client can accept.
#[test]
fn a_coalesced_opening_remainder_and_refund_leave_no_phantom_raw_bytes() {
    const K: u32 = 1024;
    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(512 * K).unwrap();
    output.forward((100 * K) as usize).unwrap();
    output.grant(576 * K + 100 * K).unwrap();
    assert_eq!(output.reserved_credit(), u64::from(64 * K), "reserve should be ACTIVE");
    assert_eq!(
        output.unreturned_output_credit(),
        0,
        "phantom raw bytes inflate repaint_budget={} beyond the client's window",
        output.repaint_budget()
    );
}

/// A large first Credit followed by output and a top-up cannot prove a reserve, so it stays legacy (#477).
///
/// After 256 KiB of a 256 KiB first Credit has been sent, a following Credit
/// may be that much refund. Counting it as fresh window could put a client
/// with a smaller window into reserve mode, so setup ends without one. The
/// server's real split uses a 16 KiB first Credit (see the test above).
#[test]
fn an_unprovable_split_opening_keeps_exact_raw_delivery() {
    const BULK_CREDIT: u32 = 1024 * 1024;
    const REPAINT_RESERVE: u32 = 64 * 1024;
    const EARLY: u32 = 256 * 1024;

    let mut output = Output::attach_with_repaint_reserve(0);
    output.grant(EARLY).unwrap();
    output.forward(EARLY as usize).unwrap();
    output.grant(BULK_CREDIT + REPAINT_RESERVE - EARLY).unwrap();
    assert_eq!(output.reserved_credit(), 0);
    assert_eq!(output.repaint_budget(), 0);
    assert_eq!(
        output.suffix(output.cursor(), BULK_CREDIT as usize),
        Ok(0..(BULK_CREDIT + REPAINT_RESERVE - EARLY) as usize),
        "every granted byte stays available to raw output"
    );
}
