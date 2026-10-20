//! Independently checks D307 output eviction, replay deadlines and session-scale storage bounds.
use super::*;

#[test]
fn two_positions_in_one_chunk_are_claimed_in_order_without_reopening_either() {
    let mut registry = Registry::default();
    let now = Instant::now();
    let session = [1; 16];
    registry.output(session, 100, b"\x1b[6n\x1b[5n", now);
    for position in [100, 104] {
        assert!(registry.accept(session, position, b"renderer answer", now));
        assert!(!registry.accept(session, position, b"another viewer", now));
    }
    assert_eq!(registry.sessions[&session].claimed.len(), 2);
}

#[test]
fn trimmed_output_refuses_its_answer_without_reopening_an_accepted_position() {
    let mut registry = Registry::default();
    let now = Instant::now();
    let session = [1; 16];
    for position in 0..=POSITIONS as u64 {
        registry.output(
            session,
            position,
            b"x",
            now + Duration::from_nanos(position),
        );
    }
    let accepted_at = now + Duration::from_millis(1);
    assert!(!registry.accept(session, 0, b"trimmed answer", accepted_at));
    assert!(registry.accept(session, 1, b"first viewer", accepted_at));
    registry.output(
        session,
        0,
        b"replayed bytes",
        now + Duration::from_millis(500),
    );
    let replayed_at = now + Duration::from_millis(500);
    assert!(!registry.accept(session, 0, b"trimmed replay answer", replayed_at));
    assert!(!registry.accept(session, 1, b"duplicate replay answer", replayed_at));
}

#[test]
fn a_lagging_viewer_cannot_renew_a_deadline_after_the_first_viewer_answered() {
    let mut registry = Registry::default();
    let now = Instant::now();
    let session = [1; 16];
    registry.output(session, 0, b"\x1b[6n", now);
    assert!(registry.accept(session, 0, b"first viewer", now));
    registry.output(session, 0, b"\x1b[6n", now + WINDOW);
    assert!(!registry.accept(session, 0, b"lagging viewer", now + WINDOW));
    registry.output(session, 4, b"\x1b[5n", now + WINDOW);
    assert!(registry.accept(session, 4, b"new live answer", now + WINDOW));
    assert!(!registry.accept(session, 0, b"old answer after claim cleanup", now + WINDOW));
}

#[test]
fn all_session_tables_remain_bounded_at_the_registry_limit() {
    let mut registry = Registry::default();
    let now = Instant::now();
    for id in 0..=SESSIONS as u64 {
        let mut session = [0; 16];
        session[..8].copy_from_slice(&id.to_le_bytes());
        for position in 0..=POSITIONS as u64 {
            let observed = now + Duration::from_nanos(position);
            registry.output(session, position, b"x", observed);
            let _ = registry.accept(session, position, b"answer", observed);
        }
    }
    assert_eq!(registry.sessions.len(), SESSIONS);
    for state in registry.sessions.values() {
        assert_eq!(state.output.len(), POSITIONS);
        assert_eq!(state.claimed.len(), POSITIONS);
    }
}
