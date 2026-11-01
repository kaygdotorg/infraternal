//! Exercises drain, restart, and secret-safe proxy log behavior [#281, #289].

use super::supervisor::{
    DRAIN_TIMEOUT, Lifecycle, LifecycleAction, LifecyclePhase, redact_log_line,
};
use std::time::{Duration, Instant};

#[test]
fn final_exposure_starts_one_ten_second_drain_then_stops_once() {
    let start = Instant::now();
    let mut lifecycle = Lifecycle::default();

    assert_eq!(lifecycle.update(1, start), LifecycleAction::Start);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Starting);
    lifecycle.child_started(1, start);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Running);
    assert_eq!(lifecycle.update(0, start), LifecycleAction::BeginDrain);
    assert_eq!(
        lifecycle.phase(),
        LifecyclePhase::Draining {
            deadline: start + DRAIN_TIMEOUT
        }
    );
    assert_eq!(
        lifecycle.tick(0, start + DRAIN_TIMEOUT - Duration::from_millis(1)),
        LifecycleAction::Keep
    );
    assert_eq!(
        lifecycle.tick(0, start + DRAIN_TIMEOUT),
        LifecycleAction::Stop
    );
    assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);
    assert_eq!(
        lifecycle.tick(0, start + DRAIN_TIMEOUT + Duration::from_secs(1)),
        LifecycleAction::Keep
    );
}

#[test]
fn a_new_exposure_cancels_the_drain_without_restarting_the_child() {
    let start = Instant::now();
    let mut lifecycle = Lifecycle::default();
    assert_eq!(lifecycle.update(1, start), LifecycleAction::Start);
    lifecycle.child_started(1, start);
    assert_eq!(lifecycle.update(0, start), LifecycleAction::BeginDrain);

    assert_eq!(
        lifecycle.update(1, start + Duration::from_secs(4)),
        LifecycleAction::Apply
    );
    assert_eq!(lifecycle.phase(), LifecyclePhase::Running);
    assert_eq!(
        lifecycle.tick(1, start + DRAIN_TIMEOUT),
        LifecycleAction::Keep
    );
}

#[test]
fn unexpected_exits_back_off_and_never_restart_without_exposures() {
    let start = Instant::now();
    let mut lifecycle = Lifecycle::default();
    assert_eq!(lifecycle.child_exited(0, start), LifecycleAction::Keep);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);

    let first_delay = Duration::from_millis(200);
    let max_delay = Duration::from_secs(30);
    assert_eq!(
        lifecycle.child_exited(1, start),
        LifecycleAction::RetryAfter(first_delay)
    );
    assert_eq!(
        lifecycle.tick(1, start + first_delay - Duration::from_millis(1)),
        LifecycleAction::Keep
    );
    assert_eq!(
        lifecycle.tick(1, start + first_delay),
        LifecycleAction::Start
    );
    lifecycle.child_started(1, start + first_delay);

    let mut now = start + first_delay;
    let mut delay = first_delay * 2;
    for _ in 0..10 {
        let action = lifecycle.child_exited(1, now);
        assert_eq!(action, LifecycleAction::RetryAfter(delay));
        assert!(delay <= max_delay);
        now += delay;
        assert_eq!(lifecycle.tick(1, now), LifecycleAction::Start);
        lifecycle.child_started(1, now);
        delay = delay.saturating_mul(2).min(max_delay);
    }
}

#[test]
fn provider_values_are_redacted_before_a_log_line_is_emitted() {
    let line = "provider failed for dns token=secret-value-123";
    let redacted = redact_log_line(line, &["secret-value-123"]);
    assert!(!redacted.contains("secret-value-123"));
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn authorization_cookie_and_query_credentials_are_redacted_without_known_values() {
    let line = "request failed Authorization: Bearer header-secret Cookie: session=cookie-secret url=https://dns.invalid/?api_key=query-secret";
    let redacted = redact_log_line(line, &[]);

    for secret in ["header-secret", "cookie-secret", "query-secret"] {
        assert!(!redacted.contains(secret), "credential leaked: {secret}");
    }
    assert!(redacted.contains("[REDACTED]"));
}
