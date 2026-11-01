//! Exercises drain, restart, and secret-safe proxy log behavior [#281, #289].

use super::supervisor::{
    DRAIN_TIMEOUT, Lifecycle, LifecycleAction, LifecyclePhase, check_private_ping,
    redact_log_line,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

fn health_server(response: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind private health fixture");
    let address = listener.local_addr().expect("health fixture address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept health probe");
        let mut request = [0_u8; 20];
        stream
            .read_exact(&mut request)
            .expect("read health request");
        assert_eq!(&request, b"GET /ping HTTP/1.1\r\n");
        stream
            .write_all(response)
            .expect("write health response");
    });
    (address, server)
}

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

#[test]
fn private_health_ping_accepts_a_success_response() {
    let (address, server) =
        health_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
    check_private_ping(address, Duration::from_secs(1)).expect("healthy private ping");
    server.join().expect("health fixture thread");
}

#[test]
fn private_health_ping_rejects_non_loopback_addresses() {
    assert_eq!(
        check_private_ping(
            "192.0.2.1:19999".parse().expect("non-loopback address"),
            Duration::from_millis(1),
        )
            .expect_err("health probe must never leave loopback")
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn private_health_ping_rejects_an_unhealthy_response() {
    let (address, server) = health_server(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(check_private_ping(address, Duration::from_secs(1)).is_err());
    server.join().expect("health fixture thread");
}
