//! Covers bounded log-line handling and queued updates during retry backoff [#281, #289].

use super::{
    Inbox, Lifecycle, LifecycleAction, LifecyclePhase, MAX_LOG_LINE_BYTES, SupervisorCommand,
    receive_command, spawn_log_reader,
};
use std::{
    io::Cursor,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[test]
fn overlong_line_is_discarded_without_leaking_secret_prefix() {
    let secret = "x".repeat(MAX_LOG_LINE_BYTES + 1024);
    let input = format!("{secret}\nroute-ready\n");
    let (sender, receiver) = mpsc::sync_channel(4);
    let reader = spawn_log_reader(
        Cursor::new(input),
        sender,
        Arc::new(vec![Zeroizing::new(secret)]),
    );

    reader.join().expect("log reader thread");
    let lines: Vec<_> = receiver.try_iter().collect();
    assert_eq!(lines, ["route-ready"]);
}

#[test]
fn queued_removal_wakes_supervisor_before_the_backoff_deadline() {
    let now = Instant::now();
    let mut lifecycle = Lifecycle::default();
    assert_eq!(
        lifecycle.child_exited(1, now),
        LifecycleAction::RetryAfter(Duration::from_millis(200))
    );
    let (sender, receiver) = mpsc::channel();
    let (reply, _response) = mpsc::channel();
    assert!(
        sender
            .send(SupervisorCommand::Replace(Vec::new(), reply))
            .is_ok(),
        "queue revocation-shaped supervisor command"
    );

    let inbox = receive_command(&receiver, lifecycle.phase());

    let Inbox::Command(SupervisorCommand::Replace(services, reply)) = inbox else {
        panic!("a queued removal must precede its retry deadline");
    };
    assert_eq!(services.len(), 0);
    assert_eq!(lifecycle.update(services.len(), now), LifecycleAction::Keep);
    assert_eq!(lifecycle.phase(), LifecyclePhase::Stopped);
    assert_eq!(
        lifecycle.tick(0, now + Duration::from_secs(30)),
        LifecycleAction::Keep
    );
    reply.send(Ok(None)).expect("reply to removal");
}
