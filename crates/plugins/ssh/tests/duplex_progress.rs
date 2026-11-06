//! Bounds bootstrap receipt silence independently of the lifetime of a duplex SSH channel.
#![allow(clippy::unwrap_used)]
use infraternal_plugin_ssh::duplex::Duplex;
use std::time::Duration;

/// A host that never emits its setup receipt fails after one inactivity interval.
#[tokio::test(start_paused = true)]
async fn silent_setup_receipt_fails_within_thirty_seconds() {
    let mut command = tokio::process::Command::new("/bin/sleep");
    command.arg("600");
    let channel = Duplex::spawn(&mut command).unwrap();
    let Ok(result) = tokio::time::timeout(Duration::from_secs(31), channel.line(32)).await else {
        panic!("the setup receipt had no 30-second inactivity bound");
    };
    assert_eq!(
        result.err().unwrap().message,
        "The SSH operation timed out."
    );
}
