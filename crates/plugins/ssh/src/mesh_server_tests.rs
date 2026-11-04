//! Checks the connection-level bounds of the mesh SSH server (J181 M2).
use super::*;
use crate::mesh_authority::{Authority, SessionRuntime};
use std::time::Instant;

/// A runtime that opens nothing; only connection bounds are under test.
struct NoRuntime;
#[allow(clippy::unused_async_trait_impl)]
impl SessionRuntime for NoRuntime {
    async fn open(
        &self,
        _: &str,
        _: &str,
        _: SessionKind,
        _: Option<Terminal>,
    ) -> Result<Attachment, Refusal> {
        Err(Refusal::LoginAccess)
    }
}

/// Host key.
fn host_key() -> PrivateKey {
    PrivateKey::random(
        &mut russh::keys::key::safe_rng(),
        russh::keys::Algorithm::Ed25519,
    )
    .unwrap()
}

/// Authenticated shells use keepalives not an idle timeout.
#[test]
fn authenticated_shells_use_keepalives_not_an_idle_timeout() {
    let config = config(host_key());
    // An idle editor must not die after ten minutes.
    assert_eq!(config.inactivity_timeout, None);
    assert!(config.keepalive_interval.is_some());
    assert!(config.keepalive_max > 0);
}

/// A silent connection is closed at the login deadline.
#[tokio::test]
async fn a_silent_connection_is_closed_at_the_login_deadline() {
    let authority = Arc::new(Authority::new(NoRuntime, |_| None));
    let (_client, server) = tokio::io::duplex(4096);
    let grace = Duration::from_millis(200);
    let started = Instant::now();
    let pending = Arc::new(());
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        serve_admitted(
            authority,
            "10.254.0.7".parse().unwrap(),
            9,
            Arc::new(config(host_key())),
            server,
            grace,
            Arc::clone(&pending),
        ),
    )
    .await
    .expect("deadline enforced");
    assert!(result.is_err());
    assert!(started.elapsed() >= grace);
    // The pending slot went with the connection.
    assert_eq!(Arc::strong_count(&pending), 1);
}
