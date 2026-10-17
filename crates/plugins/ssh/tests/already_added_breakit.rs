// SPDX-License-Identifier: AGPL-3.0-only
//! Break-it review of the shared UUID slot in `Failure` (#189): the wire key is
//! chosen by the public `already_added` flag, so a host-key challenge must never
//! be renamed into an existing-host id by setting that flag.
#![allow(clippy::unwrap_used)]
use infraternal_plugin_ssh::model::{Failure, FailureKind};

#[test]
fn a_host_key_challenge_never_serializes_as_a_host_id() {
    let challenge = uuid::Uuid::from_u128(0xc0ffee);
    let mut failure = Failure::new(FailureKind::HostKey, "Confirm this host key.");
    failure.set_host_key_challenge(Some(challenge));
    // `already_added` stays a public field; any future duplicate path that marks
    // an existing failure (instead of building one with `with_existing_host_id`)
    // turns the challenge into a "host id" the browser opens a terminal on.
    failure.already_added = true;
    let wire = serde_json::to_value(&failure).unwrap();
    assert!(
        wire.get("host_id").is_none(),
        "challenge {challenge} was sent as host_id: {wire}"
    );
}
