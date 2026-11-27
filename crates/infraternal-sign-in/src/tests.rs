//! Tests for the pure sign-in checks; they moved here with the code from the CLI.

#![allow(clippy::unwrap_used)]

use super::*;

/// A scope no action declares is not grantable; a later action that declared
/// it would otherwise become callable by keys already issued (J137 P3-6).
#[test]
fn scopes_without_an_action_are_refused() {
    assert_eq!(
        requested_scopes(&["sessions:write"]),
        Err(CheckFailure::InvalidScope)
    );
    assert!(requested_scopes(&["hosts:write"]).is_ok());
}

/// The default scopes are read-only, and asking for one again does not repeat it.
#[test]
fn default_scopes_are_read_only_and_not_repeated() {
    assert_eq!(SCOPES, ["hosts:read", "sessions:read", "status:read"]);
    assert_eq!(
        requested_scopes(&["hosts:read", "hosts:write"]).unwrap(),
        ["hosts:read", "sessions:read", "status:read", "hosts:write"]
    );
}

/// Only a bare HTTPS origin is a server address; paths, credentials, queries and fragments are not.
#[test]
fn server_input_accepts_only_a_bare_https_origin() {
    let parsed = server_url("https://Mesh.Example.org:8443/").unwrap();
    assert_eq!(
        parsed.origin().ascii_serialization(),
        "https://mesh.example.org:8443"
    );
    for invalid in [
        "http://mesh.example.org",
        "https://mesh.example.org/prefix",
        "https://mesh.example.org/?debug=1",
        "https://person:password@mesh.example.org",
        "https://mesh.example.org/#fragment",
    ] {
        assert_eq!(
            server_url(invalid).err(),
            Some(CheckFailure::InvalidServer),
            "{invalid}"
        );
    }
}

/// The approval link carries the user code and never the poll token.
#[test]
fn approval_link_carries_only_the_browser_user_code() {
    let server = server_url("https://mesh.example.org").unwrap();
    let link = approval_link(&server, "A_b-c123");

    assert_eq!(link, "https://mesh.example.org/?device_code=A_b-c123");
    assert!(!link.contains("poll_token"));
}

/// A capability must be exactly the expected length of base64url characters.
#[test]
fn server_generated_capabilities_have_exact_base64url_shapes() {
    assert!(server_capability_has_shape(&"A".repeat(43), 43));
    assert!(server_capability_has_shape(&"_".repeat(16), 16));
    assert!(!server_capability_has_shape(&"A".repeat(42), 43));
    assert!(!server_capability_has_shape(&"A".repeat(44), 43));
    assert!(!server_capability_has_shape(&("A".repeat(42) + "+"), 43));
    assert!(!server_capability_has_shape(&("A".repeat(42) + "="), 43));
}

/// A `200` redeem reply that cannot be used is "uncertain": the key may be spent.
#[test]
fn unusable_successful_redemption_bodies_are_uncertain() {
    for response in [
        b"not json".as_slice(),
        br#"{"unexpected":"field"}"#.as_slice(),
        br#"{"api_key":"not-a-capability"}"#.as_slice(),
    ] {
        assert!(matches!(
            parse_redemption_response(response),
            Err(CheckFailure::RedemptionUncertain)
        ));
    }
}

/// A start reply needs exact token and code shapes, the full lifetime and no extra fields.
#[test]
fn a_start_reply_needs_exact_shapes_and_the_full_lifetime() {
    let good = format!(
        r#"{{"poll_token":"{}","user_code":"{}","expires_in":600}}"#,
        "T".repeat(43),
        "C".repeat(16)
    );
    let approval = parse_start_response(good.as_bytes()).unwrap();
    assert_eq!(approval.user_code, "C".repeat(16));
    assert_eq!(approval.lifetime, Duration::from_secs(600));
    for bad in [
        good.replace("600", "601"),
        good.replace(&"C".repeat(16), "short"),
        good.replace('}', r#","extra":1}"#),
    ] {
        assert!(matches!(
            parse_start_response(bad.as_bytes()),
            Err(CheckFailure::BadResponse)
        ));
    }
}

/// Redeem statuses map to pending, retry-after, credential or "other".
#[test]
fn redeem_statuses_map_to_pending_retry_credential_or_other() {
    let key = format!(r#"{{"api_key":"{}"}}"#, "K".repeat(43));
    assert!(matches!(
        interpret_redemption(200, key.as_bytes(), None),
        Ok(Redemption::Credential(_))
    ));
    assert!(matches!(
        interpret_redemption(401, b"", None),
        Ok(Redemption::Pending)
    ));
    assert!(matches!(
        interpret_redemption(429, b"", Some(Duration::from_secs(3))),
        Ok(Redemption::RetryAfter(Some(delay))) if delay == Duration::from_secs(3)
    ));
    assert!(matches!(
        interpret_redemption(500, b"", None),
        Ok(Redemption::Other(500))
    ));
    assert!(matches!(
        interpret_redemption(200, b"{}", None),
        Err(CheckFailure::RedemptionUncertain)
    ));
}

/// The join link puts only the user code in the fragment.
#[test]
fn join_approval_link_places_only_the_user_code_in_the_fragment() {
    let server = Url::parse("https://mesh.example.org:8443/").unwrap();
    assert_eq!(
        join_approval_link(&server, "AbCdEfGhIjKlMnOp"),
        "https://mesh.example.org:8443/#join=AbCdEfGhIjKlMnOp"
    );
}

/// A system join asks for root mode with execution uid 0 and the exact key fingerprint.
#[test]
fn machine_start_body_binds_the_requested_mode_and_key() {
    let body = machine_start_body(
        Uuid::from_u128(1),
        "workstation",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "system",
        0,
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "join_machine",
            "device": "workstation",
            "request": {
                "host_id": "00000000-0000-0000-0000-000000000001",
                "hostname": "workstation",
                "mode": "system",
                "execution_uid": 0,
                "key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        })
    );
}

/// Bad host names and non-canonical fingerprints are refused before any request is built.
#[test]
fn machine_start_body_refuses_bad_names_and_fingerprints() {
    let good = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for (name, fingerprint) in [
        ("", good),
        ("bad\nname", good),
        (&"h".repeat(129), good),
        ("host", "SHA256:short"),
        ("host", "MD5:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        // Non-canonical trailing bits decode but do not round-trip.
        ("host", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"),
    ] {
        assert_eq!(
            machine_start_body(Uuid::nil(), name, fingerprint, "system", 0).err(),
            Some(CheckFailure::InvalidMachine),
            "{name:?} {fingerprint}"
        );
    }
}

/// A device join omits `execution_uid`, as the server's device mode requires.
#[test]
fn device_machine_start_body_omits_execution_uid() {
    let body = super::device_machine_start_body(
        Uuid::from_u128(2),
        "simulator",
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "join_machine",
            "device": "simulator",
            "request": {
                "host_id": "00000000-0000-0000-0000-000000000002",
                "hostname": "simulator",
                "mode": "device",
                "key_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        })
    );
}
