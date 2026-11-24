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

#[test]
fn default_scopes_are_read_only_and_not_repeated() {
    assert_eq!(SCOPES, ["hosts:read", "sessions:read", "status:read"]);
    assert_eq!(
        requested_scopes(&["hosts:read", "hosts:write"]).unwrap(),
        ["hosts:read", "sessions:read", "status:read", "hosts:write"]
    );
}

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

#[test]
fn approval_link_carries_only_the_browser_user_code() {
    let server = server_url("https://mesh.example.org").unwrap();
    let link = approval_link(&server, "A_b-c123");

    assert_eq!(link, "https://mesh.example.org/?device_code=A_b-c123");
    assert!(!link.contains("poll_token"));
}

#[test]
fn server_generated_capabilities_have_exact_base64url_shapes() {
    assert!(server_capability_has_shape(&"A".repeat(43), 43));
    assert!(server_capability_has_shape(&"_".repeat(16), 16));
    assert!(!server_capability_has_shape(&"A".repeat(42), 43));
    assert!(!server_capability_has_shape(&"A".repeat(44), 43));
    assert!(!server_capability_has_shape(&("A".repeat(42) + "+"), 43));
    assert!(!server_capability_has_shape(&("A".repeat(42) + "="), 43));
}

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
