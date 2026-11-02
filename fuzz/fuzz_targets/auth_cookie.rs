//! Fuzzes the production capability reader across split fields and hidden duplicates.
#![no_main]
#![forbid(unsafe_code)]
#[path = "../../crates/infraternal-server/src/auth/cookies.rs"]
mod cookies;
use axum::http::{HeaderMap, HeaderValue, header};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut headers = HeaderMap::new();
    for field in input.split(|byte| *byte == b'\n').take(64) {
        if let Ok(value) = HeaderValue::from_bytes(field) {
            headers.append(header::COOKIE, value);
        }
    }
    for prefix in ["__Host-infraternal=", "__Host-infraternal-ceremony="] {
        if let Some(value) = cookies::capability(&headers, prefix) {
            assert_eq!(value.len(), 43);
            assert!(
                value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            );
            let duplicate = format!("{prefix}{value}");
            let mut duplicated = headers.clone();
            duplicated.append(header::COOKIE, duplicate.parse().unwrap());
            assert!(cookies::capability(&duplicated, prefix).is_none());
        }
    }
    // Keep the session selector and retirement-name scan in this fuzz corpus too.
    if let Some(session) = cookies::session(&headers) {
        assert_eq!(session.token.len(), 43);
        assert!(session.login_sequence >= 0);
        assert!(session.expires >= 0);
        assert!(
            session.name == "__Host-infraternal"
                || session.name.starts_with("__Host-infraternal-session-")
        );
    }
    for name in cookies::observed_session_names(&headers) {
        assert!(name == "__Host-infraternal" || name.starts_with("__Host-infraternal-session-"));
    }
});
