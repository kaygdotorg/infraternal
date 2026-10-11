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
});
