//! Socket capability parsing accepts split fields while denying hidden duplicate cookies.
use super::session_cookie;
use axum::http::{HeaderMap, header};
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

#[test]
fn split_cookie_fields_preserve_socket_session() {
    let mut headers = HeaderMap::new();
    headers.append(
        header::COOKIE,
        "__Host-infraternal-ceremony=unrelated".parse().unwrap(),
    );
    headers.append(
        header::COOKIE,
        format!("__Host-infraternal={TOKEN}").parse().unwrap(),
    );
    assert_eq!(session_cookie(&headers), Some(TOKEN));
}

#[test]
fn duplicate_cookie_fields_deny_socket_session() {
    let mut headers = HeaderMap::new();
    for _ in 0..2 {
        headers.append(
            header::COOKIE,
            format!("__Host-infraternal={TOKEN}").parse().unwrap(),
        );
    }
    assert!(session_cookie(&headers).is_none());
}
