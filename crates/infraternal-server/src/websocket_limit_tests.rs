//! The per-account connection limit's two forms, and which admission errors count as reaching it (#523).
use super::*;

/// The upgrade permit and the row check enforce one limit.
#[test]
fn connection_limit_constants_agree() {
    assert_eq!(
        i64::try_from(MAX_USER_CONNECTIONS).unwrap(),
        MAX_USER_CONNECTION_ROWS
    );
}

/// Only the two limit refusals name the limit; storage and authority failures stay generic.
#[test]
fn only_limit_refusals_count_as_the_limit() {
    assert!(is_connection_limit(&sqlx::Error::Protocol(
        CONNECTION_LIMIT_ERROR.into()
    )));
    assert!(is_connection_limit(&resume_refused(RESUME_CAPACITY_CHECK)));
    assert!(!is_connection_limit(&resume_refused("token_mismatch")));
    assert!(!is_connection_limit(&sqlx::Error::PoolTimedOut));
}
