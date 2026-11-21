//! The per-account connection limit's two forms, which admission errors count as reaching it (#523), and which
//! refused resumes may start fresh on the same socket (#569).
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

/// A stale resume starts fresh on the same socket (#569); the account's limit, an ended cookie session and storage
/// errors never do. The limit must stay a refusal so the browser keeps its still-valid capability (#523).
#[test]
fn only_stale_resume_refusals_start_fresh() {
    for check in STALE_RESUME_CHECKS {
        assert!(is_stale_resume(&resume_refused(check)), "{check}");
        assert!(!is_connection_limit(&resume_refused(check)), "{check}");
    }
    assert!(!is_stale_resume(&resume_refused(RESUME_CAPACITY_CHECK)));
    assert!(!is_stale_resume(&sqlx::Error::Protocol(
        CONNECTION_LIMIT_ERROR.into()
    )));
    assert!(!is_stale_resume(&sqlx::Error::Protocol(
        "session authority ended".into()
    )));
    assert!(!is_stale_resume(&sqlx::Error::PoolTimedOut));
}
