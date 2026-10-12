//! Ensures Cargo emits an explicit build identity rather than guessing from optimization.
#[test]
fn release_build_marker_is_explicit() {
    let expected = if std::env::var("INFRATERNAL_RELEASE_BUILD").is_ok_and(|value| value == "1") {
        "1"
    } else {
        "0"
    };
    assert_eq!(option_env!("INFRATERNAL_RELEASE_BUILD"), Some(expected));
}
