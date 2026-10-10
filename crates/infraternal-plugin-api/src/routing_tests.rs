//! Check routing bounds and malformed topics before strict plugin filter validation [12,198].
use super::*;

#[test]
fn topic_is_borrowed_and_other_filter_fields_are_left_to_the_plugin() {
    assert!(matches!(
        subscription_topic(br#"{"topic":"mesh","tag":"ops"}"#, 64),
        Some(Cow::Borrowed("mesh"))
    ));
    assert_eq!(
        subscription_topic(br#"{"topic":"m\u0065sh"}"#, 64).as_deref(),
        Some("mesh")
    );
}
#[test]
fn invalid_or_oversized_topics_are_refused() {
    for input in [
        b"{}".as_slice(),
        br#"{"topic":1}"#,
        br#"{"topic":"mesh","topic":"mesh"}"#,
        br#"{"topic":null}"#,
        br#"{"topic":"mesh"}garbage"#,
    ] {
        assert!(subscription_topic(input, 64).is_none());
    }
    assert!(subscription_topic(br#"{"topic":"mesh"}"#, 1).is_none());
}
