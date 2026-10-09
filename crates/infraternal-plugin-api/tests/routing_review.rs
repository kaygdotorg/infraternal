//! Independent review of bounded topic discovery [D11, D198, #108].
use infraternal_plugin_api::routing::subscription_topic;
use std::borrow::Cow;

#[test]
fn review_topic_borrows_plain_and_owns_escaped() {
    assert!(matches!(
        subscription_topic(br#"{"topic":"mesh","tag":"x"}"#, 1024),
        Some(Cow::Borrowed("mesh"))
    ));
    assert!(matches!(
        subscription_topic(b"{\"topic\":\"me\x5Cu0073h\"}", 1024),
        Some(Cow::Owned(ref topic)) if topic == "mesh"
    ));
}

#[test]
fn review_topic_refuses_oversize_duplicate_and_deep_input() {
    assert_eq!(subscription_topic(br#"{"topic":"mesh"}"#, 15), None);
    assert_eq!(
        subscription_topic(br#"{"topic":"mesh","topic":"other"}"#, 1024),
        None
    );
    let deep = format!(
        r#"{{"x":{}1{},"topic":"mesh"}}"#,
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    // Ignored nesting is skipped without recursion or allocation; the frame bound caps work.
    assert!(matches!(
        subscription_topic(deep.as_bytes(), usize::MAX),
        Some(Cow::Borrowed("mesh"))
    ));
    assert_eq!(subscription_topic(br#"{"topic":"\ud800"}"#, 1024), None);
}
