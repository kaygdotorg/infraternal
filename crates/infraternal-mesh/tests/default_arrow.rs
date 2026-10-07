//! Arrow creation defaults to unrestricted services while compiled views remain deny-by-default.
#![allow(clippy::unwrap_used)]
use infraternal_mesh::rules::{Arrow, TrafficPolicy};

#[test]
fn omitted_arrow_ports_default_to_all_services() {
    let arrow: Arrow =
        serde_json::from_str(r#"{"id":1,"from":{"Node":1},"to":{"Node":2},"both_ways":false}"#)
            .unwrap();
    assert_eq!(arrow.ports, TrafficPolicy::All);
    assert_eq!(TrafficPolicy::default(), TrafficPolicy::None);
}
