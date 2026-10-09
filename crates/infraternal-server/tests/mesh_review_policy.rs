//! Independent strict-policy regression: explicit null is not an omitted all-ports policy [D164, #108].
use infraternal_server::mesh_api::{MeshApiError, parse_action};

#[test]
fn review_null_port_policy_is_refused() {
    let result = parse_action(
        "mesh.grant.create",
        br#"{"name":"restricted","from":{"Tag":"prod"},"to":{"Tag":"db"},"both_ways":false,"ports":null}"#,
    );
    println!("explicit_null_parse_result={result:?}");
    assert_eq!(result, Err(MeshApiError::InvalidInput));
}
