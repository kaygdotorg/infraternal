//! Reproduce unknown nested JSON fields crossing the supposedly strict Mesh action boundary.
#![cfg(feature = "mesh")]
#![allow(clippy::unwrap_used)] // Test fixtures must fail immediately on serialization errors.
use infraternal_server::mesh_api::{MeshApiError, parse_action};

#[test]

fn review_grant_parser_rejects_unknown_nested_port_fields() {
    let input = br#"{"name":"web","from":{"Tag":"prod"},"to":{"Tag":"db"},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":443,"unexpected":true}]}}"#;
    assert_eq!(
        parse_action("mesh.grant.create", input),
        Err(MeshApiError::InvalidInput),
        "contracts/mesh-api.md section 1 rejects unknown fields"
    );
}

#[test]
fn nested_endpoint_and_policy_fields_are_strict_without_rejecting_valid_ports() {
    let valid = serde_json::json!({"name":"web","from":{"Tag":"prod"},"to":{"Tag":"db"},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":443},{"protocol":"Udp","number":53}]}});
    assert!(parse_action("mesh.grant.create", &serde_json::to_vec(&valid).unwrap()).is_ok());
    for (field, replacement) in [
        ("from", serde_json::json!({"Tag":"prod","unexpected":true})),
        ("to", serde_json::json!({"Tag":"db","unexpected":true})),
        (
            "ports",
            serde_json::json!({"Ports":[{"protocol":"Udp","number":53,"unexpected":true}]}),
        ),
        (
            "ports",
            serde_json::json!({"Ports":[{"protocol":"Tcp","number":443}],"unexpected":true}),
        ),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = replacement;
        assert_eq!(
            parse_action("mesh.grant.create", &serde_json::to_vec(&invalid).unwrap()),
            Err(MeshApiError::InvalidInput)
        );
    }
}
