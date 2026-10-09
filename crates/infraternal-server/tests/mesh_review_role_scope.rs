//! Independent validation check for explicit null Mesh role scopes [D154, D187, #108].
#![cfg(feature = "mesh")]
use infraternal_server::mesh_api::{MeshApiError, parse_action};

#[test]
fn review_explicit_null_role_scopes_do_not_become_global_authority() {
    assert_eq!(
        parse_action(
            "mesh.role.define",
            br#"{"name":"restricted","actions":["mesh.manage_nodes"],"scopes":null}"#,
        ),
        Err(MeshApiError::InvalidInput),
        "the contract permits omitted scopes or a nonempty tag array"
    );
}

#[test]
fn role_scopes_require_an_array_when_provided() {
    for scopes in ["[]", "true", "{}", "\"prod\"", "[null]"] {
        let input =
            format!(r#"{{"name":"restricted","actions":["mesh.manage_nodes"],"scopes":{scopes}}}"#);
        assert_eq!(
            parse_action("mesh.role.define", input.as_bytes()),
            Err(MeshApiError::InvalidInput)
        );
    }
    for input in [
        br#"{"name":"global","actions":["mesh.manage_nodes"]}"#.as_slice(),
        br#"{"name":"restricted","actions":["mesh.manage_nodes"],"scopes":["prod"]}"#.as_slice(),
    ] {
        assert!(parse_action("mesh.role.define", input).is_ok());
    }
}
