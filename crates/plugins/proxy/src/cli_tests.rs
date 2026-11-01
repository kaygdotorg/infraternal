//! Pins the single owner-approved CLI table entry for publication [#281, D303, D314].

use super::cli::{ID, plugin};

#[test]
fn publish_is_the_single_root_command_with_optional_port_and_public_scope() {
    let definition = plugin();
    assert_eq!(definition.id, ID);
    assert_eq!(definition.actions.len(), 1);
    let action = &definition.actions[0];
    assert_eq!(action.command, ["publish"]);
    assert!(action.input_schema.properties.contains_key("port"));
    assert!(action.input_schema.properties.contains_key("public"));
    assert!(action.input_schema.properties.contains_key("flat_name"));
    assert!(
        action
            .input_schema
            .properties
            .contains_key("confirm_public")
    );
    assert!(action.input_schema.required.is_empty());
    assert!(!definition.actions.iter().any(|candidate| {
        candidate
            .command
            .first()
            .is_some_and(|word| word == "serve")
    }));
}
