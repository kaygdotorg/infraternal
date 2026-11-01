//! Pins the publish and unpublish CLI table entries for this node [#281, D303, D314].

use super::cli::{ID, plugin};

#[test]
fn publish_and_unpublish_are_separate_root_commands() {
    let definition = plugin();
    assert_eq!(definition.id, ID);
    assert_eq!(definition.actions.len(), 2);
    let publish = definition
        .actions
        .iter()
        .find(|action| action.command == ["publish"])
        .expect("publish command");
    assert!(publish.input_schema.properties.contains_key("port"));
    assert!(publish.input_schema.properties.contains_key("public"));
    assert!(publish.input_schema.properties.contains_key("flat_name"));
    assert!(
        publish
            .input_schema
            .properties
            .contains_key("confirm_public")
    );
    assert!(publish.input_schema.required.is_empty());
    let unpublish = definition
        .actions
        .iter()
        .find(|action| action.command == ["unpublish"])
        .expect("unpublish command");
    assert_eq!(unpublish.input_schema.required, ["target"]);
    assert!(unpublish.input_schema.properties.contains_key("target"));
    assert!(!definition.actions.iter().any(|candidate| {
        candidate
            .command
            .first()
            .is_some_and(|word| word == "serve" || word == "expose")
    }));
}
