//! Preserves existing JSON stream declarations when native metadata is absent from the build [D16,D198,D232], #146.
#![cfg(not(feature = "native-streams"))]
#[test]
fn json_declaration_preserves_legacy_wire_shape() {
    let stream = infraternal_plugin_api::StreamDef::json(
        "fixture.stream",
        infraternal_plugin_api::SchemaRef("fixture.value"),
        true,
    );
    assert!(serde_json::to_value(stream).is_ok_and(|json| json
        == serde_json::json!({"id":"fixture.stream","schema":"fixture.value","resumable":true})));
}
