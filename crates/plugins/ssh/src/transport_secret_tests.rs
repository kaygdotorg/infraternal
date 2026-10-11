//! Bounds input-only credential decoding without producing an output or diagnostic representation.
use super::Secret;

#[test]
fn secret_input_has_a_fixed_bound_and_accepts_only_strings() {
    let secret: Secret = serde_json::from_str("\"synthetic-private-input\"").unwrap();
    assert_eq!(secret.expose(), b"synthetic-private-input");
    for input in ["null", "[]", "{}", "12", "true"] {
        assert!(serde_json::from_str::<Secret>(input).is_err());
    }
    let excessive = format!("\"{}\"", "x".repeat(24_577));
    let error = serde_json::from_str::<Secret>(&excessive).err().unwrap();
    assert!(error.to_string().contains("exceeds its bound"));
    assert!(!error.to_string().contains(&"x".repeat(32)));
}
