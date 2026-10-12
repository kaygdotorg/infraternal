//! Parses bounded untrusted channel pointers; only a later signed VERSION check authenticates identity [226].
use serde::Deserialize;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pointer {
    version: String,
    #[serde(default, rename = "channel")]
    _channel: Option<String>,
    #[serde(default, rename = "files")]
    _files: Option<Vec<String>>,
    #[serde(default, rename = "sums_sha256")]
    _sums_sha256: Option<String>,
    #[serde(default, rename = "signed_at")]
    _signed_at: Option<String>,
}
/// Validate a pointer's object grammar and selected channel without trusting unsigned fields.
/// # Errors
/// Refuses oversized, ambiguous, malformed or cross-channel pointers.
pub fn parse(input: &[u8], channel: &str) -> Result<String, &'static str> {
    if input.len() > 65536 || input.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err("invalid release pointer");
    }
    let pointer: Pointer = serde_json::from_slice(input).map_err(|_| "invalid release pointer")?;
    if infraternal_plugin_api::release_version::channel(&pointer.version) != Some(channel) {
        return Err("release pointer belongs to another channel");
    }
    Ok(pointer.version)
}
