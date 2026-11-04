//! Parses bounded untrusted channel pointers; only a later signed VERSION check authenticates identity [226].
use serde::Deserialize;
/// The JSON a release channel publishes to say which version is current.
/// Unknown fields are refused so the grammar stays unambiguous.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pointer {
    /// The announced version; the only field this crate uses.
    version: String,
    // The remaining fields are accepted so a complete pointer parses, but they
    // are unsigned and so never read; the signed VERSION check is authoritative.
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
///
/// `input` is the raw pointer body (at most 64 KiB, a JSON object) and
/// `channel` the channel the caller asked for. Returns the pointer's version
/// string, which is still unauthenticated until checked against the signed
/// VERSION.
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
