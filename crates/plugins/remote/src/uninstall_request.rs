//! Decodes the private uninstall request shared by both service managers.

use infraternal_plugin_api::PluginError;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// An exact host identity and dry-run choice, without filesystem input.
pub struct Request {
    /// The exact enrolled host identity.
    pub host: String,
    /// Request only an ownership check.
    pub dry_run: bool,
}
/// Decode the same bounded object used by the authenticated uninstall handler.
/// # Errors
/// Refuses positional input, foreign fields, duplicate keys and invalid host identities.
pub fn decode_request(input: &[u8]) -> Result<Request, PluginError> {
    if input.len() > infraternal_plugin_api::MAX_ACTION_BYTES
        || input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(PluginError::Rejected);
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| PluginError::Rejected)?;
    if request.host.len() != 32
        || !request
            .host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PluginError::Rejected);
    }
    Ok(request)
}
