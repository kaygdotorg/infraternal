//! Decodes the frozen bounded source action shapes before lifecycle or helper work; the same pure boundary is fuzzed [D40,D203,D232,D349].
use crate::{
    app_icons::{ICON_CHUNK_BYTES, MAX_ICON_PNG_BYTES, valid_hash},
    protocol::Start,
};
use infraternal_plugin_api::{MAX_ACTION_BYTES, PluginError};
use serde::Deserialize;
use uuid::Uuid;

/// A validated request to the source plugin.
#[derive(Debug)]
pub enum SourceRequest {
    /// Turn the helper on (`true`) or off (`false`).
    Enabled(bool),
    /// Report status, for one session if an id is given.
    Status(Option<Uuid>),
    /// Prepare a capture for a session.
    Start {
        session_id: Uuid,
        /// What to capture; already validated.
        start: Start,
        /// Video sequence numbers continue after this value, so a restarted
        /// source never reuses numbers a viewer has already seen.
        sequence_floor: u64,
    },
    /// Stop and clean up the session with this id.
    Stop(Uuid),
    /// List windows; the cursor, if present, continues an earlier page.
    Windows(Option<String>),
    /// Read the capture clock, for one session if an id is given.
    Clock(Option<Uuid>),
    /// Read one 4 KiB piece of the app icon named by its SHA-256 (#146).
    Icon {
        /// The icon's content hash, as listed on a window row.
        sha256: String,
        /// Where the piece starts: a multiple of 4 KiB below 16 KiB.
        offset: usize,
    },
}

/// Turns an action name and its JSON body into a [`SourceRequest`].
///
/// # Errors
/// Rejects unknown actions, non-object JSON, duplicate/unknown fields, invalid
/// source identities or geometry, and inputs over the existing action limit.
pub fn decode(action: &str, input: &[u8]) -> Result<SourceRequest, PluginError> {
    match action {
        "desktop.up" | "desktop.down" => {
            let _: Empty = parse(input)?;
            Ok(SourceRequest::Enabled(action == "desktop.up"))
        }
        "desktop.status" | "desktop.source.status" => Ok(SourceRequest::Status(
            parse::<SessionInput>(input)?.session_id,
        )),
        "desktop.source.start" => {
            let request: PrepareInput = parse(input)?;
            request
                .start
                .validate()
                .map_err(|_| PluginError::Rejected)?;
            if request.session_id.is_nil() || request.sequence_floor == u64::MAX {
                return Err(PluginError::Rejected);
            }
            Ok(SourceRequest::Start {
                session_id: request.session_id,
                start: request.start,
                sequence_floor: request.sequence_floor,
            })
        }
        "desktop.source.stop" => Ok(SourceRequest::Stop(parse::<StopInput>(input)?.session_id)),
        "desktop.source.windows" => Ok(SourceRequest::Windows(
            parse::<InventoryInput>(input)?.cursor,
        )),
        "desktop.source.clock" => Ok(SourceRequest::Clock(
            parse::<SessionInput>(input)?.session_id,
        )),
        "desktop.source.icon" => {
            let IconInput { sha256, offset } = parse(input)?;
            if !valid_hash(&sha256)
                || offset >= MAX_ICON_PNG_BYTES
                || offset % ICON_CHUNK_BYTES != 0
            {
                return Err(PluginError::Rejected);
            }
            Ok(SourceRequest::Icon { sha256, offset })
        }
        _ => Err(PluginError::UnknownAction),
    }
}
/// Parses a body that must be a JSON object within the action size limit.
fn parse<T: serde::de::DeserializeOwned>(input: &[u8]) -> Result<T, PluginError> {
    if input.len() > MAX_ACTION_BYTES
        || input.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
    {
        return Err(PluginError::Rejected);
    }
    serde_json::from_slice(input).map_err(|_| PluginError::Rejected)
}
/// Body of actions that take no fields; any field is an error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
/// Body of `desktop.source.start`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInput {
    session_id: Uuid,
    start: Start,
    /// Defaults to 0 (first start); a restart passes the last sequence used.
    #[serde(default)]
    sequence_floor: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopInput {
    session_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInput {
    #[serde(default)]
    session_id: Option<Uuid>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryInput {
    #[serde(default)]
    cursor: Option<String>,
}
/// Body of `desktop.source.icon`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IconInput {
    /// 64 lowercase hex digits.
    sha256: String,
    /// Defaults to the first piece.
    #[serde(default)]
    offset: usize,
}

#[cfg(test)]
/// Checks the icon request's bounds before it reaches the store.
mod tests {
    use super::*;

    /// A hash and a chunk-aligned offset decode; anything else is refused.
    #[test]
    fn icon_requests_need_a_hash_and_an_aligned_offset() {
        let hash = "a".repeat(64);
        let ok = format!(r#"{{"sha256":"{hash}","offset":4096}}"#);
        assert!(matches!(
            decode("desktop.source.icon", ok.as_bytes()),
            Ok(SourceRequest::Icon { offset: 4096, .. })
        ));
        for bad in [
            format!(r#"{{"sha256":"{hash}","offset":1}}"#),
            format!(r#"{{"sha256":"{hash}","offset":16384}}"#),
            format!(r#"{{"sha256":"{}"}}"#, "A".repeat(64)),
            format!(r#"{{"sha256":"{}"}}"#, "a".repeat(63)),
            format!(r#"{{"sha256":"{hash}","extra":1}}"#),
        ] {
            assert!(
                decode("desktop.source.icon", bad.as_bytes()).is_err(),
                "{bad}"
            );
        }
    }
}
