//! Decodes the frozen bounded source action shapes before lifecycle or helper work; the same pure boundary is fuzzed [D40,D203,D232].
use crate::protocol::Start;
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
