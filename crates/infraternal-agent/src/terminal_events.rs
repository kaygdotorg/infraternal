//! Serializes the existing terminal event shapes directly, without temporary dynamic JSON trees (D243, D255).

use serde::Serialize;
use std::io;
use uuid::Uuid;

/// Fixed terminal events retain their existing value types and optional-field semantics.
#[derive(Serialize)]
#[serde(tag = "type")]
pub(super) enum Notice<'a> {
    /// The full list of live session ids, as UUID strings.
    #[serde(rename = "terminal.sessions.snapshot")]
    SessionsSnapshot {
        #[serde(serialize_with = "serialize_session_ids")]
        session_ids: &'a [[u8; 16]],
    },
    /// Sent when a session's replay has caught up. `out_seq` is the output cursor,
    /// written as a decimal string; `cols` and `rows` are the terminal size.
    #[serde(rename = "terminal.replay_complete")]
    ReplayComplete {
        session_id: Uuid,
        #[serde(serialize_with = "cursor")]
        out_seq: u64,
        cols: u16,
        rows: u16,
    },
    /// Tells the client that terminal query replies are not available for this
    /// session. Carries only the session id.
    #[serde(rename = "terminal.query_replies_unavailable")]
    QueryRepliesUnavailable { session_id: Uuid },
    /// The session's process ended. `status` is the exit status and `final_seq` the
    /// last output sequence number. `retired` is left out unless it is `Some`.
    #[serde(rename = "terminal.exited")]
    Exited {
        session_id: Uuid,
        status: i32,
        final_seq: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retired: Option<bool>,
    },
    /// A screen snapshot exists for `session_id` at output sequence `seq`;
    /// `approximate` says whether it is only an approximation.
    #[serde(rename = "terminal.snapshot")]
    Snapshot {
        session_id: Uuid,
        seq: u64,
        approximate: bool,
    },
    /// No snapshot could be provided for `session_id` at sequence `seq`.
    #[serde(rename = "terminal.snapshot_unavailable")]
    SnapshotUnavailable { session_id: Uuid, seq: u64 },
}
impl Notice<'_> {
    /// Serializes the notice straight to JSON bytes (the `type` field names the
    /// event). Fails only if serialization itself fails.
    pub(super) fn json(&self) -> io::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(io::Error::from)
    }
}

/// Borrow the authoritative census; UUID serialization writes its canonical string directly.
fn serialize_session_ids<S: serde::Serializer>(
    ids: &[[u8; 16]],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut sequence = serializer.serialize_seq(Some(ids.len()))?;
    for id in ids {
        sequence.serialize_element(&Uuid::from_bytes(*id))?;
    }
    sequence.end()
}

/// Replay cursors are decimal strings so clients cannot lose precision above 2^53.
#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde serialization callbacks receive a reference."
)]
fn cursor<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

#[cfg(test)]
mod tests {
    //! Preserve the existing event contract at the numeric and optional-field boundaries.
    use super::*;

    #[test]
    fn census_uses_uuid_strings_and_replay_keeps_all_cursor_bits() {
        let id = Uuid::from_bytes([0xab; 16]);
        let ids = [*id.as_bytes()];
        let census = Notice::SessionsSnapshot { session_ids: &ids }
            .json()
            .unwrap();
        let census: serde_json::Value = serde_json::from_slice(&census).unwrap();
        assert_eq!(census["type"], "terminal.sessions.snapshot");
        assert_eq!(census["session_ids"], serde_json::json!([id.to_string()]));
        let replay = Notice::ReplayComplete {
            session_id: id,
            out_seq: u64::MAX,
            cols: 80,
            rows: 24,
        }
        .json()
        .unwrap();
        let replay: serde_json::Value = serde_json::from_slice(&replay).unwrap();
        assert_eq!(replay["type"], "terminal.replay_complete");
        assert_eq!(replay["session_id"], id.to_string());
        assert_eq!(replay["out_seq"], "18446744073709551615");
    }

    #[test]
    fn reply_compatibility_notice_contains_only_session_identity() {
        let id = Uuid::from_bytes([1; 16]);
        let event = Notice::QueryRepliesUnavailable { session_id: id }
            .json()
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&event).unwrap(),
            serde_json::json!({"type":"terminal.query_replies_unavailable", "session_id":id.to_string()})
        );
    }

    #[test]
    fn ordinary_exit_omits_retired_and_snapshot_sequences_stay_numeric() {
        let id = Uuid::nil();
        for retired in [None, Some(true)] {
            let event = Notice::Exited {
                session_id: id,
                status: -1,
                final_seq: u64::MAX,
                retired,
            }
            .json()
            .unwrap();
            let event: serde_json::Value = serde_json::from_slice(&event).unwrap();
            assert_eq!(event["final_seq"].as_u64(), Some(u64::MAX));
            assert_eq!(event["status"], -1);
            if retired.is_some() {
                assert_eq!(event["retired"], true);
            } else {
                assert!(event.get("retired").is_none());
            }
        }
        for notice in [
            Notice::Snapshot {
                session_id: id,
                seq: u64::MAX,
                approximate: true,
            },
            Notice::SnapshotUnavailable {
                session_id: id,
                seq: u64::MAX,
            },
        ] {
            let event = notice.json().unwrap();
            let event: serde_json::Value = serde_json::from_slice(&event).unwrap();
            assert_eq!(event["seq"].as_u64(), Some(u64::MAX));
        }
    }
}
