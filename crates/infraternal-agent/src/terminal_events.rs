//! Serializes the existing terminal event shapes directly, without temporary dynamic JSON trees (D243, D255).

use serde::Serialize;
use std::io;
use uuid::Uuid;

/// Fixed terminal events retain their existing value types and optional-field semantics.
#[derive(Serialize)]
#[serde(tag = "type")]
pub(super) enum Notice<'a> {
    #[serde(rename = "terminal.sessions.snapshot")]
    SessionsSnapshot {
        #[serde(serialize_with = "serialize_session_ids")]
        session_ids: &'a [[u8; 16]],
    },
    #[serde(rename = "terminal.replay_complete")]
    ReplayComplete {
        session_id: Uuid,
        #[serde(serialize_with = "cursor")]
        out_seq: u64,
        cols: u16,
        rows: u16,
    },
    #[serde(rename = "terminal.query_replies_unavailable")]
    QueryRepliesUnavailable { session_id: Uuid },
    #[serde(rename = "terminal.exited")]
    Exited {
        session_id: Uuid,
        status: i32,
        final_seq: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retired: Option<bool>,
    },
    #[serde(rename = "terminal.snapshot")]
    Snapshot {
        session_id: Uuid,
        seq: u64,
        approximate: bool,
    },
    #[serde(rename = "terminal.snapshot_unavailable")]
    SnapshotUnavailable { session_id: Uuid, seq: u64 },
}
impl Notice<'_> {
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
