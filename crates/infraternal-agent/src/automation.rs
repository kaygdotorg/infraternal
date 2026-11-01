//! Saved-shell CLI actions stay within the caller's host and account; no environment value grants authority (D288/D314).
//!
//! The bounded local action socket checks peer credentials, live shim credentials and the
//! caller's kernel ancestry. That saved-shell check applies to this CLI action path. Raw
//! shim sockets use the separate OS-user boundary in `contracts/shim.md`: same-UID processes
//! are trusted, while other UIDs are refused. No server or account boundary is crossed.
mod metadata;
mod operations;
use crate::sessions::{self, Session};
use serde::Serialize;
use serde_json::{Value, json};
use std::{io, os::unix::fs::MetadataExt, path::Path, time::Duration};

/// Shared definitions generate command parsing, help and short skills.
#[must_use]
pub fn actions() -> Vec<infraternal_plugin_api::ActionDefinition> {
    metadata::actions()
}

/// Bounded result carried inside the existing public Call/Result framing.
#[derive(Debug, Serialize)]
pub struct Reply {
    pub code: u8,
    pub message: String,
    pub next: String,
    pub data: Value,
}
impl Reply {
    /// Decode through the shared JSON parser, avoiding a second typed visitor.
    /// # Errors
    /// Refuses malformed results while permitting additive future fields.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        let mut value: Value = serde_json::from_slice(bytes)?;
        let code = value["code"]
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .ok_or(io::ErrorKind::InvalidData)?;
        let Value::String(message) = value["message"].take() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        let Value::String(next) = value["next"].take() else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        let data = value
            .as_object_mut()
            .and_then(|object| object.remove("data"))
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(Self {
            code,
            message,
            next,
            data,
        })
    }
    fn ok(message: &str, data: Value) -> Self {
        Self {
            code: 0,
            message: message.into(),
            next: String::new(),
            data,
        }
    }
    pub(super) fn error(code: u8, message: impl Into<String>, next: &str) -> Self {
        Self {
            code,
            message: message.into(),
            next: next.into(),
            data: json!({}),
        }
    }
}

/// Validate syntax before connecting; the daemon repeats this on untrusted socket input.
/// # Errors
/// Returns a usage result with a concrete correction.
pub fn validate(verb: &str, input: &Value) -> Result<(), Reply> {
    let bad = || {
        Reply::error(
            2,
            "Invalid session arguments.",
            "Run infraternal sessions --help; targets use <machine>:<session>.",
        )
    };
    let object = input.as_object().ok_or_else(bad)?;
    let definitions = actions();
    let definition = definitions
        .iter()
        .find(|a| a.command.last().map(String::as_str) == Some(verb))
        .or_else(|| (verb == "list").then(|| &definitions[0]))
        .ok_or_else(bad)?;
    if object
        .keys()
        .any(|key| key == "state" || !definition.input_schema.properties.contains_key(key))
        || definition
            .input_schema
            .required
            .iter()
            .any(|key| !object.contains_key(key))
    {
        return Err(bad());
    }
    for (key, value) in object {
        let valid = match key.as_str() {
            "after" => value
                .as_str()
                .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok()),
            "last" => value.as_u64().is_some_and(|n| (1..=10000).contains(&n)),
            "name" | "machine" => value.as_str().is_some_and(name),
            "target" => value
                .as_str()
                .and_then(|t| t.split_once(':'))
                .is_some_and(|(m, s)| name(m) && name(s)),
            "text" => value.as_str().is_some_and(|t| t.len() <= 4096),
            "command" => value.as_array().is_some_and(|args| {
                !args.is_empty()
                    && args
                        .iter()
                        .all(|a| a.as_str().is_some_and(|a| !a.contains('\0')))
                    && args[0].as_str().is_some_and(|a| !a.is_empty())
            }),
            _ => false,
        };
        if !valid {
            return Err(bad());
        }
    }
    Ok(())
}
fn name(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text != "."
        && text != ".."
        && text
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn parent(pid: u32, uid: u32) -> io::Result<u32> {
    let path = format!("/proc/{pid}");
    if std::fs::metadata(&path)?.uid() != uid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let record = std::fs::read_to_string(format!("{path}/stat"))?;
    record
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1))
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}
fn belongs(mut pid: u32, uid: u32, shim: u32) -> bool {
    // Bound kernel-tree work, fail closed on reparenting, inaccessible records or UID transitions.
    for _ in 0..128 {
        if pid == shim {
            return true;
        }
        let Ok(next) = parent(pid, uid) else {
            return false;
        };
        if next <= 1 || next == pid {
            return false;
        }
        pid = next;
    }
    false
}
fn same_account(session: &Session, uid: u32, names: &operations::Names) -> bool {
    session.peer.peer_cred().is_ok_and(|peer| {
        peer.pid()
            .is_some_and(|pid| u32::try_from(pid).ok() == Some(session.pid))
    }) && ((uid != 0 && session.peer.peer_cred().is_ok_and(|peer| peer.uid() == uid))
        || names
            .get(&uuid::Uuid::from_bytes(session.id).to_string())
            .is_some_and(|entry| entry["uid"].as_u64() == Some(u64::from(uid)))
        || std::fs::read_to_string(format!(
            "/proc/{}/task/{}/children",
            session.pid, session.pid
        ))
        .is_ok_and(|children| {
            children
                .split_whitespace()
                .filter_map(|pid| pid.parse::<u32>().ok())
                .any(|pid| parent(pid, uid).ok() == Some(session.pid))
        }))
}

pub(crate) async fn execute(state: &Path, uid: u32, pid: u32, verb: &str, bytes: &[u8]) -> Reply {
    let Ok(input) = serde_json::from_slice::<Value>(bytes) else {
        return Reply::error(
            2,
            "Invalid session request.",
            "Use infraternal sessions --help.",
        );
    };
    if let Err(reply) = validate(verb, &input) {
        return reply;
    }
    let result = tokio::time::timeout(Duration::from_secs(4), async {
        let names = operations::load(state)?;
        let mut live = sessions::discover(state).await?;
        live.retain(|session| same_account(session, uid, &names));
        if !live.iter().any(|s| belongs(pid, uid, s.pid)) {
            return Ok(Reply::error(3, "Run this command from your saved infraternal session.", "Open a terminal in the app on this machine and account, then run the command there."));
        }
        let machine = input.get("machine").and_then(Value::as_str)
            .or_else(|| input.get("target").and_then(Value::as_str).and_then(|s| s.split_once(':').map(|(m, _)| m)));
        let hostname = nix::unistd::gethostname()?.to_string_lossy().into_owned();
        if machine.is_some_and(|m| m != "local" && m != hostname) {
            return Ok(Reply::error(3, "Cross-machine session automation is not allowed yet.", "Run on the target machine in your saved session; remote control requires an access rule and approval."));
        }
        operations::run(state, uid, verb, &input, live, names).await
    }).await;
    match result {
        Ok(Ok(reply)) => reply,
        Ok(Err(_)) => Reply::error(
            1,
            "The session operation failed.",
            "List sessions and check whether the target is still running before retrying.",
        ),
        Err(_) => Reply::error(
            5,
            "The session did not reply in time; the operation may have started.",
            "List sessions before retrying a change.",
        ),
    }
}

#[cfg(test)]
mod tests {
    //! Rejects malformed requests before filesystem/process discovery and unproven caller trees.
    use super::*;
    #[test]
    fn rejects_unknown_fields_types_bounds_and_path_names() {
        for (verb, value) in [
            ("list", json!([])),
            ("attach", json!({})),
            ("list", json!({"uid": 0})),
            ("list", json!({"state": "/other"})),
            ("new", json!({"machine": "local", "name": "../escape"})),
            (
                "new",
                json!({"machine": "local", "name": "ok", "command": []}),
            ),
            (
                "new",
                json!({"machine": "local", "name": "ok", "command": [""]}),
            ),
            (
                "new",
                json!({"machine": "local", "name": "ok", "command": ["a\0b"]}),
            ),
            ("read", json!({"target": "local:ok", "last": -1})),
            ("read", json!({"target": "local:ok", "last": 10001})),
            (
                "send",
                json!({"target": "local:ok", "text": "x".repeat(4097)}),
            ),
            ("send", json!({"target": "bad", "text": "x"})),
        ] {
            assert_eq!(validate(verb, &value).unwrap_err().code, 2, "{verb}");
        }
        assert!(validate("list", &json!({})).is_ok());
        assert!(validate("new", &json!({"machine":"local", "name":"ok", "command":["/bin/echo", "", "literal; safe"]})).is_ok());
    }
    #[test]
    fn reply_decoder_keeps_additive_fields_and_refuses_malformed_fields() {
        let reply = Reply::ok("ok", json!({"bytes_sent": 7}));
        let mut value = serde_json::to_value(&reply).unwrap();
        value["future"] = json!(true);
        let decoded = Reply::decode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(decoded.code, 0);
        assert_eq!(decoded.data, reply.data);
        for malformed in [
            json!([]),
            json!({"code": 256, "message":"", "next":"", "data":{}}),
            json!({"code": 0, "message":false, "next":"", "data":{}}),
            json!({"code":0, "message":"", "next":""}),
        ] {
            assert!(Reply::decode(&serde_json::to_vec(&malformed).unwrap()).is_err());
        }
    }
    #[test]
    fn caller_tree_is_kernel_derived_and_account_scoped() {
        let pid = std::process::id();
        let uid = nix::unistd::Uid::effective().as_raw();
        let parent = parent(pid, uid).unwrap();
        assert!(belongs(pid, uid, parent));
        assert!(!belongs(pid, uid.wrapping_add(1), parent));
        assert!(!belongs(pid, uid, u32::MAX));
        assert!(!belongs(u32::MAX, uid, parent));
    }

    #[tokio::test]
    async fn cross_account_session_name_has_the_same_not_found_reply_as_absent() {
        fn session(number: u128) -> (Session, u32) {
            let (peer, _shim) = tokio::net::UnixStream::pair().unwrap();
            let credentials = peer.peer_cred().unwrap();
            let pid = u32::try_from(credentials.pid().unwrap()).unwrap();
            (
                Session {
                    id: uuid::Uuid::from_u128(number).into_bytes(),
                    path: Path::new("/unused").to_owned(),
                    peer,
                    head: 0,
                    size: (80, 24),
                    pid,
                    caps: 0,
                    supports_owner: false,
                },
                credentials.uid(),
            )
        }

        let (caller, caller_peer_uid) = session(1);
        let (foreign, foreign_peer_uid) = session(2);
        let caller_uid = caller_peer_uid.wrapping_add(1);
        let caller_id = uuid::Uuid::from_bytes(caller.id).to_string();
        let foreign_id = uuid::Uuid::from_bytes(foreign.id).to_string();
        let mut names = operations::Names::new();
        names.insert(caller_id, json!({"name":"caller", "uid":caller_uid}));
        names.insert(foreign_id, json!({"name":"private", "uid":foreign_peer_uid}));

        let visible: Vec<_> = [caller, foreign]
            .into_iter()
            .filter(|session| same_account(session, caller_uid, &names))
            .collect();
        assert_eq!(visible.len(), 1, "the foreign-UID session must be filtered");

        let input = json!({"target":"local:private", "last":1});
        let cross_account = operations::run(
            Path::new("/unused"),
            caller_uid,
            "read",
            &input,
            visible,
            names.clone(),
        )
        .await
        .unwrap();
        let absent = operations::run(
            Path::new("/unused"),
            caller_uid,
            "read",
            &input,
            Vec::new(),
            names,
        )
        .await
        .unwrap();

        assert_eq!(cross_account.code, 4);
        assert_eq!(cross_account.message, absent.message);
        assert_eq!(cross_account.next, absent.next);
    }
}
