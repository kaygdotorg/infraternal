//! Implements serialized local session operations using the existing shim codec and private state.
use super::Reply;
use crate::sessions::{self, Manager, Reader, Session, send};
use infraternal_shim::frame::Frame;
use serde_json::{Value, json};
use std::fmt::Write as _;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Name {
    pub(super) name: String,
    pub(super) uid: u32,
}
pub(super) type Names = BTreeMap<String, Name>;
pub(super) fn load(state: &Path) -> io::Result<Names> {
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(state.join("session-names.json"))
    {
        Ok(file) => {
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != nix::unistd::Uid::effective().as_raw()
                || meta.mode() & 0o777 != 0o600
            {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let mut bytes = Vec::new();
            file.take(1_048_577).read_to_end(&mut bytes)?;
            if bytes.len() > 1_048_576 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let names: Names = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
            if names
                .iter()
                .any(|(id, entry)| uuid::Uuid::parse_str(id).is_err() || !super::name(&entry.name))
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(names)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Names::new()),
        Err(error) => Err(error),
    }
}
fn save(state: &Path, names: &Names) -> io::Result<()> {
    let bytes = serde_json::to_vec(names)?;
    if bytes.len() > 1_048_576 {
        return Err(io::ErrorKind::OutOfMemory.into());
    }
    let path = state.join(format!(".session-names-{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&path, state.join("session-names.json"))?;
        fs::File::open(state)?.sync_all()
    })();
    let _ = fs::remove_file(path);
    result
}
fn id(session: &Session) -> String {
    uuid::Uuid::from_bytes(session.id).to_string()
}
fn label(session: &Session, names: &Names) -> String {
    names
        .get(&id(session))
        .map_or_else(|| id(session), |entry| entry.name.clone())
}
fn row(session: &Session, names: &Names) -> Value {
    json!({"id": id(session), "name": label(session, names), "machine": "local"})
}
fn missing(wanted: &str, live: &[Session], names: &Names) -> Reply {
    let mut message = format!("No session called \"{wanted}\" on this machine.");
    // Adjacent transpositions and a single edit cover the common misspellings,
    // without pulling a fuzzy-search dependency into every host image.
    if let Some(candidate) = live
        .iter()
        .map(|s| label(s, names))
        .find(|n| similar(wanted, n))
    {
        let _ = write!(message, " Did you mean \"{candidate}\"?");
    }
    Reply::error(
        4,
        message,
        "Run infraternal sessions to see available session names.",
    )
}
fn similar(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    if a.len() == b.len() {
        let differences: Vec<_> = a
            .iter()
            .zip(b)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        return differences.len() == 1
            || (differences.len() == 2
                && differences[1] == differences[0] + 1
                && a[differences[0]] == b[differences[1]]
                && a[differences[1]] == b[differences[0]]);
    }
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    (0..long.len()).any(|skip| {
        short.iter().copied().eq(long
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip)
            .map(|(_, c)| *c))
    })
}

pub(super) async fn run(
    state: &Path,
    uid: u32,
    verb: &str,
    input: &Value,
    mut live: Vec<Session>,
    names: Names,
) -> io::Result<Reply> {
    if verb == "list" {
        let mut rows: Vec<_> = live.iter().map(|s| row(s, &names)).collect();
        rows.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        let after = input["after"].as_str().unwrap_or("");
        rows.retain(|row| row["id"].as_str().is_some_and(|id| id > after));
        // The 8 KiB result frame funds 32 worst-case rows, never a session cap.
        let next_after = if rows.len() > 32 {
            rows.truncate(32);
            rows.last()
                .and_then(|row| row["id"].as_str())
                .map(str::to_owned)
        } else {
            None
        };
        return Ok(Reply::ok(
            "Saved sessions on this machine.",
            json!({"sessions": rows, "next_after": next_after}),
        ));
    }
    if verb == "new" {
        return create(state, uid, input, &live, names).await;
    }
    let target = input["target"]
        .as_str()
        .and_then(|s| s.split_once(':').map(|(_, s)| s))
        .ok_or(io::ErrorKind::InvalidInput)?;
    let Some(index) = live
        .iter()
        .position(|s| id(s) == target || label(s, &names) == target)
    else {
        return Ok(missing(target, &live, &names));
    };
    let mut session = live.swap_remove(index);
    match verb {
        "close" => {
            drop(session.peer);
            session = sessions::connect_sequenced(session.path, session.id).await?;
            if session.caps & infraternal_shim::frame::CLOSE_SESSION == 0 {
                return Ok(Reply::error(
                    5,
                    "This saved session cannot accept a close request.",
                    "Upgrade the infraternal session shim, or close this session in the app and recreate it.",
                ));
            }
            send(&mut session.peer, &Frame::CloseSession).await?;
            Ok(Reply::ok(
                "Session close requested.",
                json!({"session": row(&session, &names), "close_requested": true}),
            ))
        }
        "send" => send_text(session, input).await,
        "read" => {
            capture(
                &mut session,
                usize::try_from(input["last"].as_u64().ok_or(io::ErrorKind::InvalidInput)?)
                    .map_err(io::Error::other)?,
            )
            .await
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}
async fn capture(session: &mut Session, last: usize) -> io::Result<Reply> {
    let head = session.head;
    let start = head.saturating_sub(4096);
    let mut cursor = start;
    let mut bytes = Vec::new();
    send(&mut session.peer, &Frame::ReadFrom(start)).await?;
    let mut reader = Reader::default();
    let mut snapshot = false;
    while cursor < head {
        match reader.read(&mut session.peer).await? {
            Frame::Output(seq, data) if seq <= cursor => {
                let skip = usize::try_from(cursor - seq).map_err(io::Error::other)?;
                let end = data
                    .len()
                    .min(usize::try_from(head - seq).map_err(io::Error::other)?);
                if skip > end {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                bytes.extend_from_slice(&data[skip..end]);
                cursor = seq + end as u64;
            }
            Frame::Snapshot(seq, data) => {
                bytes = data;
                cursor = seq;
                snapshot = true;
            }
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
    }
    // Bound the existing 8 KiB JSON action result even for control-heavy output.
    // Raw retained bytes are returned as text, never interpreted as control requests.
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    let cut = text
        .trim_end_matches('\n')
        .rmatch_indices('\n')
        .nth(last.saturating_sub(1))
        .map_or(0, |(i, _)| i + 1);
    text.drain(..cut);
    let mut truncated = start > 0 || snapshot || cut > 0;
    loop {
        let reply = Reply::ok(
            "Retained session output.",
            json!({"text": text, "truncated": truncated, "snapshot": snapshot}),
        );
        if serde_json::to_vec(&reply)?.len() <= infraternal_plugin_api::MAX_ACTION_BYTES {
            return Ok(reply);
        }
        let cut = text.char_indices().nth(256).map_or(text.len(), |(i, _)| i);
        text.drain(..cut);
        truncated = true;
    }
}

async fn create(
    state: &Path,
    uid: u32,
    input: &Value,
    live: &[Session],
    mut names: Names,
) -> io::Result<Reply> {
    let name = input["name"].as_str().ok_or(io::ErrorKind::InvalidInput)?;
    if live
        .iter()
        .any(|s| label(s, &names) == name || id(s) == name)
    {
        return Ok(Reply::error(
            2,
            format!("A session called \"{name}\" already exists."),
            "Choose another --name, or use the existing session.",
        ));
    }
    let command: Vec<String> = input["command"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let session = sessions::launch_with_command(
        &std::env::current_exe()?,
        state,
        Manager::Detached,
        uid,
        80,
        24,
        false,
        true,
        &command,
    )
    .await?;
    names.insert(
        id(&session),
        Name {
            name: name.to_owned(),
            uid,
        },
    );
    if let Err(error) = save(state, &names) {
        // A failed name publication cannot leave a successful unnamed create.
        if let Ok(mut cleanup) = sessions::connect_sequenced(session.path.clone(), session.id).await
        {
            let _ = send(&mut cleanup.peer, &Frame::CloseSession).await;
        }
        return Err(error);
    }
    Ok(Reply::ok(
        "Session created.",
        json!({"session": row(&session, &names)}),
    ))
}
async fn send_text(session: Session, input: &Value) -> io::Result<Reply> {
    let text = input["text"].as_str().ok_or(io::ErrorKind::InvalidInput)?;
    // One serialized socket owns automation input; query its current cursor,
    // then await written acknowledgement. Never retry an uncertain write.
    drop(session.peer);
    let mut session = sessions::connect_sequenced(session.path, session.id).await?;
    if session.caps & infraternal_shim::frame::SEQUENCED_INPUT == 0 {
        return Err(io::ErrorKind::Unsupported.into());
    }
    send(&mut session.peer, &Frame::InputStateRequest).await?;
    let mut reader = Reader::default();
    let accepted = loop {
        match reader.read(&mut session.peer).await? {
            Frame::InputState(_, accepted) => break accepted,
            // Reconnecting the sequenced legacy writer may publish its previous
            // written cursor before answering the explicit state request.
            Frame::InputAck(_) => {}
            _ => return Err(io::ErrorKind::InvalidData.into()),
        }
    };
    let end = accepted
        .checked_add(text.len() as u64)
        .ok_or(io::ErrorKind::InvalidInput)?;
    if !text.is_empty() {
        send(
            &mut session.peer,
            &Frame::SequencedInput(accepted, text.as_bytes().to_vec()),
        )
        .await?;
        loop {
            match reader.read(&mut session.peer).await? {
                Frame::InputAck(written) if written >= end => break,
                Frame::InputAck(_) => {}
                _ => return Err(io::ErrorKind::BrokenPipe.into()),
            }
        }
    }
    Ok(Reply::ok("Text sent.", json!({"bytes_sent": text.len()})))
}

#[cfg(test)]
mod tests {
    //! A bounded transport page must not turn into a cap on the available sessions.
    use super::*;
    #[tokio::test]
    async fn lists_500_sessions_across_bounded_pages_without_loss() {
        let mut after = None;
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let mut names = Names::new();
            let live = (1..=500)
                .map(|number| {
                    let id = uuid::Uuid::from_u128(number);
                    names.insert(
                        id.to_string(),
                        Name {
                            name: format!("{:0<64}", number),
                            uid: 1000,
                        },
                    );
                    let (peer, _) = tokio::net::UnixStream::pair().unwrap();
                    Session {
                        id: id.into_bytes(),
                        path: "/unused".into(),
                        peer,
                        head: 0,
                        size: (80, 24),
                        pid: 0,
                        caps: 0,
                        supports_owner: false,
                    }
                })
                .collect();
            let input = after
                .as_ref()
                .map_or_else(|| json!({}), |after: &String| json!({"after": after}));
            let page = run(Path::new("/unused"), 1000, "list", &input, live, names)
                .await
                .unwrap();
            assert!(
                serde_json::to_vec(&page).unwrap().len()
                    <= infraternal_plugin_api::MAX_ACTION_BYTES
            );
            for row in page.data["sessions"].as_array().unwrap() {
                assert!(seen.insert(row["id"].as_str().unwrap().to_owned()));
            }
            after = page.data["next_after"].as_str().map(str::to_owned);
            if after.is_none() {
                break;
            }
        }
        assert_eq!(seen.len(), 500);
    }
}
