//! Dispatches compiled node control on platforms without the existing Linux shim runtime; native providers reuse the common writer [D198,D232].
pub use crate::daemon_writer::approximate_snapshots_total;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) use crate::daemon_writer::hello_capabilities;
use crate::{
    channel::Channel,
    daemon_writer::{Message, reply, writer},
    plugin_control::Control,
    plugins::ExecutionMode,
    transport::{Receive, Socket},
};
use infraternal_plugin_api::admission::NodeContext;
use infraternal_protocol::Frame;
use std::{io, path::PathBuf};
use tokio::sync::mpsc;

/// Run one trusted inherited control descriptor without selecting another
/// platform's terminal engine.
/// # Errors
/// Refuses reserved descriptors, malformed frames and bounded overload.
pub async fn run(fd: i32, state: Option<PathBuf>) -> io::Result<()> {
    if fd != 3 {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let socket = Socket::inherited(fd)?;
    let state = runtime_state(state)?;
    let service =
        crate::plugin_control::Service::start(&state, ExecutionMode::Embedded, None).await?;
    let registry = service.registry.clone();
    dispatch(&socket, registry, false, None, 0).await
}

#[cfg(feature = "remote")]
use crate::remote_renewal::RenewalIdentity;
#[cfg(not(feature = "remote"))]
type RenewalIdentity = ();

/// Preserve enrolled UID admission and owned node state across connection loss.
/// # Errors
/// Refuses a UID mismatch, invalid Hello, malformed frames and bounded overload.
#[cfg(all(feature = "remote", not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) async fn run_authenticated_with_plugins(
    channel: &impl Channel,
    _: PathBuf,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
    registry: crate::plugin_control::Registry,
) -> io::Result<()> {
    let wire_caps = infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
        | registry.wire_capabilities(channel);
    if execution_uid != nix::unistd::Uid::effective().as_raw() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let _retire = Retire(channel);
    dispatch(channel, registry, true, renewal, wire_caps).await
}
#[cfg(all(feature = "remote", not(any(target_os = "linux", target_os = "macos"))))]
struct Retire<'a, C: Channel>(&'a C);
#[cfg(all(feature = "remote", not(any(target_os = "linux", target_os = "macos"))))]
impl<C: Channel> Drop for Retire<'_, C> {
    fn drop(&mut self) {
        self.0.retire();
    }
}

/// A terminal Attach never creates native capture on an unsupported platform.
/// # Errors
/// Reports only the existing missing-session close or a failed transport write.
#[cfg(feature = "remote")]
pub async fn run_bound_terminal(channel: &impl Channel, _: Option<PathBuf>) -> io::Result<()> {
    let (tx, rx) = mpsc::channel(1);
    reply(
        &tx,
        Message::Ended(
            channel
                .native_stream_id()
                .ok_or(io::ErrorKind::PermissionDenied)?,
        ),
    )?;
    drop(tx);
    writer(channel, rx, None, false, false, false, 0).await
}

async fn dispatch(
    channel: &impl Channel,
    registry: crate::plugin_control::Registry,
    admitted: bool,
    renewal: Option<&RenewalIdentity>,
    wire_caps: u64,
) -> io::Result<()> {
    registry.capabilities(wire_caps);
    let mut calls = Control::new(registry);
    let (tx, rx) = mpsc::channel(8);
    let mut renewals: tokio::task::JoinSet<(u32, io::Result<Vec<u8>>)> =
        tokio::task::JoinSet::new();
    let dispatch = async {
        let mut receive = Receive::default();
        if admitted {
            let hello =
                tokio::time::timeout(std::time::Duration::from_secs(5), receive.next(channel))
                    .await
                    .map_err(|_| io::ErrorKind::TimedOut)??;
            if !matches!(hello.frame, Frame::Hello { version: 1, .. }) || hello.stream_id != 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if let Frame::Hello { caps, .. } = hello.frame {
                calls.capabilities(caps & wire_caps);
            }
        }
        // Portable nodes have no terminal shims. The authoritative empty census
        // makes admission visible without weakening the server's readiness check.
        // The common writer guarantees Hello precedes this one startup event.
        reply(
            &tx,
            Message::Event(
                0,
                br#"{"type":"terminal.sessions.snapshot","session_ids":[]}"#.to_vec(),
            ),
        )?;
        loop {
            tokio::select! {
                result = calls.completed(), if calls.pending() => {
                    let (id, result) = result?;
                    match result { Ok(result) => reply(&tx, Message::Deferred(0, id, result))?, Err(_) => reply(&tx, Message::Result(0, id, false, br#"{"error":"plugin action rejected"}"#.to_vec()))? }
                }
                result = renewals.join_next(), if !renewals.is_empty() => {
                    let (id, result): (u32, io::Result<Vec<u8>>) = result.ok_or_else(|| io::Error::other("Renewal is unavailable."))?.map_err(io::Error::other)?;
                    let (ok, json) = match result { Ok(json) => (true, json), Err(_) => (false, b"{}".to_vec()) };
                    reply(&tx, Message::Result(0,id,ok,json))?;
                }
                decoded = receive.next(channel) => {
                    let decoded = decoded?;
                    if decoded.stream_id != 0 || admitted && matches!(decoded.frame, Frame::Hello { .. }) { return Err(io::ErrorKind::InvalidData.into()); }
                    match decoded.frame {
                        Frame::Hello { version: 1, .. } if !admitted => {},
                        Frame::Ping { nonce, sent_us } => reply(&tx, Message::Pong(0,nonce,sent_us))?,
                        #[cfg(feature = "remote")]
                        Frame::Call { call_id, action_id, input_json } if matches!(action_id, "transport.csr" | "transport.certificate") && renewal.is_some() => {
                            if !renewals.is_empty() || input_json.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON { reply(&tx,Message::Result(0,call_id,false,b"{}".to_vec()))?; }
                            else { let renewal = renewal.ok_or(io::ErrorKind::PermissionDenied)?.clone(); let action=action_id.to_owned(); let input=input_json.to_vec(); renewals.spawn_blocking(move || (call_id,renewal.action(&action,&input))); }
                        }
                        Frame::Call { call_id, action_id: "terminal.open", .. } => reply(&tx, Message::Result(0,call_id,false,infraternal_plugin_api::admission::OpenRefusal::Unavailable.json()?))?,
                        Frame::Call { call_id, action_id, input_json } => match calls.start(call_id,action_id,input_json,NodeContext::default()) {
                            Ok(Some(result)) => reply(&tx, Message::Deferred(0,call_id,result))?,
                            Ok(None) => {},
                            Err(_) => reply(&tx,Message::Result(0,call_id,false,br#"{"error":"plugin action rejected"}"#.to_vec()))?,
                        },
                        _ => return Err(io::ErrorKind::InvalidData.into()),
                    }
                    if tx.capacity() == 0 { tokio::task::yield_now().await; }
                }
            }
        }
    };
    tokio::select! { result = dispatch => result, result = writer(channel,rx,None,true,renewal.is_some(),crate::daemon_writer::supports_identity_rotation(renewal),wire_caps) => result }
}

// Native classification consumed AttachTerm while preserving its decoder;
// unsupported platforms still return the established missing-session answer.
#[cfg(all(feature = "remote", not(any(target_os = "linux", target_os = "macos"))))]
pub(crate) async fn run_bound_terminal_opened(
    channel: &impl Channel,
    state: Option<PathBuf>,
    _: Receive,
    _: Option<bytes::Bytes>,
) -> io::Result<()> {
    run_bound_terminal(channel, state).await
}

/// Native nodes require an explicit private runtime; no terminal state is created.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn runtime_state(path: Option<PathBuf>) -> io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let path = path.ok_or(io::ErrorKind::InvalidInput)?;
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(path)
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn runtime_state(path: Option<PathBuf>) -> io::Result<PathBuf> {
    crate::sessions::state(path)
}

#[cfg(all(
    feature = "remote",
    not(any(target_os = "linux", target_os = "macos")),
    any(test, feature = "native-streams")
))]
pub(crate) async fn run_bound_terminal_opened_mode(
    channel: &impl Channel,
    state: Option<PathBuf>,
    receive: Receive,
    opening: Option<bytes::Bytes>,
    _: bool,
) -> io::Result<()> {
    run_bound_terminal_opened(channel, state, receive, opening).await
}

/// Native nodes have no shim runtime; negotiated terminal intents return the same missing-session answer.
/// # Errors
/// Returns transport failure while writing the terminal close.
#[cfg(all(feature = "remote", not(any(target_os = "linux", target_os = "macos"))))]
pub async fn run_negotiated_bound_terminal(
    channel: &impl Channel,
    state: Option<PathBuf>,
) -> io::Result<()> {
    run_bound_terminal(channel, state).await
}

#[cfg(test)]
#[path = "daemon_portable_tests.rs"]
mod tests;
