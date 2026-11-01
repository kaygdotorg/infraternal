//! Shared inherited and authenticated remote leg-B dispatcher and bounded session registry for the tracer bullet [9][13][41].
//!
//! Each terminal owns one pending output frame. Input/Resize commands have eight slots;
//! shared-stream Credit is accumulated in constant space without occupying that FIFO;
//! Input/Resize overload retires only that stream; probes may be skipped. Unacknowledged
//! input is replayed on attachment using shim-owned per-writer cursors. Bulk output has eight slots
//! and awaits capacity. Control replies use a separate eight-slot lane, selected
//! first at frame boundaries; reply producers wait for bounded FIFO capacity. Native
//! terminal dispatch continues on its independent streams. Starved sessions close
//! their shim socket after 250 ms, then reconnect for a fresh credit-funded
//! ring replay or a flagged bounded repaint. Unviewed sessions stay disconnected so their PTYs keep progressing.
//! A closed shim or failed terminal task closes only its mux stream. A session
//! whose shim is gone answers its stream with the final Close 4404 (#158).
use crate::{
    channel::Channel,
    relay,
    sessions::{self, Manager, Reader, Session},
    transport::{Receive, Socket},
};
use infraternal_protocol::Frame;
use infraternal_shim::frame::{APPROXIMATE_SNAPSHOT, Frame as Shim, SEQUENCED_INPUT};
use serde::Deserialize;
use std::{collections::HashMap, io, path::PathBuf, time::Instant};

pub use crate::daemon_writer::approximate_snapshots_total;
use crate::daemon_writer::{Message, reply, writer};
#[cfg(test)]
use crate::{daemon_writer::deferred_reply, transport::Transmit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

#[path = "session_commands.rs"]
mod session_commands;
#[path = "terminal_events.rs"]
mod terminal_events;

enum Command {
    Input(u64, Vec<u8>),
    Reply(Vec<u8>),
    Credit(u32),
    Resize(u16, u16, u16, u16),
    #[cfg(feature = "remote")]
    Cursor(u64),
    Ping(u64, u64),
}
// Dropping cancellation retires a stalled handshake as well as queued commands.
struct Stream {
    commands: session_commands::Sender,
    _cancel: oneshot::Sender<()>,
}

#[cfg(feature = "remote")]
use crate::remote_renewal::RenewalIdentity;
// The private local-only dispatcher always supplies None in core builds.
#[cfg(not(feature = "remote"))]
type RenewalIdentity = ();
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    #[serde(default)]
    readiness: bool,
    uid: u32,
    cols: u16,
    rows: u16,
}

pub(crate) use crate::daemon_writer::hello_capabilities;

async fn emit(tx: &mpsc::Sender<Message>, message: Message) -> io::Result<()> {
    tx.send(message)
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe.into())
}

/// Publishes the authoritative live-shim set without ever parking terminal dispatch on a slow writer.
/// True establishes the ordered open fence; false leaves the census pending for retry.
fn publish_session_snapshot(
    tx: &mpsc::Sender<Message>,
    registry: &crate::lifecycle::Registry,
    published: &mut Option<Vec<[u8; 16]>>,
) -> io::Result<bool> {
    let session_ids = registry.session_ids();
    if published.as_ref() == Some(&session_ids) {
        return Ok(true);
    }
    let json = terminal_events::Notice::SessionsSnapshot {
        session_ids: &session_ids,
    }
    .json()?;
    match tx.try_send(Message::Event(0, json)) {
        Ok(()) => *published = Some(session_ids),
        Err(mpsc::error::TrySendError::Full(_)) => return Ok(false),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
    }
    Ok(true)
}

/// Run until the trusted server closes its inherited channel.
/// # Errors
/// Rejects invalid fd, unsafe state, malformed wire requests and resource limits.
#[allow(clippy::too_many_lines)]
pub async fn run(fd: i32, state: Option<PathBuf>) -> io::Result<()> {
    // The launch isolation wrapper closes fd 3 before exec. Other inherited
    // descriptors need their own audited CLOEXEC boundary before being supported.
    if fd != 3 {
        return Err(sessions::invalid("embedded leg B requires fd 3"));
    }
    let socket = Socket::inherited(fd)?;
    let state = sessions::state(state)?;
    let service = crate::plugin_control::Service::start(
        &state,
        crate::plugins::ExecutionMode::Embedded,
        None,
    )
    .await?;
    run_channel::<false>(
        &socket,
        state,
        None,
        None,
        Some(service.registry.clone()),
        None,
    )
    .await
}

/// Dispatch an admitted SSH or enrolled connection through the same session and shim path.
/// The caller must authenticate the transport and supply its checked execution uid;
/// neither browser JSON nor an untrusted peer can select that identity. Returning
/// drops every attachment and launch task, but never terminates surviving shims.
/// # Errors
/// Refuses invalid greeting, unsafe state, wrong uid and malformed terminal frames.
pub async fn run_authenticated(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
) -> io::Result<()> {
    dispatch_authenticated(channel, state, execution_uid, None, None).await
}

/// Serve terminal actions only on an admitted SSH reattach, without plugin control.
/// A published-setup Retry reattaches while the failed attempt's infraternal
/// agent may still hold the runtime lifetime lock that plugin control takes;
/// that runtime keeps node actions (#230). This is the same full-build
/// dispatcher instance with no registry, not the session image's [243].
/// # Errors
/// Refuses invalid greeting, unsafe state, wrong uid and malformed terminal frames.
pub async fn run_authenticated_terminal(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
) -> io::Result<()> {
    validate_authenticated(channel, execution_uid)?;
    let state = sessions::state(state)?;
    let _retire = RetireChannel(channel);
    run_channel::<false>(channel, state, Some(execution_uid), None, None, None).await
}

/// Run the first-prompt image without retaining node actions or opening other sessions.
/// The caller supplies the already authenticated, shim-owned session; all data,
/// writer cursors, credit and replay use the ordinary terminal dispatcher.
/// # Errors
/// Refuses transport identity, original-session lifetime or wire protocol failures.
pub async fn run_session_image(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
    session: Session,
) -> io::Result<()> {
    validate_authenticated(channel, execution_uid)?;
    let state = sessions::state(state)?;
    let _retire = RetireChannel(channel);
    run_channel::<true>(
        channel,
        state,
        Some(execution_uid),
        None,
        None,
        Some(session),
    )
    .await
}

/// Dispatch remote terminal and bounded certificate control actions on one authenticated channel.
/// # Errors
/// Refuses uid, greeting, state, framing or publication failure.
#[cfg(feature = "remote")]
pub async fn run_authenticated_with_renewal(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
) -> io::Result<()> {
    run_authenticated_with_installation(channel, state, execution_uid, renewal, None).await
}

/// Supply only checked local installation coordinates, never fields from a channel request.
/// # Errors
/// Refuses the same authenticated dispatch and installation bounds.
#[cfg(feature = "remote")]
pub async fn run_authenticated_with_installation(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
    installation: Option<&infraternal_plugin_remote::uninstall::Context>,
) -> io::Result<()> {
    dispatch_authenticated(channel, state, execution_uid, renewal, installation).await
}

// SSH admission and enrolled transports use the same UID/writer fence and
// cancellation boundary. The session-only build needs no certificate control
// or installation plugin, but must never fall back to embedded authorization.
async fn dispatch_authenticated(
    channel: &impl Channel,
    state: Option<PathBuf>,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
    installation: Option<&crate::plugins::Installation>,
) -> io::Result<()> {
    if channel.native_stream_id().is_some_and(|writer| writer != 0)
        || execution_uid != nix::unistd::Uid::effective().as_raw()
    {
        return Err(sessions::invalid(
            "enrolled uid differs from infraternal agent uid",
        ));
    }
    let state = sessions::state(state)?;
    let service = crate::plugin_control::Service::start(
        &state,
        crate::plugins::ExecutionMode::Remote,
        installation,
    )
    .await?;
    run_authenticated_with_plugins(
        channel,
        state,
        execution_uid,
        renewal,
        service.registry.clone(),
    )
    .await
}
pub(crate) async fn run_authenticated_with_plugins(
    channel: &impl Channel,
    state: PathBuf,
    execution_uid: u32,
    renewal: Option<&RenewalIdentity>,
    plugins: crate::plugin_control::Registry,
) -> io::Result<()> {
    validate_authenticated(channel, execution_uid)?;
    // Cancellation retires the authenticated channel as well as its task set;
    // a caller cannot reuse it with detached readers or unfinished wire writes.
    let _retire = RetireChannel(channel);
    run_channel::<false>(
        channel,
        state,
        Some(execution_uid),
        renewal,
        Some(plugins),
        None,
    )
    .await
}

/// Reject identity and writer mismatches before state creation or channel IO.
fn validate_authenticated(channel: &impl Channel, execution_uid: u32) -> io::Result<()> {
    if channel.native_stream_id().is_some_and(|writer| writer != 0)
        || execution_uid != nix::unistd::Uid::effective().as_raw()
    {
        return Err(sessions::invalid(
            "enrolled uid differs from infraternal agent uid",
        ));
    }
    Ok(())
}

struct RetireChannel<'a, C: Channel>(&'a C);
impl<C: Channel> Drop for RetireChannel<'_, C> {
    fn drop(&mut self) {
        self.0.retire();
    }
}

#[allow(clippy::too_many_lines)]
async fn run_channel<const SESSION_ONLY: bool>(
    socket: &impl Channel,
    state: PathBuf,
    execution_uid: Option<u32>,
    renewal: Option<&RenewalIdentity>,
    plugins: Option<crate::plugin_control::Registry>,
    original: Option<Session>,
) -> io::Result<()> {
    // The dedicated image supplies no node registry. Const specialization keeps
    // action admission, workers and their receive branches out of that image;
    // the installed host retains this same loop with its ordinary registry.
    // A None argument alone leaves the factory in an opaque future's poll
    // function. Keep it behind the const branch so the image cannot retain it.
    let plugins = if SESSION_ONLY { None } else { plugins };
    let mut events = plugins
        .as_ref()
        .map(crate::plugin_control::Registry::subscribe);
    let mut plugin_calls = plugins
        .as_ref()
        .map(|plugins| crate::plugin_control::Control::new(plugins.clone()));
    let wire_caps = if SESSION_ONLY {
        0
    } else {
        infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS
            | plugins
                .as_ref()
                .map_or(0, |plugins| plugins.wire_capabilities(socket))
    };
    let running = std::env::current_exe()?;
    // A sealed/deleted image has no install pathname for an indirect init
    // launcher. Use the existing detached shim mode and direct kernel image.
    let anonymous = running
        .as_os_str()
        .as_encoded_bytes()
        .ends_with(b" (deleted)");
    // Detection is warmed in the background; only terminal.open awaits the
    // single result, so the authenticated greeting and census can proceed first.
    let manager = std::sync::Arc::new(tokio::sync::OnceCell::<Manager>::new());
    let exe = if anonymous {
        manager
            .set(Manager::Detached)
            .map_err(|_| sessions::invalid("init manager was already selected"))?;
        PathBuf::from("/proc/self/exe")
    } else {
        if !SESSION_ONLY {
            let warm = manager.clone();
            tokio::spawn(async move {
                warm.get_or_init(Manager::detect).await;
            });
        }
        running
    };
    let retirements = sessions::SessionEvents::new(&state)?;
    let mut registry = crate::lifecycle::Registry::default();
    let original_id = if SESSION_ONLY {
        let session = original.ok_or_else(|| sessions::invalid("original session required"))?;
        // Startup already proved this rendezvous. Never scan unrelated sessions
        // or hold the original unfunded data peer while greeting the browser.
        let id = session.id;
        registry.insert(&session)?;
        drop(session);
        Some(id)
    } else {
        for session in sessions::discover(&state).await? {
            registry.insert(&session)?;
            // Startup discovery authenticates identity, but does not stall unviewed PTYs.
            drop(session);
        }
        None
    };
    let (tx, rx) = mpsc::channel(8);
    let (control, control_rx) = mpsc::channel(8);
    #[cfg(test)]
    let control_observer = census_retry_tests::observer(&state);
    let dispatch = async {
        let mut published_sessions = None;
        let mut census_pending =
            !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
        let mut receive = Receive::default();
        if execution_uid.is_some() {
            // The whole greeting has one deadline, including an entirely silent
            // authenticated peer. Established idle channels have no timer.
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let hello = receive.next(socket).await?;
                if hello.stream_id != 0 || !matches!(hello.frame, Frame::Hello { version: 1, caps, .. } if socket.native_stream_id().is_none() || caps & infraternal_plugin_api::channel::REMOTE_WRITER_BINDING != 0) {
                    return Err(sessions::invalid("remote control Hello required"));
                }
                if let Frame::Hello { caps, .. } = hello.frame
                    && let Some(plugins) = &plugins { plugins.capabilities(caps & wire_caps); }
                Ok(())
            })
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        }
        let mut streams: HashMap<u32, Stream> = HashMap::new();
        let mut jobs: JoinSet<(u32, io::Result<()>)> = JoinSet::new();
        let mut renewals = JoinSet::new();
        let mut opens: JoinSet<(
            u32,
            u32,
            Result<Session, infraternal_plugin_api::admission::OpenRefusal>,
        )> = JoinSet::new();
        loop {
            // One selected source emits at most two replies. The sole producer
            // cannot lose this capacity while polling a branch. Deferring the
            // source retains its existing bounded state and response ordering.
            let control_ready = control.capacity() >= 2;
            #[cfg(test)]
            if let Some(observer) = &control_observer {
                observer.publish(&control, census_pending);
            }
            tokio::select! {
                changed = retirements.changed() => {
                    changed?;
                    registry.refresh();
                    census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                }
                exited = registry.changed() => {
                    registry.exited(&exited?);
                    registry.refresh();
                    census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                }
                capacity = control.reserve_many(if census_pending { 1 } else { 2 }), if census_pending || !control_ready => {
                    // A pending census needs one slot; a fresh reply turn needs
                    // two. Capacity is the only retry wakeup, with no idle timer.
                    drop(capacity.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?);
                    census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                }
                result=async { match plugin_calls.as_mut() { Some(control) => control.completed().await, None => std::future::pending().await } }, if !SESSION_ONLY && control_ready && plugin_calls.as_ref().is_some_and(crate::plugin_control::Control::pending) => {
                    let (call_id,result)=result?;
                    match result {
                        Ok(result)=>reply(&control,Message::Deferred(0,call_id,result))?,
                        Err(_)=>reply(&control,Message::Result(0,call_id,false,b"{\"error\":\"plugin action rejected\"}".to_vec()))?,
                    }
                }
                event=async {
                    if let Some(events) = events.as_mut() {
                        events.recv().await
                    } else {
                        std::future::pending().await
                    }
                }, if !SESSION_ONLY && control_ready => {
                    let event=match event {
                        Ok(event)=>event,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>b"{\"type\":\"plugin.event\",\"id\":\"plugins.resync\"}".to_vec(),
                        Err(tokio::sync::broadcast::error::RecvError::Closed)=>return Err(sessions::invalid("plugin events stopped")),
                    };
                    reply(&control,Message::Event(0,event))?;
                }
                result = jobs.join_next(), if control_ready && !jobs.is_empty() => {
                    let (stream, result) = result.ok_or_else(|| sessions::invalid("missing relay task"))?.map_err(io::Error::other)?;
                    // Close/re-attach may reuse a stream before the old task exits.
                    // Its completion must not remove the replacement's live sender.
                    if streams.get(&stream).is_some_and(|entry| entry.commands.is_closed()) {
                        streams.remove(&stream);
                        if result.is_err() {
                            reply(&control, Message::Close(stream, "terminal shim disconnected"))?;
                        }
                    }
                    registry.refresh();
                    census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                }
                result = renewals.join_next(), if !SESSION_ONLY && control_ready && !renewals.is_empty() => {
                    // The private image never starts these jobs. Keep their result
                    // handlers outside that monomorph as well as the select mask.
                    if SESSION_ONLY { return Err(sessions::invalid("session image cannot complete identity renewal")); }
                    let (call_id, result): (u32, io::Result<Vec<u8>>) = result.ok_or_else(|| sessions::invalid("missing renewal task"))?.map_err(io::Error::other)?;
                    let (ok, json) = match result { Ok(json) => (true, json), Err(_) => (false, b"{}".to_vec()) };
                    reply(&control, Message::Result(0, call_id, ok, json))?;
                }
                result = opens.join_next(), if !SESSION_ONLY && control_ready && !opens.is_empty() => {
                    // The private image never starts these jobs. Keep their result
                    // handlers outside that monomorph as well as the select mask.
                    if SESSION_ONLY { return Err(sessions::invalid("session image cannot complete session launch")); }
                    let (stream, call_id, result) = result.ok_or_else(|| sessions::invalid("missing launch task"))?.map_err(io::Error::other)?;
                    match result {
                        Ok(session) => {
                            let json = serde_json::to_vec(&serde_json::json!({"session_id": uuid::Uuid::from_bytes(session.id)}))?;
                            registry.insert(&session)?;
                            // The new-ID census must enter the same FIFO before its Result.
                            // A full queue cannot publish success without this fence, even
                            // if the writer drains capacity between these two try_sends.
                            if !publish_session_snapshot(&control, &registry, &mut published_sessions)? {
                                return Err(io::Error::new(io::ErrorKind::WouldBlock, "census reply queue full"));
                            }
                            census_pending = false;
                            reply(&control, Message::Result(stream, call_id, true, json))?;
                        }
                        Err(reason) => reply(&control, Message::Result(stream, call_id, false, reason.json()?))?,
                    }
                }
                decoded = receive.next(socket), if control_ready => {
                    let decoded = decoded?;
                    let stream = decoded.stream_id;
                    if execution_uid.is_some() && (stream % 2 != 0 || matches!(decoded.frame, Frame::Hello { .. })) {
                        return Err(sessions::invalid("invalid remote stream or duplicate Hello"));
                    }
                    match decoded.frame {
                        Frame::Hello {version: 1, ..} if stream == 0 => {}
                        Frame::Ping {nonce, sent_us} if stream == 0 => {
                            reply(&control, Message::Pong(0, nonce, sent_us))?;
                            #[cfg(test)]
                            if let Some(observer) = &control_observer { observer.replied(); }
                        },
                        #[cfg(feature = "remote")]
                        Frame::Call {call_id, action_id, input_json} if stream == 0 && matches!(action_id, "transport.csr" | "transport.certificate") && renewal.is_some() => {
                            if !renewals.is_empty() || input_json.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON {
                                reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?;
                            } else {
                                let renewal = renewal.ok_or_else(|| sessions::invalid("missing renewal identity"))?.clone();
                                let action = action_id.to_owned(); let input = input_json.to_vec();
                                renewals.spawn_blocking(move || (call_id, renewal.action(&action, &input)));
                            }
                        }
                        Frame::Call {call_id, action_id: "terminal.open", input_json} if !SESSION_ONLY && plugins.is_some() && (execution_uid.is_none() || stream == 0) => {
                            use infraternal_plugin_api::admission::OpenRefusal;
                            registry.refresh();
                            census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                            let input = if input_json.len() <= infraternal_plugin_api::channel::MAX_CONTROL_JSON { serde_json::from_slice::<Open>(input_json).ok() } else { None };
                            if let Some(input) = input && execution_uid.is_none_or(|uid| input.uid == uid)
                                && (nix::unistd::Uid::effective().is_root() || input.uid == nix::unistd::Uid::effective().as_raw())
                                && input.cols > 0 && input.rows > 0 && usize::from(input.cols) * usize::from(input.rows) <= 200_000 {
                                let exe = exe.clone(); let state = state.clone();
                                let manager = manager.clone();
                                let plugins = plugins.as_ref().ok_or_else(|| sessions::invalid("missing node registry"))?.clone(); let context = registry.context();
                                // Admission shares mutable plugin settings with actions, but
                                // waiting for its worker never parks terminal dispatch.
                                opens.spawn(async move {
                                    let result = async {
                                        plugins.admit("terminal.open", context).await?;
                                        let manager = *manager.get_or_init(Manager::detect).await;
                                        sessions::launch_with_readiness(&exe, &state, manager, input.uid, input.cols, input.rows, input.readiness).await.map_err(|error| match error.kind() {
                                            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData | io::ErrorKind::PermissionDenied => OpenRefusal::Invalid,
                                            _ => OpenRefusal::ResourceUnavailable,
                                        })
                                    }.await;
                                    (stream, call_id, result)
                                });
                            } else {
                                reply(&control, Message::Result(stream, call_id, false, OpenRefusal::Invalid.json()?))?;
                            }
                        }
                        Frame::Call {call_id, action_id: "terminal.startup", input_json} if !SESSION_ONLY && plugins.is_some() && stream == 0 => {
                            if input_json.len() > 8192 || renewals.len() >= 4 {
                                reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?;
                            } else {
                                let exe = exe.clone(); let state = state.clone(); let input = input_json.to_vec();
                                renewals.spawn(async move { (call_id, crate::startup_guard::execute(&exe, &state, &input, execution_uid).await) });
                            }
                        }
                        Frame::Call {call_id, action_id, input_json} if !SESSION_ONLY && plugin_calls.is_some() && stream == 0 => {
                            let plugin_calls = plugin_calls.as_mut().ok_or_else(|| sessions::invalid("missing node control"))?;
                            registry.refresh();
                            census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                            match plugin_calls.start(call_id, action_id, input_json, registry.context()) {
                                Ok(Some(result)) => reply(&control, Message::Deferred(0, call_id, result))?,
                                Ok(None) => {},
                                Err(_) => reply(&control, Message::Result(0, call_id, false, b"{\"error\":\"plugin action rejected\"}".to_vec()))?,
                            }
                        }
                        // A registry-less reattach (#230) refuses actions as the image does.
                        Frame::Call {call_id, ..} if (SESSION_ONLY || plugin_calls.is_none()) && stream == 0 => {
                            reply(&control, Message::Result(0, call_id, false, b"{\"error\":\"This action is unavailable during host provisioning.\"}".to_vec()))?;
                        }
                        Frame::AttachTerm {session_id, last_out_seq, last_in_seq} if stream != 0 => {
                            if SESSION_ONLY && original_id.is_some_and(|id| session_id != &id) {
                                reply(&control, Message::Ended(stream))?;
                                continue;
                            }
                            if streams.len() >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS || streams.contains_key(&stream) {
                                return Err(sessions::invalid("terminal stream already attached or limit reached"));
                            }
                            // The registry only caches shims this process has seen. A miss is not
                            // proof of death, and never a reason to drop every sibling stream: the
                            // rendezvous derives from the id alone, and `terminal` answers a final
                            // Close when no shim listens there (#158).
                            let path = registry.get(session_id).cloned().unwrap_or_else(|| sessions::rendezvous(&state, *session_id));
                            let id = *session_id;
                            let (commands, rx) = session_commands::channel();
                            let (cancel, cancelled) = oneshot::channel();
                            streams.insert(stream, Stream { commands, _cancel: cancel });
                            let tx = tx.clone();
                            jobs.spawn(async move {
                                let result = tokio::select! {
                                    result = terminal(path, id, stream, last_out_seq, last_in_seq, rx, tx) => result,
                                    _ = cancelled => Ok(()),
                                };
                                (stream, result)
                            });
                        }
                        frame => {
                            let command = match frame {
                                Frame::Input {in_seq, bytes} => Command::Input(in_seq, bytes.to_vec()),
                                Frame::InputReply {bytes, ..} => Command::Reply(bytes.to_vec()),
                                Frame::Ping {nonce, sent_us} => Command::Ping(nonce, sent_us),
                                Frame::Credit {bytes} => Command::Credit(bytes),
                                Frame::Resize {cols, rows, px_w, px_h} => Command::Resize(cols, rows, px_w, px_h),
                                Frame::Close {..} => {
                                    streams.remove(&stream);
                                    registry.refresh();
                                    census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                                    continue;
                                }
                                _ => return Err(sessions::invalid("unexpected leg-B request")),
                            };
                            // Never await a session's capacity in shared dispatch.
                            // Retire overload before accepting this command. Drop the
                            // cancellation sender to release even a stalled handshake;
                            // shim-owned accepted/written cursors make input replay safe.
                            let overloaded = streams.get_mut(&stream).is_some_and(|entry| {
                                matches!(entry.commands.try_send(command), Err(mpsc::error::TrySendError::Full(_)))
                            });
                            if overloaded {
                                streams.remove(&stream);
                                reply(&control, Message::Close(stream, "terminal command queue full; reattach and replay unacknowledged input"))?;
                            }
                            // Frames already in flight after a stream closes are
                            // ignored; the terminal task emits its own Close.
                        }
                    }
                }
            }
        }
    };
    tokio::select! { result = dispatch => result, result = writer(socket, rx, Some(control_rx), true, renewal.is_some(), wire_caps) => result }
}

/// Run one authenticated, capability-bound native terminal using the common shim relay.
/// The connection supervisor must cancel this future when server authority is lost;
/// this function never opens a PTY, accepts a Call or creates its own writer identity.
/// # Errors
/// Refuses missing/reserved binding, a missing bounded `AttachTerm`, unknown shim,
/// malformed post-attachment traffic and overload. Returning never stops the shim.
#[allow(clippy::too_many_lines)]
#[cfg(feature = "remote")]
pub async fn run_bound_terminal(channel: &impl Channel, state: Option<PathBuf>) -> io::Result<()> {
    run_bound_terminal_mode(
        channel,
        state,
        false,
        #[cfg(any(test, feature = "native-streams"))]
        Receive::default(),
        #[cfg(any(test, feature = "native-streams"))]
        None,
    )
    .await
}

/// Accept optional per-stream priming intent on a capability-negotiated connection.
/// Ordinary writers omit the marker, including new writers after promotion.
/// The supervisor must verify native priming capability and cancel on lost authority.
/// # Errors
/// Refuses malformed priming intent or the same attachment/framing failures
/// as `run_bound_terminal`; ordinary unmarked streams retain normal semantics.
#[cfg(feature = "remote")]
pub async fn run_negotiated_bound_terminal(
    channel: &impl Channel,
    state: Option<PathBuf>,
) -> io::Result<()> {
    run_bound_terminal_mode(
        channel,
        state,
        true,
        #[cfg(any(test, feature = "native-streams"))]
        Receive::default(),
        #[cfg(any(test, feature = "native-streams"))]
        None,
    )
    .await
}

#[cfg(feature = "remote")]
#[allow(clippy::too_many_lines)]
async fn run_bound_terminal_mode(
    channel: &impl Channel,
    state: Option<PathBuf>,
    allow_priming: bool,
    #[cfg(any(test, feature = "native-streams"))] mut receive: Receive,
    #[cfg(any(test, feature = "native-streams"))] opening: Option<bytes::Bytes>,
) -> io::Result<()> {
    let writer_id = channel
        .native_stream_id()
        .filter(|id| *id != 0 && id & 1 == 0)
        .ok_or_else(|| sessions::invalid("native terminal writer binding required"))?;
    let _retire = RetireChannel(channel);
    let state = sessions::state(state)?;
    // Generic native classification may hand off an owned opening. Terminal-only
    // builds retain the borrowed reader and never carry that optional packet.
    #[cfg(not(any(test, feature = "native-streams")))]
    let mut receive = Receive::default();
    let (id, cursor, input, primed) =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            #[cfg(not(any(test, feature = "native-streams")))]
            let first = receive.next(channel).await?.frame;
            #[cfg(any(test, feature = "native-streams"))]
            let first = match opening.as_ref() {
                Some(packet) => {
                    infraternal_protocol::decode_frame(packet)
                        .map_err(io::Error::other)?
                        .frame
                }
                None => receive.next(channel).await?.frame,
            };
            // Shared intent is ordered on this writer, so a binding already in
            // flight across promotion cannot become an ordinary replacement.
            let primed = matches!(
                first,
                Frame::Call {
                    call_id: 0,
                    action_id: "transport.prime",
                    input_json: b"{}",
                }
            ) && allow_priming;
            let first = if primed {
                receive.next(channel).await?.frame
            } else {
                first
            };
            match first {
                Frame::AttachTerm {
                    session_id,
                    last_out_seq,
                    last_in_seq,
                } => Ok((*session_id, last_out_seq, last_in_seq, primed)),
                _ => Err(sessions::invalid("native terminal AttachTerm required")),
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    let path = sessions::rendezvous(&state, id);
    let (tx, rx) = mpsc::channel(8);
    let (commands, command_rx) = mpsc::channel(8);
    let dispatch = async {
        loop {
            let decoded = receive.next(channel).await?;
            let command = match decoded.frame {
                Frame::Input { in_seq, bytes } => Command::Input(in_seq, bytes.to_vec()),
                Frame::InputReply { bytes, .. } => Command::Reply(bytes.to_vec()),
                Frame::Ping { nonce, sent_us } => Command::Ping(nonce, sent_us),
                Frame::Credit { bytes } => Command::Credit(bytes),
                Frame::Call {
                    call_id: 0,
                    action_id: "transport.cursor",
                    input_json,
                } if primed => Command::Cursor(crate::remote_cursor::decode(input_json)?),
                Frame::Resize {
                    cols,
                    rows,
                    px_w,
                    px_h,
                } => Command::Resize(cols, rows, px_w, px_h),
                Frame::Close { .. } => return Ok(()),
                _ => return Err(sessions::invalid("unexpected native terminal request")),
            };
            // This dispatcher belongs to one native stream. Awaiting its bounded
            // queue propagates QUIC flow control without parking control or any
            // sibling stream. Ordinary coalesced Credit bursts must not retire
            // an authenticated attachment while its shim handshake is pending.
            if commands.send(command).await.is_err() {
                // Receiver closure belongs to terminal completion, including its
                // recorded-exit fallback. Dispatch must not cancel that answer
                // or its bounded FIFO drain because a late command lost its sink.
                return std::future::pending::<io::Result<()>>().await;
            }
        }
    };
    let writer = writer(channel, rx, None, false, false, 0);
    tokio::pin!(writer);
    tokio::select! {
        result = dispatch => result,
        result = &mut writer => result,
        result = terminal_mode(path, id, writer_id, cursor, input, session_commands::Receiver::Native(command_rx), tx, primed) => {
            result?;
            // Successful terminal returns can queue a final Close (gone session,
            // unsupported shim or refused request). Its sole sender is now gone:
            // drain the FIFO before RetireChannel cancels the native writes.
            // Bound the whole drain so an unread peer cannot pin this stream.
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut writer)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        },
    }
}

/// One shim connection reuses transmit and cancellation-safe receive storage.
struct Link {
    session: Session,
    transmit: Vec<u8>,
    reader: Reader,
}
impl Link {
    async fn connect(path: PathBuf, id: [u8; 16], writer: u32, shared: bool) -> io::Result<Self> {
        let session = if shared {
            sessions::connect_shared_writer(path, id, writer).await?
        } else {
            sessions::connect_writer(path, id, writer).await?
        };
        Ok(Self {
            session,
            transmit: Vec::new(),
            reader: Reader::default(),
        })
    }
    async fn send(&mut self, frame: &Shim) -> io::Result<()> {
        frame.encode_into(&mut self.transmit)?;
        self.session.peer.write_all(&self.transmit).await
    }
    // Inspect readiness without consuming bytes or waiting: a retired shim's
    // unread final frames are irreplaceable once its rendezvous is removed.
    async fn read_closed(&self) -> io::Result<bool> {
        let ready = self.session.peer.ready(tokio::io::Interest::READABLE);
        tokio::pin!(ready);
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match std::future::Future::poll(ready.as_mut(), cx) {
                std::task::Poll::Ready(Ok(ready)) => Ok(ready.is_read_closed()),
                std::task::Poll::Ready(Err(error)) => Err(error),
                std::task::Poll::Pending => Ok(false),
            })
        })
        .await
    }
    async fn read(&mut self) -> io::Result<Shim> {
        let frame = self.reader.read(&mut self.session.peer).await?;
        if matches!(frame, Shim::SnapshotWithFlags(..))
            && self.session.caps & APPROXIMATE_SNAPSHOT == 0
        {
            return Err(sessions::invalid("unnegotiated approximate Snapshot"));
        }
        Ok(frame)
    }
}
async fn input_state(link: &mut Link) -> io::Result<u64> {
    if link.session.caps & SEQUENCED_INPUT == 0 {
        return Err(sessions::invalid(
            "shim lacks restart-safe input capability",
        ));
    }
    // Retained accepted input can advance after capability selection and before
    // StateRequest reaches the shim. Acks may legally precede the State reply.
    // Bound the whole exchange, rather than resetting the deadline for each Ack.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        link.send(&Shim::InputStateRequest).await?;
        let mut acked = 0;
        loop {
            match link.read().await? {
                Shim::InputAck(seq) if seq >= acked => acked = seq,
                Shim::InputState(written, accepted) if acked <= written && written <= accepted => {
                    return Ok(written);
                }
                _ => return Err(sessions::invalid("invalid shim input state")),
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shim input state timed out"))?
}

/// State fences may replace a standalone Ack; forward only newly written input.
/// Unchanged probes must remain Pong-only, avoiding idle storage work upstream.
async fn input_progress(
    tx: &mpsc::Sender<Message>,
    stream: u32,
    acknowledged: &mut u64,
    written: u64,
) -> io::Result<()> {
    if written < *acknowledged {
        return Err(sessions::invalid("shim input cursor regressed"));
    }
    if written > *acknowledged {
        emit(tx, Message::Shim(stream, Shim::InputAck(written))).await?;
        *acknowledged = written;
    }
    Ok(())
}

/// Limits one affordable raw suffix so a shim frame cannot cross the replay boundary.
fn replay_prefix_len(cursor: u64, available: usize, fence: Option<u64>) -> usize {
    let Some(fence) = fence else {
        return available;
    };
    usize::try_from(fence.saturating_sub(cursor)).map_or(available, |length| available.min(length))
}

/// Sends the ordered end of bytes present when this shim link was opened.
async fn replay_complete(
    tx: &mpsc::Sender<Message>,
    stream: u32,
    id: [u8; 16],
    out_seq: u64,
    (cols, rows): (u16, u16),
) -> io::Result<()> {
    let json = terminal_events::Notice::ReplayComplete {
        session_id: uuid::Uuid::from_bytes(id),
        out_seq,
        cols,
        rows,
    }
    .json()?;
    emit(tx, Message::Event(stream, json)).await
}

/// Final event is ordered through the writer before ownership can be released.
async fn exited(
    tx: &mpsc::Sender<Message>,
    stream: u32,
    id: [u8; 16],
    status: i32,
    final_seq: u64,
    retired: bool,
) -> io::Result<()> {
    // A saved exit proves status, but cannot promise a final repaint after retirement.
    let json = terminal_events::Notice::Exited {
        session_id: uuid::Uuid::from_bytes(id),
        status,
        final_seq,
        retired: retired.then_some(true),
    }
    .json()?;
    if retired {
        // The shim has already retired: no ownership remains to acknowledge.
        // Queue both final frames on one FIFO so the native completion drain
        // bounds a stuck peer, including writes of this saved-status event.
        return emit(tx, Message::Event(stream, json)).await;
    }
    let (delivered, delivery) = oneshot::channel();
    emit(tx, Message::Exited(stream, json, delivered)).await?;
    delivery
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
}

/// A verified record is authoritative even while the retiring socket still exists.
async fn recorded_end(
    path: &std::path::Path,
    id: [u8; 16],
    stream: u32,
    tx: &mpsc::Sender<Message>,
) -> io::Result<bool> {
    let Some((status, seq)) = infraternal_shim::ended::read(path)? else {
        return Ok(false);
    };
    exited(tx, stream, id, status, seq, true).await?;
    emit(tx, Message::Ended(stream)).await?;
    Ok(true)
}

/// An absent rendezvous is final; known records add status, other errors propagate.
async fn relink(
    path: &std::path::Path,
    id: [u8; 16],
    stream: u32,
    tx: &mpsc::Sender<Message>,
    primed: bool,
) -> io::Result<Option<Link>> {
    match Link::connect(path.to_path_buf(), id, stream, primed).await {
        Ok(link) => Ok(Some(link)),
        Err(error) if sessions::gone(&error) => {
            if !recorded_end(path, id, stream, tx).await? {
                emit(tx, Message::Ended(stream)).await?;
            }
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// All relay errors preserve a sealed exit, including incomplete final handshakes.
#[allow(clippy::too_many_arguments)]
async fn terminal(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
) -> io::Result<()> {
    terminal_mode(path, id, stream, cursor, last_input, commands, tx, false).await
}

#[allow(clippy::too_many_arguments)]
async fn terminal_mode(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
    primed: bool,
) -> io::Result<()> {
    match terminal_run(
        path.clone(),
        id,
        stream,
        cursor,
        last_input,
        commands,
        tx.clone(),
        primed,
    )
    .await
    {
        Err(error) => {
            // EOF may occur in Hello, ownership confirmation or input-state
            // recovery before the steady-state select can observe owner EOF.
            if recorded_end(&path, id, stream, &tx).await? {
                Ok(())
            } else {
                Err(error)
            }
        }
        Ok(()) => Ok(()),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn terminal_run(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    mut commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
    primed: bool,
) -> io::Result<()> {
    // Install ownership before output requests can exhaust credit. Dropping this
    // guard on cancellation/ordered exit releases only this window, even when
    // several windows or daemon connections share a shim.
    let Some(link) = relink(&path, id, stream, &tx, primed).await? else {
        return Ok(());
    };
    let mut owner = if link.session.supports_owner {
        match sessions::own(path.clone(), id).await {
            Ok(owner) => owner,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                relink(&path, id, stream, &tx, primed).await?;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    // Keep geometry paired with this replay's Hello even if queued Resize
    // commands reach the shim before credit allows the completion event.
    let replay_size = link.session.size;
    // Only a delivered cursor on a primed link starts a new replay capture.
    #[cfg(feature = "remote")]
    let mut replay_size = replay_size;
    let mut session = Some(link);
    // Hello.head is a stable split between bytes already present on this shim
    // link and output produced while the attach is being established.
    let mut replay_until = (!primed).then(|| {
        session
            .as_ref()
            .map_or(cursor, |link| link.session.head.max(cursor))
    });
    if session
        .as_ref()
        .is_none_or(|s| s.session.caps & SEQUENCED_INPUT == 0)
    {
        emit(
            &tx,
            Message::Close(stream, "shim lacks restart-safe input capability"),
        )
        .await?;
        return Ok(());
    }
    let written = input_state(
        session
            .as_mut()
            .ok_or_else(|| sessions::invalid("missing shim"))?,
    )
    .await?;
    if last_input > written {
        return Err(sessions::invalid(
            "client input cursor exceeds shim write cursor",
        ));
    }
    emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
    let mut acknowledged = written;
    if !primed {
        session
            .as_mut()
            .ok_or_else(|| sessions::invalid("missing shim"))?
            .send(&Shim::ReadFrom(cursor))
            .await?;
    }
    #[cfg(feature = "plugin-host-facts")]
    let _window = crate::lifecycle::windows::Attachment::new(path.clone());
    let mut output = relay::Output::attach(cursor);
    if replay_until.is_some_and(|fence| output.cursor() >= fence) {
        replay_complete(&tx, stream, id, output.cursor(), replay_size).await?;
        replay_until = None;
    }
    let mut pending: Option<Shim> = None;
    let mut deadline = None;
    let mut finished_peer = false;
    // One state fence in flight bounds shim work even if probes are pipelined over the network.
    // It belongs to the data socket: parking that socket must clear its pending fence.
    let mut probe = None;
    let mut reply_unavailable_announced = false;
    loop {
        if let Some(frame) = pending.take() {
            match frame {
                Shim::Output(seq, bytes) => {
                    let frame_len = bytes.len();
                    let range = output
                        .suffix(seq, bytes.len())
                        .map_err(|_| sessions::invalid("output gap"))?;
                    // Stop an Output exactly at the Hello.head boundary. A shim
                    // frame may contain both retained history and newer bytes.
                    let length = replay_prefix_len(output.cursor(), range.len(), replay_until);
                    let end = range.start + length;
                    if length > 0 {
                        // Whole frames transfer their payload ownership to the
                        // writer. Only partial credit/overlap needs a suffix copy.
                        if range.start == 0 && end == frame_len {
                            emit(
                                &tx,
                                Message::Shim(stream, Shim::Output(output.cursor(), bytes)),
                            )
                            .await?;
                            output
                                .forward(length)
                                .map_err(|_| sessions::invalid("output credit invariant"))?;
                            if replay_until.is_some_and(|fence| output.cursor() >= fence) {
                                replay_complete(&tx, stream, id, output.cursor(), replay_size)
                                    .await?;
                                replay_until = None;
                            }
                            continue;
                        }
                        emit(
                            &tx,
                            Message::Shim(
                                stream,
                                Shim::Output(output.cursor(), bytes[range.start..end].to_vec()),
                            ),
                        )
                        .await?;
                        output
                            .forward(length)
                            .map_err(|_| sessions::invalid("output credit invariant"))?;
                    }
                    if replay_until.is_some_and(|fence| output.cursor() >= fence) {
                        replay_complete(&tx, stream, id, output.cursor(), replay_size).await?;
                        replay_until = None;
                    }
                    if end < frame_len {
                        pending = Some(Shim::Output(seq, bytes));
                        deadline = output
                            .pending(Instant::now())
                            .map(tokio::time::Instant::from_std);
                    }
                }
                frame @ (Shim::Snapshot(..) | Shim::SnapshotWithFlags(..)) => {
                    let (seq, length, approximate) = match &frame {
                        Shim::Snapshot(seq, bytes) => (*seq, bytes.len(), false),
                        Shim::SnapshotWithFlags(seq, flags, bytes) => {
                            (*seq, bytes.len(), flags & 1 != 0)
                        }
                        _ => return Err(sessions::invalid("invalid Snapshot variant")),
                    };
                    if seq < output.cursor() {
                        return Err(sessions::invalid("snapshot cursor regressed"));
                    }
                    if output.repaint(seq, length).is_ok() {
                        deadline = None;
                        if approximate {
                            let json = terminal_events::Notice::Snapshot {
                                session_id: uuid::Uuid::from_bytes(id),
                                seq,
                                approximate: true,
                            }
                            .json()?;
                            emit(&tx, Message::Event(stream, json)).await?;
                        }
                        emit(&tx, Message::Shim(stream, frame)).await?;
                        if replay_until.is_some_and(|fence| seq >= fence) {
                            // Repaint bytes contain state through seq, so the
                            // ordered completion event uses the repaint cursor.
                            replay_complete(&tx, stream, id, seq, replay_size).await?;
                            replay_until = None;
                        }
                    } else {
                        pending = Some(frame);
                        // A repaint is indivisible. Positive credit below its
                        // cost needs the same bounded pause as zero-credit raw
                        // output; expiry preserves the client cursor and parks
                        // serialization until the remembered cost is affordable.
                        deadline = output
                            .pending(Instant::now())
                            .map(tokio::time::Instant::from_std);
                    }
                }
                _ => return Err(sessions::invalid("invalid pending frame")),
            }
        }
        // No further timer is needed for a closed peer: credit or cancellation
        // alone wakes this relay, and the bounded final frames stay available.
        if finished_peer {
            deadline = None;
        }
        if output.needs_snapshot() && session.is_none() {
            let Some(mut next) = relink(&path, id, stream, &tx, primed).await? else {
                return Ok(());
            };
            let written = input_state(&mut next).await?;
            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
            acknowledged = acknowledged.max(written);
            // A credit deadline discards only the daemon's pending frame,
            // never the client's offset. Let the shim select retained replay
            // first, then faithful or negotiated approximate repaint on a gap.
            next.send(&Shim::ReadFrom(output.cursor())).await?;
            output.resume_replay();
            // Recovery continues this attach's replay. The new Hello may
            // already reflect its Resize, so retain the original geometry
            // through raw retries and Snapshot restarts alike (#257).
            replay_until = Some(next.session.head.max(output.cursor()));
            if replay_until.is_some_and(|fence| output.cursor() >= fence) {
                replay_complete(&tx, stream, id, output.cursor(), replay_size).await?;
                replay_until = None;
            }
            session = Some(next);
        }
        tokio::select! {
            result = async {
                if let Some(owner) = &mut owner {
                    let mut byte = [0; 1];
                    owner.peer.read(&mut byte).await
                } else { std::future::pending().await }
            } => {
                if result? != 0 { return Err(sessions::invalid("unexpected ownership data")); }
                // Ownership and data are separate sockets: EOF on the owner
                // can arrive while final output/Exited remains queued on data.
                // Private probes deliberately have no durable ended record.
                // Drain the existing data link in order before consulting one;
                // a parked attachment still needs its saved-record fallback.
                owner = None;
                if session.is_some() {
                    finished_peer = true;
                    continue;
                }
                if recorded_end(&path, id, stream, &tx).await? {
                    return Ok(());
                }
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            command = commands.next() => {
                let Some(command) = command else { return Ok(()); };
                match command {
                    Command::Credit(bytes) => { output.grant(bytes).map_err(|_| sessions::invalid("credit overflow"))?; if session.is_none() && bytes > 0 { output.retry_recovery(); } deadline = None; }
                    _ if finished_peer => {}
                    #[cfg(feature = "remote")]
                    Command::Cursor(cursor) if primed => {
                        // The server alone knows which output reached leg A.
                        // Reset only this shadow relay, before its ordered Credit;
                        // already queued duplicates remain bounded and are trimmed
                        // by the server rather than charged to browser credit again.
                        output = relay::Output::attach(cursor);
                        pending = None;
                        deadline = None;
                        if session.is_none() {
                            let Some(mut next) = relink(&path, id, stream, &tx, true).await? else { return Ok(()); };
                            let written = input_state(&mut next).await?;
                            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
                            acknowledged = acknowledged.max(written);
                            session = Some(next);
                        }
                        let link = session.as_mut().ok_or_else(|| sessions::invalid("missing shim"))?;
                        // Primed relays begin their replay fence only when a delivered
                        // cursor subscribes to output, never while parked for input.
                        // A primed link may have waited while another viewer
                        // resized. Hello-only observation cannot replace its
                        // durable writer or consume pending output/input Acks.
                        replay_size = sessions::replay_size(path.clone(), id).await?;
                        replay_until = Some(link.session.head.max(cursor));
                        link.send(&Shim::ReadFrom(cursor)).await?;
                        if replay_until.is_some_and(|fence| cursor >= fence) {
                            replay_complete(&tx, stream, id, cursor, replay_size).await?;
                            replay_until = None;
                        }
                    }
                    other => {
                        let detached = session.is_none();
                        if detached {
                            let Some(mut next) = relink(&path, id, stream, &tx, primed).await? else { return Ok(()); };
                            let written = input_state(&mut next).await?;
                            input_progress(&tx, stream, &mut acknowledged, written).await?;
                            session = Some(next);
                        }
                        let peer = session.as_mut().ok_or_else(|| sessions::invalid("missing shim"))?;
                        match other {
                            Command::Reply(bytes) => {
                                // An older surviving shim cannot accept the extension. Drop
                                // rather than interpreting a renderer reply as typing [307].
                                if peer.session.caps & infraternal_shim::frame::QUERY_REPLIES != 0 {
                                    peer.send(&Shim::QueryReply(bytes)).await?;
                                } else if !reply_unavailable_announced {
                                    reply_unavailable_announced = true;
                                    let json = terminal_events::Notice::QueryRepliesUnavailable { session_id: uuid::Uuid::from_bytes(id) }.json()?;
                                    emit(&tx, Message::Event(stream, json)).await?;
                                }
                            }
                            Command::Input(seq, bytes) => peer.send(&Shim::SequencedInput(seq, bytes)).await?,
                            Command::Resize(cols, rows, px_w, px_h) => peer.send(&Shim::Resize {cols, rows, px_w, px_h}).await?,
                            Command::Ping(nonce, sent_us) => {
                                if detached {
                                    // The preceding relink/state exchange crossed this shim, even when output is parked.
                                    emit(&tx, Message::Pong(stream, nonce, sent_us)).await?;
                                    session = None; probe = None;
                                    continue;
                                }
                                if probe.is_none() {
                                    peer.send(&Shim::InputStateRequest).await?;
                                    probe = Some((nonce, sent_us));
                                }
                            }
                            Command::Credit(_) => return Err(sessions::invalid("unexpected credit dispatch")),
                            #[cfg(feature = "remote")]
                            Command::Cursor(_) => return Err(sessions::invalid("unnegotiated terminal cursor")),
                        }
                        if detached {
                            // Reconnecting the same writer can supersede
                            // this socket before it reads an already-written
                            // command. An ordered State reply proves input was
                            // accepted (or resize handled) before peer loss;
                            // accepted input survives until the PTY writes it.
                            let written = input_state(peer).await?;
                            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
                            acknowledged = acknowledged.max(written);
                            session = None; probe = None;
                            output.retry_recovery();
                        }
                    }
                }
            }
            () = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; } else { std::future::pending::<()>().await; } } => {
                finished_peer = match session.as_ref() {
                    Some(peer) => peer.read_closed().await?,
                    None => false,
                };
                if !finished_peer {
                    output.expire(Instant::now()); session = None; probe = None; pending = None;
                }
                deadline = None;
            }
            frame = async {
                if let Some(session) = &mut session { session.read().await }
                else { std::future::pending().await }
            }, if pending.is_none() => {
                match frame? {
                    frame @ (Shim::Output(..) | Shim::Snapshot(..) | Shim::SnapshotWithFlags(..)) => pending = Some(frame),
                    Shim::InputAck(seq) => {
                        emit(&tx, Message::Shim(stream, Shim::InputAck(seq))).await?;
                        acknowledged = acknowledged.max(seq);
                    }
                    Shim::InputState(written, accepted) if written <= accepted && probe.is_some() => {
                        input_progress(&tx, stream, &mut acknowledged, written).await?;
                        let (nonce, sent_us) = probe.take().ok_or_else(|| sessions::invalid("missing liveness fence"))?;
                        emit(&tx, Message::Pong(stream, nonce, sent_us)).await?;
                    }
                    Shim::Exited(status, final_seq) => {
                        exited(&tx, stream, id, status, final_seq, false).await?;
                        return Ok(());
                    }
                    Shim::Error(1 | 2, _) => {
                        // Older shims cannot negotiate approximation. Park
                        // until credit/input/resize triggers recovery: keep the
                        // live mux stream, but neither busy-loop nor block PTY.
                        let json = terminal_events::Notice::SnapshotUnavailable {
                            session_id: uuid::Uuid::from_bytes(id), seq: output.cursor(),
                        }.json()?;
                        emit(&tx, Message::Event(stream, json)).await?;
                        session = None; probe = None;
                    }
                    Shim::Error(..) => { emit(&tx, Message::Close(stream, "shim refused terminal request")).await?; return Ok(()); }
                    _ => return Err(sessions::invalid("unexpected shim relay frame")),
                }
            }
        }
    }
}

#[cfg(all(test, feature = "remote"))]
#[path = "daemon_remote_tests.rs"]
mod remote_tests;

#[cfg(test)]
#[path = "daemon_readiness_tests.rs"]
mod readiness_tests;

#[cfg(test)]
#[path = "daemon_gone_tests.rs"]
mod gone_tests;

#[cfg(test)]
#[path = "stream_memory_tests.rs"]
mod stream_memory_tests;

#[cfg(test)]
#[path = "daemon_census_retry_tests.rs"]
mod census_retry_tests;
#[cfg(test)]
#[path = "readiness_exit_tests.rs"]
mod readiness_exit_tests;

#[cfg(test)]
#[path = "daemon_liveness_tests.rs"]
mod liveness_tests;

#[cfg(test)]
#[path = "daemon_authenticated_tests.rs"]
mod authenticated_tests;

/// Preserve classified opening bytes and the decoder through negotiated priming.
#[cfg(all(feature = "remote", any(test, feature = "native-streams")))]
pub(crate) async fn run_bound_terminal_opened_mode(
    channel: &impl Channel,
    state: Option<PathBuf>,
    receive: Receive,
    opening: Option<bytes::Bytes>,
    allow_priming: bool,
) -> io::Result<()> {
    run_bound_terminal_mode(channel, state, allow_priming, receive, opening).await
}
