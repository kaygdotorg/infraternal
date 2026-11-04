//! Adapts the decided SSH engine to current login authority and shim attachments.
//!
//! This is a library adapter, disabled in component actions until D235 Q14 is
//! satisfied. It binds no ports, starts no shells and owns no access-rule store.
//! A caller supplies mesh-only accepted streams, host identity and shared runtime.
//!
//! Security shape: only public-key authentication with an SSH certificate is
//! offered. A successful authentication opens nothing by itself. Every shell,
//! command or file-transfer request re-runs `mesh_login::authorize` under a
//! fresh authority guard and also requires the same identity as at login, so a
//! revocation takes effect on the next open. Anything not explicitly supported
//! (environment variables, X11, extended data, other subsystems than `sftp`,
//! terminals without the certificate's `permit-pty` extension) is refused.
//! Per connection there are at most 4 channels and bounded terminal and
//! command sizes.

use crate::{
    mesh_admission::Refusal,
    mesh_certificate::Identity,
    mesh_flow::{Ingress, PACKET_BYTES, RECEIVE_WINDOW},
    mesh_login::{
        self, Attachment, Control, Exit, LoginAuthority, LoginGuard, SessionKind, Terminal,
        TerminalSize,
    },
};
use russh::{
    Channel, ChannelId,
    keys::{Certificate, PrivateKey},
    server::{self, Auth, ChannelOpenHandle, Msg, Session},
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    task::JoinHandle,
};

/// Most simultaneous session channels per connection; further opens are ignored.
const MAX_CHANNELS: usize = 4;
/// How long a connection may take to authenticate, like OpenSSH's
/// `LoginGraceTime` (J181 M2). A certificate login over the mesh completes
/// in well under a second; this bounds peers that never try.
pub const LOGIN_GRACE: Duration = Duration::from_secs(20);
/// Keepalives detect a dead peer on an idle but authenticated session,
/// instead of an inactivity timeout that would end an idle editor.
const KEEPALIVE: Duration = Duration::from_secs(15);
/// Longest accepted terminal type name, in bytes.
const MAX_TERM_NAME: usize = 64;
/// Most terminal mode entries accepted in one PTY request.
const MAX_TERM_MODES: usize = 64;
/// Longest accepted `exec` command, in bytes.
const MAX_COMMAND: usize = 16 * 1024;

/// Engine settings for consumption-aware transport. The host key comes from
/// the component lifecycle; this function never creates or persists one.
///
/// Offers only the public-key method, uses a fixed receive window that the
/// application returns by hand once bytes are written downstream
/// (`manual_receive_window`), and sets small queue sizes and `TCP_NODELAY`.
/// [`serve`] refuses configs that change the window settings.
#[must_use]
pub fn config(key: PrivateKey) -> server::Config {
    server::Config {
        keys: vec![key],
        // Unsigned method discovery reads no identity/authority, so it needs no
        // rejection delay. Actual failed authentication keeps the engine delay.
        auth_rejection_time_initial: Some(Duration::ZERO),
        methods: russh::MethodSet::from(&[russh::MethodKind::PublicKey][..]),
        window_size: RECEIVE_WINDOW,
        maximum_packet_size: RECEIVE_WINDOW / 4,
        manual_receive_window: true,
        channel_buffer_size: 1,
        event_buffer_size: 4,
        nodelay: true,
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: 4,
        ..Default::default()
    }
}

/// Serve one accepted mesh stream with structured connection ownership.
/// Component shutdown must drop/abort this future and await its owner task;
/// the protocol worker and its attachment futures then end together.
///
/// # Errors
/// Returns protocol/I/O errors or refuses incompatible receive-window settings.
pub async fn serve<A, R>(
    authority: Arc<A>,
    source: IpAddr,
    target_node: u64,
    config: Arc<server::Config>,
    stream: R,
) -> Result<(), russh::Error>
where
    A: LoginAuthority,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !config.manual_receive_window || config.window_size != RECEIVE_WINDOW {
        return Err(russh::Error::Inconsistent);
    }
    server::serve_stream(
        config,
        stream,
        Connection::new(authority, source, target_node),
    )
    .await
}

/// Serve one accepted stream with a login deadline. `pending` is the
/// caller's unauthenticated-connection slot: it is released as soon as the
/// peer authenticates, and a peer that has not authenticated within `grace`
/// is disconnected.
///
/// # Errors
/// Returns protocol/I/O errors, refuses incompatible receive-window settings
/// and reports a missed login deadline as `ConnectionTimeout`.
pub async fn serve_admitted<A, R, P>(
    authority: Arc<A>,
    source: IpAddr,
    target_node: u64,
    config: Arc<server::Config>,
    stream: R,
    grace: Duration,
    pending: P,
) -> Result<(), russh::Error>
where
    A: LoginAuthority,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !config.manual_receive_window || config.window_size != RECEIVE_WINDOW {
        return Err(russh::Error::Inconsistent);
    }
    let (admitted, on_admitted) = tokio::sync::oneshot::channel();
    let mut connection = Connection::new(authority, source, target_node);
    connection.admitted = Some(admitted);
    let serving = server::serve_stream(config, stream, connection);
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => return result,
        () = tokio::time::sleep(grace) => return Err(russh::Error::ConnectionTimeout),
        Ok(()) = on_admitted => {}
    }
    drop(pending);
    serving.await
}

/// What a successful authentication remembers so later opens can recheck it.
/// It is not a permission: each open verifies again against current authority.
#[derive(Clone)]
struct Authenticated {
    /// The verified certificate presented by the client.
    certificate: Certificate,
    /// The OS account the client asked to log in as.
    account: String,
    /// Registration found at login; an open must resolve to the same one.
    identity: Identity,
}

/// Per-channel state from channel open until close.
struct ChannelState {
    /// Sends output to the client (the engine honours the peer's window).
    writer: russh::ChannelWriteHalf<Msg>,
    /// Queue for client input to this channel.
    input: Ingress,
    /// PTY settings, if a terminal was requested before the shell or command.
    terminal: Option<Terminal>,
    /// A shell, command or file transfer was started; a channel runs only one.
    active: bool,
    /// Sender for resize and signal messages once active.
    control: Option<mpsc::Sender<Control>>,
    /// Background tasks of this channel; aborted when the channel is dropped.
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for ChannelState {
    fn drop(&mut self) {
        // Attachment cancellation never kills the underlying shim session.
        // Aborting both pumps drops their streams even if either is blocked.
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// One authenticated connection; every resource open rechecks current authority.
pub struct Connection<A: LoginAuthority> {
    /// Source of current access decisions.
    authority: Arc<A>,
    /// Peer address from the accepted socket, not from anything the client sent.
    source: IpAddr,
    /// Mesh node this server runs on.
    target_node: u64,
    /// Set after a successful certificate login; cleared at each new attempt.
    authenticated: Option<Authenticated>,
    /// Open session channels.
    channels: HashMap<ChannelId, ChannelState>,
    /// Told once, when the peer first authenticates.
    admitted: Option<tokio::sync::oneshot::Sender<()>>,
}
impl<A: LoginAuthority> Connection<A> {
    /// A connection handler for one accepted stream from `source` to `target_node`; not yet authenticated.
    #[must_use]
    pub fn new(authority: Arc<A>, source: IpAddr, target_node: u64) -> Self {
        Self {
            authority,
            source,
            target_node,
            authenticated: None,
            channels: HashMap::new(),
            admitted: None,
        }
    }

    /// Trusted host clock as Unix seconds; a clock before 1970 is refused as a time error.
    fn now() -> Result<u64, Refusal> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|time| time.as_secs())
            .map_err(|_| Refusal::CertificateTime)
    }

    /// Start a shell or command on channel `id`.
    ///
    /// Fails the request if the channel is unknown or already used, or if the
    /// connection is not authenticated. Otherwise it spawns a task that takes a
    /// fresh authority guard, re-authorizes the stored certificate, checks the
    /// identity is unchanged and opens the session; the client's reply is deferred
    /// until then. Refusal closes the channel. Success pumps data until exit.
    fn open(
        &mut self,
        id: ChannelId,
        kind: SessionKind,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let Some(state) = self.channels.get_mut(&id).filter(|state| !state.active) else {
            return session.channel_failure(id);
        };
        let Some(auth) = self.authenticated.clone() else {
            return session.channel_failure(id);
        };
        state.active = true;
        let terminal = state.terminal.clone();
        let authority = Arc::clone(&self.authority);
        let source = self.source;
        let target = self.target_node;
        let input = state.input.clone();
        let writer = state.writer.make_writer();
        let error_writer = state.writer.make_writer_ext(Some(1));
        let handle = session.handle();
        let reply = session.defer_channel_reply(id);
        let (control, controls) = mpsc::channel(8);
        state.control = Some(control);
        // Admission and runtime registration may wait for disk/PAM. Keeping
        // them off the protocol loop preserves all other channels and controls.
        state.tasks.push(tokio::spawn(async move {
            let opened = async {
                let guard = authority.current().await?;
                let login = mesh_login::authorize(
                    &guard,
                    &auth.certificate,
                    source,
                    target,
                    &auth.account,
                    Self::now()?,
                )?;
                if login.identity() != &auth.identity {
                    return Err(Refusal::Revoked);
                }
                guard.open_session(&login, kind, terminal).await
            }
            .await;
            if let Ok(attachment) = opened {
                if handle.reply_channel_request(reply, true).await.is_ok() {
                    drive(
                        input,
                        writer,
                        error_writer,
                        attachment,
                        controls,
                        id,
                        handle,
                    )
                    .await;
                }
            } else {
                let _ = handle.reply_channel_request(reply, false).await;
                let _ = handle.close(id).await;
            }
        }));
        Ok(())
    }
}

/// Pump one attachment against its SSH channel until it ends.
///
/// Runs three flows at once: client input to the session (returning receive
/// credit as bytes are accepted), session output and errors to the client, and
/// control messages (resize, signal). On output end it reports the exit status
/// and EOF. Any exit path closes the channel.
async fn drive<W: AsyncWrite + Unpin, E: AsyncWrite + Unpin>(
    ingress: Ingress,
    mut writer: W,
    mut error_writer: E,
    attachment: Attachment,
    mut controls: mpsc::Receiver<Control>,
    id: ChannelId,
    handle: server::Handle,
) {
    let Attachment {
        input,
        output,
        errors,
        control,
        exit,
    } = attachment;
    let input_handle = handle.clone();
    let input = ingress.forward(input, |amount| {
        let handle = input_handle.clone();
        async move {
            handle
                .consumed(id, amount)
                .await
                .map_err(std::io::Error::other)
        }
    });
    let output = async {
        let stdout = copy(output, &mut writer);
        let stderr = async {
            if let Some(errors) = errors {
                copy(errors, &mut error_writer).await
            } else {
                Ok(())
            }
        };
        tokio::try_join!(stdout, stderr)?;
        let status = exit.await.map_err(std::io::Error::other)?;
        Ok::<_, std::io::Error>(status)
    };
    let control = async {
        while let Some(message) = controls.recv().await {
            control.send(message).await.map_err(std::io::Error::other)?;
        }
        Ok::<_, std::io::Error>(())
    };
    tokio::pin!(input, output, control);
    let mut input_done = false;
    loop {
        tokio::select! {
            result = &mut input, if !input_done => {
                input_done = true;
                if result.is_err() { break; }
            }
            result = &mut output => {
                if let Ok(Exit::Status(status)) = result {
                    let _ = handle.exit_status_request(id, status).await;
                    let _ = handle.eof(id).await;
                }
                break;
            }
            _ = &mut control => break,
        }
    }
    let _ = handle.close(id).await;
}

/// Copy `reader` to `writer` in bounded chunks until EOF, holding one fixed buffer.
async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    writer: &mut W,
) -> std::io::Result<()> {
    // Explicitly bound scratch space per pump; copy does not collect output.
    let mut buffer = vec![0; PACKET_BYTES];
    loop {
        let count = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        writer.write_all(&buffer[..count]).await?;
    }
}

// Engine callbacks are async by contract; bounded synchronous work needs no await.
#[allow(clippy::unused_async_trait_impl)]
impl<A: LoginAuthority> server::Handler for Connection<A> {
    type Error = russh::Error;

    /// Accept a certificate login only if it passes `mesh_login::authorize`
    /// against current authority. Any earlier login on this connection is
    /// forgotten first. A rejection reveals no reason to the peer.
    async fn auth_openssh_certificate(
        &mut self,
        account: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.authenticated = None;
        let verified = async {
            let guard = self.authority.current().await?;
            let login = mesh_login::authorize(
                &guard,
                certificate,
                self.source,
                self.target_node,
                account,
                Self::now()?,
            )?;
            Ok::<_, Refusal>(login.identity().clone())
        }
        .await;
        if let Ok(identity) = verified {
            self.authenticated = Some(Authenticated {
                certificate: certificate.clone(),
                account: account.to_owned(),
                identity,
            });
            if let Some(admitted) = self.admitted.take() {
                let _ = admitted.send(());
            }
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    /// Accept a session channel only after login and below the channel limit.
    /// Silently declines otherwise. Input comes through callbacks, so the
    /// engine's own reader half is dropped.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.authenticated.is_none() || self.channels.len() >= MAX_CHANNELS {
            return Ok(());
        }
        if !session.config().manual_receive_window || session.config().window_size != RECEIVE_WINDOW
        {
            return Err(russh::Error::Inconsistent);
        }
        let id = channel.id();
        let (reader, writer) = channel.split();
        // Input arrives through callbacks. An unread receiver would block the
        // engine before those callbacks, including resize and signal handling.
        drop(reader);
        self.channels.insert(
            id,
            ChannelState {
                writer,
                input: Ingress::default(),
                terminal: None,
                active: false,
                control: None,
                tasks: Vec::new(),
            },
        );
        reply.accept().await;
        Ok(())
    }

    /// Client environment variables are never accepted.
    async fn env_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }

    /// X11 forwarding is never accepted.
    async fn x11_request(
        &mut self,
        id: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }

    /// Record terminal settings for a later shell or command.
    ///
    /// Requires the certificate to carry an empty `permit-pty` extension. Refuses
    /// a second PTY, one after the channel started, control characters or
    /// over-long names, too many modes and sizes that do not fit 16 bits.
    async fn pty_request(
        &mut self,
        id: ChannelId,
        name: &str,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.authenticated.as_ref().is_some_and(|auth| {
            auth.certificate
                .extensions()
                .get("permit-pty")
                .is_some_and(String::is_empty)
        }) {
            return session.channel_failure(id);
        }
        let size = dimensions(columns, rows, width, height, TerminalSize::default());
        let Some(state) = self
            .channels
            .get_mut(&id)
            .filter(|state| !state.active && state.terminal.is_none())
        else {
            return session.channel_failure(id);
        };
        if name.len() > MAX_TERM_NAME
            || name.bytes().any(|byte| byte.is_ascii_control())
            || modes.len() > MAX_TERM_MODES
            || size.is_none()
        {
            return session.channel_failure(id);
        }
        if let Some(size) = size {
            state.terminal = Some(Terminal {
                name: name.to_owned(),
                size,
                modes: modes.to_vec(),
            });
        }
        session.channel_success(id)
    }

    /// Start an interactive shell through the shared runtime.
    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.open(id, SessionKind::Shell, session)
    }
    /// Run a command through the shared runtime. The bytes are passed on
    /// untouched; commands over 16 KiB or containing NUL are refused.
    async fn exec_request(
        &mut self,
        id: ChannelId,
        command: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if command.len() > MAX_COMMAND || command.contains(&0) {
            return session.channel_failure(id);
        }
        self.open(id, SessionKind::Exec(command.to_vec()), session)
    }
    /// Start file transfer. Only the `sftp` subsystem, only on a fresh channel
    /// without a terminal. Authorization is repeated like for `Connection::open`;
    /// the file handler is bridged to the channel through an in-memory pipe.
    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self
            .channels
            .get_mut(&id)
            .filter(|state| !state.active && state.terminal.is_none())
        else {
            return session.channel_failure(id);
        };
        if name != "sftp" {
            return session.channel_failure(id);
        }
        let Some(auth) = self.authenticated.clone() else {
            return session.channel_failure(id);
        };
        state.active = true;
        let authority = Arc::clone(&self.authority);
        let source = self.source;
        let target = self.target_node;
        let input = state.input.clone();
        let writer = state.writer.make_writer();
        let error_writer = state.writer.make_writer_ext(Some(1));
        let handle = session.handle();
        let reply = session.defer_channel_reply(id);
        state.tasks.push(tokio::spawn(async move {
            let opened = async {
                let guard = authority.current().await?;
                let login = mesh_login::authorize(
                    &guard,
                    &auth.certificate,
                    source,
                    target,
                    &auth.account,
                    Self::now()?,
                )?;
                if login.identity() != &auth.identity {
                    return Err(Refusal::Revoked);
                }
                guard.open_files(&login).await
            }
            .await;
            let Ok(files) = opened else {
                let _ = handle.reply_channel_request(reply, false).await;
                let _ = handle.close(id).await;
                return;
            };
            if handle.reply_channel_request(reply, true).await.is_err() {
                return;
            }
            let (bridge, service) = tokio::io::duplex(PACKET_BYTES);
            let (output, runtime_input) = tokio::io::split(bridge);
            let (exit, completion) = tokio::sync::oneshot::channel();
            let (control, _unused_control) = mpsc::channel(1);
            let (_controls, controls) = mpsc::channel(1);
            let attachment = Attachment {
                input: Box::pin(runtime_input),
                output: Box::pin(output),
                errors: None,
                control,
                exit: completion,
            };
            let service = async {
                let result = russh_sftp::server::serve_with_config(
                    service,
                    files,
                    russh_sftp::server::Config {
                        max_client_packet_len: 256 * 1024,
                    },
                )
                .await;
                let _ = exit.send(Exit::Status(u32::from(result.is_err())));
            };
            let bridge = drive(
                input,
                writer,
                error_writer,
                attachment,
                controls,
                id,
                handle,
            );
            tokio::pin!(service, bridge);
            tokio::select! {
                () = &mut service => bridge.await,
                () = &mut bridge => (),
            }
        }));
        Ok(())
    }

    /// Queue client input; overflowing the receive window is a protocol error.
    async fn data(
        &mut self,
        id: ChannelId,
        bytes: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels
            .get(&id)
            .ok_or(russh::Error::Inconsistent)?
            .input
            .push(bytes)
            .map_err(|_| russh::Error::Inconsistent)
    }
    /// Extended (stderr-style) data from the client is not allowed.
    async fn extended_data(
        &mut self,
        _: ChannelId,
        _: u32,
        _: &[u8],
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        Err(russh::Error::Inconsistent)
    }
    /// Mark client input finished, ordered after the bytes already queued.
    async fn channel_eof(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.get(&id) {
            state.input.eof().map_err(|_| russh::Error::Inconsistent)?;
        }
        Ok(())
    }
    /// Drop the channel state, which aborts its tasks (the shim session itself lives on).
    async fn channel_close(&mut self, id: ChannelId, _: &mut Session) -> Result<(), Self::Error> {
        self.channels.remove(&id);
        Ok(())
    }
    /// Forward a terminal resize. If the control queue is full or gone, the channel is closed.
    async fn window_change_request(
        &mut self,
        id: ChannelId,
        columns: u32,
        rows: u32,
        width: u32,
        height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(state) = self.channels.get_mut(&id) else {
            return session.channel_failure(id);
        };
        let Some(terminal) = state.terminal.as_mut() else {
            return session.channel_failure(id);
        };
        let Some(size) = dimensions(columns, rows, width, height, terminal.size) else {
            return session.channel_failure(id);
        };
        terminal.size = size;
        if state
            .control
            .as_ref()
            .is_some_and(|control| control.try_send(Control::Resize(size)).is_err())
        {
            session.channel_failure(id)?;
            self.channels.remove(&id);
            return session.close(id);
        }
        session.channel_success(id)
    }
    /// Forward a signal to the session. If the control queue is full or gone, the channel is closed.
    async fn signal(
        &mut self,
        id: ChannelId,
        signal: russh::Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(control) = self
            .channels
            .get(&id)
            .and_then(|state| state.control.as_ref())
        else {
            return session.channel_failure(id);
        };
        if control.try_send(Control::Signal(signal)).is_err() {
            session.channel_failure(id)?;
            self.channels.remove(&id);
            return session.close(id);
        }
        session.channel_success(id)
    }
}

/// Combine requested terminal dimensions with `previous`; zero means "unchanged".
/// Returns `None` if any value does not fit in 16 bits.
fn dimensions(
    columns: u32,
    rows: u32,
    width: u32,
    height: u32,
    previous: TerminalSize,
) -> Option<TerminalSize> {
    // RFC 4254 6.2/6.7 treats each zero dimension as unspecified. Preserve
    // current dimensions on resize, or the ordinary 80x24 initial size.
    let dimension = |value: u32, current: u16| {
        if value == 0 {
            Some(current)
        } else {
            u16::try_from(value).ok()
        }
    };
    Some(TerminalSize {
        columns: dimension(columns, previous.columns)?,
        rows: dimension(rows, previous.rows)?,
        width_pixels: dimension(width, previous.width_pixels)?,
        height_pixels: dimension(height, previous.height_pixels)?,
    })
}

#[cfg(test)]
#[path = "mesh_server_tests.rs"]
mod tests;
