//! Server-held sessions fan out immutable access units without letting a viewer stall capture [D104,D200,D208].
use infraternal_plugin_api::streams::Authority;
use infraternal_protocol::desktop::Input;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, watch};

pub use crate::media::{ASSEMBLY_TIMEOUT, Error, SessionId, Video};
/// Every authority decision is supplied by the existing server access rule adapter.
/// Implementations check access against the session's actual host; each socket
/// adapter additionally supplies its own live login through `attach_authorized`.
/// IDs carried by the viewer never establish an access rule or a host binding.
/// Checks are nonblocking and must not reenter Session; adapters use the existing
/// event-driven authority projection rather than per-frame database queries.
pub trait AccessRules: Send + Sync {
    fn may_view(&self, user: &str, host: &str, owner: &str) -> bool;
    fn may_control(&self, user: &str, host: &str, owner: &str) -> bool;
    /// Guard the actual viewer write through the host's live admission lease.
    /// Implementations with revocation events cancel the operation without polling.
    fn authorized_view<'a>(
        &'a self,
        user: &'a str,
        host: &'a str,
        owner: &'a str,
        operation: infraternal_plugin_api::Operation<'a, Result<(), ()>>,
    ) -> infraternal_plugin_api::Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            if !self.may_view(user, host, owner) {
                return Err(());
            }
            let result = operation.await;
            if self.may_view(user, host, owner) {
                result
            } else {
                Err(())
            }
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCommand {
    Control {
        viewer: u64,
        lease: u64,
    },
    Keyframe,
    Size {
        viewer: u64,
        lease: u64,
        width: u16,
        height: u16,
        density_milli: u16,
    },
    Input {
        viewer: u64,
        lease: u64,
        input: Input,
    },
    /// A handover/disconnect releases held remote input before a new controller types.
    ReleaseInput,
}
struct Principal {
    user: String,
    authority: Option<Arc<dyn Authority>>,
}
struct State {
    keyframe: Option<Arc<Video>>,
    last_sequence: u64,
    last_forwarded_size: Option<crate::protocol::Size>,
    viewers: HashMap<u64, Principal>,
    controller: Option<u64>,
    controller_lease: u64,
    next_viewer: u64,
    repair_pending: bool,
    closed: bool,
}
/// No task, listener or timer is created by construction. The owner keeps this
/// object in the server registry even when every viewer detaches.
pub struct Session {
    id: SessionId,
    host: String,
    owner: String,
    access: Arc<dyn AccessRules>,
    state: Mutex<State>,
    frames: watch::Sender<Option<Arc<Video>>>,
    commands: mpsc::Sender<HostCommand>,
    stopping: watch::Sender<bool>,
    controller_changed: watch::Sender<()>,
    viewers_changed: watch::Sender<()>,
}
impl Session {
    #[must_use]
    pub fn new(
        id: SessionId,
        host: String,
        owner: String,
        access: Arc<dyn AccessRules>,
    ) -> (Arc<Self>, mpsc::Receiver<HostCommand>) {
        let (commands, receiver) = mpsc::channel(8);
        (
            Arc::new(Self {
                id,
                host,
                owner,
                access,
                state: Mutex::new(State {
                    keyframe: None,
                    last_sequence: 0,
                    last_forwarded_size: None,
                    viewers: HashMap::new(),
                    controller: None,
                    controller_lease: 0,
                    next_viewer: 1,
                    repair_pending: false,
                    closed: false,
                }),
                frames: watch::channel(None).0,
                commands,
                stopping: watch::channel(false).0,
                controller_changed: watch::channel(()).0,
                viewers_changed: watch::channel(()).0,
            }),
            receiver,
        )
    }
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }
    fn repair(&self, state: &mut State) -> Result<(), Error> {
        if !state.repair_pending {
            self.commands
                .try_send(HostCommand::Keyframe)
                .map_err(|_| Error::Busy)?;
            state.repair_pending = true;
        }
        Ok(())
    }
    /// Attach checks the current access rule; the fifth viewer bound protects frame and transport buffers.
    /// # Errors
    /// Refuses ended sessions, revoked access, exhausted IDs or capacity.
    pub fn attach(self: &Arc<Self>, user: String) -> Result<Viewer, Error> {
        self.attach_inner(user, None)
    }
    /// Socket adapters bind each viewer to its own live login projection.
    /// # Errors
    /// Refuses expired socket authority and all ordinary attach refusals.
    pub fn attach_authorized(
        self: &Arc<Self>,
        user: String,
        authority: Arc<dyn Authority>,
    ) -> Result<Viewer, Error> {
        self.attach_inner(user, Some(authority))
    }
    fn attach_inner(
        self: &Arc<Self>,
        user: String,
        authority: Option<Arc<dyn Authority>>,
    ) -> Result<Viewer, Error> {
        if authority
            .as_ref()
            .is_some_and(|authority| !authority.permits())
        {
            return Err(Error::Forbidden);
        }
        if !self.access.may_view(&user, &self.host, &self.owner) {
            return Err(Error::Forbidden);
        }
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if state.closed {
            return Err(Error::Unavailable);
        }
        if state.viewers.len() == 5 {
            return Err(Error::Limit);
        }
        let id = state.next_viewer;
        state.next_viewer = id.checked_add(1).ok_or(Error::Limit)?;
        self.repair(&mut state)?;
        let cached = state.keyframe.clone();
        // Subscribe while holding the publish lock so the cached IDR and cursor
        // form one observation; a newly published IDR cannot be missed here.
        let frames = self.frames.subscribe();
        state.viewers.insert(
            id,
            Principal {
                user: user.clone(),
                authority: authority.clone(),
            },
        );
        Ok(Viewer {
            session: Arc::clone(self),
            id,
            user,
            authority,
            frames,
            cached,
            last_sequence: 0,
            waiting_keyframe: true,
        })
    }
    /// Restore visibility after a source reconnect without replaying input.
    /// # Errors
    /// Refuses a poisoned lifecycle lock.
    pub fn control_command(&self) -> Result<Option<HostCommand>, Error> {
        let command = {
            let state = self.state.lock().map_err(|_| Error::Unavailable)?;
            state.controller.map(|viewer| HostCommand::Control {
                viewer,
                lease: state.controller_lease,
            })
        };
        match command {
            Some(command) if self.command_allowed(command)? => Ok(Some(command)),
            _ => Ok(None),
        }
    }
    /// Producer ordering is session-global. Immutable payloads are shared with all viewers.
    /// # Errors
    /// Rejects invalid or nonmonotonic access units and retired sessions.
    pub fn publish(&self, video: Video) -> Result<(), Error> {
        video.validate()?;
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if state.closed {
            return Err(Error::Unavailable);
        }
        if video.sequence <= state.last_sequence {
            return Err(Error::Invalid);
        }
        state.last_sequence = video.sequence;
        let frame = Arc::new(video);
        if frame.keyframe {
            state.keyframe = Some(Arc::clone(&frame));
            state.repair_pending = false;
        }
        self.frames.send_replace(Some(frame));
        Ok(())
    }
    /// Recheck queued input at the forwarding boundary. A command cannot inherit
    /// a later controller's authority or survive its originating viewer's drop.
    /// The transport also guards the write against host/socket cancellation.
    /// Release remains admissible during retirement so held native input clears.
    /// # Errors
    /// Refuses a poisoned lifecycle lock.
    pub fn command_allowed(&self, command: HostCommand) -> Result<bool, Error> {
        let state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if matches!(command, HostCommand::ReleaseInput) {
            return Ok(true);
        }
        if state.closed {
            return Ok(false);
        }
        let (viewer, lease) = match command {
            HostCommand::Control { viewer, lease }
            | HostCommand::Input { viewer, lease, .. }
            | HostCommand::Size { viewer, lease, .. } => (viewer, lease),
            HostCommand::Keyframe | HostCommand::ReleaseInput => return Ok(true),
        };
        let Some(principal) = state.viewers.get(&viewer) else {
            return Ok(false);
        };
        Ok(state.controller == Some(viewer)
            && state.controller_lease == lease
            && principal
                .authority
                .as_ref()
                .is_none_or(|authority| authority.permits())
            && self
                .access
                .may_view(&principal.user, &self.host, &self.owner)
            && self
                .access
                .may_control(&principal.user, &self.host, &self.owner))
    }

    /// Cancel an actual pending input/resize write when its originating login,
    /// controller lease or session ends. Subscribe before the final access rule check
    /// so a handover cannot be missed, including a quick handover back. Callers
    /// must retire a partially written native lane when this waiter completes.
    pub async fn command_cancelled(&self, command: HostCommand) {
        let viewer = match command {
            HostCommand::Control { viewer, .. }
            | HostCommand::Input { viewer, .. }
            | HostCommand::Size { viewer, .. } => viewer,
            HostCommand::Keyframe | HostCommand::ReleaseInput => {
                std::future::pending::<()>().await;
                return;
            }
        };
        let mut changed = self.controller_changed.subscribe();
        let mut stopped = self.stopped();
        let authority = {
            let Ok(state) = self.state.lock() else {
                return;
            };
            let Some(principal) = state.viewers.get(&viewer) else {
                return;
            };
            principal.authority.clone()
        };
        if !self.command_allowed(command).unwrap_or(false) {
            return;
        }
        tokio::select! { biased;
            _ = changed.changed() => {},
            _ = stopped.changed() => {},
            () = async {
                match authority {
                    Some(authority) => authority.cancelled().await,
                    None => std::future::pending().await,
                }
            } => {},
        }
    }

    /// Guard the actual native forwarding operation with the originating
    /// viewer's login, then cancel it on handover or session retirement.
    /// The socket adapter retains a weak host lease, preventing a runtime cycle.
    /// # Errors
    /// Refuses ended login/controller authority or a failed native operation.
    pub async fn command_authorized(
        &self,
        command: HostCommand,
        operation: infraternal_plugin_api::Operation<'_, Result<(), ()>>,
    ) -> Result<(), Error> {
        let authority = {
            let state = self.state.lock().map_err(|_| Error::Unavailable)?;
            match command {
                HostCommand::Control { viewer, .. }
                | HostCommand::Input { viewer, .. }
                | HostCommand::Size { viewer, .. } => state
                    .viewers
                    .get(&viewer)
                    .ok_or(Error::Forbidden)?
                    .authority
                    .clone(),
                HostCommand::Keyframe | HostCommand::ReleaseInput => None,
            }
        };
        if !self.command_allowed(command)? {
            return Err(Error::Forbidden);
        }
        tokio::select! { biased;
            () = self.command_cancelled(command) => Err(Error::Forbidden),
            result = async {
                match authority {
                    Some(authority) => authority.authorized(operation).await,
                    None => operation.await,
                }
            } => result.map_err(|()| Error::Forbidden),
        }
    }

    /// Checkpoint geometry only after the authorized native write succeeds. Input
    /// is deliberately never retained: reconnect cannot replay a click or key.
    pub(crate) fn checkpoint_size(&self, command: HostCommand) -> Result<(), Error> {
        if let HostCommand::Size {
            width,
            height,
            density_milli,
            ..
        } = command
        {
            let backing_scale = f64::from(density_milli) / 1000.0;
            let size = crate::protocol::Size {
                width: u32::from(width),
                height: u32::from(height),
                canvas_width: f64::from(width) / backing_scale,
                canvas_height: f64::from(height) / backing_scale,
                backing_scale,
            };
            size.validate().map_err(|_| Error::Invalid)?;
            self.state
                .lock()
                .map_err(|_| Error::Unavailable)?
                .last_forwarded_size = Some(size);
        }
        Ok(())
    }
    /// The server-held video high water survives node process replacement.
    pub(crate) fn sequence_floor(&self) -> Result<u64, Error> {
        self.state
            .lock()
            .map(|state| state.last_sequence)
            .map_err(|_| Error::Unavailable)
    }
    pub(crate) fn last_forwarded_size(&self) -> Option<crate::protocol::Size> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.last_forwarded_size)
    }
    /// Runtime disable clears retained video and closes pending receivers, without timers.
    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.keyframe = None;
            state.viewers.clear();
            state.controller = None;
            let _ = self.commands.try_send(HostCommand::ReleaseInput);
            self.frames.send_replace(None);
            self.stopping.send_replace(true);
        }
    }
    /// The producer watches this signal to retire its input/video lease on disable
    /// or overloaded cleanup; no polling timer is needed.
    #[must_use]
    pub fn stopped(&self) -> watch::Receiver<bool> {
        self.stopping.subscribe()
    }

    /// Resource accounting excludes payload allocations retained by in-flight writers.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        let Ok(state) = self.state.lock() else {
            return 0;
        };
        let latest = self.frames.borrow();
        let key = state.keyframe.as_ref();
        let mut bytes = key.map_or(0, |frame| frame.bytes.len());
        if let Some(latest) = latest.as_ref()
            && key.is_none_or(|key| !Arc::ptr_eq(key, latest))
        {
            bytes += latest.bytes.len();
        }
        bytes
    }
}
/// Dropping a viewer relinquishes only its attachment. The server session remains.
pub struct Viewer {
    session: Arc<Session>,
    id: u64,
    user: String,
    authority: Option<Arc<dyn Authority>>,
    frames: watch::Receiver<Option<Arc<Video>>>,
    cached: Option<Arc<Video>>,
    last_sequence: u64,
    waiting_keyframe: bool,
}
impl Viewer {
    /// Retain identity, never the Viewer itself, across a bounded transport queue.
    #[must_use]
    pub fn delivery_authority(&self) -> Arc<dyn Authority> {
        Arc::new(ViewerDelivery {
            session: self.session.clone(),
            id: self.id,
            user: self.user.clone(),
            login: self.authority.clone(),
        })
    }
    fn allowed(&self, control: bool) -> Result<(), Error> {
        if self
            .authority
            .as_ref()
            .is_some_and(|authority| !authority.permits())
        {
            return Err(Error::Forbidden);
        }
        let session = &self.session;
        let allowed = if control {
            session
                .access
                .may_control(&self.user, &session.host, &session.owner)
        } else {
            session
                .access
                .may_view(&self.user, &session.host, &session.owner)
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::Forbidden)
        }
    }
    /// Receive one decodable access unit; missed deltas trigger one coalesced repair.
    /// Cached IDR is returned first, then only a fresh IDR can start current deltas.
    /// # Errors
    /// Refuses ended sessions or withdrawn access before exposing any bytes.
    pub async fn next(&mut self) -> Result<Arc<Video>, Error> {
        loop {
            self.allowed(false)?;
            if self
                .session
                .state
                .lock()
                .map_err(|_| Error::Unavailable)?
                .closed
            {
                return Err(Error::Unavailable);
            }
            if let Some(cached) = self.cached.take() {
                self.last_sequence = cached.sequence;
                return Ok(cached);
            }
            tokio::select! { biased;
                () = async {
                    match &self.authority {
                        Some(authority) => authority.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => return Err(Error::Forbidden),
                changed = self.frames.changed() => changed.map_err(|_| Error::Unavailable)?,
            }
            self.allowed(false)?;
            let frame = self
                .frames
                .borrow_and_update()
                .clone()
                .ok_or(Error::Unavailable)?;
            if frame.sequence <= self.last_sequence {
                continue;
            }
            let continuous = self.last_sequence.checked_add(1) == Some(frame.sequence);
            if frame.keyframe {
                self.waiting_keyframe = false;
            } else if self.waiting_keyframe || !continuous {
                self.waiting_keyframe = true;
                let mut state = self.session.state.lock().map_err(|_| Error::Unavailable)?;
                self.session.repair(&mut state)?;
                continue;
            }
            self.last_sequence = frame.sequence;
            return Ok(frame);
        }
    }
    /// Handover is explicit and releases held input before replacing the controller.
    /// # Errors
    /// Refuses withdrawn access or an overloaded host control lane.
    pub fn take_control(&self) -> Result<(), Error> {
        self.allowed(false)?;
        self.allowed(true)?;
        let mut state = self.session.state.lock().map_err(|_| Error::Unavailable)?;
        if state.closed {
            return Err(Error::Unavailable);
        }
        if state.controller != Some(self.id) {
            // Viewer identity can regain control. A queued command must retain
            // its original lease rather than inherit authority after A→B→A.
            let lease = state.controller_lease.checked_add(1).ok_or(Error::Limit)?;
            self.session
                .commands
                .try_send(HostCommand::Control {
                    viewer: self.id,
                    lease,
                })
                .map_err(|_| Error::Busy)?;
            state.controller = Some(self.id);
            state.controller_lease = lease;
            self.session.controller_changed.send_replace(());
        }
        Ok(())
    }
    /// Input is forwarded only under current control authority, never replayed.
    /// The native helper enforces local-input priority using its own clock.
    /// # Errors
    /// Refuses invalid input, revoked access, another controller or queue overload.
    pub fn input(&self, input: Input) -> Result<(), Error> {
        self.session
            .commands
            .try_send(self.input_command(input)?)
            .map_err(|_| Error::Busy)
    }
    /// Wait for bounded host capacity under the original controller lease.
    /// # Errors
    /// Refuses invalid input, retirement, a changed controller or a stalled host.
    pub async fn input_wait(&self, input: Input) -> Result<(), Error> {
        self.queue_command(self.input_command(input)?).await
    }
    async fn queue_command(&self, command: HostCommand) -> Result<(), Error> {
        // Authority cancellation and the forwarding fence keep queued input from
        // inheriting a later controller, including a quick handover back.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.session.command_authorized(
                command,
                Box::pin(async { self.session.commands.send(command).await.map_err(|_| ()) }),
            ),
        )
        .await
        .map_err(|_| Error::Busy)?
    }
    fn input_command(&self, input: Input) -> Result<HostCommand, Error> {
        // Only the server lease transition owns the Mac's visible control state.
        if matches!(input, Input::Control { .. }) {
            return Err(Error::Forbidden);
        }
        infraternal_protocol::desktop::Message::Input(input)
            .validate()
            .map_err(|_| Error::Invalid)?;
        self.allowed(false)?;
        self.allowed(true)?;
        let state = self.session.state.lock().map_err(|_| Error::Unavailable)?;
        if state.closed || state.controller != Some(self.id) {
            return Err(Error::Forbidden);
        }
        Ok(HostCommand::Input {
            viewer: self.id,
            lease: state.controller_lease,
            input,
        })
    }
    /// The controlling viewer's actual pixel needs drive the single encoder.
    /// # Errors
    /// Refuses invalid dimensions, withdrawn access, missing control or overload.
    pub fn resize(&self, width: u16, height: u16, density_milli: u16) -> Result<(), Error> {
        self.session
            .commands
            .try_send(self.resize_command(width, height, density_milli)?)
            .map_err(|_| Error::Busy)
    }
    /// Wait for bounded size forwarding under the originating controller lease.
    /// # Errors
    /// Refuses invalid dimensions, retirement, handover or a stalled host.
    pub async fn resize_wait(
        &self,
        width: u16,
        height: u16,
        density_milli: u16,
    ) -> Result<(), Error> {
        self.queue_command(self.resize_command(width, height, density_milli)?)
            .await
    }
    fn resize_command(
        &self,
        width: u16,
        height: u16,
        density_milli: u16,
    ) -> Result<HostCommand, Error> {
        infraternal_protocol::desktop::Message::Size {
            width,
            height,
            density_milli,
        }
        .validate()
        .map_err(|_| Error::Invalid)?;
        self.allowed(false)?;
        self.allowed(true)?;
        let state = self.session.state.lock().map_err(|_| Error::Unavailable)?;
        if state.closed || state.controller != Some(self.id) {
            return Err(Error::Forbidden);
        }
        Ok(HostCommand::Size {
            viewer: self.id,
            lease: state.controller_lease,
            width,
            height,
            density_milli,
        })
    }
    /// A writer that discarded a stale frame seals deltas until the next IDR.
    /// # Errors
    /// Refuses withdrawn access or an overloaded control lane.
    pub fn request_keyframe(&mut self) -> Result<(), Error> {
        self.allowed(false)?;
        self.waiting_keyframe = true;
        let mut state = self.session.state.lock().map_err(|_| Error::Unavailable)?;
        self.session.repair(&mut state)
    }
}
impl Drop for Viewer {
    fn drop(&mut self) {
        if let Ok(mut state) = self.session.state.lock() {
            state.viewers.remove(&self.id);
            // Membership and controller fencing are distinct: a spectator
            // leaving must never cancel another controller's native input.
            self.session.viewers_changed.send_replace(());
            if state.controller == Some(self.id) {
                state.controller = None;
                self.session.controller_changed.send_replace(());
                // A disconnected controller must release held input. If the
                // bounded lane cannot accept cleanup, retire the session instead
                // of allowing stuck keys to pass into a later handover.
                if self
                    .session
                    .commands
                    .try_send(HostCommand::ReleaseInput)
                    .is_err()
                {
                    state.closed = true;
                    state.keyframe = None;
                    state.viewers.clear();
                    self.session.frames.send_replace(None);
                    self.session.stopping.send_replace(true);
                }
            }
        }
    }
}

// Queue leases carry the original viewer identity; its removal seals already
// encoded packets before a later sink can expose bytes under a different access rule.
struct ViewerDelivery {
    session: Arc<Session>,
    id: u64,
    user: String,
    login: Option<Arc<dyn Authority>>,
}
impl Authority for ViewerDelivery {
    fn permits(&self) -> bool {
        self.login.as_ref().is_none_or(|login| login.permits())
            && self
                .session
                .access
                .may_view(&self.user, &self.session.host, &self.session.owner)
            && self
                .session
                .state
                .lock()
                .is_ok_and(|state| !state.closed && state.viewers.contains_key(&self.id))
    }
    fn cancelled(&self) -> infraternal_plugin_api::Operation<'_, ()> {
        let mut changed = self.session.viewers_changed.subscribe();
        let mut stopped = self.session.stopped();
        Box::pin(async move {
            loop {
                if !self.permits() {
                    return;
                }
                tokio::select! { biased;
                    () = async { match &self.login { Some(login) => login.cancelled().await, None => std::future::pending().await } } => return,
                    result = stopped.changed() => { if result.is_err() || *stopped.borrow_and_update() { return; } },
                    result = changed.changed() => { if result.is_err() { return; } },
                }
            }
        })
    }
    fn authorized<'a>(
        &'a self,
        operation: infraternal_plugin_api::Operation<'a, Result<(), ()>>,
    ) -> infraternal_plugin_api::Operation<'a, Result<(), ()>> {
        let guarded = Box::pin(async move {
            if !self.permits() {
                return Err(());
            }
            tokio::select! { biased;
                () = self.cancelled() => Err(()),
                result = operation => if self.permits() { result } else { Err(()) },
            }
        });
        let operation = self.session.access.authorized_view(
            &self.user,
            &self.session.host,
            &self.session.owner,
            guarded,
        );
        // The public socket already wraps the actual sink with its login
        // checks. Keep this packet projection event-driven, avoiding a second
        // database admission per video packet; cancelled() watches that login.
        operation
    }
}
