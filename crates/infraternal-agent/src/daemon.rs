//! Shared inherited and authenticated remote leg-B dispatcher and bounded session registry for the tracer bullet [9][13][41].
//!
//! Each terminal owns one credit-waiting shim frame and at most one extra raw frame
//! already charged to that stream's output credit. Input/Resize commands have eight slots;
//! shared-stream Credit is accumulated in constant space without occupying that FIFO;
//! Input/Resize overload retires only that stream; probes may be skipped. Unacknowledged
//! input is replayed on attachment using shim-owned per-writer cursors. Bulk output has eight slots;
//! raw-output enqueue never awaits capacity. While one raw frame waits for writer capacity, the
//! shim reader can fill one extra bounded pending slot so `InputAck` and liveness replies still
//! move; it pauses again once that slot is occupied. Commands and timers stay live throughout.
//! Control replies use a separate eight-slot lane, selected
//! first at frame boundaries; reply producers wait for bounded FIFO capacity. Native
//! terminal dispatch continues on its independent streams. Starved sessions close
//! their shim socket after 250 ms, then reconnect for a fresh credit-funded
//! ring replay or a flagged bounded repaint. Unviewed sessions stay disconnected so their PTYs keep progressing.
//!
//! D381 keeps four relay invariants: no Snapshot reaches the writer before its full
//! payload length is approved by this stream's credit ledger; input cannot mint credit.
//! A repaint spends the separate 64 KiB reserve or borrows only from raw output this
//! stream drops for the replacement; each raw byte backs at most one repaint until
//! its credit returns, and borrowed bytes become debt. Raw output cannot spend the
//! remaining reserve. A key-triggered capture follows that key's shim `InputAck` and
//! leaves one frame for its PTY echo.
//! Dropping stalled output affects only its own stream. Coalesced key input
//! cannot mint credit or create unbounded captures. After the latest coalesced
//! key is acknowledged, its capture waits one 8 ms terminal frame so the PTY
//! program can render the echo. A funded key that replaces a stalled raw frame
//! starts its own 250 ms capture deadline, independent of bulk credit and shared
//! by coalesced keys. Ordinary unfunded frames keep their bulk starvation
//! deadline. A key preempts when raw output is waiting for bulk credit or has
//! built the backlog threshold, including a pending shim frame
//! when no earlier raw bytes remain in flight. When bulk credit is exhausted
//! and repaint credit remains, a key also triggers before its echo is queued;
//! the key itself supplies the output that would otherwise wait. A small quiet
//! write alone does not trigger a repaint. The bounded writer
//! priority lane sends only shim-confirmed key acknowledgments and credit-approved
//! Snapshots; it drops or trims only same-stream raw bytes covered by the cursor.
//! A 1 MiB Snapshot may borrow from the bulk output it replaces, while a hostile
//! key burst still shares the same finite credit ledger and coalesced capture.
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
use std::{collections::HashMap, io, path::PathBuf, sync::Arc};

pub use crate::daemon_writer::approximate_snapshots_total;
use crate::daemon_writer::{Message, PRIORITY_CAPACITY, PriorityMessage, reply, writer};
#[cfg(test)]
use crate::{daemon_writer::deferred_reply, transport::Transmit};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::Instant,
};

/// Give the PTY program a short render head start while leaving time in D375's
/// 120 Hz flood budget for capture, delivery and paint. Later PTY output is
/// still relayed in order from the snapshot cursor.
const KEY_REPAINT_GRACE: std::time::Duration = std::time::Duration::from_millis(2);

/// Explicit session ends wait for shell exit without borrowing launch or renewal capacity.
const MAX_ENDING_TERMINALS: usize = 4;
/// Bound a hung shim handshake or exit so it cannot hold an end slot indefinitely.
const TERMINAL_END_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// Wait for a relay operation while its active repaint still has time to finish.
///
/// Prefer expiry when both become ready. The relay drops the old shim link
/// after cancellation because an interrupted frame write may be partial.
async fn during_key_capture<T>(
    deadline: Option<Instant>,
    operation: impl std::future::Future<Output = T>,
) -> Option<T> {
    if let Some(deadline) = deadline {
        if Instant::now() >= deadline {
            return None;
        }
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(deadline) => None,
            result = operation => Some(result),
        }
    } else {
        Some(operation.await)
    }
}

/// Request one capture after the acknowledged input's render grace.
///
/// The cumulative target coalesces key bursts. This common gate keeps credit
/// returns and completed captures from bypassing the render grace, and it spends
/// no credit itself; the later `Snapshot` must still fit the current repaint
/// budget, including raw bytes that this capture replaces.
async fn request_key_repaint_if_ready(
    session: &mut Option<Link>,
    target: Option<u64>,
    requested: &mut Option<u64>,
    acknowledged: u64,
    repaint_budget: u64,
    ready: &mut bool,
    finished_peer: bool,
) -> io::Result<()> {
    let Some(target) = target else {
        return Ok(());
    };
    if finished_peer
        || session.is_none()
        || requested.is_some()
        || target > acknowledged
        || repaint_budget == 0
        || !*ready
    {
        return Ok(());
    }

    session
        .as_mut()
        .ok_or_else(|| sessions::invalid("missing shim"))?
        .send(&Shim::SnapshotRequest)
        .await?;
    *requested = Some(target);
    *ready = false;
    Ok(())
}

/// Forward the shim's confirmation that input through `seq` reached the PTY.
///
/// The shim keeps a single reply slot per peer, so a key's confirmation arrives either as an
/// `InputAck` or, when a route proof's `InputStateRequest` was outstanding, inside that proof's
/// `InputState` (#477). Both replies come here. While a key repaint is pending the Ack takes the
/// writer's priority lane: that keeps it ahead of the Snapshot showing the key's echo and lets the
/// writer drop the raw output the Snapshot replaces. An `InputAck` is always forwarded (`always`);
/// a state reply only when it advances the cursor. Returns whether it advanced.
async fn forward_input_confirmation(
    tx: &mpsc::Sender<Message>,
    priority: &mpsc::Sender<PriorityMessage>,
    stream: u32,
    attachment: u64,
    seq: u64,
    output_cursor: u64,
    repaint_pending: bool,
    always: bool,
    acknowledged: &mut u64,
) -> io::Result<bool> {
    let advanced = seq > *acknowledged;
    if advanced || always {
        if repaint_pending {
            emit_priority(
                priority,
                PriorityMessage::InputAck {
                    stream,
                    attachment,
                    seq,
                    output_cursor,
                },
            )
            .await?;
        } else {
            emit(tx, Message::Shim(stream, Shim::InputAck(seq))).await?;
        }
    }
    *acknowledged = (*acknowledged).max(seq);
    Ok(advanced)
}

/// Whether a confirmation through `seq` should start the pending key repaint's render grace.
///
/// It must, whichever shim reply carried it: the relay discards raw output while a key repaint is
/// pending, so a key confirmed without starting its grace would never be repainted and the screen
/// would stay frozen with the client's credit unused (#477). A confirmation that does not advance
/// still starts a grace that is neither running nor finished, for a key whose cursor advanced on
/// another path first.
fn key_repaint_grace_due(
    target: Option<u64>,
    requested: Option<u64>,
    seq: u64,
    advanced: bool,
    ready: bool,
    ready_at_set: bool,
) -> bool {
    target.is_some_and(|target| {
        requested.is_none_or(|requested| target > requested)
            && seq >= target
            && (advanced || (!ready && !ready_at_set))
    })
}

/// Decide whether a key should replace output that is waiting for flow-control credit.
///
/// A writer-staged raw frame or already-sent backlog shows that output is
/// waiting. The credit-starved shim frame is also waiting, even when every
/// earlier raw byte has been returned; its bytes have not been charged yet.
/// With bulk credit exhausted, the next key's own echo would wait too, so a
/// still-funded repaint can be requested before another raw frame is staged.
fn output_waiting_for_key_repaint(
    pending: Option<&Shim>,
    pending_bulk: Option<&Message>,
    output: &relay::Output,
) -> bool {
    let unreturned = output.unreturned_output_credit();
    pending_bulk.is_some()
        || (matches!(pending, Some(Shim::Output(..))) && output.bulk_starved())
        || (output.bulk_starved() && output.repaint_budget() > 0)
        || (unreturned > 0 && (output.bulk_starved() || unreturned >= relay::KEY_REPAINT_BACKLOG))
}

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
/// One terminal stream the shared dispatcher has attached: where its commands go,
/// and how to stop its relay task.
struct Stream {
    /// The relay task's bounded command queue.
    commands: session_commands::Sender,
    /// Stops the relay task. Dropping it retires a stalled handshake as well as
    /// queued commands; [`Stream::retire`] also tells the task to clear the
    /// writer's per-stream state.
    cancel: oneshot::Sender<u64>,
}

impl Stream {
    /// Stop this stream's relay because the server closed it (or dispatch retired it).
    ///
    /// Sends a fresh attachment id as a floor: every attachment this relay ever
    /// announced is older, and any relay that later reattaches the same stream
    /// id is newer. The cancelled task forwards it as [`Message::Forget`] on the
    /// bulk lane, after everything the old relay queued, so the writer's
    /// per-stream cursor state goes away without touching a replacement's (#477).
    ///
    /// It also tells the writer, on the control lane that the writer serves ahead of its bulk
    /// FIFO, to drop the raw output this relay still has queued ([`Message::Retire`], #583).
    /// That runs here, synchronously in dispatch, so it is ordered before anything a
    /// reattach of the same stream id can queue, and before any control reply (such as a
    /// Pong fence) sent after the close. A full control lane only loses the drop, which is
    /// the old behaviour, so the failure is not fatal.
    fn retire(self, control: &mpsc::Sender<Message>, stream: u32) {
        let floor = crate::daemon_writer::next_attachment();
        // Only when the relay task is still there to follow with its Forget: that Forget is
        // what clears the writer's retired state again (a finished relay has queued all it
        // ever will, and leaves no state to clear).
        if self.cancel.send(floor).is_ok() {
            let _ = reply(control, Message::Retire(stream, floor));
        }
    }
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
    person: Option<uuid::Uuid>,
    #[serde(default)]
    account: Option<String>,
    /// Login access for `person` on this host (D235 Q14). A person open
    /// without one is refused, so an older server cannot skip the check.
    #[serde(default)]
    grant: Option<infraternal_plugin_api::login_access::LoginGrant>,
    #[serde(default)]
    readiness: bool,
    uid: u32,
    cols: u16,
    rows: u16,
}

pub(crate) use crate::daemon_writer::hello_capabilities;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// The trusted server's request to revoke one person's host logins (`terminal.login.revoke`).
struct RevokeLogin {
    person: uuid::Uuid,
    /// Whether the D356 access report is wanted. The server leaves it out
    /// for a host removal (D398), so the default is to scan: a caller that
    /// says nothing is a person's revoke.
    #[serde(default = "wants_report")]
    report: bool,
}

/// The default of [`RevokeLogin::report`].
fn wants_report() -> bool {
    true
}

struct Opened {
    session: Option<Session>,
    json: Vec<u8>,
}

// Preserve absent legacy fields versus the explicit null requested account of
// a person login. Serialize directly, avoiding a per-open dynamic object map.
#[derive(Default)]
struct OpenReply {
    account: Option<String>,
    fallback: Option<bool>,
    note: Option<String>,
    #[allow(clippy::option_option)] // The wire distinguishes missing from explicit null.
    requested_account: Option<Option<String>>,
    prepared: Option<bool>,
    session_id: Option<uuid::Uuid>,
}

// Unknown map length avoids computing the same optional-field predicates once
// for a derived struct length and again for its contents. The existing map
// serializer still owns all escaping and preserves explicit null values.
impl serde::Serialize for OpenReply {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        if let Some(value) = &self.account {
            map.serialize_entry("account", value)?;
        }
        if let Some(value) = self.fallback {
            map.serialize_entry("fallback", &value)?;
        }
        if let Some(value) = &self.note {
            map.serialize_entry("note", value)?;
        }
        if let Some(value) = self.prepared {
            map.serialize_entry("prepared", &value)?;
        }
        if let Some(value) = &self.requested_account {
            map.serialize_entry("requested_account", value)?;
        }
        if let Some(value) = self.session_id {
            map.serialize_entry("session_id", &value)?;
        }
        map.end()
    }
}

#[cfg(test)]
mod open_reply_tests {
    //! Keep person metadata and legacy field absence identical after direct serialization.
    use super::OpenReply;

    #[test]
    fn legacy_and_person_fields_preserve_exact_json_shape() {
        let id = uuid::Uuid::from_u128(1);
        let legacy = OpenReply {
            session_id: Some(id),
            ..OpenReply::default()
        };
        assert_eq!(
            serde_json::to_vec(&legacy).unwrap(),
            serde_json::to_vec(&serde_json::json!({"session_id": id})).unwrap()
        );
        let prepared = OpenReply {
            account: Some("root".into()),
            fallback: Some(false),
            note: Some(String::new()),
            prepared: Some(true),
            session_id: None,
            requested_account: Some(None),
        };
        assert_eq!(
            serde_json::to_vec(&prepared).unwrap(),
            serde_json::to_vec(
                &serde_json::json!({"account":"root", "fallback":false, "note":"",
                "prepared":true, "requested_account":null})
            )
            .unwrap()
        );
        let terminal = OpenReply {
            prepared: None,
            requested_account: Some(Some("absent".into())),
            fallback: Some(true),
            note: Some("No user absent here, opened as root".into()),
            session_id: Some(id),
            ..prepared
        };
        assert_eq!(
            serde_json::to_vec(&terminal).unwrap(),
            serde_json::to_vec(&serde_json::json!({"account":"root", "fallback":true,
                "note":"No user absent here, opened as root", "requested_account":"absent",
                "session_id":id}))
            .unwrap()
        );
    }
}

type OpenResult = Result<Opened, infraternal_plugin_api::admission::OpenRefusal>;
type OpenTasks = JoinSet<(u32, u32, OpenResult)>;
// Backend detection belongs to the first admitted login operation. The shared
// cell serializes concurrent first requests without an idle task or probe;
// cancellation leaves an unfinished initialization retryable by another call.
type LoginManager = Arc<tokio::sync::OnceCell<Manager>>;

// Even the shared synchronization state belongs to first use: its constructors
// must not populate executable pages or allocate while the host has no logins.
#[cold]
#[inline(never)]
fn login_manager(slot: &mut Option<LoginManager>) -> LoginManager {
    slot.get_or_insert_with(|| Arc::new(tokio::sync::OnceCell::new()))
        .clone()
}

// Anonymous own-account shims can reuse their inherited context. A root host
// must retain first-use detection of its real login backend.
#[inline]
fn anonymous_login_manager(root: bool) -> Option<LoginManager> {
    if root {
        return None;
    }
    let slot = Arc::new(tokio::sync::OnceCell::new());
    let _ = slot.set(Manager::Detached);
    Some(slot)
}

#[cfg(all(test, target_os = "linux"))]
mod image_tests {
    //! Keep anonymous shim launch distinct from the host login path [D18,D247].
    use super::*;
    use std::path::Path;

    #[tokio::test]
    async fn anonymous_image_retains_root_login_backend() {
        let mut initial = anonymous_login_manager(true);
        let manager = login_manager(&mut initial);
        let backend = *manager.get_or_init(|| async { Manager::System }).await;
        assert!(
            matches!(backend, Manager::System),
            "anonymous root image replaced the host login backend"
        );
        assert!(matches!(
            backend.for_shim(Path::new("/proc/self/exe"), false),
            Manager::Detached
        ));
        assert!(matches!(*manager.get().unwrap(), Manager::System));
    }

    #[tokio::test]
    async fn anonymous_image_reuses_rootless_context_without_backend_probe() {
        let mut initial = anonymous_login_manager(false);
        let manager = login_manager(&mut initial);
        let backend = *manager
            .get_or_init(|| async { panic!("anonymous own-account image probed a login backend") })
            .await;
        assert!(matches!(backend, Manager::Detached));
    }

    #[test]
    fn anonymous_image_uses_direct_shim_launch_without_changing_named_launches() {
        let anonymous = Path::new("/proc/self/exe");
        let named = Path::new("/installed/infraternal");
        assert!(matches!(
            Manager::System.for_shim(anonymous, false),
            Manager::Detached
        ));
        assert!(matches!(
            Manager::User.for_shim(anonymous, false),
            Manager::Detached
        ));
        assert!(matches!(
            Manager::System.for_shim(named, false),
            Manager::System
        ));
        assert!(matches!(
            Manager::User.for_shim(named, false),
            Manager::User
        ));
        assert!(matches!(
            Manager::System.for_shim(named, true),
            Manager::Detached
        ));
    }
}

struct OpenTask {
    exe: PathBuf,
    state: PathBuf,
    manager: LoginManager,
    input: Open,
    prepare: bool,
    plugins: crate::plugin_control::Registry,
    context: infraternal_plugin_api::admission::NodeContext,
}

/// Public reason for a failed terminal open. A rootless host's refused login is a fact the person can act on, so it
/// is named instead of reading as a malformed request (#327). Every other `PermissionDenied` (a revoked person, a
/// worker owned by another account) stays `Invalid`, so root hosts answer exactly as before.
fn open_refusal(error: &io::Error) -> infraternal_plugin_api::admission::OpenRefusal {
    use crate::logins::RootlessRefusal;
    use infraternal_plugin_api::admission::OpenRefusal;
    if crate::logins::NoSystemd::of(error) {
        return OpenRefusal::NoSystemd;
    }
    if crate::logins::ProbeTimeout::of(error) {
        return OpenRefusal::ProbeTimeout;
    }
    match (RootlessRefusal::of(error), error.kind()) {
        (Some(RootlessRefusal::NoMatchingLogin), _) => OpenRefusal::NoLogin,
        (Some(RootlessRefusal::OtherAccount), _) => OpenRefusal::Permission,
        (
            None,
            io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::PermissionDenied,
        ) => OpenRefusal::Invalid,
        (None, _) => {
            log_unclassified_open_failure(error);
            OpenRefusal::ResourceUnavailable
        }
    }
}

/// Says on stderr why an open was answered `resource_unavailable` (#562).
///
/// The browser only learns "try again", so this line is the only place the
/// cause shows. It prints the `io::ErrorKind`, the raw errno when there is
/// one and the error's own text. The text comes from the failing call
/// (`spawn`, `openpty`, a systemd answer), never from the request, so it
/// carries no argv, environment or secret; account names and grants are not
/// part of it. Lines are capped so a runaway message cannot flood the log.
fn log_unclassified_open_failure(error: &io::Error) {
    const CAP: usize = 240;
    let text = error.to_string();
    let text: String = text.chars().filter(|c| !c.is_control()).take(CAP).collect();
    eprintln!(
        "terminal open refused as resource_unavailable: kind={:?} errno={} detail={text}",
        error.kind(),
        error
            .raw_os_error()
            .map_or_else(|| "none".to_owned(), |code| code.to_string()),
    );
}

#[cfg(test)]
mod refusal_tests {
    //! A refused login names its true reason; only malformed requests are "invalid" (#327).
    use super::*;
    use infraternal_plugin_api::admission::OpenRefusal;

    /// Plain I/O failures map to the generic reasons: only malformed requests
    /// and refused ownership are "invalid", anything else "resource unavailable".
    #[test]
    fn io_kinds_map_to_their_reason() {
        let kind = |kind| open_refusal(&io::Error::from(kind));
        assert_eq!(kind(io::ErrorKind::InvalidInput), OpenRefusal::Invalid);
        assert_eq!(kind(io::ErrorKind::InvalidData), OpenRefusal::Invalid);
        // Revocation and worker ownership are not rootless facts: root hosts keep answering as before.
        assert_eq!(kind(io::ErrorKind::PermissionDenied), OpenRefusal::Invalid);
        assert_eq!(
            kind(io::ErrorKind::TimedOut),
            OpenRefusal::ResourceUnavailable
        );
    }

    /// #401: a login image that `SELinux` would not let us mark executable is a
    /// host or policy condition, so the open is refused as unavailable, never
    /// as a malformed request.
    #[cfg(target_os = "linux")]
    #[test]
    fn selinux_label_failure_is_not_an_invalid_request() {
        let failure = crate::exec_label::label_failure("test");
        assert_eq!(failure.kind(), io::ErrorKind::Unsupported);
        assert_eq!(open_refusal(&failure), OpenRefusal::ResourceUnavailable);
    }

    /// A root open whose manager probe stayed silent names its own reason, so
    /// the browser can say "busy, try again" rather than a generic failure.
    #[test]
    fn a_silent_manager_probe_names_its_own_reason() {
        let refused = io::Error::new(io::ErrorKind::TimedOut, crate::logins::ProbeTimeout);
        assert_eq!(open_refusal(&refused), OpenRefusal::ProbeTimeout);
        // A plain timeout stays the generic, retryable reason.
        assert_eq!(
            open_refusal(&io::Error::from(io::ErrorKind::TimedOut)),
            OpenRefusal::ResourceUnavailable
        );
    }

    /// A root host without systemd names its own reason, not "try again" (D354).
    #[test]
    fn a_root_host_without_systemd_names_why_it_cannot_log_in() {
        let refused = io::Error::new(io::ErrorKind::Unsupported, crate::logins::NoSystemd);
        assert_eq!(open_refusal(&refused), OpenRefusal::NoSystemd);
    }

    #[test]
    fn rootless_host_names_why_it_cannot_log_in() {
        if nix::unistd::Uid::effective().is_root() {
            eprintln!("SKIP rootless refusal: runs only as a non-root account");
            return;
        }
        // A person whose name is no account here: a root host would fall back to root, a rootless one cannot.
        let absent = crate::logins::account("j142-no-such-account").unwrap_err();
        assert_eq!(open_refusal(&absent), OpenRefusal::NoLogin);
        // An account that exists but is not this infraternal agent's own.
        let other = crate::logins::account("root").unwrap_err();
        assert_eq!(open_refusal(&other), OpenRefusal::Permission);
    }
}

// Construct cold login futures only when requested. Keeping their creation
// outside the dispatcher poll function avoids touching their much larger code
// working set on every idle greeting/receive, without an eager heap allocation.
/// Start one admitted `terminal.open` as its own task, so a slow launch never blocks the dispatcher.
#[cold]
#[inline(never)]
fn spawn_open(opens: &mut OpenTasks, stream: u32, call_id: u32, task: OpenTask) {
    opens.spawn(async move {
        let result = async {
            task.plugins.admit("terminal.open", task.context).await?;
            let manager = Manager::resolve(&task.manager).await;
            open_requested(&task.exe, &task.state, manager, task.input, task.prepare)
                .await
                .map_err(|error| open_refusal(&error))
        }
        .await;
        (stream, call_id, result)
    });
}

/// Serialized size the revoke reply stays under, below the control-frame
/// JSON limit with room for the envelope.
const REVOKE_REPLY_BUDGET: usize = 30 * 1024;

/// The revoke result for the server: `revoked`, D353's `warning` when
/// background programs may remain, and D356's `access` report, which
/// only the person revoking sees (never a log). If the report would not fit a
/// control frame, its last lines are dropped and it says it is truncated.
fn revoke_reply(revoked: &crate::logins::Revoked, report: bool) -> Vec<u8> {
    let mut access = revoked.access.clone();
    loop {
        let mut reply = serde_json::json!({ "revoked": true });
        if revoked.background_may_remain {
            // D353: others still share the account, or linger came back (J308).
            reply["warning"] = "Background programs of this host account may still be running: other people still have access to it, linger returned, or account shutdown could not be verified.".into();
        }
        // D356: always sent, so "nothing changed" is never confused with
        // "not checked" (an older agent sends none).
        // A revoke that was not asked for a report (a host removal, D398)
        // sends none; the server never reads one then.
        if report {
            reply["access"] = serde_json::to_value(&access).unwrap_or_default();
        }
        let bytes = serde_json::to_vec(&reply).unwrap_or_else(|_| b"{\"revoked\":true}".to_vec());
        if bytes.len() <= REVOKE_REPLY_BUDGET {
            return bytes;
        }
        // Lines go first; then whole files, counted, never silently.
        if !trim_report(&mut access) {
            return bytes;
        }
    }
}

/// How much the person revoking needs to see a reported file: what admits
/// a login most, then what runs without one, then the rest. Trimming takes
/// from the least first, so `authorized_keys*` goes last (J334 P2-2).
fn report_value(path: &str) -> u8 {
    if path.contains("/.ssh/authorized_keys") {
        3
    } else if path == "crontab"
        || path.starts_with("at job")
        || path.contains("/systemd/user")
        || path.contains("/environment.d")
    {
        2
    } else {
        1
    }
}

/// Makes the report smaller by one step, marking the account it took from
/// truncated. The order is by value, across kinds: lines of the least
/// valuable files, then of the middling ones, then not-scanned names, then
/// whole files from the least valuable up (counted in `omitted_files`), and
/// only last what admits a login (J334 P2-2). `false` when nothing is left.
fn trim_report(access: &mut crate::access_files::Access) -> bool {
    /// One step of the order.
    enum Step {
        /// A line of a file worth this much.
        Line(u8),
        /// A not-scanned name.
        Unscanned,
        /// A whole file worth this much.
        File(u8),
    }
    for account in access.accounts.iter_mut().rev() {
        if !account.processes.is_empty() {
            account.processes.truncate(account.processes.len() / 2);
            // Keep programs_may_remain: trimming evidence never proves shutdown.
            return true;
        }
    }
    let order = [
        Step::Line(1),
        Step::Line(2),
        Step::Unscanned,
        Step::File(1),
        Step::File(2),
        Step::Line(3),
        Step::File(3),
    ];
    for step in order {
        let found = match step {
            Step::Unscanned => access
                .accounts
                .iter()
                .rposition(|account| !account.unscanned.is_empty())
                .map(|a| (a, None)),
            Step::Line(value) | Step::File(value) => {
                let lines = matches!(step, Step::Line(_));
                access
                    .accounts
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(a, account)| {
                        account
                            .files
                            .iter()
                            .rposition(|file| {
                                report_value(&file.path) == value
                                    && (!lines || !file.lines.is_empty())
                            })
                            .map(|f| (a, Some((f, lines))))
                    })
            }
        };
        let Some((a, place)) = found else {
            continue;
        };
        let account = &mut access.accounts[a];
        match place {
            None => {
                account.unscanned.pop();
            }
            Some((f, true)) => {
                let file = &mut account.files[f];
                file.lines.pop();
                let more = "more new lines than the report shows";
                match &mut file.note {
                    Some(note) if note.contains(more) => {}
                    Some(note) => {
                        note.push_str("; ");
                        note.push_str(more);
                    }
                    None => file.note = Some(more.to_owned()),
                }
            }
            Some((f, false)) => {
                account.files.remove(f);
                account.omitted_files += 1;
            }
        }
        account.truncated = true;
        account.complete = false;
        return true;
    }
    false
}

#[cfg(test)]
mod revoke_reply_tests {
    //! D356: the revoke reply always says what was checked, and fits a frame.
    use crate::access_files::{Access, AccountReport, Change, ChangeKind, State};

    /// A report far over the frame budget is cut to fit; lines go first,
    /// then not-scanned names, then whole files, which are counted, and the
    /// account says truncated. J334's hostile reply (P2-2): 300 not-scanned
    /// names of control characters and 400 big files cannot push out the
    /// planted key, which is the last thing trimmed. A report with nothing
    /// changed still carries its outcome.
    #[test]
    fn the_reply_fits_a_frame_and_counts_what_it_drops() {
        let file = |index: usize| Change {
            path: format!("~/.config/autostart/{index}.desktop"),
            change: ChangeKind::Added,
            lines: vec!["x".repeat(190); 4],
            note: None,
        };
        let mut files = vec![Change {
            path: "~/.ssh/authorized_keys".into(),
            change: ChangeKind::Added,
            lines: vec!["ssh-ed25519 AAAAplanted left-behind".into()],
            note: None,
        }];
        files.extend((0..400).map(file));
        let revoked = crate::logins::Revoked {
            background_may_remain: true,
            access: Access {
                state: State::Changed,
                reason: None,
                omitted_accounts: 3,
                accounts: vec![AccountReport {
                    account: "deploy".into(),
                    state: State::Changed,
                    files,
                    unscanned: (0..300).map(|_| "\u{fffd}".repeat(200)).collect(),
                    ..AccountReport::default()
                }],
            },
        };
        let bytes = super::revoke_reply(&revoked, true);
        assert!(bytes.len() <= super::REVOKE_REPLY_BUDGET);
        let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(reply["access"]["omitted_accounts"], 3);
        let account = &reply["access"]["accounts"][0];
        assert_eq!(account["truncated"], true);
        let listed = account["files"].as_array().unwrap().len();
        assert_eq!(
            listed + usize::try_from(account["omitted_files"].as_u64().unwrap()).unwrap(),
            401
        );
        assert_eq!(
            account["files"][0]["lines"][0], "ssh-ed25519 AAAAplanted left-behind",
            "the planted key was trimmed before less valuable files"
        );
        assert!(reply["warning"].is_string(), "D353's warning was dropped");
        let clean = super::revoke_reply(&crate::logins::Revoked::default(), true);
        let clean: serde_json::Value = serde_json::from_slice(&clean).unwrap();
        assert_eq!(clean["access"]["state"], "unchanged");
    }
    /// D398: a revoke that was not asked for a report (a host removal) sends
    /// none, and still carries the receipt and D353's warning.
    #[test]
    fn a_revoke_without_a_report_sends_only_the_receipt() {
        let revoked = crate::logins::Revoked {
            background_may_remain: true,
            ..crate::logins::Revoked::default()
        };
        let reply: serde_json::Value =
            serde_json::from_slice(&super::revoke_reply(&revoked, false)).unwrap();
        assert_eq!(reply["revoked"], true);
        assert!(reply.get("access").is_none(), "a report was sent: {reply}");
        assert!(reply["warning"].is_string());
        let asked: serde_json::Value =
            serde_json::from_slice(&super::revoke_reply(&revoked, true)).unwrap();
        assert!(asked.get("access").is_some());
    }
    /// D362 process evidence cannot overflow a reply or lose its warning during trimming.
    #[test]
    fn process_lists_fit_the_reply_without_claiming_shutdown() {
        use crate::access_files::{Access, AccountReport, Reason, State};
        let account = AccountReport {
            state: State::NotChecked,
            reason: Some(Reason::ProgramsMayRemain),
            programs_may_remain: true,
            processes: vec![format!("1234 {}", "w".repeat(64)); 64],
            ..AccountReport::default()
        };
        let revoked = crate::logins::Revoked {
            background_may_remain: true,
            access: Access {
                state: State::NotChecked,
                reason: Some(Reason::ProgramsMayRemain),
                omitted_accounts: 0,
                accounts: vec![account; 64],
            },
        };
        let bytes = super::revoke_reply(&revoked, true);
        assert!(bytes.len() <= super::REVOKE_REPLY_BUDGET);
        let reply: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            reply["access"]["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|account| account["programs_may_remain"] == true
                    && account["state"] == "not_checked")
        );
    }
}

/// Revoke or restore one person's terminals on its own task, after the first login operation has chosen a manager.
#[cold]
#[inline(never)]
fn spawn_revocation(
    state: PathBuf,
    manager: LoginManager,
    person: uuid::Uuid,
    restore: bool,
    report: bool,
    finished: oneshot::Sender<OpenResult>,
) -> tokio::task::JoinHandle<()> {
    use infraternal_plugin_api::admission::OpenRefusal;
    tokio::spawn(async move {
        let manager = Manager::resolve(&manager).await;
        let result = if restore {
            crate::logins::restore(&state, person)
                .await
                .map(|()| b"{\"restored\":true}".to_vec())
        } else {
            crate::logins::revoke_reporting(&state, manager, person, report)
                .await
                .map(|revoked| revoke_reply(&revoked, report))
        }
        .map(|json| Opened {
            session: None,
            json,
        })
        .map_err(|error| match error.kind() {
            io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput => OpenRefusal::Invalid,
            _ => OpenRefusal::ResourceUnavailable,
        });
        let _ = finished.send(result);
    })
}

/// Open `person`'s shell as `account` for mesh SSH [D235, D240], #221.
///
/// It goes through the browser terminal's ordered admission path:
/// account resolution, the login access check, the real login (PAM session,
/// environment, limits) and its fencing. The caller, the mesh SSH authority,
/// has already admitted exactly this person and account under its current
/// snapshot, so the grant here names only that account: a fallback to root
/// for an account that vanished in between is refused, never widened.
/// # Errors
/// Returns the same refusals as a browser terminal open.
pub async fn open_mesh_ssh_shell(
    state: &std::path::Path,
    person: uuid::Uuid,
    account: &str,
    cols: u16,
    rows: u16,
) -> io::Result<Session> {
    static MANAGER: tokio::sync::OnceCell<Manager> = tokio::sync::OnceCell::const_new();
    let exe = std::env::current_exe()?;
    let manager = Manager::resolve(&MANAGER).await;
    let input = Open {
        person: Some(person),
        account: Some(account.to_owned()),
        grant: Some(infraternal_plugin_api::login_access::LoginGrant {
            accounts: [account.to_owned()].into(),
            ..Default::default()
        }),
        readiness: false,
        uid: nix::unistd::Uid::effective().as_raw(),
        cols,
        rows,
    };
    open_requested(&exe, state, manager, input, false)
        .await?
        .session
        .ok_or_else(|| io::Error::other("login opened no session"))
}

/// Refuse a person's open unless their login access grant allows the account
/// this host resolved [D235, D319].
fn login_access_allows(
    grant: Option<&infraternal_plugin_api::login_access::LoginGrant>,
    user: &nix::unistd::User,
) -> io::Result<()> {
    let ordinary = infraternal_plugin_api::login_access::OrdinaryUids::host();
    if grant.is_some_and(|grant| grant.allows(&user.name, user.uid.as_raw(), ordinary)) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "no login access to this account",
        ))
    }
}

/// Apply trusted server authority, resolve the account and fence shell creation.
/// A positive login snapshot never clears a pending or persisted revocation.
async fn open_requested(
    exe: &std::path::Path,
    state: &std::path::Path,
    manager: Manager,
    input: Open,
    prepare: bool,
) -> io::Result<Opened> {
    if input.readiness {
        if prepare || input.person.is_some() || input.account.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "readiness cannot select a person login",
            ));
        }
        let session = sessions::launch_with_readiness(
            exe, state, manager, input.uid, input.cols, input.rows, true,
        )
        .await?;
        return Ok(Opened {
            json: serde_json::to_vec(&OpenReply {
                session_id: Some(uuid::Uuid::from_bytes(session.id)),
                ..OpenReply::default()
            })?,
            session: Some(session),
        });
    }
    let mut json = OpenReply::default();
    let (uid, endpoint) = if let Some(person) = input.person {
        let (user, fallback) = if let Some(account) = input.account.as_deref() {
            crate::logins::account(account)?
        } else {
            (
                nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(input.uid))
                    .map_err(io::Error::from)?
                    .ok_or_else(|| io::Error::other("login account absent"))?,
                false,
            )
        };
        // The account database here decides which account opens, including
        // D231's fallback to root, so the grant is checked against that
        // result, before any login unit exists for it.
        login_access_allows(input.grant.as_ref(), &user)?;
        // This trusted server request is the positive authority resync for
        // this person after startup. It never clears a pending/durable refusal;
        // a revoked remote host cannot obtain such a request from the server.
        crate::logins::synchronize(state, person)?;
        let endpoint = crate::logins::ensure(exe, state, manager, person, &user).await?;
        json.account = Some(user.name);
        json.fallback = Some(fallback);
        json.note = Some(if fallback {
            let mut note = String::from("No user ");
            note.push_str(input.account.as_deref().unwrap_or_default());
            note.push_str(" here, opened as root");
            note
        } else {
            String::new()
        });
        json.requested_account = Some(input.account);
        (user.uid.as_raw(), endpoint)
    } else {
        if prepare {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "login preparation requires a person",
            ));
        }
        (input.uid, None)
    };
    let group = match (endpoint.as_deref(), input.person) {
        (Some(endpoint), Some(person)) => {
            crate::logins::cgroup(endpoint, manager, person, uid).await?
        }
        _ => None,
    };
    let session = if prepare {
        json.prepared = Some(true);
        None
    } else {
        let session = if let Some(person) = input.person
            && endpoint.is_none()
            && !nix::unistd::Uid::effective().is_root()
        {
            crate::rootless_sessions::launch(
                exe, state, manager, person, uid, input.cols, input.rows,
            )
            .await?
        } else {
            sessions::launch_with_login(
                exe,
                state,
                manager,
                uid,
                input.cols,
                input.rows,
                endpoint.as_deref(),
                group
                    .as_ref()
                    .filter(|identity| !identity.group.as_os_str().is_empty())
                    .map(|identity| identity.group.as_path()),
                group.as_ref().map(|identity| identity.pid),
                group
                    .as_ref()
                    .and_then(|identity| identity.parent.as_ref().map(|parent| parent.pid)),
                group.as_ref().map(|identity| identity.process.as_ref()),
            )
            .await?
        };
        json.session_id = Some(uuid::Uuid::from_bytes(session.id));
        Some(session)
    };
    Ok(Opened {
        session,
        json: serde_json::to_vec(&json)?,
    })
}

async fn emit(tx: &mpsc::Sender<Message>, message: Message) -> io::Result<()> {
    tx.send(message)
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe.into())
}

/// Queue an already credit-approved raw frame without waiting on the shared writer FIFO.
///
/// When the FIFO is full, retain one frame in `staged`; the caller may read one more shim frame
/// into its bounded `pending` slot so acknowledgments and liveness replies stay live. A key
/// repaint may discard the staged frame, and then retracts it from the relay ledger
/// ([`relay::Output::retract`]): it was charged but is never sent. No caller may stage a second
/// frame.
/// # Errors
/// Returns `WouldBlock` if a frame is already staged, or `BrokenPipe` if the writer is closed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn queue_raw_output(
    tx: &mpsc::Sender<Message>,
    staged: &mut Option<Message>,
    stream: u32,
    seq: u64,
    bytes: Vec<u8>,
) -> io::Result<()> {
    if staged.is_some() {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    let message = Message::Shim(stream, Shim::Output(seq, bytes));
    match tx.try_send(message) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(message)) => {
            *staged = Some(message);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(io::ErrorKind::BrokenPipe.into()),
    }
}

/// Send the raw Output that [`queue_raw_output`] staged, if any, ahead of an
/// ordered message whose meaning depends on the bytes before it.
///
/// A staged frame is otherwise sent only from the relay's `reserve_owned`
/// select arm. An ordered message the relay awaits directly (`emit`) takes
/// the next free FIFO slot instead, so without this flush it overtakes the
/// staged bytes: a `ReplayComplete` names a cursor the client does not hold
/// yet, and an exit notice or Close ends the stream while the relay drops
/// the bytes (#477, J775). Call it before every replay completion, exit,
/// end, Close, snapshot-unavailable notice and attachment marker that can
/// follow staged output. Flushing waits for the same FIFO the next message
/// waits for anyway, so it adds no wait of its own.
/// # Errors
/// Returns `BrokenPipe` if the writer is closed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn flush_staged(tx: &mpsc::Sender<Message>, staged: &mut Option<Message>) -> io::Result<()> {
    match staged.take() {
        Some(message) => emit(tx, message).await,
        None => Ok(()),
    }
}

/// Keep the shim reader live while one raw Output waits for the shared writer.
///
/// The pending slot is the one-frame read-ahead bound beside `pending_bulk`.
/// Reading control replies in that slot keeps input acknowledgments and liveness
/// state moving while writer backpressure holds raw bytes. Once that slot is
/// occupied, stop reading until the pending frame is sent, retried, or replaced
/// by a key repaint.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn can_read_shim_frame(pending: Option<&Shim>, pending_bulk: Option<&Message>) -> bool {
    pending.is_none()
        && pending_bulk.is_none_or(|message| matches!(message, Message::Shim(_, Shim::Output(..))))
}

/// Queue a trusted key acknowledgment or repaint on the bounded writer priority lane.
async fn emit_priority(
    tx: &mpsc::Sender<PriorityMessage>,
    message: PriorityMessage,
) -> io::Result<()> {
    tx.send(message)
        .await
        .map_err(|_| io::ErrorKind::BrokenPipe.into())
}

/// Tell the writer this relay gave up its pending key repaint, so the raw output the key's
/// acknowledgment held is written in order (#477, J799).
///
/// Call it wherever a pending repaint ends without its Snapshot: the starvation timer, a shim
/// that cannot capture, and every exit or close. The relay's cursor already counts those bytes
/// as sent, so without it the client misses them and the next replay starts after a gap. It
/// rides the priority lane, so the writer applies it before anything this relay queues later.
/// With no key repaint pending there is nothing held and nothing is sent.
async fn release_key_cover(
    priority: &mpsc::Sender<PriorityMessage>,
    stream: u32,
    attachment: u64,
    key_repaint_target: Option<u64>,
) -> io::Result<()> {
    if key_repaint_target.is_none() {
        return Ok(());
    }
    emit_priority(priority, PriorityMessage::Release { stream, attachment }).await
}

/// The relay's next command: the client's next one, or raw output the writer dropped under a
/// key repaint, presented as the Credit the client can no longer send for it (#477, J799).
///
/// A refund is exactly a return of charged bytes, so it takes the same path as the client's
/// own Credit: it pays repaint debt first, then refills the reserve and the bulk window. Only
/// a relay whose reserve is ACTIVE sends key repaints, so a refund never lands in reserve
/// setup, where a grant's meaning is still being worked out. Cancel-safe, like both sources.
async fn next_command(
    commands: &mut session_commands::Receiver,
    refunds: &mut crate::daemon_writer::RefundReceiver,
) -> Option<Command> {
    tokio::select! {
        biased;
        command = commands.next() => command,
        bytes = refunds.next() => Some(Command::Credit(bytes)),
    }
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
pub async fn run(fd: i32, state: Option<PathBuf>) -> io::Result<()> {
    run_with_mesh_state(fd, state, None).await
}

/// Run the trusted embedded channel with separate session and Mesh state paths.
/// # Errors
/// Rejects an invalid fd, unsafe state, malformed wire requests and resource limits.
pub async fn run_with_mesh_state(
    fd: i32,
    state: Option<PathBuf>,
    mesh_state: Option<PathBuf>,
) -> io::Result<()> {
    // The launch isolation wrapper closes fd 3 before exec. Other inherited
    // descriptors need their own audited CLOEXEC boundary before being supported.
    if fd != 3 {
        return Err(sessions::invalid("embedded leg B requires fd 3"));
    }
    let socket = Socket::inherited(fd)?;
    let state = sessions::state(state)?;
    let service = match mesh_state.as_deref() {
        Some(mesh_state) => {
            crate::plugin_control::Service::start_with_mesh_state(&state, mesh_state).await?
        }
        None => {
            crate::plugin_control::Service::start(
                &state,
                crate::plugins::ExecutionMode::Embedded,
                None,
            )
            .await?
        }
    };
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
    installation: Option<&crate::plugins::Installation>,
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

/// Run the channel to its end, then give launch cleanups still in flight a bounded window to finish,
/// so a runtime that outlives this agent does not drop them half done.
async fn run_channel<const SESSION_ONLY: bool>(
    socket: &impl Channel,
    state: PathBuf,
    execution_uid: Option<u32>,
    renewal: Option<&RenewalIdentity>,
    plugins: Option<crate::plugin_control::Registry>,
    original: Option<Session>,
) -> io::Result<()> {
    // Boxed: the wrapper holds its arguments, and the loop's state would be counted again on top of
    // them inside every caller's future (clippy large_futures, already within bytes of its bound).
    // One allocation per channel run, in place of the same bytes inline.
    let result = Box::pin(run_channel_inner::<SESSION_ONLY>(
        socket,
        state,
        execution_uid,
        renewal,
        plugins,
        original,
    ))
    .await;
    if sessions::cleanups_pending() {
        // Boxed: the wait is rare, and its state must not grow every channel future.
        Box::pin(sessions::drain_cleanups()).await;
    }
    result
}

/// The channel loop itself, before the shutdown drain.
async fn run_channel_inner<const SESSION_ONLY: bool>(
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
    // An anonymous shim must execute directly. Root retains first-use host
    // backend detection; an inherited own-account context needs no probe.
    let anonymous = running
        .as_os_str()
        .as_encoded_bytes()
        .ends_with(b" (deleted)");
    // Detection is warmed in the background; only terminal.open awaits the
    // single result, so the authenticated greeting and census can proceed first.
    let manager = Arc::new(tokio::sync::OnceCell::<Manager>::new());
    let exe = if anonymous {
        manager
            .set(Manager::Detached)
            .map_err(|_| sessions::invalid("init manager was already selected"))?;
        PathBuf::from("/proc/self/exe")
    } else {
        if !SESSION_ONLY {
            let warm = manager.clone();
            tokio::spawn(async move {
                Manager::resolve(&warm).await;
            });
        }
        running
    };
    let mut login_manager_slot = if anonymous {
        anonymous_login_manager(nix::unistd::Uid::effective().is_root())
    } else {
        Some(manager.clone())
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
    let (priority, priority_rx) = mpsc::channel(PRIORITY_CAPACITY);
    #[cfg(test)]
    let control_observer = census_retry_tests::observer(&state);

    // Accepted access revocations own their cleanup independently of a leg-B
    // connection. Normal EOF drains them before an embedded reactor can exit;
    // cancellation drops join handles without aborting remote-service tasks.
    let mut revocations: Vec<tokio::task::JoinHandle<()>> = Vec::new();
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
        let mut terminal_ends = JoinSet::new();
        // A root upgrade's `privilege.*` calls have their own small lane, so
        // a stuck relay can never hold up certificate renewal or terminal
        // startup (J415 B4). Each call is also bounded in time. Builds
        // without root upgrades keep it empty, which masks its select arm.
        #[cfg_attr(not(all(feature = "remote", target_os = "linux")), allow(unused_mut))]
        let mut privileges: JoinSet<(
            u32,
            io::Result<infraternal_plugin_api::ActionReply>,
        )> = JoinSet::new();
        let mut opens: JoinSet<(
            u32,
            u32,
            Result<Opened, infraternal_plugin_api::admission::OpenRefusal>,
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
                        Err(error)=>reply(&control,Message::Result(0,call_id,false,error.control_error_json()))?,
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
                result = terminal_ends.join_next(), if !SESSION_ONLY && control_ready && !terminal_ends.is_empty() => {
                    let (call_id, status) = result.ok_or_else(|| sessions::invalid("missing terminal end task"))?.map_err(io::Error::other)?;
                    let json = match status {
                        Some(status) => serde_json::to_vec(&status)?,
                        None => b"{}".to_vec(),
                    };
                    reply(&control, Message::Result(0, call_id, status.is_some(), json))?;
                }
                result = join_privilege(&mut privileges), if !SESSION_ONLY && control_ready && !privileges.is_empty() => {
                    let (call_id, result) = result.ok_or_else(|| sessions::invalid("missing privilege task"))?.map_err(io::Error::other)?;
                    match result {
                        Ok(reply_value) => reply(&control, Message::Deferred(0, call_id, reply_value))?,
                        Err(_) => reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?,
                    }
                }
                result = opens.join_next(), if !SESSION_ONLY && control_ready && !opens.is_empty() => {
                    // The private image never starts these jobs. Keep their result
                    // handlers outside that monomorph as well as the select mask.
                    if SESSION_ONLY { return Err(sessions::invalid("session image cannot complete session launch")); }
                    let (stream, call_id, result) = result.ok_or_else(|| sessions::invalid("missing launch task"))?.map_err(io::Error::other)?;
                    match result {
                        Ok(opened) => {
                            if let Some(session) = opened.session {
                                registry.insert(&session)?;
                                if !publish_session_snapshot(&control, &registry, &mut published_sessions)? {
                                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "census reply queue full"));
                                }
                                census_pending = false;
                            }
                            reply(&control, Message::Result(stream, call_id, true, opened.json))?;
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
                        Frame::Call {call_id, action_id, input_json} if stream == 0 && matches!(action_id, "transport.csr" | "transport.certificate" | "transport.csr.rotate" | "transport.identity.rotate.certificate" | "transport.identity.rotate.ack") && renewal.is_some() => {
                            if !renewals.is_empty() || input_json.len() > infraternal_plugin_api::channel::MAX_CONTROL_JSON {
                                reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?;
                            } else {
                                let renewal = renewal.ok_or_else(|| sessions::invalid("missing renewal identity"))?.clone();
                                let action = action_id.to_owned(); let input = input_json.to_vec();
                                renewals.spawn_blocking(move || (call_id, renewal.action(&action, &input)));
                            }
                        }
                        Frame::Call {call_id, action_id: action @ ("terminal.login.revoke" | "terminal.login.restore"), input_json} if stream == 0 => {
                            use infraternal_plugin_api::admission::OpenRefusal;
                            let input = if input_json.len() <= infraternal_plugin_api::channel::MAX_CONTROL_JSON {
                                serde_json::from_slice::<RevokeLogin>(input_json).ok()
                            } else { None };
                            if let Some(input) = input {
                                // This action comes only from the trusted server control
                                // stream. Revocation must not depend on open admission or
                                // remaining resource quota, and keeps terminal dispatch live.
                                revocations.retain(|task| !task.is_finished());
                                let (finished, result) = tokio::sync::oneshot::channel();
                                revocations.push(spawn_revocation(state.clone(), login_manager(&mut login_manager_slot), input.person, action == "terminal.login.restore", input.report, finished));
                                opens.spawn(async move {
                                    (stream, call_id, result.await.unwrap_or(Err(OpenRefusal::ResourceUnavailable)))
                                });
                            } else {
                                reply(&control, Message::Result(stream, call_id, false, OpenRefusal::Invalid.json()?))?;
                            }
                        }
                        Frame::Call {call_id, action_id: action @ ("terminal.open" | "terminal.login.prepare"), input_json} if !SESSION_ONLY && plugins.is_some() && (execution_uid.is_none() || stream == 0) => {
                            use infraternal_plugin_api::admission::OpenRefusal;
                            registry.refresh();
                            census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                            let input = if input_json.len() <= infraternal_plugin_api::channel::MAX_CONTROL_JSON { serde_json::from_slice::<Open>(input_json).ok() } else { None };
                            if let Some(input) = input && execution_uid.is_none_or(|uid| input.uid == uid)
                                && (nix::unistd::Uid::effective().is_root() || input.uid == nix::unistd::Uid::effective().as_raw())
                                && input.cols > 0 && input.rows > 0 && usize::from(input.cols) * usize::from(input.rows) <= 200_000 {
                                // Waiting for plugin admission never parks terminal dispatch.
                                let manager = if input.person.is_some() || action == "terminal.login.prepare" {
                                    login_manager(&mut login_manager_slot)
                                } else {
                                    manager.clone()
                                };
                                spawn_open(&mut opens, stream, call_id, OpenTask {
                                    exe: exe.clone(), state: state.clone(), manager, input,
                                    prepare: action == "terminal.login.prepare",
                                    plugins: plugins.clone().ok_or_else(|| sessions::invalid("missing node registry"))?,
                                    context: registry.context(),
                                });
                            } else {
                                reply(&control, Message::Result(stream, call_id, false, OpenRefusal::Invalid.json()?))?;
                            }
                        }
                        // A root upgrade (D376, #399): only from the server's control
                        // stream, outside the one-at-a-time plugin worker, because an
                        // elevation takes seconds and the relay carries the payload.
                        #[cfg(all(feature = "remote", target_os = "linux"))]
                        Frame::Call {call_id, action_id, input_json} if !SESSION_ONLY && stream == 0 && crate::privilege_agent::ACTIONS.contains(&action_id) => {
                            if input_json.len() > 2 * 1024 * 1024 || privileges.len() >= crate::privilege_agent::LANE {
                                reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?;
                            } else {
                                let action = action_id.to_owned(); let state = state.clone(); let input = input_json.to_vec();
                                privileges.spawn(async move {
                                    let bound = if action == "privilege.abandon" {
                                        crate::privilege_agent::ABANDON_CALL_BOUND
                                    } else {
                                        crate::privilege_agent::CALL_BOUND
                                    };
                                    let result = tokio::time::timeout(bound, crate::privilege_agent::execute(&action, &input, &state)).await;
                                    (call_id, result.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into())))
                                });
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
                        Frame::Call {call_id, action_id: "terminal.end", input_json} if !SESSION_ONLY && stream == 0 => {
                            // Leg A resolves ownership and routing before asking this trusted host link.
                            if input_json.len() == 36 + 2 && terminal_ends.len() < MAX_ENDING_TERMINALS
                                && let Ok(id) = serde_json::from_slice::<uuid::Uuid>(input_json)
                            {
                                let id = id.into_bytes();
                                let path = registry.get(&id).cloned().unwrap_or_else(|| sessions::rendezvous(&state, id));
                                terminal_ends.spawn(async move {
                                    let status = tokio::time::timeout(
                                        TERMINAL_END_TIMEOUT,
                                        sessions::end_terminal(path, id),
                                    ).await.ok().and_then(Result::ok);
                                    (call_id, status)
                                });
                            } else {
                                reply(&control, Message::Result(0, call_id, false, b"{}".to_vec()))?;
                            }
                        }
                        Frame::Call {call_id, action_id, input_json} if !SESSION_ONLY && plugin_calls.is_some() && stream == 0 => {
                            let plugin_calls = plugin_calls.as_mut().ok_or_else(|| sessions::invalid("missing node control"))?;
                            registry.refresh();
                            census_pending = !publish_session_snapshot(&control, &registry, &mut published_sessions)?;
                            match plugin_calls.start(call_id, action_id, input_json, registry.context()) {
                                Ok(Some(result)) => reply(&control, Message::Deferred(0, call_id, result))?,
                                Ok(None) => {},
                                Err(error) => reply(&control, Message::Result(0, call_id, false, error.control_error_json()))?,
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
                            if streams.contains_key(&stream) {
                                return Err(sessions::invalid("terminal stream already attached"));
                            }
                            // A full link refuses this one stream at once and keeps
                            // its siblings: the server turns the Close into a plain
                            // sentence for the person (#562).
                            if streams.len() >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS {
                                reply(&control, Message::Close(stream, "terminal stream limit"))?;
                                continue;
                            }
                            // The registry only caches shims this process has seen. A miss is not
                            // proof of death, and never a reason to drop every sibling stream: the
                            // rendezvous derives from the id alone, and `terminal` answers a final
                            // Close when no shim listens there (#158).
                            let path = registry.get(session_id).cloned().unwrap_or_else(|| sessions::rendezvous(&state, *session_id));
                            let id = *session_id;
                            let (commands, rx) = session_commands::channel();
                            let (cancel, cancelled) = oneshot::channel();
                            streams.insert(stream, Stream { commands, cancel });
                            let tx = tx.clone();
                            let forget = tx.clone();
                            let priority = priority.clone();
                            jobs.spawn(async move {
                                let result = tokio::select! {
                                    // Cancellation first: retiring a stream also drops its
                                    // command sender, which can end the relay in the same
                                    // poll and would otherwise skip the Forget.
                                    biased;
                                    floor = cancelled => match floor {
                                        // Ordered after the dropped relay's queued output, so
                                        // its marker cannot re-create the state (#477, J730 P3).
                                        Ok(floor) => emit(&forget, Message::Forget(stream, floor)).await,
                                        // Dispatch itself ended: the writer goes with it.
                                        Err(_) => Ok(()),
                                    },
                                    result = terminal_with_priority(path, id, stream, last_out_seq, last_in_seq, rx, tx, priority) => result,
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
                                    if let Some(entry) = streams.remove(&stream) {
                                        entry.retire(&control, stream);
                                    }
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
                                if let Some(entry) = streams.remove(&stream) {
                                    entry.retire(&control, stream);
                                }
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
    let result = tokio::select! {
        result = dispatch => result,
        result = writer(
            socket,
            rx,
            Some(control_rx),
            Some(priority_rx),
            true,
            renewal.is_some(),
            crate::daemon_writer::supports_identity_rotation(renewal),
            wire_caps,
        ) => result,
    };
    for revocation in revocations {
        let _ = revocation.await;
    }
    result
}

/// Run one authenticated, capability-bound native terminal using the common shim relay.
/// The connection supervisor must cancel this future when server authority is lost;
/// this function never opens a PTY, accepts a Call or creates its own writer identity.
/// # Errors
/// Refuses missing/reserved binding, a missing bounded `AttachTerm`, unknown shim,
/// malformed post-attachment traffic and overload. Returning never stops the shim.
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

/// Serve a channel bound to one terminal session, as a remote terminal attach uses.
#[cfg(feature = "remote")]
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
    let (priority, priority_rx) = mpsc::channel(PRIORITY_CAPACITY);
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
    let writer = writer(channel, rx, None, Some(priority_rx), false, false, false, 0);
    tokio::pin!(writer);
    tokio::select! {
        result = dispatch => result,
        result = &mut writer => result,
        result = terminal_mode(path, id, writer_id, cursor, input, session_commands::Receiver::Native(command_rx), tx, priority, primed) => {
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
    /// Read the next shim frame, refusing frames of a capability this link did
    /// not select (approximate Snapshots, echo state) as a protocol error.
    async fn read(&mut self) -> io::Result<Shim> {
        let frame = self.reader.read(&mut self.session.peer).await?;
        if matches!(frame, Shim::SnapshotWithFlags(..))
            && self.session.caps & APPROXIMATE_SNAPSHOT == 0
        {
            return Err(sessions::invalid("unnegotiated approximate Snapshot"));
        }
        if matches!(frame, Shim::EchoState(..))
            && self.session.caps & infraternal_shim::frame::ECHO_STATE == 0
        {
            return Err(sessions::invalid("unnegotiated echo state"));
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
async fn terminal_with_priority(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
    priority: mpsc::Sender<PriorityMessage>,
) -> io::Result<()> {
    terminal_mode(
        path, id, stream, cursor, last_input, commands, tx, priority, false,
    )
    .await
}

/// Preserve existing terminal fixtures while collecting priority replies into their FIFO.
#[cfg(test)]
async fn terminal(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
) -> io::Result<()> {
    let (priority, mut priority_rx) = mpsc::channel(PRIORITY_CAPACITY);
    let forwarded = tx.clone();
    let collector = tokio::spawn(async move {
        while let Some(message) = priority_rx.recv().await {
            match message {
                PriorityMessage::InputAck { stream, seq, .. } => {
                    emit(&forwarded, Message::Shim(stream, Shim::InputAck(seq))).await?;
                }
                PriorityMessage::Snapshot {
                    stream,
                    seq,
                    bytes,
                    approximate,
                    notice,
                    ..
                } => {
                    if let Some(notice) = notice {
                        emit(&forwarded, Message::Event(stream, notice)).await?;
                    }
                    let frame = if approximate {
                        Shim::SnapshotWithFlags(seq, 1, bytes)
                    } else {
                        Shim::Snapshot(seq, bytes)
                    };
                    emit(&forwarded, Message::Shim(stream, frame)).await?;
                }
                // Nothing is held without a real writer.
                PriorityMessage::Release { .. } => {}
            }
        }
        Ok::<(), io::Error>(())
    });
    let result =
        terminal_with_priority(path, id, stream, cursor, last_input, commands, tx, priority).await;
    collector.await.map_err(io::Error::other)??;
    result
}

/// Relay one terminal stream (see `terminal_run`), and when the relay fails, report the
/// session's saved exit if it has one.
///
/// Before that report, a failed relay releases any raw output a key's acknowledgment still
/// holds in the writer (#477, J813). Every way the relay's loop ends a pending key repaint on
/// purpose sends its own release, but an error can end the loop anywhere: a shim reply it did
/// not ask for, or a write to a shim that has just gone. Those held bytes were charged and the
/// relay's cursor counts them, so without the release they would never reach the client, and
/// the exit reported next would claim output the client never got. A release that finds
/// nothing held writes nothing, so it is sent unconditionally.
async fn terminal_mode(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
    priority: mpsc::Sender<PriorityMessage>,
    primed: bool,
) -> io::Result<()> {
    let mut attachment = 0;
    let release = priority.clone();
    let result = terminal_run(
        path.clone(),
        id,
        stream,
        cursor,
        last_input,
        commands,
        tx.clone(),
        priority,
        primed,
        &mut attachment,
    )
    .await;
    if result.is_err() {
        // The writer may be gone too; then there is nobody left to deliver to.
        let _ = emit_priority(&release, PriorityMessage::Release { stream, attachment }).await;
    }
    // A bound terminal's writer stops taking priority messages once every sender is gone.
    drop(release);
    match result {
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

/// The relay loop of one terminal stream: shim output to the writer under the client's credit,
/// client commands to the shim. `announced` tracks the attachment it last announced to the
/// writer (see `terminal_mode`).
async fn terminal_run(
    path: PathBuf,
    id: [u8; 16],
    stream: u32,
    cursor: u64,
    last_input: u64,
    mut commands: session_commands::Receiver,
    tx: mpsc::Sender<Message>,
    priority: mpsc::Sender<PriorityMessage>,
    primed: bool,
    announced: &mut u64,
) -> io::Result<()> {
    // Announce this attachment before any of its frames. The writer then stops
    // trimming this stream's output by repaints of an earlier attachment that
    // reused the stream id (a resumed browser), and ignores that attachment's
    // late priority frames (#477). `announced` always holds the latest one, so
    // `terminal_mode` can release what it holds if this relay fails.
    #[cfg_attr(not(feature = "remote"), allow(unused_mut))]
    let mut attachment = crate::daemon_writer::next_attachment();
    *announced = attachment;
    // Raw bytes of this attachment that the writer drops under a key repaint
    // come back here as credit (#477, J799).
    let (refund_cell, mut refunds) = crate::daemon_writer::refunds();
    emit(&tx, Message::Attached(stream, attachment, refund_cell)).await?;
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
    let mut output = relay::Output::attach_with_repaint_reserve(cursor);
    if replay_until.is_some_and(|fence| output.cursor() >= fence) {
        replay_complete(&tx, stream, id, output.cursor(), replay_size).await?;
        replay_until = None;
    }
    let mut pending: Option<Shim> = None;
    // One credit-charged Output may wait here if the shared writer FIFO is full.
    // Invariant: it reaches the writer before any ordered message emitted
    // after it was staged (see `flush_staged`), unless a key repaint
    // discards it on purpose and retracts it from the ledger.
    let mut pending_bulk: Option<Message> = None;
    let mut deadline = None;
    // The latest input offset a repaint must show, and the offset covered by
    // the one SnapshotRequest already sent to the shim, if any.
    let mut key_repaint_target: Option<u64> = None;
    let mut key_repaint_requested: Option<u64> = None;
    let mut key_repaint_ready_at: Option<Instant> = None;
    let mut key_repaint_ready = false;
    let mut capture_deadline = None;
    // A canceled write may have sent a frame prefix. Keep the complete command
    // for the fresh link, which starts at a frame boundary.
    let mut retry_shim_write = None;
    // The shim may confirm input while the priority lane cannot accept its Ack.
    let mut unpublished_ack = None;
    let mut finished_peer = false;
    // One state fence in flight bounds shim work even if probes are pipelined over the network.
    // It belongs to the data socket: parking that socket must clear its pending fence.
    let mut probe = None;
    let mut reply_unavailable_announced = false;
    'relay: loop {
        // A branch can await a writer slot or a shim write after the main
        // select has picked it. Race those waits against this same deadline.
        macro_rules! capture_io {
            ($operation:expr $(, $on_expiry:expr)?) => {
                match during_key_capture(capture_deadline, $operation).await {
                    Some(result) => result,
                    None => {
                        $( $on_expiry; )?
                        continue 'relay;
                    }
                }
            };
        }

        if capture_deadline.is_some_and(|end| Instant::now() >= end) {
            // Close before waiting for writer capacity. Release makes already
            // queued raw bytes deliverable, so recovery can continue from the
            // cursor that includes them. An unqueued Snapshot never moves it.
            session = None;
            probe = None;
            pending = None;
            output.abandon_repaint();
            capture_deadline = None;
            key_repaint_ready_at = None;
            key_repaint_ready = false;
            key_repaint_requested = None;
            release_key_cover(&priority, stream, attachment, key_repaint_target.take()).await?;
            if let Some(seq) = unpublished_ack.take()
                && seq > acknowledged
            {
                input_progress(&tx, stream, &mut acknowledged, seq).await?;
            }
        }
        if pending_bulk.is_none()
            && let Some(frame) = pending.take()
        {
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
                            queue_raw_output(
                                &tx,
                                &mut pending_bulk,
                                stream,
                                output.cursor(),
                                bytes,
                            )?;
                            output
                                .forward(length)
                                .map_err(|_| sessions::invalid("output credit invariant"))?;
                            if replay_until.is_some_and(|fence| output.cursor() >= fence) {
                                flush_staged(&tx, &mut pending_bulk).await?;
                                replay_complete(&tx, stream, id, output.cursor(), replay_size)
                                    .await?;
                                replay_until = None;
                            }
                            continue;
                        }
                        queue_raw_output(
                            &tx,
                            &mut pending_bulk,
                            stream,
                            output.cursor(),
                            bytes[range.start..end].to_vec(),
                        )?;
                        output
                            .forward(length)
                            .map_err(|_| sessions::invalid("output credit invariant"))?;
                    }
                    if replay_until.is_some_and(|fence| output.cursor() >= fence) {
                        flush_staged(&tx, &mut pending_bulk).await?;
                        replay_complete(&tx, stream, id, output.cursor(), replay_size).await?;
                        replay_until = None;
                    }
                    if end < frame_len {
                        pending = Some(Shim::Output(seq, bytes));
                        deadline = output
                            .pending(Instant::now().into_std())
                            .map(Instant::from_std);
                        // This relay stops reading the shim while a frame is
                        // pending, and re-enters `pending` only at the top of
                        // this loop. After a pass that forwarded bytes, the remainder
                        // may be affordable at once: the replay fence that
                        // limited this pass is gone, or credit remains. Waiting
                        // for the select below would leave it parked until an
                        // unrelated command arrives (#324). A pass that forwarded
                        // nothing is credit-starved, has armed `deadline`, and
                        // must wait; looping there would spin. Each repeat
                        // consumes at least one byte of a finite frame.
                        if length > 0 {
                            continue;
                        }
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
                    // A capture that raced ahead of the key's InputAck cannot
                    // prove that it contains the echo, so discard it.
                    if key_repaint_target.is_some() && key_repaint_requested.is_none() {
                        continue;
                    }
                    let reserved = key_repaint_requested.is_some();
                    // Preserve the delivered cursor and charged credit if
                    // expiry cancels a reserved Snapshot's writer admission.
                    let mut next_output = output.clone();
                    let repainted = if reserved {
                        next_output.repaint_reserved(seq, length)
                    } else {
                        next_output.repaint(seq, length)
                    };
                    if repainted.is_ok() {
                        deadline = None;
                        let notice = if approximate {
                            Some(
                                terminal_events::Notice::Snapshot {
                                    session_id: uuid::Uuid::from_bytes(id),
                                    seq,
                                    approximate: true,
                                }
                                .json()?,
                            )
                        } else {
                            None
                        };
                        if reserved {
                            let (Shim::Snapshot(_, bytes) | Shim::SnapshotWithFlags(_, _, bytes)) =
                                frame
                            else {
                                return Err(sessions::invalid("invalid key repaint Snapshot"));
                            };
                            let permit = capture_io!(priority.reserve())
                                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                            permit.send(PriorityMessage::Snapshot {
                                stream,
                                attachment,
                                seq,
                                bytes,
                                approximate,
                                notice,
                            });
                        } else {
                            if let Some(notice) = notice {
                                emit(&tx, Message::Event(stream, notice)).await?;
                            }
                            emit(&tx, Message::Shim(stream, frame)).await?;
                        }
                        output = next_output;
                        if let Some(requested) = key_repaint_requested.take()
                            && key_repaint_target.is_some_and(|target| target <= requested)
                        {
                            capture_deadline = None;
                            key_repaint_target = None;
                            key_repaint_ready_at = None;
                            key_repaint_ready = false;
                        }
                        if replay_until.is_some_and(|fence| seq >= fence) {
                            // Repaint bytes contain state through seq, so the
                            // ordered completion event uses the repaint cursor.
                            capture_io!(replay_complete(&tx, stream, id, seq, replay_size))?;
                            replay_until = None;
                        }
                        capture_io!(request_key_repaint_if_ready(
                            &mut session,
                            key_repaint_target,
                            &mut key_repaint_requested,
                            acknowledged,
                            output.repaint_budget(),
                            &mut key_repaint_ready,
                            finished_peer,
                        ))?;
                    } else {
                        output = next_output;
                        pending = Some(frame);
                        if !reserved {
                            deadline = output
                                .pending(Instant::now().into_std())
                                .map(Instant::from_std);
                        }
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
        if session.is_none() && (output.needs_snapshot() || retry_shim_write.is_some()) {
            // The relink may end the stream, and the replay it restarts
            // continues after the staged bytes.
            flush_staged(&tx, &mut pending_bulk).await?;
            let Some(mut next) = relink(&path, id, stream, &tx, primed).await? else {
                return Ok(());
            };
            let written = input_state(&mut next).await?;
            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
            acknowledged = acknowledged.max(written);
            if let Some(frame) = retry_shim_write.take() {
                next.send(&frame).await?;
                let written = input_state(&mut next).await?;
                input_progress(&tx, stream, &mut acknowledged, written).await?;
                if !output.needs_snapshot() {
                    continue;
                }
            }
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
                release_key_cover(&priority, stream, attachment, key_repaint_target).await?;
                flush_staged(&tx, &mut pending_bulk).await?;
                if recorded_end(&path, id, stream, &tx).await? {
                    return Ok(());
                }
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            command = next_command(&mut commands, &mut refunds) => {
                let Some(command) = command else { return Ok(()); };
                match command {
                    Command::Credit(bytes) => {
                        output.grant(bytes).map_err(|_| sessions::invalid("credit overflow"))?;
                        if session.is_none() && bytes > 0 {
                            output.retry_recovery();
                        }
                        capture_io!(request_key_repaint_if_ready(
                            &mut session,
                            key_repaint_target,
                            &mut key_repaint_requested,
                            acknowledged,
                            output.repaint_budget(),
                            &mut key_repaint_ready,
                            finished_peer,
                        ))?;
                        deadline = None;
                    }
                    _ if finished_peer => {}
                    #[cfg(feature = "remote")]
                    Command::Cursor(cursor) if primed => {
                        // The server alone knows which output reached leg A.
                        // Reset only this shadow relay, before its ordered Credit;
                        // already queued duplicates remain bounded and are trimmed
                        // by the server rather than charged to browser credit again.
                        // The marker below ends the old attachment's cover.
                        // An in-flight capture on its shim cannot answer this replay.
                        if capture_deadline.take().is_some() {
                            session = None;
                            probe = None;
                        }
                        output.reset_cursor(cursor);
                        // The rewind starts a new replay below any cursor an
                        // earlier key repaint covered: scope it afresh (#477).
                        attachment = crate::daemon_writer::next_attachment();
                        *announced = attachment;
                        // The server's reissued credit already excludes
                        // anything the writer drops from before the rewind,
                        // so only the new ledger takes refunds.
                        let (refund_cell, next_refunds) = crate::daemon_writer::refunds();
                        refunds = next_refunds;
                        // Output the old attachment staged belongs before
                        // the marker, where the writer may still trim it.
                        flush_staged(&tx, &mut pending_bulk).await?;
                        emit(&tx, Message::Attached(stream, attachment, refund_cell)).await?;
                        pending = None;
                        deadline = None;
                        key_repaint_target = None;
                        key_repaint_requested = None;
                        key_repaint_ready_at = None;
                        key_repaint_ready = false;
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
                            flush_staged(&tx, &mut pending_bulk).await?;
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
                                    let frame = Shim::QueryReply(bytes);
                                    capture_io!(peer.send(&frame), retry_shim_write = Some(frame))?;
                                } else if !reply_unavailable_announced {
                                    reply_unavailable_announced = true;
                                    let json = terminal_events::Notice::QueryRepliesUnavailable { session_id: uuid::Uuid::from_bytes(id) }.json()?;
                                    capture_io!(emit(&tx, Message::Event(stream, json)))?;
                                }
                            }
                            Command::Input(seq, bytes) => {
                                if !bytes.is_empty() {
                                    // A small prior write is not a blocked flood;
                                    // this also catches a key just before bulk credit runs out.
                                    let output_waiting = output_waiting_for_key_repaint(
                                        pending.as_ref(),
                                        pending_bulk.as_ref(),
                                        &output,
                                    );
                                    if key_repaint_target.is_some()
                                        || (output_waiting && output.repaint_budget() > 0)
                                    {
                                        let length = u64::try_from(bytes.len())
                                            .map_err(|_| sessions::invalid("input length overflow"))?;
                                        let target = seq
                                            .checked_add(length)
                                            .ok_or_else(|| sessions::invalid("input sequence overflow"))?;
                                        if output_waiting && key_repaint_target.is_none() {
                                            // This stream is starved even when
                                            // its next frame has not been read.
                                            // Discard only this stream's pending
                                            // raw payload so the repaint replaces it.
                                            pending = None;
                                            // The staged frame was charged but is
                                            // never sent: give its credit and
                                            // cursor back, or the window shrinks
                                            // for good and a recovery that skips
                                            // the repaint resumes after a gap
                                            // (#477, J794).
                                            if let Some(Message::Shim(_, Shim::Output(seq, bytes))) = pending_bulk.take() {
                                                output
                                                    .retract(seq, bytes.len())
                                                    .map_err(|_| sessions::invalid("output credit invariant"))?;
                                            }
                                            // The old bulk timer no longer has a
                                            // frame to protect. Credit grants do
                                            // not change the capture's deadline.
                                            deadline = None;
                                            capture_deadline = Some(Instant::now() + relay::STARVATION);
                                        }
                                        key_repaint_target = Some(
                                            key_repaint_target.map_or(target, |seen| seen.max(target)),
                                        );
                                    }
                                }
                                let frame = Shim::SequencedInput(seq, bytes);
                                capture_io!(peer.send(&frame), retry_shim_write = Some(frame))?;
                            }
                            Command::Resize(cols, rows, px_w, px_h) => {
                                let frame = Shim::Resize {cols, rows, px_w, px_h};
                                capture_io!(peer.send(&frame), retry_shim_write = Some(frame))?;
                            }
                            Command::Ping(nonce, sent_us) => {
                                if detached {
                                    // The preceding relink/state exchange crossed this shim, even when output is parked.
                                    emit(&tx, Message::Pong(stream, nonce, sent_us)).await?;
                                    session = None; probe = None;
                                    continue;
                                }
                                // A frame held for client credit means this relay is not
                                // reading the shim, so its state reply could not be read
                                // until the 250 ms starvation recovery, which can exceed
                                // the server's route budget under a flood (#477). The
                                // agent is alive and answering, and a shim that has
                                // closed still takes the fenced path below.
                                if pending.is_some()
                                    && probe.is_none()
                                    && !peer.read_closed().await?
                                {
                                    capture_io!(emit(&tx, Message::Pong(stream, nonce, sent_us)))?;
                                    continue;
                                }
                                if probe.is_none() {
                                    capture_io!(peer.send(&Shim::InputStateRequest))?;
                                    probe = Some((nonce, sent_us));
                                }
                            }
                            Command::Credit(_) => return Err(sessions::invalid("unexpected credit dispatch")),
                            #[cfg(feature = "remote")]
                            Command::Cursor(_) => return Err(sessions::invalid("unnegotiated terminal cursor")),
                        }
                        if detached && key_repaint_target.is_none() {
                            // Reconnecting the same writer can supersede
                            // this socket before it reads an already-written
                            // command. An ordered State reply proves input was
                            // accepted (or resize handled) before peer loss;
                            // accepted input survives until the PTY writes it.
                            // A key-triggered repaint keeps this replacement
                            // link until its SnapshotRequest and capture finish.
                            let written = input_state(peer).await?;
                            emit(&tx, Message::Shim(stream, Shim::InputAck(written))).await?;
                            acknowledged = acknowledged.max(written);
                            session = None; probe = None;
                            output.retry_recovery();
                        }
                    }
                }
            }
            permit = tx.clone().reserve_owned(), if pending_bulk.is_some() => {
                let permit = permit.map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
                let message = pending_bulk
                    .take()
                    .ok_or_else(|| sessions::invalid("missing staged raw output"))?;
                permit.send(message);
            }
            () = async {
                if let Some(ready_at) = key_repaint_ready_at {
                    tokio::time::sleep_until(ready_at).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                key_repaint_ready_at = None;
                key_repaint_ready = true;
                capture_io!(request_key_repaint_if_ready(
                    &mut session,
                    key_repaint_target,
                    &mut key_repaint_requested,
                    acknowledged,
                    output.repaint_budget(),
                    &mut key_repaint_ready,
                    finished_peer,
                ))?;
            }
            () = async {
                if let Some(end) = capture_deadline {
                    tokio::time::sleep_until(end).await;
                }
            }, if capture_deadline.is_some() => {},
            () = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; } else { std::future::pending::<()>().await; } } => {
                finished_peer = match session.as_ref() {
                    Some(peer) => peer.read_closed().await?,
                    None => false,
                };
                if !finished_peer {
                    output.expire(Instant::now().into_std());
                    session = None;
                    probe = None;
                    pending = None;
                }
                deadline = None;
            }
            frame = async {
                if let Some(session) = &mut session { session.read().await }
                else { std::future::pending().await }
            }, if can_read_shim_frame(pending.as_ref(), pending_bulk.as_ref()) => {
                let frame = match frame {
                    Ok(frame) => frame,
                    Err(error) => {
                        // The link failed, but bytes the shim sent before it are
                        // good and already charged: deliver them ahead of the
                        // saved exit `terminal_mode` reports next (#477, J799).
                        release_key_cover(&priority, stream, attachment, key_repaint_target).await?;
                        flush_staged(&tx, &mut pending_bulk).await?;
                        return Err(error);
                    }
                };
                match frame {
                    Shim::Output(..) if key_repaint_target.is_some() => {}
                    Shim::Snapshot(..) | Shim::SnapshotWithFlags(..)
                        if key_repaint_target.is_some() && key_repaint_requested.is_none() => {}
                    frame @ (Shim::Output(..) | Shim::Snapshot(..) | Shim::SnapshotWithFlags(..)) => pending = Some(frame),
                    reply @ (Shim::InputAck(_) | Shim::InputState(..)) => {
                        let (seq, is_ack) = match reply {
                            Shim::InputAck(seq) => (seq, true),
                            Shim::InputState(written, accepted) if written <= accepted && probe.is_some() => {
                                if written < acknowledged {
                                    return Err(sessions::invalid("shim input cursor regressed"));
                                }
                                (written, false)
                            }
                            _ => return Err(sessions::invalid("unexpected shim relay frame")),
                        };
                        let advanced = capture_io!(forward_input_confirmation(
                            &tx,
                            &priority,
                            stream,
                            attachment,
                            seq,
                            output.cursor(),
                            key_repaint_target.is_some(),
                            is_ack,
                            &mut acknowledged,
                        ), unpublished_ack = Some(seq))?;
                        if key_repaint_grace_due(
                            key_repaint_target,
                            key_repaint_requested,
                            seq,
                            advanced,
                            key_repaint_ready,
                            key_repaint_ready_at.is_some(),
                        ) {
                            key_repaint_ready_at =
                                Some(Instant::now() + KEY_REPAINT_GRACE);
                            key_repaint_ready = false;
                        }
                        capture_io!(request_key_repaint_if_ready(
                            &mut session,
                            key_repaint_target,
                            &mut key_repaint_requested,
                            acknowledged,
                            output.repaint_budget(),
                            &mut key_repaint_ready,
                            finished_peer,
                        ))?;
                        // A state reply also answers the route proof that asked for it.
                        if !is_ack {
                            let (nonce, sent_us) = probe.take().ok_or_else(|| sessions::invalid("missing liveness fence"))?;
                            capture_io!(emit(&tx, Message::Pong(stream, nonce, sent_us)))?;
                        }
                    }
                    Shim::EchoState(seq, flags) => {
                        // A state, not a cursor fence: it may pass output held
                        // for credit, so a prompt's report is never late (#569).
                        let json = terminal_events::Notice::Echo {
                            session_id: uuid::Uuid::from_bytes(id),
                            seq,
                            hidden: flags & infraternal_shim::frame::ECHO_HIDDEN != 0,
                        }.json()?;
                        emit(&tx, Message::Event(stream, json)).await?;
                    }
                    Shim::Exited(status, final_seq) => {
                        release_key_cover(&priority, stream, attachment, key_repaint_target).await?;
                        flush_staged(&tx, &mut pending_bulk).await?;
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
                        // The notice's seq already counts the staged bytes,
                        // and the bytes the key's Ack passed.
                        session = None;
                        probe = None;
                        capture_deadline = None;
                        key_repaint_requested = None;
                        key_repaint_ready_at = None;
                        key_repaint_ready = false;
                        release_key_cover(&priority, stream, attachment, key_repaint_target.take()).await?;
                        flush_staged(&tx, &mut pending_bulk).await?;
                        emit(&tx, Message::Event(stream, json)).await?;
                    }
                    Shim::Error(..) => {
                        release_key_cover(&priority, stream, attachment, key_repaint_target).await?;
                        flush_staged(&tx, &mut pending_bulk).await?;
                        emit(&tx, Message::Close(stream, "shim refused terminal request")).await?;
                        return Ok(());
                    }
                    _ => return Err(sessions::invalid("unexpected shim relay frame")),
                }
            }
        }
    }
}

#[cfg(all(test, feature = "remote", target_os = "linux"))]
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

/// Exercise bounded, input-triggered repaint ordering with real shim sockets.
#[cfg(test)]
#[path = "daemon_key_repaint_tests.rs"]
mod key_repaint_tests;

#[cfg(test)]
#[path = "daemon_replay_fence_tests.rs"]
mod replay_fence_tests;

/// Staged raw output survives the end of its shim link (#477).
#[cfg(test)]
#[path = "daemon_link_end_tests.rs"]
mod link_end_tests;

/// A relay and the real writer together: output a key repaint passes keeps its credit and order.
#[cfg(test)]
#[path = "daemon_writer_credit_tests.rs"]
mod writer_credit_tests;

/// A server Close leaves no per-stream state in the shared writer (#477).
#[cfg(test)]
#[path = "daemon_close_forget_tests.rs"]
mod close_forget_tests;

#[cfg(all(test, target_os = "linux"))]
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

/// The next finished `privilege.*` call. On builds without root upgrades
/// the lane stays empty, so its select arm is always masked off.
async fn join_privilege(
    privileges: &mut JoinSet<(u32, io::Result<infraternal_plugin_api::ActionReply>)>,
) -> Option<Result<(u32, io::Result<infraternal_plugin_api::ActionReply>), tokio::task::JoinError>>
{
    privileges.join_next().await
}
