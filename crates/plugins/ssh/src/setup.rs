//! Retains host-bound D255 setup progress independently of wizard sockets, with bounded replay and no idle task.
//!
//! While a host is being set up, the worker reports progress through
//! [`Status`]. A browser can disconnect and later reconnect, so each host keeps
//! its last 16 events and the latest event of each stage. A client that asks for
//! events after a cursor that has already been dropped is told to resync and
//! receives the current state of every stage instead. Every call is bound to an
//! owner id: a different person can neither read nor change another's host.
//! Events carry only fixed, safe messages, never output from the remote host.

use crate::model::{Failure, InstallStep};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};
use tokio::sync::watch;
use uuid::Uuid;

/// Remaining setup stages consumed by the window's machine pill.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    /// Copying and installing the infraternal binary on the host.
    Install,
    /// Joining the host to the mesh.
    Join,
    /// Starting the service.
    Start,
    /// The host is ready for use.
    Ready,
}

/// Only confirmed operation outcomes advance a stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// The stage is in progress.
    Running,
    /// The stage finished and was confirmed.
    Done,
    /// The stage failed.
    Failed,
}

/// Public host/session coordinates and fixed safe diagnostics, never remote output.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    /// The host being set up.
    pub host_id: Uuid,
    /// The terminal session the setup runs in.
    pub session_id: Uuid,
    /// Attempt number, starting at 1 (at most 8).
    pub attempt: u32,
    /// Per-host event counter; never repeats or goes backwards, also across attempts.
    pub sequence: u64,
    /// Stage this event is about.
    pub stage: Stage,
    /// Outcome for that stage.
    pub state: State,
    /// Attempt eligibility; current authority and worker admission still apply.
    pub retry_available: bool,
    /// Install step that failed, when the event is a failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<InstallStep>,
    /// Fixed user-facing failure text; never contains remote output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'static str>,
}

/// Everything remembered about one host's setup.
struct Host {
    /// Owner id; every call must present the same one.
    owner: String,
    /// The session this host's setup is bound to; fixed after the first attempt.
    session: Uuid,
    /// Current attempt number.
    attempt: u32,
    /// Sequence of the latest event.
    sequence: u64,
    /// Replay window: the latest 16 events.
    events: VecDeque<Event>,
    /// Latest event per stage in `Stage` order, cleared when a new attempt begins.
    current: [Option<Event>; 4],
    /// Carries the latest sequence number to subscribers.
    changed: watch::Sender<u64>,
}

/// At most 10,000 tracked hosts and 16 fixed-shape events per host; no retained
/// credential, socket, task or batch. Admission requires a trusted owner id.
#[derive(Default)]
pub struct Status(Mutex<HashMap<Uuid, Host>>);
impl Status {
    /// Register only after terminal ownership is published. Existing coordinates
    /// cannot be replaced by another person or a different session.
    ///
    /// The first call for a host creates it (attempt 1); each later call starts
    /// the next attempt, up to 8, and clears the per-stage state but keeps the
    /// sequence counter running.
    /// # Errors
    /// Refuses changed identity or the bounded host cap.
    pub fn begin(&self, owner: &str, host: Uuid, session: Uuid) -> Result<(), Failure> {
        let mut hosts = super::bootstrap::lock(&self.0);
        if let Some(entry) = hosts.get_mut(&host) {
            if entry.owner != owner || entry.session != session {
                return Err(unavailable());
            }
            if entry.attempt >= 8 {
                return Err(unavailable());
            }
            entry.attempt += 1;
            entry.current = std::array::from_fn(|_| None);
        } else {
            if hosts.len() >= 10_000 {
                return Err(unavailable());
            }
            hosts.insert(
                host,
                Host {
                    owner: owner.to_owned(),
                    session,
                    attempt: 1,
                    sequence: 0,
                    events: VecDeque::new(),
                    current: std::array::from_fn(|_| None),
                    changed: watch::channel(0).0,
                },
            );
        }
        Ok(())
    }

    /// Publish confirmed stage progress from the trusted setup worker.
    ///
    /// Assigns the next sequence number, keeps it in the replay window, wakes
    /// subscribers, and offers a retry only for a failure before the 8th attempt.
    /// Only the failure's fixed message and step are stored.
    /// # Errors
    /// Refuses absent or foreign host ownership.
    pub fn emit(
        &self,
        owner: &str,
        host: Uuid,
        stage: Stage,
        outcome: State,
        failure: Option<&Failure>,
    ) -> Result<(), Failure> {
        let mut hosts = super::bootstrap::lock(&self.0);
        let entry = hosts
            .get_mut(&host)
            .filter(|entry| entry.owner == owner)
            .ok_or_else(unavailable)?;
        entry.sequence += 1;
        if entry.events.len() == 16 {
            entry.events.pop_front();
        }
        let event = Event {
            host_id: host,
            session_id: entry.session,
            attempt: entry.attempt,
            sequence: entry.sequence,
            stage,
            state: outcome,
            retry_available: outcome == State::Failed && entry.attempt < 8,
            failed_step: failure.and_then(|failure| failure.failed_step),
            message: failure.map(|failure| failure.message),
        };
        let index = match stage {
            Stage::Install => 0,
            Stage::Join => 1,
            Stage::Start => 2,
            Stage::Ready => 3,
        };
        entry.current[index] = Some(event.clone());
        entry.events.push_back(event);
        entry.changed.send_replace(entry.sequence);
        Ok(())
    }

    /// Subscribe before fetching replay, so a publication in between cannot be lost.
    /// # Errors
    /// Refuses absent or foreign host ownership.
    pub fn subscribe(&self, owner: &str, host: Uuid) -> Result<watch::Receiver<u64>, Failure> {
        let hosts = super::bootstrap::lock(&self.0);
        Ok(hosts
            .get(&host)
            .filter(|entry| entry.owner == owner)
            .ok_or_else(unavailable)?
            .changed
            .subscribe())
    }

    /// Return replay after a cursor; an old cursor receives authoritative current
    /// stage states plus an explicit resync flag instead of inventing missing events.
    ///
    /// Returns `(resync, events)` where events are in sequence order and all have
    /// a sequence above `after` unless `resync` is true.
    /// # Errors
    /// Refuses absent or foreign host ownership.
    pub fn events(
        &self,
        owner: &str,
        host: Uuid,
        after: u64,
    ) -> Result<(bool, Vec<Event>), Failure> {
        let hosts = super::bootstrap::lock(&self.0);
        let entry = hosts
            .get(&host)
            .filter(|entry| entry.owner == owner)
            .ok_or_else(unavailable)?;
        let resync = entry
            .events
            .front()
            .is_some_and(|event| after.saturating_add(1) < event.sequence);
        let mut events: Vec<Event> = entry
            .events
            .iter()
            .filter(|event| resync || event.sequence > after)
            .cloned()
            .collect();
        if resync {
            events = entry.current.iter().flatten().cloned().collect();
            events.sort_by_key(|event| event.sequence);
        }
        Ok((resync, events))
    }
}
/// One answer for unknown host, foreign owner and cap reached, so a caller cannot tell them apart.
fn unavailable() -> Failure {
    Failure::unsupported("The host setup status is unavailable.")
}

#[cfg(test)]
mod tests {
    //! Verifies authority, retention, monotonic retry sequences and replay overflow.
    use super::*;
    #[test]
    fn host_status_outlives_its_subscriber_and_keeps_exact_identity() {
        let status = Status::default();
        let host = Uuid::new_v4();
        let session = Uuid::new_v4();
        status.begin("owner", host, session).unwrap();
        let subscription = status.subscribe("owner", host).unwrap();
        drop(subscription);
        status
            .emit("owner", host, Stage::Install, State::Done, None)
            .unwrap();
        assert!(status.subscribe("foreign", host).is_err());
        assert!(status.begin("owner", host, Uuid::new_v4()).is_err());
        assert!(
            status
                .emit("foreign", host, Stage::Ready, State::Done, None)
                .is_err()
        );
        let (resync, events) = status.events("owner", host, 0).unwrap();
        assert!(!resync);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].session_id, session);
        status.begin("owner", host, session).unwrap();
        for _ in 0..65 {
            status
                .emit("owner", host, Stage::Join, State::Running, None)
                .unwrap();
        }
        let (resync, events) = status.events("owner", host, 0).unwrap();
        assert!(resync);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].attempt, 2);
        assert_eq!(events[0].sequence, 66);
        assert!(status.events("foreign", host, 0).is_err());
    }

    #[test]
    fn exhausted_setup_failure_retains_reason_without_offering_retry() {
        let status = Status::default();
        let host = Uuid::new_v4();
        let session = Uuid::new_v4();
        let failure = Failure::install("The host could not join. Try again.").at(InstallStep::Join);
        for attempt in 1..=8 {
            status.begin("owner", host, session).unwrap();
            status
                .emit("owner", host, Stage::Join, State::Failed, Some(&failure))
                .unwrap();
            let event = status
                .events("owner", host, attempt - 1)
                .unwrap()
                .1
                .pop()
                .unwrap();
            assert_eq!(event.retry_available, attempt < 8);
            assert_eq!(event.message, Some(failure.message));
            assert!(matches!(event.failed_step, Some(InstallStep::Join)));
            assert_eq!(event.session_id, session);
        }
        assert!(status.begin("owner", host, session).is_err());
    }
}
