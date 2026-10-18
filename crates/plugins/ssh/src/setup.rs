//! Retains host-bound D255 setup progress independently of wizard sockets, with bounded replay and no idle task.

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
    Install,
    Join,
    Start,
    Ready,
}

/// Only confirmed operation outcomes advance a stage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Running,
    Done,
    Failed,
}

/// Public host/session coordinates and fixed safe diagnostics, never remote output.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub host_id: Uuid,
    pub session_id: Uuid,
    pub attempt: u32,
    pub sequence: u64,
    pub stage: Stage,
    pub state: State,
    /// Attempt eligibility; current authority and worker admission still apply.
    pub retry_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<InstallStep>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<&'static str>,
}

struct Host {
    owner: String,
    session: Uuid,
    attempt: u32,
    sequence: u64,
    events: VecDeque<Event>,
    current: [Option<Event>; 4],
    changed: watch::Sender<u64>,
}

/// At most 10,000 tracked hosts and 16 fixed-shape events per host; no retained
/// credential, socket, task or batch. Admission requires a trusted owner id.
#[derive(Default)]
pub struct Status(Mutex<HashMap<Uuid, Host>>);
impl Status {
    /// Register only after terminal ownership is published. Existing coordinates
    /// cannot be replaced by another person or a different session.
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
