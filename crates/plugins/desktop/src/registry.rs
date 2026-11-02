//! Retains server-owned capture sessions across viewer and path lifetimes; runtime disable retires every retained frame [D104,D198,D232].
use crate::session::{Error, Session, SessionId, Viewer};
use infraternal_plugin_api::streams::Authority;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

struct State {
    enabled: bool,
    sessions: HashMap<SessionId, Arc<Session>>,
}
/// Constructors declare capacity without starting work. Authenticated producers
/// register sessions after host admission; viewers cannot create a capture by
/// supplying an unknown UUID. The host transport remains owned by its plugin.
pub struct Registry {
    state: Mutex<State>,
    limit: usize,
}
impl Registry {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            state: Mutex::new(State {
                enabled: false,
                sessions: HashMap::new(),
            }),
            limit,
        }
    }
    /// Runtime lifecycle changes never create a server or a node-side component.
    /// Turning off clears cached video before any future attachment can succeed.
    /// # Errors
    /// Refuses a poisoned lifecycle lock.
    pub fn set_enabled(&self, enabled: bool) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        state.enabled = enabled;
        if !enabled {
            for (_, session) in state.sessions.drain() {
                session.close();
            }
        }
        Ok(())
    }
    /// Register a session only after the existing host transport verifies its
    /// principal, host binding and access rule source. Duplicate IDs never replace a
    /// live capture; reconnect reuses the existing object and its sequence clock.
    /// # Errors
    /// Refuses disabled state, duplicate IDs or the declared capacity.
    pub fn insert(&self, session: Arc<Session>) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if !state.enabled {
            return Err(Error::Unavailable);
        }
        if state.sessions.contains_key(&session.id()) {
            return Err(Error::Invalid);
        }
        if state.sessions.len() >= self.limit {
            return Err(Error::Limit);
        }
        state.sessions.insert(session.id(), session);
        Ok(())
    }
    /// A lookup cannot establish authority: `Session::attach` rechecks live view
    /// access against the immutable host and owner stored at producer admission.
    /// # Errors
    /// Refuses unknown/disabled captures, withdrawn access or viewer capacity.
    pub fn attach(&self, id: &SessionId, user: String) -> Result<Viewer, Error> {
        let state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if !state.enabled {
            return Err(Error::Unavailable);
        }
        state
            .sessions
            .get(id)
            .ok_or(Error::Unavailable)?
            .attach(user)
    }
    /// Public socket adapters bind each viewer to its own login projection.
    /// # Errors
    /// Refuses disabled/unknown sessions, expired logins and ordinary attach limits.
    pub fn attach_authorized(
        &self,
        id: &SessionId,
        user: String,
        authority: Arc<dyn Authority>,
    ) -> Result<Viewer, Error> {
        let state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if !state.enabled {
            return Err(Error::Unavailable);
        }
        state
            .sessions
            .get(id)
            .ok_or(Error::Unavailable)?
            .attach_authorized(user, authority)
    }

    /// The authorized owner-facing adapter stops one capture independently of
    /// its viewers. Held input and cached bytes retire through `Session::close`.
    /// # Errors
    /// Refuses a poisoned lifecycle lock or missing capture.
    pub fn remove(&self, id: &SessionId) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        let session = state.sessions.remove(id).ok_or(Error::Unavailable)?;
        session.close();
        Ok(())
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.sessions.len())
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Shared payload accounting; wire/QUIC buffers and in-flight viewer frames
    /// must be reported separately in whole-process memory measurements.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.state.lock().map_or(0, |state| {
            state
                .sessions
                .values()
                .map(|session| session.retained_bytes())
                .sum()
        })
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            for (_, session) in state.sessions.drain() {
                session.close();
            }
        }
    }
}
