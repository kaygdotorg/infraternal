//! Owns one ordered bounded native shadow flight per writer and joins cancellation before promotion [128,215], #129.
use super::{AgentConnection, Bytes, Peer};
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};

pub(super) struct Completion {
    pub(super) stream: u32,
    pub(super) session: [u8; 16],
    pub(super) success: bool,
}
#[derive(Default)]
pub(super) struct State {
    tasks: JoinSet<Completion>,
    active: HashMap<u32, ([u8; 16], AbortHandle)>,
    completed: VecDeque<Completion>,
}
impl State {
    pub(super) fn active(&self) -> bool {
        !self.tasks.is_empty() || !self.completed.is_empty()
    }
    // A reaped completion remains owned until the actor applies its result;
    // queued failure cannot race another admission during a sibling join.
    pub(super) fn owns(&self, stream: u32) -> bool {
        self.active.contains_key(&stream)
            || self
                .completed
                .iter()
                .any(|completion| completion.stream == stream)
    }
    pub(super) fn abort_writer(&mut self, stream: u32) {
        if let Some((_, handle)) = self.active.get(&stream) {
            handle.abort();
        }
    }
    pub(super) fn schedule(
        &mut self,
        connection: &mut AgentConnection,
        stream: u32,
        session: [u8; 16],
        frames: Vec<Bytes>,
    ) -> bool {
        if self.owns(stream)
            || self.active.len() >= infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS
        {
            return false;
        }
        let task = match &mut connection.peer {
            Peer::Remote(link) if link.native() => {
                let link = link.clone();
                self.tasks.spawn(async move {
                    let success = tokio::time::timeout(Duration::from_secs(1), async {
                        for frame in frames {
                            link.write_encoded_terminal(stream, &frame).await?;
                        }
                        Ok::<(), std::io::Error>(())
                    })
                    .await
                    .is_ok_and(|result| result.is_ok());
                    Completion {
                        stream,
                        session,
                        success,
                    }
                })
            }
            _ => return false,
        };
        self.active.insert(stream, (session, task));
        true
    }
    fn resolve(&mut self, result: Result<(Id, Completion), JoinError>) -> Option<Completion> {
        let (id, completion) = match result {
            Ok((id, completion)) => (id, completion),
            Err(error) => {
                let id = error.id();
                let (stream, (session, _)) = self
                    .active
                    .iter()
                    .find(|(_, (_, handle))| handle.id() == id)?;
                (
                    id,
                    Completion {
                        stream: *stream,
                        session: *session,
                        success: false,
                    },
                )
            }
        };
        if !self
            .active
            .get(&completion.stream)
            .is_some_and(|(session, handle)| *session == completion.session && handle.id() == id)
        {
            return None;
        }
        self.active.remove(&completion.stream);
        Some(completion)
    }
    pub(super) async fn next(&mut self) -> Completion {
        loop {
            if let Some(completion) = self.completed.pop_front() {
                return completion;
            }
            match self.tasks.join_next_with_id().await {
                Some(result) => {
                    if let Some(completion) = self.resolve(result) {
                        return completion;
                    }
                }
                None => return std::future::pending().await,
            }
        }
    }
    /// Only this writer is cancelled; completed siblings are retained for the
    /// actor's ordinary completion branch rather than lost during the join.
    pub(super) async fn retire(&mut self, stream: u32) {
        let Some((_, handle)) = self.active.get(&stream) else {
            return;
        };
        let cancelled = handle.id();
        handle.abort();
        while let Some(result) = self.tasks.join_next_with_id().await {
            let id = match &result {
                Ok((id, _)) => *id,
                Err(error) => error.id(),
            };
            if let Some(completion) = self.resolve(result)
                && id != cancelled
            {
                self.completed.push_back(completion);
            }
            if id == cancelled {
                break;
            }
        }
        self.completed
            .retain(|completion| completion.stream != stream);
    }
    /// Join every owner before handing its reserved state to promotion. A
    /// finished write stays successful; an aborted write cannot publish grants
    /// whose bytes may never have reached its native channel.
    pub(super) async fn stop(&mut self) -> Vec<Completion> {
        self.tasks.abort_all();
        let mut completions = Vec::with_capacity(self.active.len() + self.completed.len());
        completions.extend(self.completed.drain(..));
        while let Some(result) = self.tasks.join_next_with_id().await {
            if let Some(completion) = self.resolve(result) {
                completions.push(completion);
            }
        }
        self.active.clear();
        completions
    }
}
