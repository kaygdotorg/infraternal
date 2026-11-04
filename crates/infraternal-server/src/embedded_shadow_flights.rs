//! Owns one ordered bounded native shadow flight per writer and joins cancellation before promotion [128,215], #129.
use super::{AgentConnection, Bytes, Peer};
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};

/// Outcome of one finished shadow flight.
pub(super) struct Completion {
    /// Writer id the flight ran on.
    pub(super) stream: u32,
    /// Terminal session the flight was for.
    pub(super) session: [u8; 16],
    /// True if the flight finished without error.
    pub(super) success: bool,
}
/// All shadow flights of one connection: the running tasks, which writer owns which session, and finished results not yet applied.
#[derive(Default)]
pub(super) struct State {
    tasks: JoinSet<Completion>,
    active: HashMap<u32, ([u8; 16], AbortHandle)>,
    completed: VecDeque<Completion>,
    // Production priming is native-only. Unix fixtures retain their existing
    // framing while moving the same writer ownership outside the actor.
    #[cfg(test)]
    local: Option<std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>>,
}
impl State {
    /// True while any flight is running or a finished result is waiting to be applied.
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
            #[cfg(test)]
            Peer::Local { writer, .. } => {
                use tokio::io::AsyncWriteExt;
                let owned = if let Some(writer) = &self.local {
                    writer.clone()
                } else {
                    let Ok((placeholder, _unused)) = tokio::net::UnixStream::pair() else {
                        return false;
                    };
                    let (_, replacement) = placeholder.into_split();
                    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(std::mem::replace(
                        writer,
                        replacement,
                    )));
                    self.local = Some(writer.clone());
                    writer
                };
                self.tasks.spawn(async move {
                    let success = tokio::time::timeout(Duration::from_secs(1), async {
                        {
                            let mut writer = owned.lock().await;
                            for frame in frames {
                                writer.write_all(&frame).await?;
                            }
                            Ok::<(), std::io::Error>(())
                        }
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
        #[cfg(test)]
        {
            self.local = None;
        }
        completions
    }
}

#[cfg(test)]
mod tests {
    //! Keeps a real-QUIC sibling failure owned while another blocked flight is joined.
    use super::*;
    use infraternal_agent::{remote_native::NativeChannel, transport::Receive};
    use infraternal_plugin_remote::remote_quic;
    use infraternal_protocol::Frame;
    #[tokio::test(flavor = "current_thread")]
    async fn stop_preserves_finished_success_and_identifies_unpolled_cancellation() {
        use tokio::io::AsyncReadExt;
        let (socket, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let mut connection = super::super::tests::shadow(socket).connection;
        let mut state = State::default();
        assert!(state.schedule(
            &mut connection,
            42,
            [7; 16],
            vec![Bytes::from_static(b"ok")]
        ));
        let mut received = [0; 2];
        peer.read_exact(&mut received).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.active[&42].1.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(received, *b"ok");
        assert!(state.schedule(
            &mut connection,
            43,
            [8; 16],
            vec![Bytes::from_static(b"no")]
        ));
        // This current-thread task cannot start before stop aborts it. The
        // previous socket write has completed but has not been actor-reaped.
        let completions = state.stop().await;
        assert_eq!(completions.len(), 2);
        assert!(completions.iter().any(|c| c.stream == 42 && c.success));
        assert!(completions.iter().any(|c| c.stream == 43 && !c.success));
        assert!(!state.owns(42));
        assert!(!state.owns(43));
    }
    #[tokio::test]
    async fn queued_sibling_failure_stays_owned_until_the_actor_observes_it() {
        let (link, _control, _listener, _endpoint, peer) =
            crate::remote_runtime::tests::native_link_pair().await;
        let hello = Frame::Hello {
            version: 1,
            caps: remote_quic::REMOTE_WRITER_BINDING,
            client_info: "shadow completion fixture",
        };
        let binding = remote_quic::negotiate_binding(&peer, &hello).unwrap();
        let attach = Frame::AttachTerm {
            session_id: &[7; 16],
            last_out_seq: 0,
            last_in_seq: 0,
        };
        let mut encoded = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(42, &attach, &mut encoded).unwrap();
        link.write(42, &attach, &encoded).await.unwrap();
        let parked =
            NativeChannel::terminal(remote_quic::accept_bound(&binding).await.unwrap()).unwrap();
        assert!(matches!(
            Receive::default().next(&parked).await.unwrap().frame,
            Frame::AttachTerm { .. }
        ));
        link.limit_send_window(256);
        let (socket, _unused) = tokio::net::UnixStream::pair().unwrap();
        let mut connection = super::super::tests::shadow(socket).connection;
        connection.peer = Peer::Remote(link.clone());
        let mut encoded = Vec::new();
        infraternal_protocol::encode_frame_into(
            &Frame::Input {
                in_seq: 0,
                bytes: &[b'x'; 16384],
            },
            &mut encoded,
        )
        .unwrap();
        let mut state = State::default();
        assert!(state.schedule(&mut connection, 42, [7; 16], vec![Bytes::from(encoded)]));
        // Stream43 has no bound channel, so its task fails independently of the
        // unread stream42. Wait for that completion before cancelling42.
        assert!(state.schedule(&mut connection, 43, [7; 16], vec![Bytes::from_static(b"x")]));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !state.active[&43].1.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        state.retire(42).await;
        let owned = state.owns(43);
        let failed = state.next().await;
        let _ = state.stop().await;
        link.retire_writer(42).await;
        assert_eq!(failed.stream, 43);
        assert!(!failed.success);
        assert!(
            owned,
            "a queued failure must keep its writer owned until actor delivery"
        );
    }
}
