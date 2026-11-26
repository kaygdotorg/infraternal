//! Proves that terminals on a full or troubled host link stay independent, over real QUIC
//! (D214, #562).
//!
//! A host link carries at most [`MAX_TERMINAL_STREAMS`] terminals, each on its own QUIC
//! stream. When one browser socket drops and its terminals attach again, the link closes
//! those streams and opens new ones. The infraternal agent only tells the server about
//! freed streams in batches, so the transport needs room above the terminal bound, or a
//! replacement waits for a stream that is never granted and takes the whole link with it.
//!
//! A terminal that cannot be served must cost only itself. An infraternal agent that predates
//! the extra stream credit leaves a replacement waiting for ever, and a terminal whose stream
//! the agent stops reading blocks every later write on it. Neither may close the host link.
//!
//! The pair here is the real one: the server's host actor on one side, and on the other a
//! stand-in infraternal agent that connects with the agent's own QUIC settings and ends each
//! terminal stream the way the real relay does.

use super::*;
use crate::embedded::{AgentError, AttachmentHandle, TerminalAttachment, TerminalOutput};
use infraternal_agent::remote_native::NativeChannel;
use infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
use tokio::task::JoinSet;

/// How long one attach may take on loopback before the test calls it stuck. The actor gives
/// each terminal write one second, so a starved stream fails well inside this.
const ATTACH_BOUND: Duration = Duration::from_secs(5);

/// How long a refusal may take. Well under the one second the host actor gives a terminal
/// write, so it proves the actor never sat waiting for a stream the agent will not grant.
const REFUSAL_BOUND: Duration = Duration::from_millis(900);

/// How the stand-in infraternal agent differs from today's agent.
#[derive(Clone, Copy, Default)]
struct StandIn {
    /// Server-opened streams it allows at once; `None` keeps the agent's own setting.
    stream_credit: Option<u32>,
    /// Bytes it accepts on one stream before it reads them; `None` keeps the agent's own
    /// setting.
    stream_window: Option<u32>,
    /// A writer id whose stream it binds and then never reads, as a stuck terminal would.
    deaf_writer: Option<u32>,
}

/// A connected host actor and the stand-in infraternal agent behind it.
struct FullHost {
    actor: EmbeddedAgent,
    /// Ends when the QUIC connection ends; owns every relay task.
    agent: tokio::task::JoinHandle<()>,
    connection: quinn::Connection,
    /// The next unused leg-B writer id (even, never zero).
    next_writer: u32,
    /// Held open: the actor stops when no replacement link can ever arrive.
    _accepts: mpsc::Sender<RemoteLink>,
    _server: quinn::Endpoint,
}

impl FullHost {
    /// Connect the pair over loopback with the production server and agent QUIC settings.
    async fn new() -> Self {
        Self::with_agent(StandIn::default()).await
    }

    /// Connect the pair over loopback to a stand-in agent that behaves as `stand_in` says.
    async fn with_agent(stand_in: StandIn) -> Self {
        let (server, host, root, _) = identities();
        let listener = quinn::Endpoint::server(
            remote_quic::server_config(&server, std::slice::from_ref(&root)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = remote_quic::client_config(&host, &[root]).unwrap();
        if stand_in.stream_credit.is_some() || stand_in.stream_window.is_some() {
            let credit = stand_in.stream_credit.unwrap_or_else(|| {
                u32::try_from(infraternal_link::quic::TERMINAL_STREAM_CREDIT).unwrap()
            });
            let mut transport = remote_quic::transport_with_liveness(
                credit,
                Duration::from_secs(15),
                Duration::from_secs(60),
                true,
            );
            if let Some(window) = stand_in.stream_window {
                std::sync::Arc::get_mut(&mut transport)
                    .expect("a new configuration has one owner")
                    .stream_receive_window(window.into());
            }
            client.transport_config(transport);
        }
        endpoint.set_default_client_config(client);
        let address = listener.local_addr().unwrap();
        let agent = tokio::spawn(async move {
            let connection = endpoint
                .connect(address, "localhost")
                .unwrap()
                .await
                .unwrap();
            stand_in_agent(connection, stand_in.deaf_writer).await;
        });
        let connection = listener.accept().await.unwrap().await.unwrap();
        let link = RemoteLink::quic(connection.clone()).await.unwrap();
        let (actor, accepts) = EmbeddedAgent::remote(1002);
        accepts.send(link).await.unwrap();
        Self {
            actor,
            agent,
            connection,
            next_writer: 2,
            _accepts: accepts,
            _server: listener,
        }
    }

    /// Attach terminal session `writer` on that writer's stream, failing if it takes too long.
    async fn attach_writer(&self, writer: u32) -> TerminalAttachment {
        let mut session = [0; 16];
        session[..4].copy_from_slice(&writer.to_be_bytes());
        tokio::time::timeout(ATTACH_BOUND, self.actor.attach(session, 0, 0, writer))
            .await
            .unwrap_or_else(|_| panic!("writer {writer}: attach did not answer"))
            .unwrap_or_else(|error| {
                panic!(
                    "writer {writer}: attach refused with {error:?}, link closed: {:?}",
                    self.connection.close_reason()
                )
            })
    }

    /// Attach `count` new terminals, each on a writer id never used on this link.
    async fn attach_new(&mut self, count: usize) -> Vec<(u32, TerminalAttachment)> {
        let mut attached = Vec::with_capacity(count);
        for _ in 0..count {
            let writer = self.next_writer;
            self.next_writer += 2;
            attached.push((writer, self.attach_writer(writer).await));
        }
        attached
    }
}

/// The infraternal agent's side of the link: greet, answer liveness probes on the control
/// stream, acknowledge each terminal's attach and input, and hold each terminal stream until
/// the server closes or resets it. The stream of `deaf_writer` is held without being read.
async fn stand_in_agent(connection: quinn::Connection, deaf_writer: Option<u32>) {
    let (send, receive) = connection.open_bi().await.unwrap();
    let control = NativeChannel::control(send, receive).unwrap();
    let hello = Frame::Hello {
        version: 1,
        caps: remote_quic::REMOTE_WRITER_BINDING,
        client_info: "stream bound fixture",
    };
    Transmit::default().send(&control, 0, &hello).await.unwrap();
    let binding = remote_quic::negotiate_binding(&connection, &hello).unwrap();
    let mut relays = JoinSet::new();
    relays.spawn(async move {
        let mut receive = Receive::default();
        while let Ok(decoded) = receive.next(&control).await {
            if let Frame::Ping { nonce, sent_us } = decoded.frame {
                let pong = Frame::Pong { nonce, sent_us };
                if Transmit::default().send(&control, 0, &pong).await.is_err() {
                    return;
                }
            }
        }
    });
    while let Ok(bound) = remote_quic::accept_bound(&binding).await {
        let deaf = Some(bound.writer_id) == deaf_writer;
        relays.spawn(async move {
            let writer = bound.writer_id;
            let channel = NativeChannel::terminal(bound).unwrap();
            if deaf {
                std::future::pending::<()>().await;
            }
            let mut receive = Receive::default();
            while let Ok(decoded) = receive.next(&channel).await {
                let in_seq_acked = match decoded.frame {
                    Frame::Close { .. } => break,
                    Frame::AttachTerm { last_in_seq, .. } => last_in_seq,
                    Frame::Input { in_seq, bytes } => in_seq + bytes.len() as u64,
                    _ => continue,
                };
                let ack = Frame::Ack { in_seq_acked };
                if Transmit::default()
                    .send(&channel, writer, &ack)
                    .await
                    .is_err()
                {
                    break;
                }
            }
            channel.retire();
        });
    }
}

/// A browser socket drops at the host's terminal bound and its terminals attach again on a
/// new socket (J1220: three hosts, 128 terminals each; ten of one host's were on the socket).
/// Every replacement must attach, and the link and its other terminals must stay up.
#[tokio::test]
async fn replacing_a_dropped_sockets_terminals_on_a_full_link_succeeds() {
    let mut pair = FullHost::new().await;
    let mut attached = pair.attach_new(MAX_TERMINAL_STREAMS).await;
    // One socket's share of this host, fewer than an eighth of the bound: the agent had
    // announced no new stream credit for so few freed streams.
    drop(attached.drain(..10).collect::<Vec<_>>());
    let replacements = pair.attach_new(10).await;
    assert!(pair.connection.close_reason().is_none());
    assert!(!pair.agent.is_finished());
    drop((attached, replacements));
}

/// A resumed browser attaches a stream the full link already carries. The server closes the
/// old QUIC stream and opens a fresh one for the same writer.
#[tokio::test]
async fn reattaching_a_routed_terminal_on_a_full_link_succeeds() {
    let mut pair = FullHost::new().await;
    let attached = pair.attach_new(MAX_TERMINAL_STREAMS).await;
    let mut resumed = Vec::new();
    for (writer, _) in attached.iter().take(32) {
        resumed.push(pair.attach_writer(*writer).await);
    }
    assert!(pair.connection.close_reason().is_none());
    drop((attached, resumed));
}

/// Every terminal of a full link is replaced at once, twice over: the worst case of closing
/// streams still unacknowledged while their replacements open.
#[tokio::test]
async fn replacing_every_terminal_of_a_full_link_succeeds() {
    let mut pair = FullHost::new().await;
    let mut attached = pair.attach_new(MAX_TERMINAL_STREAMS).await;
    for _ in 0..2 {
        drop(attached);
        attached = pair.attach_new(MAX_TERMINAL_STREAMS).await;
    }
    assert!(pair.connection.close_reason().is_none());
    drop(attached);
}

/// The two halves of an attached terminal, as the browser socket holds them.
type Terminal = (AttachmentHandle, mpsc::Receiver<TerminalOutput>);

/// One keystroke on `terminal` that must come back acknowledged: the terminal still works.
async fn type_and_expect_ack(terminal: &mut Terminal, in_seq: u64) {
    let (handle, output) = terminal;
    send_input(handle, in_seq, b"x").await;
    let acknowledged = in_seq + 1;
    tokio::time::timeout(ATTACH_BOUND, async {
        loop {
            match output.recv().await {
                Some(TerminalOutput::Ack { in_seq_acked }) if in_seq_acked == acknowledged => break,
                Some(_) => {}
                None => panic!("the terminal's output ended"),
            }
        }
    })
    .await
    .expect("input was never acknowledged");
}

/// Queue `bytes` as the browser's input on this terminal.
async fn send_input(handle: &AttachmentHandle, in_seq: u64, bytes: &[u8]) {
    let mut wire = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(1, &Frame::Input { in_seq, bytes }, &mut wire)
        .unwrap();
    handle.send_frame(wire.into()).await.unwrap();
}

/// Attach `writer`, require the host actor to refuse it with `Unavailable`, and say how
/// long the answer took.
async fn expect_refused(pair: &FullHost, writer: u32) -> Duration {
    let mut session = [0; 16];
    session[..4].copy_from_slice(&writer.to_be_bytes());
    let asked = std::time::Instant::now();
    let refused = tokio::time::timeout(ATTACH_BOUND, pair.actor.attach(session, 0, 0, writer))
        .await
        .unwrap_or_else(|_| panic!("writer {writer}: attach did not answer"));
    assert!(
        matches!(refused, Err(AgentError::Unavailable)),
        "writer {writer}: expected a refusal, link closed: {:?}",
        pair.connection.close_reason()
    );
    asked.elapsed()
}

/// An infraternal agent without the extra stream credit (#562) frees streams in batches of more
/// than an eighth of 128, so replacing ten terminals on a full link finds no stream to open. Each
/// of those attaches is refused alone, at once. The link, its other terminals and a later retry
/// all keep working.
#[tokio::test]
async fn an_attach_with_no_stream_to_open_is_refused_alone() {
    let bound = u32::try_from(MAX_TERMINAL_STREAMS).unwrap();
    let mut pair = FullHost::with_agent(StandIn {
        stream_credit: Some(bound),
        ..StandIn::default()
    })
    .await;
    let mut attached = pair.attach_new(MAX_TERMINAL_STREAMS).await;
    drop(attached.drain(..10).collect::<Vec<_>>());
    let mut waits = vec![expect_refused(&pair, pair.next_writer).await];
    // sleep: a link the first attach took down has finished closing by now.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        pair.connection.close_reason().is_none(),
        "one attach without a stream closed the link"
    );
    for index in 1..10 {
        waits.push(expect_refused(&pair, pair.next_writer + 2 * index).await);
    }
    // A resumed browser reattaching a routed terminal needs a new stream too.
    let (resumed, previous) = attached.remove(0);
    waits.push(expect_refused(&pair, resumed).await);
    drop(previous);
    assert!(
        pair.connection.close_reason().is_none(),
        "the link was closed"
    );
    assert!(
        waits.iter().all(|wait| *wait < REFUSAL_BOUND),
        "a refusal held the host actor: {waits:?}"
    );
    let mut attached: Vec<Terminal> = attached
        .into_iter()
        .map(|(_, attachment)| attachment.split())
        .collect();
    for terminal in &mut attached {
        type_and_expect_ack(terminal, 0).await;
    }
    // More freed streams than an eighth of the credit reach the server, and a retry succeeds.
    drop(attached.drain(..10).collect::<Vec<_>>());
    let writer = pair.next_writer + 100;
    let retried = tokio::time::timeout(ATTACH_BOUND, async {
        loop {
            let mut session = [0; 16];
            session[..4].copy_from_slice(&writer.to_be_bytes());
            match pair.actor.attach(session, 0, 0, writer).await {
                Ok(attachment) => break attachment,
                Err(AgentError::Unavailable) => {
                    // sleep: a browser waits before it retries a refused terminal.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => panic!("retry refused with {error:?}"),
            }
        }
    })
    .await
    .expect("no stream after the agent was told of freed ones");
    assert!(pair.connection.close_reason().is_none());
    drop((attached, retried));
}

/// A terminal whose stream the agent has stopped reading has no room for the server's `Close`.
/// Detaching it retires that stream only: the link and its other terminals keep working.
#[tokio::test]
async fn a_close_the_agent_does_not_read_retires_only_that_terminal() {
    const WINDOW: u32 = 1024;
    const DEAF: u32 = 2;
    let mut pair = FullHost::with_agent(StandIn {
        stream_window: Some(WINDOW),
        deaf_writer: Some(DEAF),
        ..StandIn::default()
    })
    .await;
    let mut attached = pair.attach_new(2).await;
    let (writer, stuck) = attached.remove(0);
    assert_eq!(writer, DEAF);
    let (stuck, _unread) = stuck.split();
    // Fill the stuck stream's window exactly: the binding and the attach are in it already.
    let size = |frame: &Frame<'_>| {
        let mut wire = Vec::new();
        infraternal_protocol::encode_frame_into(frame, &mut wire).unwrap();
        wire.len()
    };
    let mut session = [0; 16];
    session[..4].copy_from_slice(&DEAF.to_be_bytes());
    let used = size(&Frame::Call {
        call_id: 0,
        action_id: "transport.bind",
        input_json: br#"{"writer_id":2}"#,
    }) + size(&Frame::AttachTerm {
        session_id: &session,
        last_out_seq: 0,
        last_in_seq: 0,
    });
    let room = usize::try_from(WINDOW).unwrap() - used;
    let filler = (0..room)
        .rev()
        .map(|length| vec![b'x'; length])
        .find(|bytes| size(&Frame::Input { in_seq: 0, bytes }) <= room)
        .unwrap();
    send_input(&stuck, 0, &filler).await;
    // sleep: the input reaches the actor through its own task; the detach below must follow it.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Dropping the handle detaches, as a closed window does.
    drop(stuck);
    let mut survivor = attached.remove(0).1.split();
    // sleep: let the actor reach the blocked Close and pass its one-second write bound.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    type_and_expect_ack(&mut survivor, 0).await;
    assert!(
        pair.connection.close_reason().is_none(),
        "the link was closed"
    );
}
