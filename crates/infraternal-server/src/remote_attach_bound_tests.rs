//! Proves that replacing terminals on a full host link works over real QUIC (D214, #562).
//!
//! A host link carries at most [`MAX_TERMINAL_STREAMS`] terminals, each on its own QUIC
//! stream. When one browser socket drops and its terminals attach again, the link closes
//! those streams and opens new ones. The infraternal agent only tells the server about
//! freed streams in batches, so the transport needs room above the terminal bound, or a
//! replacement waits for a stream that is never granted and takes the whole link with it.
//!
//! The pair here is the real one: the server's host actor on one side, and on the other a
//! stand-in infraternal agent that connects with the agent's own QUIC settings and ends each
//! terminal stream the way the real relay does.

use super::*;
use crate::embedded::TerminalAttachment;
use infraternal_agent::remote_native::NativeChannel;
use infraternal_plugin_api::channel::MAX_TERMINAL_STREAMS;
use tokio::task::JoinSet;

/// How long one attach may take on loopback before the test calls it stuck. The actor gives
/// each terminal write one second, so a starved stream fails well inside this.
const ATTACH_BOUND: Duration = Duration::from_secs(5);

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
        let (server, host, root, _) = identities();
        let listener = quinn::Endpoint::server(
            remote_quic::server_config(&server, std::slice::from_ref(&root)).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(remote_quic::client_config(&host, &[root]).unwrap());
        let address = listener.local_addr().unwrap();
        let agent = tokio::spawn(async move {
            let connection = endpoint
                .connect(address, "localhost")
                .unwrap()
                .await
                .unwrap();
            stand_in_agent(connection).await;
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
/// stream, and hold each terminal stream until the server closes or resets it.
async fn stand_in_agent(connection: quinn::Connection) {
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
        relays.spawn(async move {
            let channel = NativeChannel::terminal(bound).unwrap();
            let mut receive = Receive::default();
            while let Ok(decoded) = receive.next(&channel).await {
                if matches!(decoded.frame, Frame::Close { .. }) {
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
