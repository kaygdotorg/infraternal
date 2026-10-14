//! Keeps shipping-proof browser sockets responsive independently of test work [D265, #199].

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use infraternal_protocol::{Frame, decode_muxed_frame, encode_muxed_frame_into};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

// Fixture ordinals identify sockets in safe receipts without logging authority.
static NEXT_BROWSER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

/// A fixture event loop answers probes even while the caller runs deployment or sibling setup.
/// Queues are bounded; overflowing test output fails rather than hiding a stalled client.
pub(crate) struct Browser {
    pub(crate) ordinal: usize,
    commands: mpsc::Sender<(Bytes, oneshot::Sender<bool>)>,
    messages: mpsc::Receiver<Message>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Browser {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Browser {
    pub(crate) fn new(
        mut socket: tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Self {
        let ordinal = NEXT_BROWSER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (commands, mut outgoing) = mpsc::channel::<(Bytes, oneshot::Sender<bool>)>(32);
        let (incoming, messages) = mpsc::channel(4096);
        let task = tokio::spawn(async move {
            let mut encoded = Vec::new();
            loop {
                tokio::select! {
                    command = outgoing.recv() => {
                        let Some((bytes, done)) = command else { break; };
                        let sent = socket.send(Message::Binary(bytes)).await.is_ok();
                        let _ = done.send(sent);
                        if !sent { break; }
                    }
                    message = socket.next() => {
                        let message = match message {
                            Some(Ok(message)) => message,
                            Some(Err(error)) => {
                                println!("STAGING browser_transport_error_kind={:?}", std::mem::discriminant(&error));
                                break;
                            }
                            None => { println!("STAGING browser_transport_end=true"); break; }
                        };
                        let reply = match &message {
                            Message::Binary(bytes) => {
                                let decoded = decode_muxed_frame(bytes).unwrap();
                                if decoded.stream_id == 0
                                    && let Frame::Ping { nonce, sent_us } = decoded.frame {
                                    encode_muxed_frame_into(0, &Frame::Pong { nonce, sent_us }, &mut encoded).unwrap();
                                    Some(Message::Binary(Bytes::copy_from_slice(&encoded)))
                                } else { None }
                            }
                            Message::Ping(bytes) => Some(Message::Pong(bytes.clone())),
                            Message::Pong(_) | Message::Frame(_) => continue,
                            Message::Close(_) | Message::Text(_) => None,
                        };
                        if let Some(reply) = reply {
                            if let Err(error) = socket.send(reply).await {
                                println!("STAGING browser_probe_write_error_kind={:?}", std::mem::discriminant(&error));
                                // Drain the close after a stale probe instead of hiding
                                // it behind a BrokenPipe from the diagnostic write.
                            }
                        } else {
                            let closed = matches!(message, Message::Close(_));
                            if let Message::Close(ref frame) = message {
                                println!("STAGING browser={ordinal} terminal_message=Close code={:?}", frame.as_ref().map(|frame| frame.code));
                            }
                            // Never await a full output queue: that would stop answering
                            // probes and recreate the client's original failure mode.
                            assert!(incoming.try_send(message).is_ok(), "shipping browser output queue full");
                            if closed { break; }
                        }
                    }
                }
            }
        });
        Self {
            ordinal,
            commands,
            messages,
            task,
        }
    }

    pub(crate) async fn send(&mut self, stream: u32, frame: &Frame<'_>) {
        let mut encoded = Vec::new();
        encode_muxed_frame_into(stream, frame, &mut encoded).unwrap();
        let (done, sent) = oneshot::channel();
        self.commands.send((encoded.into(), done)).await.unwrap();
        assert!(sent.await.unwrap(), "shipping browser send failed");
    }

    pub(crate) async fn read(&mut self) -> Bytes {
        match tokio::time::timeout(std::time::Duration::from_secs(15), self.messages.recv())
            .await
            .unwrap()
            .expect("shipping browser transport ended")
        {
            Message::Binary(bytes) => bytes,
            Message::Close(frame) => {
                // Only type/code may enter receipts: reasons and text can contain secrets.
                println!(
                    "STAGING terminal_message=Close code={:?}",
                    frame.map(|frame| frame.code)
                );
                panic!("unexpected terminal Close");
            }
            Message::Text(_) => panic!("unexpected terminal Text"),
            _ => unreachable!("browser event loop consumes transport controls"),
        }
    }
}

#[path = "ca_handoff_browser_loop_tests.rs"]
mod tests;
