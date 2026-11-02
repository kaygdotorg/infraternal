//! Tests native QUIC framing and cancellation against real quinn streams; mux identities never enter raw bytes [64][130], #78.

use crate::{channel::Channel, remote_native::*};
use crate::{
    remote_quic,
    remote_tls::tests::{leaf, root},
    transport::{Receive, Transmit},
};
use infraternal_protocol::{Frame, decode_frame, encode_frame_into};
use std::{io, time::Duration};

#[path = "remote_primed_tests.rs"]
mod primed;

pub(super) struct Pair {
    server_endpoint: quinn::Endpoint,
    client_endpoint: quinn::Endpoint,
    server: quinn::Connection,
    pub(super) client: quinn::Connection,
}
impl Pair {
    pub(super) async fn new() -> Self {
        let ca = root();
        let server = quinn::Endpoint::server(
            remote_quic::server_config(&leaf(&ca, true), std::slice::from_ref(&ca.certificate))
                .unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            remote_quic::client_config(&leaf(&ca, false), &[ca.certificate]).unwrap(),
        );
        let (local, remote) = tokio::join!(
            client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap(),
            async { server.accept().await.unwrap().await }
        );
        Self {
            server_endpoint: server,
            client_endpoint: client,
            server: remote.unwrap(),
            client: local.unwrap(),
        }
    }
    pub(super) fn binding(&self, server: bool) -> remote_quic::BindingConnection {
        remote_quic::negotiate_binding(
            if server { &self.server } else { &self.client },
            &Frame::Hello {
                version: 1,
                caps: remote_quic::REMOTE_WRITER_BINDING,
                client_info: "test",
            },
        )
        .unwrap()
    }
}

#[tokio::test]
async fn bound_writer_uses_raw_frames_and_rejects_cross_writer_transmit() {
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let server = server.unwrap();
    let mut host = host.unwrap();
    let channel = NativeChannel::terminal(server).unwrap();
    let mut tx = Transmit::default();
    let input = Frame::Input {
        in_seq: 11,
        bytes: b"native-input",
    };
    assert_eq!(
        tx.send(&channel, 44, &input).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    tx.send(&channel, 42, &input).await.unwrap();
    let mut expected = Vec::new();
    encode_frame_into(&input, &mut expected).unwrap();
    let mut raw = vec![0; expected.len()];
    host.receive.read_exact(&mut raw).await.unwrap();
    let decoded = decode_frame(&raw).unwrap();
    assert_eq!(raw, expected);
    assert_eq!(decoded.frame, input);
    assert_eq!(decoded.wire_len, raw.len());
    let mut raw = Vec::new();
    encode_frame_into(&Frame::Ack { in_seq_acked: 11 }, &mut raw).unwrap();
    let mut suffix = Vec::new();
    encode_frame_into(
        &Frame::Output {
            out_seq: 99,
            bytes: b"raw-output",
        },
        &mut suffix,
    )
    .unwrap();
    raw.extend_from_slice(&suffix);
    host.send.write_all(&raw).await.unwrap();
    let mut rx = Receive::default();
    let decoded = rx.next(&channel).await.unwrap();
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(decoded.frame, Frame::Ack { in_seq_acked: 11 });
    let decoded = rx.next(&channel).await.unwrap();
    assert_eq!(decoded.stream_id, 42);
    assert_eq!(
        decoded.frame,
        Frame::Output {
            out_seq: 99,
            bytes: b"raw-output"
        }
    );
}

#[tokio::test]
async fn partial_native_write_cancellation_retires_both_directions() {
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, _host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let channel = NativeChannel::terminal(server.unwrap()).unwrap();
    // The peer retains its stream without consuming. Outstanding flow credit is
    // 1MiB, so this larger write cannot complete before cancellation.
    let bytes = vec![0; 8 * 1024 * 1024];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), channel.write(&bytes))
            .await
            .is_err()
    );
    assert_eq!(
        channel.write(b"suffix").await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    assert_eq!(
        channel.read(&mut [0; 1]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[tokio::test]
async fn control_must_be_host_initiated_stream_zero_and_terminal_halves_cannot_impersonate_it() {
    let pair = Pair::new().await;
    let (mut host_send, host_receive) = pair.client.open_bi().await.unwrap();
    host_send.write_all(&[0]).await.unwrap();
    let (send, receive) = pair.server.accept_bi().await.unwrap();
    let channel = NativeChannel::control(send, receive).unwrap();
    assert_eq!(channel.native_stream_id(), Some(0));
    drop(host_receive);
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let server = server.unwrap();
    assert!(NativeChannel::control(server.send, server.receive).is_err());
    drop(host.unwrap());
}

#[path = "native_terminal_tests.rs"]
mod terminal;

// Metadata is immutable provider code; packet bytes cannot select the lane role.
pub(crate) static PLUGIN_WIRE: infraternal_plugin_api::streams::WireStreamDef =
    infraternal_plugin_api::streams::WireStreamDef {
        browser_capability: None,
        capability: infraternal_protocol::desktop::NATIVE_CAPABILITY,
        opening_tag: 0x40,
        opening_identity: None,
        requests: &[0x40, 0x42, 0x43, 0x44],
        replies: &[0x41],
        max_streams: 2,
        datagram_tag: None,
        datagram_identity: None,
    };

#[tokio::test]
async fn plugin_lane_preserves_large_raw_packets_and_compiled_directions() {
    use infraternal_plugin_api::streams::WireLane;
    use infraternal_protocol::desktop::Message;
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let requester = crate::wire::Lane::new(
        NativeChannel::terminal(server.unwrap()).unwrap(),
        &PLUGIN_WIRE,
        crate::wire::Side::Requester,
        None,
    )
    .unwrap();
    let provider = crate::wire::Lane::new(
        NativeChannel::terminal(host.unwrap()).unwrap(),
        &PLUGIN_WIRE,
        crate::wire::Side::Provider,
        None,
    )
    .unwrap();
    let mut opening = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Attach {
            session_id: &[1; 16],
            delivery: infraternal_protocol::desktop::Delivery::Reliable,
        }),
        &mut opening,
    )
    .unwrap();
    requester.send(&opening).await.unwrap();
    assert_eq!(provider.receive().await.unwrap().as_ref(), opening);
    let unit = vec![7; 1024 * 1024];
    let mut video = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence: 1,
            capture_ns: 1,
            keyframe: true,
            bytes: &unit,
        }),
        &mut video,
    )
    .unwrap();
    assert!(requester.send(&video).await.is_err());
    let (sent, received) = tokio::join!(provider.send(&video), requester.receive());
    sent.unwrap();
    assert_eq!(received.unwrap().as_ref(), video);
    requester.send(&opening).await.unwrap();
    assert_eq!(provider.receive().await.unwrap().as_ref(), opening);
    assert_eq!(requester.stream_id(), 42);
}

#[tokio::test]
async fn malformed_incoming_plugin_direction_retires_only_its_lane() {
    use infraternal_plugin_api::streams::WireLane;
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let requester = crate::wire::Lane::new(
        NativeChannel::terminal(server.unwrap()).unwrap(),
        &PLUGIN_WIRE,
        crate::wire::Side::Requester,
        None,
    )
    .unwrap();
    let mut host = host.unwrap();
    let mut invalid = Vec::new();
    encode_frame_into(
        &Frame::Ping {
            nonce: 1,
            sent_us: 1,
        },
        &mut invalid,
    )
    .unwrap();
    host.send.write_all(&invalid).await.unwrap();
    assert!(requester.receive().await.is_err());
    assert!(requester.receive().await.is_err());
    assert!(pair.server.close_reason().is_none());
    assert!(pair.client.close_reason().is_none());
}

fn plugin_datagram_identity(packet: &[u8]) -> Option<[u8; 16]> {
    let decoded = decode_frame(packet).ok()?;
    if decoded.wire_len != packet.len() {
        return None;
    }
    match decoded.frame {
        Frame::Desktop(infraternal_protocol::desktop::Message::Fragment { session_id, .. }) => {
            Some(*session_id)
        }
        _ => None,
    }
}
static PLUGIN_DATAGRAM_WIRE: infraternal_plugin_api::streams::WireStreamDef =
    infraternal_plugin_api::streams::WireStreamDef {
        datagram_tag: Some(0x45),
        datagram_identity: Some(plugin_datagram_identity),
        ..PLUGIN_WIRE
    };

#[tokio::test]
async fn cancelled_plugin_write_withdraws_cloned_datagram_handles() {
    use infraternal_plugin_api::streams::WireLane;
    use infraternal_protocol::desktop::Message;
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let _host = host.unwrap(); // Keep the peer alive but never drain its flow window.
    let datagrams =
        infraternal_plugin_remote::wire_datagrams::NativeDatagrams::new(pair.server.clone());
    let datagrams = datagrams.admit(&PLUGIN_DATAGRAM_WIRE, [1; 16]).unwrap();
    let provider = crate::wire::Lane::new(
        NativeChannel::terminal(server.unwrap()).unwrap(),
        &PLUGIN_DATAGRAM_WIRE,
        crate::wire::Side::Provider,
        Some(datagrams),
    )
    .unwrap();
    let retained = provider.datagrams().unwrap();
    let pending = retained.receive();
    tokio::pin!(pending);
    std::future::poll_fn(|cx| {
        assert!(pending.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let mut packet = Vec::new();
    let unit = vec![7; 2 * 1024 * 1024];
    encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence: 1,
            capture_ns: 1,
            keyframe: true,
            bytes: &unit,
        }),
        &mut packet,
    )
    .unwrap();
    {
        let write = provider.send(&packet);
        tokio::pin!(write);
        std::future::poll_fn(|cx| {
            assert!(write.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
    }
    assert!(pending.await.is_err());
    assert!(retained.receive().await.is_err());
    assert!(retained.send(b"invalid").await.is_err());
    assert!(retained.max_payload().is_none());
    assert!(provider.send(&packet).await.is_err());
    assert!(pair.server.close_reason().is_none());
    assert!(pair.client.close_reason().is_none());
}

struct PreparedProvider {
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    lane: std::sync::Arc<
        std::sync::Mutex<Option<std::sync::Arc<dyn infraternal_plugin_api::streams::WireLane>>>,
    >,
}
impl infraternal_plugin_api::streams::WireProvider for PreparedProvider {
    fn serve(
        &self,
        _: &'static infraternal_plugin_api::streams::WireStreamDef,
        opening: bytes::Bytes,
        lane: std::sync::Arc<dyn infraternal_plugin_api::streams::WireLane>,
    ) -> infraternal_plugin_api::Operation<'static, Result<(), ()>> {
        use std::sync::atomic::Ordering;
        let calls = self.calls.clone();
        let retained = self.lane.clone();
        Box::pin(async move {
            if !matches!(decode_frame(&opening).map_err(|_| ())?.frame,Frame::Desktop(infraternal_protocol::desktop::Message::Attach{session_id,..}) if session_id==&[1;16])
            {
                return Err(());
            }
            calls.fetch_add(1, Ordering::SeqCst);
            *retained.lock().map_err(|_| ())? = Some(lane.clone());
            let suffix = lane.receive().await.expect("prepared provider suffix read");
            if !matches!(
                decode_frame(&suffix).map_err(|_| ())?.frame,
                Frame::Desktop(infraternal_protocol::desktop::Message::Size {
                    width: 960,
                    height: 600,
                    ..
                })
            ) {
                panic!(
                    "wrong prepared provider suffix: {:?}",
                    decode_frame(&suffix)
                );
            }
            let mut video = Vec::new();
            encode_frame_into(
                &Frame::Desktop(infraternal_protocol::desktop::Message::Video {
                    sequence: 7,
                    capture_ns: 9,
                    keyframe: true,
                    bytes: &[1, 2, 3],
                }),
                &mut video,
            )
            .map_err(|_| ())?;
            lane.send(&video)
                .await
                .expect("prepared provider video write");
            Ok(())
        })
    }
}
#[tokio::test]
async fn native_dispatch_routes_prepared_provider_and_preserves_opening_suffix() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    let pair = Pair::new().await;
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, 42),
        remote_quic::accept_bound(&host_binding)
    );
    let requester = NativeChannel::terminal(server.unwrap()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let retained = Arc::new(Mutex::new(None));
    let entries = Arc::new(
        crate::native_dispatch::Routes::new(vec![
            infraternal_plugin_api::streams::WireProviderEntry {
                definition: &PLUGIN_WIRE,
                provider: Arc::new(PreparedProvider {
                    calls: calls.clone(),
                    lane: retained.clone(),
                }),
            },
        ])
        .unwrap(),
    );
    let mut combined = Vec::new();
    for frame in [
        Frame::Desktop(infraternal_protocol::desktop::Message::Attach {
            session_id: &[1; 16],
            delivery: infraternal_protocol::desktop::Delivery::Reliable,
        }),
        Frame::Desktop(infraternal_protocol::desktop::Message::Size {
            width: 960,
            height: 600,
            density_milli: 1000,
        }),
    ] {
        let mut packet = Vec::new();
        encode_frame_into(&frame, &mut packet).unwrap();
        combined.extend_from_slice(&packet);
    }
    requester.write(&combined).await.unwrap();
    let job = tokio::spawn(crate::native_dispatch::serve(
        host.unwrap(),
        entries,
        PLUGIN_WIRE.capability,
        infraternal_plugin_remote::wire_datagrams::NativeDatagrams::new(pair.client.clone()),
        None,
    ));
    job.await.unwrap().unwrap();
    let mut receive = Receive::default();
    let video = tokio::time::timeout(Duration::from_secs(2), receive.next(&requester))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        video.frame,
        Frame::Desktop(infraternal_protocol::desktop::Message::Video { sequence: 7, .. })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let lane = retained.lock().unwrap().take().unwrap();
    assert!(
        lane.receive().await.is_err(),
        "completed provider retained a live native lane"
    );
}
#[tokio::test]
async fn native_dispatch_refuses_unnegotiated_or_unknown_opening_without_provider_work() {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    let pair = Pair::new().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let entries = Arc::new(
        crate::native_dispatch::Routes::new(vec![
            infraternal_plugin_api::streams::WireProviderEntry {
                definition: &PLUGIN_WIRE,
                provider: Arc::new(PreparedProvider {
                    calls: calls.clone(),
                    lane: Arc::new(Mutex::new(None)),
                }),
            },
        ])
        .unwrap(),
    );
    for (writer, caps, id) in [(42, 0, [1; 16]), (44, PLUGIN_WIRE.capability, [2; 16])] {
        let server_binding = pair.binding(true);
        let host_binding = pair.binding(false);
        let (server, host) = tokio::join!(
            remote_quic::open_bound(&server_binding, writer),
            remote_quic::accept_bound(&host_binding)
        );
        let requester = NativeChannel::terminal(server.unwrap()).unwrap();
        Transmit::default()
            .send(
                &requester,
                writer,
                &Frame::Desktop(infraternal_protocol::desktop::Message::Attach {
                    session_id: &id,
                    delivery: infraternal_protocol::desktop::Delivery::Reliable,
                }),
            )
            .await
            .unwrap();
        assert!(
            crate::native_dispatch::serve(
                host.unwrap(),
                entries.clone(),
                caps,
                infraternal_plugin_remote::wire_datagrams::NativeDatagrams::new(
                    pair.client.clone()
                ),
                None
            )
            .await
            .is_err()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

struct QuotaProvider {
    starts: std::sync::Arc<tokio::sync::Notify>,
}
impl infraternal_plugin_api::streams::WireProvider for QuotaProvider {
    fn serve(
        &self,
        _: &'static infraternal_plugin_api::streams::WireStreamDef,
        _: bytes::Bytes,
        lane: std::sync::Arc<dyn infraternal_plugin_api::streams::WireLane>,
    ) -> infraternal_plugin_api::Operation<'static, Result<(), ()>> {
        let starts = self.starts.clone();
        Box::pin(async move {
            starts.notify_one();
            lane.receive().await.map(|_| ())
        })
    }
}

async fn quota_opening(pair: &Pair, writer: u32) -> (NativeChannel, remote_quic::BoundStream) {
    let server_binding = pair.binding(true);
    let host_binding = pair.binding(false);
    let (server, host) = tokio::join!(
        remote_quic::open_bound(&server_binding, writer),
        remote_quic::accept_bound(&host_binding)
    );
    let requester = NativeChannel::terminal(server.unwrap()).unwrap();
    Transmit::default()
        .send(
            &requester,
            writer,
            &Frame::Desktop(infraternal_protocol::desktop::Message::Attach {
                session_id: &[1; 16],
                delivery: infraternal_protocol::desktop::Delivery::Reliable,
            }),
        )
        .await
        .unwrap();
    (requester, host.unwrap())
}

#[tokio::test]
async fn native_dispatch_enforces_provider_quota_and_releases_cancelled_slot() {
    use std::sync::Arc;
    static ONE: infraternal_plugin_api::streams::WireStreamDef =
        infraternal_plugin_api::streams::WireStreamDef {
            max_streams: 1,
            ..PLUGIN_WIRE
        };
    let pair = Pair::new().await;
    let starts = Arc::new(tokio::sync::Notify::new());
    let entries = Arc::new(
        crate::native_dispatch::Routes::new(vec![
            infraternal_plugin_api::streams::WireProviderEntry {
                definition: &ONE,
                provider: Arc::new(QuotaProvider {
                    starts: starts.clone(),
                }),
            },
        ])
        .unwrap(),
    );
    let datagrams =
        infraternal_plugin_remote::wire_datagrams::NativeDatagrams::new(pair.client.clone());
    let (_first, first_bound) = quota_opening(&pair, 42).await;
    let first = tokio::spawn(crate::native_dispatch::serve(
        first_bound,
        entries.clone(),
        PLUGIN_WIRE.capability,
        datagrams.clone(),
        None,
    ));
    tokio::time::timeout(Duration::from_secs(2), starts.notified())
        .await
        .unwrap();
    let (_second, second_bound) = quota_opening(&pair, 44).await;
    assert!(
        matches!(
            tokio::time::timeout(
                Duration::from_millis(200),
                crate::native_dispatch::serve(
                    second_bound,
                    entries.clone(),
                    PLUGIN_WIRE.capability,
                    datagrams.clone(),
                    None
                )
            )
            .await,
            Ok(Err(_))
        ),
        "provider admission exceeded its declared one-lane quota"
    );
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let (_third, third_bound) = quota_opening(&pair, 46).await;
    let third = tokio::spawn(crate::native_dispatch::serve(
        third_bound,
        entries,
        PLUGIN_WIRE.capability,
        datagrams,
        None,
    ));
    tokio::time::timeout(Duration::from_secs(2), starts.notified())
        .await
        .unwrap();
    third.abort();
    assert!(third.await.unwrap_err().is_cancelled());
    assert!(pair.client.close_reason().is_none());
    assert!(pair.server.close_reason().is_none());
}
