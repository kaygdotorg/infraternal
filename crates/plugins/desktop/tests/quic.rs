//! Exercises reliable and fragmented video over the production mTLS QUIC configuration [D232].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_desktop::{
    datagram::Reassembler,
    delivery::{ReliableReader, Sender, Sent, receive_datagram},
    session::Video,
};
use infraternal_plugin_remote::{
    remote_quic::{client_config, server_config},
    remote_tls::tests::{leaf, root},
};
use infraternal_protocol::{Frame, desktop::Message, encode_frame_into};
use std::time::{Duration, Instant};

async fn pair() -> (
    quinn::Endpoint,
    quinn::Endpoint,
    quinn::Connection,
    quinn::Connection,
) {
    let ca = root();
    let server = leaf(&ca, true);
    let client = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        server_config(&server, std::slice::from_ref(&ca.certificate)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config(&client, &[ca.certificate]).unwrap());
    let dial = endpoint
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, connection) = tokio::join!(dial, async { server.accept().await.unwrap().await });
    (server, endpoint, connection.unwrap(), client.unwrap())
}
fn video(sequence: u64, keyframe: bool) -> Video {
    Video {
        sequence,
        capture_ns: 123_456,
        keyframe,
        bytes: vec![7; 4097].into(),
    }
}

#[tokio::test]
async fn both_explicit_modes_deliver_exact_video_over_mutual_tls() {
    let (_server, _client, server, client) = pair().await;
    let frame = video(1, true);
    let id = [146; 16];
    let mut encoded = Vec::new();
    let mut sender = Sender::Datagram {
        connection: &client,
        session: id,
    };
    assert_eq!(
        sender
            .send(&frame, Instant::now(), &mut encoded)
            .await
            .unwrap(),
        Sent::Complete
    );
    let mut assembly = Reassembler::new(id);
    let mut decoded = None;
    while decoded.is_none() {
        let wire = tokio::time::timeout(Duration::from_secs(2), server.read_datagram())
            .await
            .unwrap()
            .unwrap();
        decoded = receive_datagram(&mut assembly, &wire, Instant::now()).unwrap();
    }
    let decoded = decoded.unwrap();
    assert_eq!(decoded.sequence, frame.sequence);
    assert_eq!(decoded.bytes, frame.bytes);
    assert!(decoded.keyframe);
    let (mut send, _) = client.open_bi().await.unwrap();
    assert_eq!(
        Sender::Reliable(&mut send)
            .send(&frame, Instant::now(), &mut encoded)
            .await
            .unwrap(),
        Sent::Complete
    );
    let (_, recv) = server.accept_bi().await.unwrap();
    let mut reader = ReliableReader::new(recv);
    let decoded = reader.next().await.unwrap();
    assert_eq!(decoded.bytes, frame.bytes);
    assert_eq!(decoded.capture_ns, frame.capture_ns);
    assert_eq!(
        Sender::Reliable(&mut send)
            .send(
                &video(2, false),
                Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
                &mut encoded
            )
            .await
            .unwrap(),
        Sent::Stale
    );
    assert_eq!(
        Sender::Reliable(&mut send)
            .send(&video(3, true), Instant::now(), &mut encoded)
            .await
            .unwrap(),
        Sent::Complete
    );
    assert_eq!(reader.next().await.unwrap().sequence, 3);
}

#[tokio::test]
async fn cancelled_read_preserves_partial_frame_and_active_expiry_retires_lane() {
    let (_server, _client, server, client) = pair().await;
    let frame = video(1, true);
    let mut encoded = Vec::new();
    encode_frame_into(
        &Frame::Desktop(Message::Video {
            sequence: 1,
            capture_ns: frame.capture_ns,
            keyframe: true,
            bytes: &frame.bytes,
        }),
        &mut encoded,
    )
    .unwrap();
    let (mut send, _) = client.open_bi().await.unwrap();
    send.write_all(&encoded[..20]).await.unwrap();
    let (_, recv) = server.accept_bi().await.unwrap();
    let mut reader = ReliableReader::new(recv);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), reader.next())
            .await
            .is_err()
    );
    send.write_all(&encoded[20..]).await.unwrap();
    assert_eq!(reader.next().await.unwrap().bytes, frame.bytes);
    send.write_all(&encoded[..20]).await.unwrap();
    assert_eq!(
        reader.next().await.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert!(send.stopped().await.unwrap().is_some());
}

#[tokio::test]
async fn malformed_prefix_is_rejected_before_body_allocation() {
    let (_server, _client, server, client) = pair().await;
    let (mut send, _) = client.open_bi().await.unwrap();
    send.write_all(&[0xff, 0xff, 0xff, 0xff, 0x7f])
        .await
        .unwrap();
    let (_, recv) = server.accept_bi().await.unwrap();
    let mut reader = ReliableReader::new(recv);
    assert_eq!(
        reader.next().await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[tokio::test]
async fn cancelling_partial_video_write_seals_the_lane_before_another_frame() {
    let (_server, _client, server, client) = pair().await;
    let (mut send, _) = client.open_bi().await.unwrap();
    let large = Video {
        sequence: 1,
        capture_ns: 1,
        keyframe: true,
        bytes: vec![7; infraternal_protocol::desktop::MAX_VIDEO_BYTES].into(),
    };
    let mut encoded = Vec::new();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(30),
            Sender::Reliable(&mut send).send(&large, Instant::now(), &mut encoded)
        )
        .await
        .is_err()
    );
    let (_, mut recv) = server.accept_bi().await.unwrap();
    let drain =
        tokio::spawn(async move { recv.read_to_end(infraternal_protocol::MAX_FRAME_LEN).await });
    let reused = Sender::Reliable(&mut send)
        .send(&video(2, true), Instant::now(), &mut encoded)
        .await;
    let _ = send.reset(1u32.into());
    let _ = drain.await;
    assert!(
        reused.is_err(),
        "a cancelled partial frame must leave its lane sealed"
    );
}

/// Diagnostic only: run inside this job's isolated netem namespace. Synthetic
/// access units isolate transport loss/repair; they do not measure native capture
/// or decoding. The in-memory CA and endpoints reuse the real mTLS fixture.
#[tokio::test]
#[ignore = "explicit scoped netem measurement, not an ordinary gate"]
async fn measured_loss_profile() {
    let mode = std::env::var("DESKTOP_MEASURE_MODE").unwrap();
    assert!(mode == "reliable" || mode == "datagram");
    let (_server_endpoint, _client_endpoint, server, client) = pair().await;
    let origin = Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let id = [146; 16];
    let repair = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let repair_flag = repair.clone();
    let control_client = client.clone();
    // Repairs traverse a real reliable QUIC direction before the sender observes
    // them; a shared in-process flag alone would erase the configured return RTT.
    let controls = tokio::spawn(async move {
        while let Ok(Ok((_, mut stream))) =
            tokio::time::timeout_at(deadline, control_client.accept_bi()).await
        {
            let wire = stream.read_to_end(128).await.unwrap();
            let decoded = infraternal_protocol::decode_frame(&wire).unwrap();
            assert_eq!(decoded.wire_len, wire.len());
            assert!(matches!(
                decoded.frame,
                Frame::Desktop(Message::Repair { .. })
            ));
            repair_flag.store(true, std::sync::atomic::Ordering::Release);
        }
    });
    let receiving = server.clone();
    let datagram = mode == "datagram";
    let receiver = tokio::spawn(async move {
        let mut latencies = Vec::new();
        let mut gaps = Vec::new();
        let mut last = origin;
        let mut repairs = 0u64;
        let mut assembly = Reassembler::new(id);
        let mut reliable = None;
        loop {
            let next = async {
                if datagram {
                    let expiration = assembly.deadline().map(tokio::time::Instant::from_std);
                    let wire = tokio::select! {
                        result = receiving.read_datagram() => result.ok(),
                        () = async {
                            if let Some(expiration) = expiration {
                                tokio::time::sleep_until(expiration).await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => None,
                    };
                    let result = if let Some(wire) = wire {
                        receive_datagram(&mut assembly, &wire, Instant::now()).unwrap()
                    } else {
                        assembly.expire(Instant::now());
                        None
                    };
                    if assembly.take_repair() {
                        repairs += 1;
                        let mut wire = Vec::new();
                        encode_frame_into(
                            &Frame::Desktop(Message::Repair { last_sequence: 0 }),
                            &mut wire,
                        )
                        .unwrap();
                        let (mut stream, _) = receiving.open_bi().await.unwrap();
                        stream.write_all(&wire).await.unwrap();
                        stream.finish().unwrap();
                    }
                    result
                } else {
                    if reliable.is_none() {
                        let (_, stream) = receiving.accept_bi().await.unwrap();
                        reliable = Some(ReliableReader::new(stream));
                    }
                    if let Ok(video) = reliable.as_mut().unwrap().next().await {
                        Some(video)
                    } else {
                        reliable = None;
                        None
                    }
                }
            };
            let Ok(video) = tokio::time::timeout_at(deadline, next).await else {
                break;
            };
            if let Some(video) = video {
                assert_eq!(video.bytes.len(), 8192);
                let now = Instant::now();
                latencies.push(
                    u64::try_from(now.duration_since(origin).as_micros()).unwrap()
                        - video.capture_ns / 1000,
                );
                gaps.push(u64::try_from(now.duration_since(last).as_micros()).unwrap());
                last = now;
            }
        }
        gaps.push(
            u64::try_from(
                (origin + Duration::from_secs(10))
                    .saturating_duration_since(last)
                    .as_micros(),
            )
            .unwrap(),
        );
        (latencies, gaps, repairs, assembly.retained_bytes())
    });
    let (mut stream, _) = client.open_bi().await.unwrap();
    let mut timer = tokio::time::interval(Duration::from_nanos(1_000_000_000 / 30));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut encoded = Vec::new();
    let payload = bytes::Bytes::from(vec![7; 8192]);
    let mut sent = 0u64;
    let mut stale = 0u64;
    for sequence in 1..=300u64 {
        timer.tick().await;
        let now = Instant::now();
        let frame = Video {
            sequence,
            capture_ns: u64::try_from(now.duration_since(origin).as_nanos()).unwrap(),
            keyframe: sequence == 1
                || sequence % 30 == 0
                || repair.swap(false, std::sync::atomic::Ordering::AcqRel),
            bytes: payload.clone(),
        };
        let result = if datagram {
            Sender::Datagram {
                connection: &client,
                session: id,
            }
            .send(&frame, now, &mut encoded)
            .await
        } else {
            Sender::Reliable(&mut stream)
                .send(&frame, now, &mut encoded)
                .await
        };
        match result {
            Ok(Sent::Complete) => sent += 1,
            Ok(Sent::Stale) => stale += 1,
            Err(_) if !datagram => {
                stale += 1;
                (stream, _) = client.open_bi().await.unwrap();
            }
            Err(error) => panic!("datagram sender failed: {error}"),
        }
    }
    let elapsed = origin.elapsed().as_secs_f64();
    let stats = client.stats();
    let (mut latencies, gaps, repairs, retained) = receiver.await.unwrap();
    controls.await.unwrap();
    latencies.sort_unstable();
    assert_ne!(latencies.len(), 0);
    let percentile = |p: usize| latencies[(latencies.len() - 1) * p / 100];
    println!(
        "MEASUREMENT {}",
        serde_json::json!({"scope":"synthetic-mTLS-QUIC-transport-only",
        "mode":mode,"payload_bytes":8192,"target_fps":30,"sent":sent,"stale":stale,
        "received":latencies.len(),"p50_us":percentile(50),"p95_us":percentile(95),"p99_us":percentile(99),
        "freeze_threshold_us":250_000,"freeze_gaps":gaps.iter().filter(|gap| **gap > 250_000).count(),
        "largest_gap_us":gaps.iter().max(),"repairs":repairs,"retained_bytes_at_end":retained,
        "sender_elapsed_s":elapsed,"udp_tx_bytes":stats.udp_tx.bytes,
        "udp_tx_bits_per_second":f64::from(u32::try_from(stats.udp_tx.bytes).unwrap()) * 8.0 / elapsed})
    );
    client.close(0u32.into(), b"measurement complete");
}
