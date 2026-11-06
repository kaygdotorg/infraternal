//! Independent #158 scale diagnostic: 200 vanished-session replies must preserve the same real channel.

use super::*;

#[tokio::test]
#[ignore = "scale measurement; run alone under CPUWeight=10000"]
async fn two_hundred_vanished_sessions_preserve_the_same_channel() {
    let base = crate::test_state_root().join("fds");
    std::fs::create_dir_all(&base).unwrap();
    let state = sessions::state(Some(base.join(format!(
        "s{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ))))
    .unwrap();
    let (host, server) = std::os::unix::net::UnixStream::pair().unwrap();
    host.set_nonblocking(true).unwrap();
    server.set_nonblocking(true).unwrap();
    let socket = Socket::inherited(host.into_raw_fd()).unwrap();
    let path = state.clone();
    let task = tokio::spawn(async move {
        let service = crate::plugin_control::Service::start(
            &path,
            crate::plugins::ExecutionMode::Embedded,
            None,
        )
        .await?;
        run_channel::<false>(
            &socket,
            path,
            None,
            None,
            Some(service.registry.clone()),
            None,
        )
        .await
    });
    let mut peer = tokio::net::UnixStream::from_std(server).unwrap();
    let mut buffer = Vec::new();
    let mut samples = Vec::new();
    let initial_load = std::fs::read_to_string("/proc/loadavg").unwrap();
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut wire = Vec::new();
        send(
            &mut wire,
            0,
            &Frame::Ping {
                nonce: 0,
                sent_us: 0,
            },
        );
        tokio::io::AsyncWriteExt::write_all(&mut peer, &wire)
            .await
            .unwrap();
        while next(&mut peer, &mut buffer).await != Seen::Pong(0) {}
        for index in 1..=200_u32 {
            let id = *uuid::Uuid::new_v4().as_bytes();
            let stream = index * 2;
            wire.clear();
            send(
                &mut wire,
                stream,
                &Frame::AttachTerm {
                    session_id: &id,
                    last_out_seq: 0,
                    last_in_seq: 0,
                },
            );
            send(&mut wire, stream, &Frame::Credit { bytes: 4096 });
            let started = std::time::Instant::now();
            tokio::io::AsyncWriteExt::write_all(&mut peer, &wire)
                .await
                .unwrap();
            assert_eq!(
                next(&mut peer, &mut buffer).await,
                Seen::Close(stream, CLOSE_SESSION_GONE, "session ended".to_owned())
            );
            samples.push(started.elapsed().as_micros());
            // Late input and its Close cannot affect control or the next session.
            wire.clear();
            send(
                &mut wire,
                stream,
                &Frame::Input {
                    in_seq: 0,
                    bytes: b"late",
                },
            );
            send(
                &mut wire,
                stream,
                &Frame::Close {
                    code: 1000,
                    reason: "review detach",
                },
            );
            send(
                &mut wire,
                0,
                &Frame::Ping {
                    nonce: u64::from(index),
                    sent_us: 0,
                },
            );
            tokio::io::AsyncWriteExt::write_all(&mut peer, &wire)
                .await
                .unwrap();
            assert_eq!(
                next(&mut peer, &mut buffer).await,
                Seen::Pong(u64::from(index))
            );
        }
    })
    .await;
    let finished = task.is_finished();
    task.abort();
    let _ = task.await;
    std::fs::remove_dir_all(state).unwrap();
    assert!(outcome.is_ok(), "scale diagnostic did not complete");
    assert!(!finished, "vanished sessions stopped the channel");
    samples.sort_unstable();
    println!(
        "vanished_session_replies n=200 p50_us={} p99_us={} max_us={} initial_load={} final_load={}",
        samples[99],
        samples[197],
        samples[199],
        initial_load.trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
