//! Independent subscription lifetime checks for Mesh admission refusals on the shared socket [D11, D164, #108].
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn review_oversized_replacement_ends_the_previous_mesh_subscription() {
    refusal_ends_subscription(Refusal::Oversized).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_refusal_cannot_reinstall_a_queued_mesh_subscription() {
    refusal_ends_subscription(Refusal::QueuedOversized).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saturated_refusal_cannot_reinstall_a_queued_mesh_subscription() {
    refusal_ends_subscription(Refusal::Saturated).await;
}

/// Exercise both admission limits, including a watch already queued behind a writer.
#[derive(Clone, Copy)]
enum Refusal {
    Oversized,
    QueuedOversized,
    Saturated,
}

async fn refusal_ends_subscription(case: Refusal) {
    let _guard = SERIAL.lock().await;
    // WAL retains independent authority reads while the worker's writer waits.
    // Reuse the registered fixture and production's eight-connection pool shape.
    let root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || std::path::PathBuf::from("target"),
        std::path::PathBuf::from,
    );
    let path = root.join(format!("mesh-refusal-{}.sqlite", Uuid::new_v4()));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        // Private SQLite fixtures can open slowly while workspace jobs share disk I/O.
        .acquire_timeout(Duration::from_secs(60))
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                .busy_timeout(Duration::from_secs(5)),
        )
        .await
        .unwrap();
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    let (f, address, server) = socket_fixture_from_fixture(f, Some(Duration::from_secs(2))).await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let (mut socket, _) = connect_async(test_ws_request(address, &cookie))
        .await
        .unwrap();
    assert_server_hello(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "mesh-subscription-review",
        },
    )
    .await;
    read_welcome(&mut socket).await;
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 82,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let first = read_client_frame(&mut socket).await;
    let Frame::Event {
        sub_id: 82,
        event_json,
    } = decode_muxed_frame(&first).unwrap().frame
    else {
        panic!("initial Mesh snapshot missing");
    };
    let initial: Value = serde_json::from_slice(event_json).unwrap();
    assert_eq!(initial["type"], "snapshot");

    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 83,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    let unrelated = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&unrelated).unwrap().frame,
        Frame::Event { sub_id: 83, .. }
    ));

    let mut writer = if matches!(case, Refusal::Oversized) {
        None
    } else {
        let mut writer = f.auth.pool.begin().await.unwrap();
        sqlx::query("UPDATE mesh_state SET revision=revision WHERE singleton=1")
            .execute(&mut *writer)
            .await
            .unwrap();
        client_ws_send(
            &mut socket,
            0,
            &Frame::Call {
                call_id: 101,
                action_id: "mesh.tag.create",
                input_json: br#"{"name":"pending"}"#,
            },
        )
        .await;
        // This admitted replacement cannot execute before the writer is released.
        client_ws_send(
            &mut socket,
            0,
            &Frame::Subscribe {
                sub_id: 82,
                filter_json: br#"{"topic":"mesh"}"#,
            },
        )
        .await;
        if matches!(case, Refusal::Saturated) {
            // The active writer plus at least four queued requests fills admission.
            // Filler refusals are read below; the target refusal must remain immediate.
            for call_id in 102..106 {
                client_ws_send(
                    &mut socket,
                    0,
                    &Frame::Call {
                        call_id,
                        action_id: "mesh.list",
                        input_json: br"{}",
                    },
                )
                .await;
            }
        }
        Some(writer)
    };

    // Whitespace preserves valid JSON while exceeding only Mesh's admission
    // limit. The global frozen codec still accepts this replacement frame.
    let mut oversized = br#"{"topic":"mesh"}"#.to_vec();
    oversized.resize(65_536, b' ');
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 82,
            filter_json: if matches!(case, Refusal::Saturated) {
                br#"{"topic":"mesh"}"#
            } else {
                &oversized
            },
        },
    )
    .await;
    let mut post_refusal_events = Vec::new();
    let mut unrelated_changed = false;
    let mut filler_results = 0;
    loop {
        let refused = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&refused).unwrap().frame {
            Frame::Event {
                sub_id: 82,
                event_json,
            } => {
                // The oversized filter cannot identify a provider, so the
                // dispatcher must use its generic response. The saturated
                // case has a valid Mesh topic and keeps the specific refusal.
                let expected_error = if matches!(case, Refusal::Saturated)
                    || !(cfg!(feature = "canvas") || cfg!(feature = "remote"))
                {
                    "mesh unavailable"
                } else {
                    "plugin unavailable"
                };
                assert_eq!(
                    serde_json::from_slice::<Value>(event_json).unwrap(),
                    json!({"type":"error","error": expected_error})
                );
                break;
            }
            Frame::Result {
                call_id: 102..=105,
                ok: false,
                ..
            } => {
                filler_results += 1;
            }
            _ => panic!("replacement refusal missing"),
        }
    }
    // A control fence works even before the pending writer is released.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 1000,
            sent_us: 0,
        },
    )
    .await;
    let fence = read_client_frame(&mut socket).await;
    assert!(matches!(
        decode_muxed_frame(&fence).unwrap().frame,
        Frame::Pong { nonce: 1000, .. }
    ));
    if let Some(writer) = writer.take() {
        writer.rollback().await.unwrap();
        let mut writer_done = false;
        let expected_fillers = if matches!(case, Refusal::Saturated) {
            4
        } else {
            0
        };
        // Drain every earlier call before admitting the final mutation. This
        // proves queue progress without waiting a guessed scheduling interval.
        while !writer_done || filler_results < expected_fillers {
            let wire = read_client_frame(&mut socket).await;
            match decode_muxed_frame(&wire).unwrap().frame {
                Frame::Result {
                    call_id: 101,
                    ok: true,
                    ..
                } => {
                    writer_done = true;
                }
                Frame::Result {
                    call_id: 102..=105, ..
                } => {
                    filler_results += 1;
                }
                Frame::Event {
                    sub_id: 82,
                    event_json,
                } => post_refusal_events.push(serde_json::from_slice::<Value>(event_json).unwrap()),
                Frame::Event {
                    sub_id: 83,
                    event_json,
                } => {
                    unrelated_changed |=
                        serde_json::from_slice::<Value>(event_json).unwrap()["type"] == "changed";
                }
                _ => panic!("pending call progress missing"),
            }
        }
    }

    client_ws_send(
        &mut socket,
        0,
        &Frame::Call {
            call_id: 201,
            action_id: "mesh.tag.create",
            input_json: br#"{"name":"after-refusal"}"#,
        },
    )
    .await;
    // Observe through a control round trip after the successful mutation. The
    // server must retain socket usability but stop events for the refused ID.
    loop {
        let wire = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Result {
                call_id: 201,
                ok: true,
                ..
            } => break,
            Frame::Event {
                sub_id: 82,
                event_json,
            } => post_refusal_events.push(serde_json::from_slice::<Value>(event_json).unwrap()),
            Frame::Event {
                sub_id: 83,
                event_json,
            } => {
                unrelated_changed |=
                    serde_json::from_slice::<Value>(event_json).unwrap()["type"] == "changed";
            }
            Frame::Result {
                call_id: 101..=105, ..
            } => {}
            _ => panic!("unexpected frame after Mesh edit"),
        }
    }
    // Observe an unrelated watch's update so cancellation cannot silently stop
    // every subscription. Buffered events for the refused ID stay visible here.
    while !unrelated_changed {
        let wire = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Event {
                sub_id: 82,
                event_json,
            } => post_refusal_events.push(serde_json::from_slice::<Value>(event_json).unwrap()),
            Frame::Event {
                sub_id: 83,
                event_json,
            } => {
                unrelated_changed =
                    serde_json::from_slice::<Value>(event_json).unwrap()["type"] == "changed";
            }
            _ => panic!("unrelated subscription update missing"),
        }
    }
    client_ws_send(
        &mut socket,
        0,
        &Frame::Ping {
            nonce: 92,
            sent_us: 0,
        },
    )
    .await;
    loop {
        let wire = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Pong { nonce: 92, .. } => break,
            Frame::Event {
                sub_id: 82,
                event_json,
            } => post_refusal_events.push(serde_json::from_slice::<Value>(event_json).unwrap()),
            Frame::Event { sub_id: 83, .. } => {}
            _ => panic!("unexpected frame after control probe"),
        }
    }
    // A new watch with the same ID has a distinct lifetime and remains usable.
    client_ws_send(
        &mut socket,
        0,
        &Frame::Subscribe {
            sub_id: 82,
            filter_json: br#"{"topic":"mesh"}"#,
        },
    )
    .await;
    loop {
        let wire = read_client_frame(&mut socket).await;
        match decode_muxed_frame(&wire).unwrap().frame {
            Frame::Event {
                sub_id: 82,
                event_json,
            } => {
                let event: Value = serde_json::from_slice(event_json).unwrap();
                if event["type"] == "snapshot" {
                    assert_eq!(
                        event["snapshot"]["revision"],
                        if matches!(case, Refusal::Oversized) {
                            1
                        } else {
                            2
                        }
                    );
                    break;
                }
                post_refusal_events.push(event);
            }
            Frame::Event { sub_id: 83, .. } => {}
            _ => panic!("fresh subscription snapshot missing"),
        }
    }
    server.abort();
    let _ = server.await;
    f.auth.pool.close().await;
    for suffix in ["", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(file));
    }
    assert_eq!(
        post_refusal_events,
        Vec::<Value>::new(),
        "a server error must end the Mesh subscription"
    );
}
