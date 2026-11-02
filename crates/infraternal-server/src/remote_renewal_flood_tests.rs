//! Uses the existing credited 50 MiB flood oracle on a remote CLI session during live renewal, #78.
use super::*;

async fn credited_flood(
    browser: &mut Browser,
    cursor: &mut u64,
    fixture: &Fixture,
    guard: &crate::remote_guard::AuthorityGuard,
    predecessor: [u8; 32],
) -> (usize, bool) {
    let mut payload = Vec::new();
    let mut unlocked = false;
    let mut renewed = false;
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "credited flood stalled"
        );
        let wire = next(browser).await;
        let decoded = decode_muxed_frame(&wire).unwrap();
        match decoded.frame {
            Frame::Output { out_seq, bytes } => {
                assert_eq!(out_seq, *cursor, "flood output gap or duplication");
                *cursor += u64::try_from(bytes.len()).unwrap();
                let marker_start = payload.len().saturating_sub(b"FLOOD_DONE".len() - 1);
                payload.extend_from_slice(bytes);
                send(
                    browser,
                    1,
                    &Frame::Credit {
                        bytes: u32::try_from(bytes.len()).unwrap(),
                    },
                )
                .await;
                if !unlocked && payload.len() >= 65536 {
                    fixture
                        .signer
                        .unlock_from(&Administrator(fixture.material.clone()))
                        .unwrap();
                    unlocked = true;
                }
                if !renewed && unlocked {
                    renewed = guard.predecessor() != predecessor;
                }
                if payload[marker_start..]
                    .windows(b"FLOOD_DONE".len())
                    .any(|part| part == b"FLOOD_DONE")
                {
                    break;
                }
            }
            Frame::Snapshot { .. } => {
                panic!("credited renewal flood replaced raw bytes with Snapshot")
            }
            Frame::Close { code, reason } => panic!(
                "terminal closed code={code} bytes_received={} reader_fell_behind={} reason_length={}",
                payload.len(),
                reason == "reader fell behind; reattach",
                reason.len()
            ),
            _ => {}
        }
    }
    let end = payload
        .windows(b"FLOOD_DONE".len())
        .position(|part| part == b"FLOOD_DONE")
        .unwrap();
    let size = 50 * 1024 * 1024;
    let start = end.checked_sub(size).unwrap();
    for chunk in payload[start..end].chunks(65536) {
        assert_eq!(chunk, b"y\n".repeat(chunk.len() / 2));
    }
    assert!(
        unlocked && renewed,
        "renewal did not finish during the active flood"
    );
    (size, renewed)
}

#[tokio::test]
#[ignore = "real CLI 50MiB renewal proof: exclusive4701 and release binary; no own build/browser overlap"]
async fn remote_cli_renewal_under_50m_load_preserves_every_byte_and_writer() {
    let binary = PathBuf::from(
        std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").expect("real CLI required"),
    );
    assert_ne!(nix::unistd::Uid::effective().as_raw(), 0);
    let directory = Directory::new();
    let fixture = fixture_at_with_lock(
        &directory,
        "127.0.0.1:4701".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        true,
    )
    .await;
    let (host, identity) = super::super::renewal::enrolled_at_half_life(&fixture).await;
    seed_cli_identity(&directory, &fixture, host, &identity);
    let process = cli(&binary, &directory, false, "https://localhost:4701");
    let mut browser = browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    let session = open_remote(&mut browser, host, Instant::now()).await;
    // The detached shim leaves the measurement scope. Reuse the gate fixture's
    // existing UUID-scoped CPU-weight inheritance, so producer and consumer are
    // measured with the same requested priority without changing production.
    let priority = Command::new("python3")
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts"))
        .args([
            "-c",
            "import sys,uuid; sys.dont_write_bytecode=True; from types import SimpleNamespace; from agent_fixture import Binary; Binary.inherit_scope_priority(SimpleNamespace(id=uuid.UUID(sys.argv[1])))",
            &session.to_string(),
        ])
        .status()
        .unwrap();
    assert!(priority.success(), "owned shim priority inheritance failed");
    send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: session.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    send(&mut browser, 1, &Frame::Credit { bytes: 1024 * 1024 }).await;
    let mut cursor = 0;
    let mut before = Vec::new();
    until(&mut browser, &mut before, &mut cursor, b"shim-test").await;
    let prepare = b"stty -echo -opost; printf 'READY_%s' RENEW\n";
    send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq: 0,
            bytes: prepare,
        },
    )
    .await;
    until(&mut browser, &mut before, &mut cursor, b"READY_RENEW").await;
    let guard = fixture
        .listeners
        .as_ref()
        .unwrap()
        .diagnostic_hosts
        .admission_for_test(host)
        .await
        .unwrap();
    let predecessor = guard.predecessor();
    let sockets = assert_transport(process.0.id());
    let flood = b"yes | head -c 50M; printf 'FLOOD_%s' DONE\n";
    let started = Instant::now();
    send(
        &mut browser,
        1,
        &Frame::Input {
            in_seq: u64::try_from(prepare.len()).unwrap(),
            bytes: flood,
        },
    )
    .await;
    let (bytes, renewed) =
        credited_flood(&mut browser, &mut cursor, &fixture, &guard, predecessor).await;
    assert_eq!(
        network_sockets(process.0.id()),
        sockets,
        "renewal changed flood connection"
    );
    println!(
        "remote_renewal_flood rootless=true bytes={bytes} lost=0 duplicated=0 snapshots=0 transport_interruption=0 renewed_during_flood={renewed} elapsed_us={} agent_rss_kib={} machine={} cores={} load={}",
        started.elapsed().as_micros(),
        process_rss_kib(process.0.id()),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
