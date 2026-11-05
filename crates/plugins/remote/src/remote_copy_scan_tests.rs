//! Measures production copy-poll bookkeeping for 1000 bounded histories; this is not a transport or terminal acceptance proof (#201, D243, D263).
use super::*;
use quinn::{Runtime as _, UdpPoller, udp::RecvMeta};
use std::{
    io,
    io::IoSliceMut,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

/// Delegate socket metadata/readiness, but reject any physical transmission:
/// dormant and distant-future queues must remain a bookkeeping-only workload.
#[derive(Debug)]
struct NoSend(Arc<dyn AsyncUdpSocket>);
impl AsyncUdpSocket for NoSend {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.0.clone().create_io_poller()
    }
    fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
        panic!("copy scan benchmark attempted physical IO")
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "31 bookkeeping samples per profile on the authorized perf VM under its fair lock; not transport acceptance."]
async fn copy_poll_cost_at_one_thousand_retained_histories() {
    const PEERS: usize = 1000;
    const SAMPLES: usize = 31;
    const POLLS: usize = 10;
    let machine = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    assert_eq!(
        machine.trim(),
        "infraternal-perf-test",
        "physical timings belong on the authorized perf VM"
    );
    let load_start = std::fs::read_to_string("/proc/loadavg").unwrap();
    let socket = NoSend(
        quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
            .unwrap(),
    );
    let mut profiles = Vec::new();
    for (name, future, invalidate) in [
        ("dormant_unchanged", false, false),
        ("future_unchanged", true, false),
        ("future_invalidated_each_poll", true, true),
    ] {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        let mut peers = Peers::default();
        for index in 0..PEERS {
            let port = 10000 + u16::try_from(index).unwrap();
            let logical = SocketAddr::new("127.0.0.3".parse().unwrap(), port);
            let alternate = SocketAddr::new("127.0.0.4".parse().unwrap(), port);
            assert!(peers.insert(u64::try_from(index).unwrap() + 1, logical, alternate));
            let peer = peers.get_mut(logical).unwrap();
            peer.physical = alternate;
            peer.mesh = Some(MeshRoute {
                binding: None,
                local: None,
            });
            let recent = peer.recent_mut();
            for value in 0..MAX_DATAGRAMS {
                recent.keep(&Transmit {
                    destination: logical,
                    contents: &[u8::try_from(value).unwrap(); 32],
                    ecn: None,
                    segment_size: None,
                    src_ip: None,
                });
            }
            if future {
                for entry in &mut recent.datagrams {
                    entry.copy_at = Some(deadline);
                }
            }
        }
        assert_eq!(peers.len(), PEERS);
        let expected = future.then_some(deadline);
        // Warm the same production poll once; cold invalidation is retained as
        // a separate profile rather than hidden in the unchanged-queue result.
        assert_eq!(peers.copies(&socket, true, &[]), expected);
        let mut samples = Vec::new();
        for sample in 0..SAMPLES {
            let mut results = Vec::with_capacity(POLLS);
            let began = std::time::Instant::now();
            for _ in 0..POLLS {
                if invalidate {
                    for peer in peers.iter_mut() {
                        std::hint::black_box(peer.recent_mut());
                    }
                }
                results.push(std::hint::black_box(&mut peers).copies(&socket, true, &[]));
            }
            let elapsed = began.elapsed();
            assert!(results.iter().all(|value| *value == expected));
            samples.push(
                serde_json::json!({"sample":sample,"elapsed_ns":elapsed.as_nanos(),"polls":POLLS}),
            );
        }
        profiles.push(serde_json::json!({"profile":name,"samples":samples}));
    }
    let report = serde_json::json!({
        "scope":"direct production copy-poll bookkeeping only; no transport, terminal, timer publication or physical sends",
        "machine":machine.trim(),"cores":std::thread::available_parallelism().unwrap().get(),"worker_threads":1,
        "peers":PEERS,"retained_datagrams_per_peer":MAX_DATAGRAMS,"opaque_bytes_per_datagram":32,
        "samples_per_profile":SAMPLES,"polls_per_sample":POLLS,
        "peer_inline_bytes":std::mem::size_of::<Peer>(),"recent_inline_bytes":std::mem::size_of::<Recent>(),"datagram_inline_bytes":std::mem::size_of::<Datagram>(),
        "layout_excludes_heap_payload_and_allocator":true,"load_start":load_start.trim(),"load_end":std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        "profiles":profiles
    });
    if let Some(directory) = std::env::var_os("INFRATERNAL_MESH_PROOF_SCRATCH") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("copy-poll-1000.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
    println!("{report}");
}

/// An idle scan, oldest-entry eviction and a later enrolled replay must not
/// hide new work. Physical ciphertext repeats on return are intentional;
/// authenticated stream tests separately verify plaintext deduplication.
#[tokio::test]
async fn history_mutation_after_an_idle_poll_still_sends_every_due_datagram() {
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let logical = receiver.local_addr().unwrap();
    let alternate = SocketAddr::new("127.0.0.2".parse().unwrap(), logical.port());
    let socket = quinn::TokioRuntime
        .wrap_udp_socket(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    let source = socket.local_addr().unwrap();
    let mut writable = socket.clone().create_io_poller();
    std::future::poll_fn(|cx| writable.as_mut().poll_writable(cx))
        .await
        .unwrap();
    let mut peers = Peers::default();
    assert!(peers.insert(1, logical, alternate));
    {
        let peer = peers.get_mut(logical).unwrap();
        for value in 0..MAX_DATAGRAMS {
            peer.recent_mut().keep(&Transmit {
                destination: logical,
                contents: &[u8::try_from(value).unwrap(); 32],
                ecn: None,
                segment_size: None,
                src_ip: None,
            });
        }
    }
    assert!(peers.copies(socket.as_ref(), true, &[]).is_none());
    {
        let peer = peers.get_mut(logical).unwrap();
        let recent = peer.recent_mut();
        recent.keep_copying(
            &Transmit {
                destination: logical,
                contents: b"new-copy",
                ecn: None,
                segment_size: None,
                src_ip: None,
            },
            true,
        );
        // Publish the already-due entry directly: this tests scheduling/data
        // correctness without imposing a physical wall-clock timing threshold.
        recent.datagrams.back_mut().unwrap().copy_at = Some(tokio::time::Instant::now());
    }
    assert!(peers.copies(socket.as_ref(), true, &[]).is_none());
    let mut bytes = [0; 64];
    let (count, address) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        receiver.recv_from(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!((&bytes[..count], address), (&b"new-copy"[..], source));
    assert!(peers.copies(socket.as_ref(), true, &[]).is_none());
    peers.get_mut(logical).unwrap().recent_mut().replay(None);
    assert!(peers.copies(socket.as_ref(), true, &[]).is_some());
    for value in 1_u8..=32 {
        let (count, address) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            receiver.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(address, source);
        assert_eq!(&bytes[..count], &[value; 32]);
    }
    assert_eq!(
        receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "one poll exceeded the32-send budget"
    );
    assert!(peers.copies(socket.as_ref(), true, &[]).is_none());
    for value in 33_u8..64 {
        let (count, address) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            receiver.recv_from(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(address, source);
        assert_eq!(&bytes[..count], &[value; 32]);
    }
    // The newly inserted backup already arrived once above. Only the 63
    // uncopied legacy originals belong to this explicit recovery.
    assert!(peers.copies(socket.as_ref(), true, &[]).is_none());
    assert!(peers.get(logical).unwrap().recent().datagrams.is_empty());
    assert_eq!(
        receiver.try_recv_from(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}
