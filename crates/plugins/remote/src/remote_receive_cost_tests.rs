//! Measures trusted repeated mesh-ingress bookkeeping with bounded histories (#201, D243, D263).
use super::*;
use crate::remote_peer_routes::MeshRoute;
use std::net::Ipv4Addr;

/// This calls the production receive adapter with public opaque fixtures. It
/// measures neither QUIC authentication nor end-to-end terminal delivery.
#[tokio::test(flavor = "current_thread")]
#[ignore = "Component timing on the authorized perf VM under its fair lock; not transport acceptance."]
async fn repeated_mesh_ingress_cost_at_one_thousand_retained_histories() {
    const PEERS: u16 = 1000;
    const SAMPLES: usize = 31;
    const ROUNDS: usize = 10;
    let machine = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap();
    assert_eq!(machine.trim(), "infraternal-perf-test");
    let load_start = std::fs::read_to_string("/proc/loadavg").unwrap();
    let bindings = Bindings::new(
        quinn::Runtime::wrap_udp_socket(
            &quinn::TokioRuntime,
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        )
        .unwrap(),
    );
    let mut leases = Vec::new();
    for index in 0..PEERS {
        let logical = SocketAddr::new("127.0.0.3".parse().unwrap(), 10000 + index);
        let alternate = SocketAddr::new("127.0.0.4".parse().unwrap(), logical.port());
        leases.push(bindings.route_peer(logical, alternate).unwrap());
        let mut peers = bindings.peers.lock().unwrap();
        let peer = peers.get_mut(logical).unwrap();
        peer.physical = alternate;
        peer.mesh = Some(MeshRoute {
            binding: None,
            local: None,
        });
        for value in 0..64_u8 {
            peer.recent_mut().keep(&Transmit {
                destination: logical,
                contents: &[value; 32],
                ecn: None,
                segment_size: None,
                src_ip: None,
            });
        }
    }
    let history = bindings.retained_history().unwrap();
    assert_eq!(
        history,
        [usize::from(PEERS) * 64, usize::from(PEERS) * 2048, 0, 0]
    );
    let mut samples = Vec::new();
    // Warm fingerprint storage once. Every later batch repeats one known
    // ciphertext; a duplicate still updates coordinates without choosing a route.
    for sample in 0..=SAMPLES {
        let began = std::time::Instant::now();
        for _ in 0..ROUNDS {
            for index in 0..PEERS {
                let mut contents = [7_u8; 32];
                let buffers = [IoSliceMut::new(&mut contents)];
                let mut metadata = [RecvMeta {
                    addr: SocketAddr::new(Ipv4Addr::new(127, 0, 0, 4).into(), 10000 + index),
                    len: 32,
                    stride: 32,
                    dst_ip: None,
                    ..RecvMeta::default()
                }];
                bindings.receive_peer(None, &buffers, &mut metadata);
                std::hint::black_box(metadata);
            }
        }
        let elapsed = began.elapsed();
        if sample != 0 {
            samples.push(serde_json::json!({"sample":sample-1,"elapsed_ns":elapsed.as_nanos(),"callbacks":usize::from(PEERS)*ROUNDS}));
        }
    }
    assert_eq!(bindings.retained_history().unwrap(), history);
    let report = serde_json::json!({
        "scope":"production adapter callback only; repeated trusted physical coordinates and ciphertext; no authentication or physical IO",
        "machine":machine.trim(),"cores":std::thread::available_parallelism().unwrap().get(),
        "peers":PEERS,"retained_datagrams_per_peer":64,"opaque_bytes_per_datagram":32,
        "samples":samples,"load_start":load_start.trim(),
        "load_end":std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
    });
    if let Some(directory) = std::env::var_os("INFRATERNAL_MESH_PROOF_SCRATCH") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("repeated-mesh-ingress-1000.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .unwrap();
    }
    println!("{report}");
}
