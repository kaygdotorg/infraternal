//! Local transport diagnostics at 300 ms simulated RTT and 1000 retained connection pairs; not pinned performance acceptance or live-session proof, #78.

use crate::{
    remote_quic, remote_tls,
    remote_tls::tests::{leaf, root},
};
use infraternal_plugin_remote::remote_path_socket::PathSocket;
use quinn::{AsyncUdpSocket as _, Runtime as _};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
};

/// Resident memory of this process in KiB, read from `/proc/self/status`.
/// Panics if the file cannot be read (diagnostic code only).
fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}
/// CPU time this process has used so far (user plus system) in clock ticks,
/// read from `/proc/self/stat`.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}
/// Prints one `transport_diagnostic` line. Timing percentiles (p50, p99) come
/// from `timings`, which is sorted in place. `baseline` and `retained` are RSS in
/// KiB before and after holding 1000 connection pairs; `cpu` is the CPU ticks
/// spent connecting them. The machine name and load average are included so
/// readings can be judged later.
fn report(kind: &str, timings: &mut [u128], baseline: u64, retained: u64, cpu: u64) {
    timings.sort_unstable();
    println!(
        "transport_diagnostic kind={kind} simulated_rtt_ms=300 handshake_n={} admitted_p50_us={} admitted_p99_us={} connection_pairs=1000 baseline_rss_kib={baseline} retained_rss_kib={retained} combined_client_server_delta_kib_per_pair={} combined_delta_kib_at1000={} connect_cpu_ticks={cpu} machine={} load={}",
        timings.len(),
        timings[timings.len() / 2],
        timings[(timings.len() * 99 / 100).min(timings.len() - 1)],
        f64::from(u32::try_from(retained.saturating_sub(baseline)).unwrap()) / 1000.0,
        retained.saturating_sub(baseline),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
/// Copies `reader` to `writer`, delaying every chunk by 150 ms to imitate half
/// of a 300 ms round trip. Each chunk's delay starts when it arrives, and at
/// most 64 chunks wait at once, which bounds memory and pushes back on the
/// sender. At end of input it flushes everything pending, then shuts `writer`
/// down. Returns the first I/O error.
pub(crate) async fn delayed_copy(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut bytes = vec![0; 16 * 1024];
    let mut pending = VecDeque::<(tokio::time::Instant, Vec<u8>)>::new();
    let mut eof = false;
    loop {
        if eof && pending.is_empty() {
            return writer.shutdown().await;
        }
        let deadline = pending
            .front()
            .map_or_else(tokio::time::Instant::now, |(deadline, _)| *deadline);
        tokio::select! {
            biased;
            ()=tokio::time::sleep_until(deadline),if !pending.is_empty()=>{
                let (_,payload) = pending.pop_front().unwrap();
                // Complete each write outside select: cancelling a partial
                // write_all on a new read would duplicate its already-sent prefix.
                writer.write_all(&payload).await?;
            }
            count=reader.read(&mut bytes),if !eof && pending.len()<64=>{
                let count = count?;
                if count==0 { eof=true; } else {
                    // Flight time starts when the chunk arrives, independently
                    // of earlier chunks. A 1 MiB FIFO bounds pressure and flushes
                    // all retained bytes before forwarding a half-close.
                    pending.push_back((tokio::time::Instant::now()+Duration::from_millis(150),bytes[..count].to_vec()));
                }
            }
        }
    }
}

/// A TCP relay to `upstream` on an ephemeral loopback port; see `tcp_proxy_at`.
async fn tcp_proxy(upstream: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    tcp_proxy_at(upstream, "127.0.0.1:0".parse().unwrap()).await
}
/// Starts a TCP relay listening on `address` that forwards to `upstream` with
/// 300 ms of added round-trip time: an extra 300 ms before each connect, plus
/// `delayed_copy` in both directions. Returns the bound address and the task;
/// abort the task to stop the relay.
pub(crate) async fn tcp_proxy_at(
    upstream: SocketAddr,
    address: SocketAddr,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind(address).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                incoming=listener.accept()=>{
                    let (socket,_)=incoming.unwrap();
                    jobs.spawn(async move {
                        // Emulate the extra TCP connect RTT as well as TLS payload RTT.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        let peer=TcpStream::connect(upstream).await.unwrap();
                        socket.set_nodelay(true).unwrap();peer.set_nodelay(true).unwrap();
                        let (ar,aw)=socket.into_split();let (br,bw)=peer.into_split();
                        let _=tokio::try_join!(delayed_copy(ar,bw),delayed_copy(br,aw));
                    });
                }
                _=jobs.join_next(),if !jobs.is_empty()=>{}
            }
        }
    });
    (address, task)
}
/// Sends one datagram to `target` after 150 ms. Holding `permit` until the send
/// finishes bounds how many datagrams can be in flight.
async fn delayed_datagram(
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    bytes: Vec<u8>,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let _permit = permit;
    tokio::time::sleep(Duration::from_millis(150)).await;
    let _ = socket.send_to(&bytes, target).await;
}
/// Forwards replies from upstream (read on `peer`) back to one `client` through
/// `front`, each after 150 ms. When all in-flight slots in `pending` are taken
/// the reply is dropped, which QUIC treats as ordinary packet loss.
async fn udp_replies(
    peer: Arc<UdpSocket>,
    front: Arc<UdpSocket>,
    client: SocketAddr,
    pending: Arc<tokio::sync::Semaphore>,
) {
    let mut bytes = vec![0; 65535];
    let mut sends = JoinSet::new();
    loop {
        tokio::select! {
            received=peer.recv(&mut bytes)=>{
                let count = match received {
                    Ok(count) => count,
                    Err(error) if error.kind()==io::ErrorKind::ConnectionRefused => continue,
                    Err(_) => return,
                };
                if let Ok(permit) = pending.clone().try_acquire_owned() {
                    sends.spawn(delayed_datagram(front.clone(),client,bytes[..count].to_vec(),permit));
                }
            }
            _=sends.join_next(),if !sends.is_empty()=>{}
        }
    }
}
/// Starts a UDP relay on an ephemeral loopback port that forwards to `upstream`
/// with 300 ms added round-trip time. Returns the bound address and the task.
pub(crate) async fn udp_proxy(upstream: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    udp_proxy_on(socket, upstream)
}

/// Start a relay on an already reserved socket so a fixture can own both
/// transport ports before any dial races begin.
pub(crate) fn udp_proxy_on(
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
) -> (SocketAddr, JoinHandle<()>) {
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        let mut peers = HashMap::<SocketAddr, Arc<UdpSocket>>::new();
        let pending = Arc::new(tokio::sync::Semaphore::new(4096));
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                received=socket.recv_from(&mut bytes)=>{
                    let (count,client)=received.unwrap();
                    // A separate upstream socket fixes reply ownership even when
                    // supervisors restart with a different local UDP address.
                    if !peers.contains_key(&client) {
                        if peers.len()>=1024 { continue; }
                        let peer = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        peer.connect(upstream).await.unwrap();
                        jobs.spawn(udp_replies(peer.clone(),socket.clone(),client,pending.clone()));
                        peers.insert(client,peer);
                    }
                    // Bound delayed ciphertext rather than retaining an unlimited
                    // flood. QUIC treats exhausted relay capacity as packet loss.
                    if let Ok(permit) = pending.clone().try_acquire_owned() {
                        jobs.spawn(delayed_datagram(peers[&client].clone(),upstream,bytes[..count].to_vec(),permit));
                    }
                }
                _=jobs.join_next(),if !jobs.is_empty()=>{}
            }
        }
    });
    (address, task)
}

/// Diagnostic: times 25 TCP+TLS handshakes through the 300 ms relay, then holds
/// 1000 direct connection pairs and reports their memory and CPU cost. Ignored by
/// default; run alone on a quiet machine.
#[tokio::test]
#[ignore = "diagnostic only; run alone without build or browser overlap"]
async fn tcp_300ms_and_1000_connection_pairs() {
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let server =
        remote_tls::server_config(&server_identity, std::slice::from_ref(&ca.certificate)).unwrap();
    let client =
        remote_tls::client_config(&client_identity, std::slice::from_ref(&ca.certificate)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let direct = listener.local_addr().unwrap();
    let (proxy, task) = tcp_proxy(direct).await;
    let mut timings = Vec::new();
    for _ in 0..25 {
        let start = Instant::now();
        let (a, b) = tokio::join!(remote_tls::dial(proxy, "localhost", &client), async {
            remote_tls::accept(listener.accept().await.unwrap().0, &server).await
        });
        timings.push(start.elapsed().as_micros());
        drop(a.unwrap());
        drop(b.unwrap());
    }
    task.abort();
    let _ = task.await;
    let baseline = rss();
    let cpu = cpu_ticks();
    let mut retained = Vec::new();
    for _ in 0..1000 {
        let (a, b) = tokio::join!(remote_tls::dial(direct, "localhost", &client), async {
            remote_tls::accept(listener.accept().await.unwrap().0, &server).await
        });
        retained.push((a.unwrap(), b.unwrap()));
    }
    report("tcp_tls", &mut timings, baseline, rss(), cpu_ticks() - cpu);
    drop(retained);
}

/// Diagnostic: the same measurement as the TCP one, over QUIC. Ignored by
/// default; run alone on a quiet machine.
#[tokio::test]
#[ignore = "diagnostic only; run alone without build or browser overlap"]
async fn quic_300ms_and_1000_connection_pairs() {
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(
        remote_quic::client_config(&client_identity, &[ca.certificate]).unwrap(),
    );
    let direct = server.local_addr().unwrap();
    let (proxy, task) = udp_proxy(direct).await;
    let mut timings = Vec::new();
    for _ in 0..25 {
        let start = Instant::now();
        let (a, b) = tokio::join!(client.connect(proxy, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        });
        timings.push(start.elapsed().as_micros());
        let a = a.unwrap();
        let b = b.unwrap();
        a.close(0u32.into(), b"");
        b.close(0u32.into(), b"");
    }
    task.abort();
    let _ = task.await;
    let baseline = rss();
    let cpu = cpu_ticks();
    let mut retained = Vec::new();
    for _ in 0..1000 {
        let (a, b) = tokio::join!(client.connect(direct, "localhost").unwrap(), async {
            server.accept().await.unwrap().await
        });
        retained.push((a.unwrap(), b.unwrap()));
    }
    report("quic_bbr", &mut timings, baseline, rss(), cpu_ticks() - cpu);
    for (a, b) in retained {
        a.close(0u32.into(), b"");
        b.close(0u32.into(), b"");
    }
    server.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
}

/// Measure the crypto/transport path with an exact bounded 50 MiB payload.
/// Connection establishment is excluded; the receiver checks every byte before
/// returning a completion Ack, so buffering alone cannot count as throughput.
/// Two workers represent the separately scheduled server/host processes: one
/// reactor for both peers and the relay introduces artificial UDP burst loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "size investigation diagnostic; run alone without build or browser overlap"]
async fn quic_bulk_50m_exact_bytes() {
    measure_quic_bulk(None).await;
}

/// A private kernel-latency namespace separates socket configuration from the
/// existing relay's explicitly documented artificial burst loss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Exact 50MiB kernel-latency control on the perf VM in an owned network namespace."]
async fn quic_bulk_50m_kernel_latency() {
    let original =
        std::env::var("INFRATERNAL_BULK_HOST_NETNS").expect("owned network namespace required");
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net")
            .unwrap()
            .to_string_lossy(),
        original
    );
    measure_quic_bulk(Some(300)).await;
}

/// Runs the 50 MiB QUIC transfer and reports throughput. `kernel_rtt` is the
/// round trip imposed by a kernel network namespace in milliseconds, or `None`
/// to use the userspace delaying relay. Panics unless the host name is the
/// authorized perf VM, since throughput numbers from other machines mean nothing.
#[allow(clippy::too_many_lines)]
async fn measure_quic_bulk(kernel_rtt: Option<u32>) {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test",
        "physical throughput belongs on the authorized perf VM"
    );
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let server = quinn::Endpoint::server(
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let direct = server.local_addr().unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dedicated = std::env::var_os("INFRATERNAL_BULK_DEDICATED_CLIENT").is_some();
    let path = if dedicated {
        PathSocket::from_udp(socket, direct, &quinn::TokioRuntime).unwrap()
    } else {
        PathSocket::new(quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(), direct)
    };
    let receive_segments = path.max_receive_segments();
    let mut client = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        path,
        Arc::new(quinn::TokioRuntime),
    )
    .unwrap();
    client.set_default_client_config(
        remote_quic::client_config(&client_identity, &[ca.certificate]).unwrap(),
    );
    let reverse = std::env::var_os("INFRATERNAL_BULK_REVERSE").is_some();
    let direction = if reverse {
        "server_to_host"
    } else {
        "host_to_server"
    };
    for rtt in kernel_rtt.map_or_else(|| vec![0, 300], |rtt| vec![rtt]) {
        let proxy = if rtt == 300 && kernel_rtt.is_none() {
            Some(udp_proxy(direct).await)
        } else {
            None
        };
        let address = proxy.as_ref().map_or(direct, |(address, _)| *address);
        let samples = if rtt == 0 || kernel_rtt.is_some() {
            3
        } else {
            1
        };
        for sample in 0..samples {
            let (a, b) = tokio::join!(client.connect(address, "localhost").unwrap(), async {
                server.accept().await.unwrap().await
            });
            let a = a.unwrap();
            let b = b.unwrap();
            if kernel_rtt.is_some() {
                assert!(
                    a.rtt() >= Duration::from_millis(250),
                    "kernel RTT control was not applied"
                );
            }
            let started = Instant::now();
            let cpu = cpu_ticks();
            let payload: Vec<u8> = (0..16_384)
                .map(|n| u8::try_from(n % 251).unwrap())
                .collect();
            let bytes = 50 * 1024 * 1024;
            let transfer = if reverse {
                exact_bulk(&b, &a, &payload, bytes)
            } else {
                exact_bulk(&a, &b, &payload, bytes)
            };
            if tokio::time::timeout(Duration::from_secs(90), transfer)
                .await
                .is_err()
            {
                println!(
                    "bulk_timeout rtt_ms={rtt} client={:?} server={:?}",
                    a.stats(),
                    b.stats()
                );
                panic!("exact transfer diagnostic exceeded its bounded deadline");
            }
            println!(
                "bulk_diagnostic transport=quic dedicated_client={dedicated} receive_segments={receive_segments} direction={direction} rtt_ms={rtt} kernel_latency={} sample={sample} bytes={bytes} elapsed_us={} cpu_ticks={} rss_kib={} application_missing=0 application_duplicates=0 load={}",
                kernel_rtt.is_some(),
                started.elapsed().as_micros(),
                cpu_ticks() - cpu,
                rss(),
                std::fs::read_to_string("/proc/loadavg").unwrap().trim()
            );
            a.close(0u32.into(), b"");
            b.close(0u32.into(), b"");
        }
        if let Some((_, task)) = proxy {
            task.abort();
            let _ = task.await;
        }
    }
    server.close(0u32.into(), b"");
    client.close(0u32.into(), b"");
}

/// Sends `bytes` bytes (repeats of `payload`) from `a` over one stream. `b`
/// checks every byte against the pattern and replies with the count it received;
/// panics on any mismatch.
async fn exact_bulk(a: &quinn::Connection, b: &quinn::Connection, payload: &[u8], bytes: usize) {
    tokio::join!(
        async {
            let (mut send, mut receive) = a.open_bi().await.unwrap();
            for _ in 0..bytes / payload.len() {
                send.write_all(payload).await.unwrap();
            }
            send.finish().unwrap();
            let mut ack = [0; 8];
            receive.read_exact(&mut ack).await.unwrap();
            assert_eq!(u64::from_le_bytes(ack), u64::try_from(bytes).unwrap());
        },
        async {
            let (mut send, mut receive) = b.accept_bi().await.unwrap();
            let mut chunk = vec![0; 16_384];
            let mut count = 0;
            while let Some(n) = receive.read(&mut chunk).await.unwrap() {
                for (i, value) in chunk[..n].iter().enumerate() {
                    assert_eq!(*value, payload[(count + i) % payload.len()]);
                }
                count += n;
            }
            assert_eq!(count, bytes);
            send.write_all(&u64::try_from(count).unwrap().to_le_bytes())
                .await
                .unwrap();
            send.finish().unwrap();
        }
    );
}
