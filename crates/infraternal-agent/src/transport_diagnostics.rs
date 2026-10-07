//! Local transport diagnostics at 300 ms simulated RTT and 1000 retained connection pairs; not pinned performance acceptance or live-session proof, #78.

use crate::{
    remote_quic, remote_tls,
    remote_tls::tests::{leaf, root},
};
use std::{
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
async fn delayed_copy(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut bytes = vec![0; 16 * 1024];
    loop {
        let n = reader.read(&mut bytes).await?;
        if n == 0 {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        writer.write_all(&bytes[..n]).await?;
    }
}
async fn tcp_proxy(upstream: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
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
async fn udp_proxy(upstream: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = vec![0; 65535];
        let mut client = None;
        let mut jobs = JoinSet::new();
        loop {
            tokio::select! {
                received=socket.recv_from(&mut bytes)=>{
                    let (n,from)=received.unwrap();
                    let target=if from==upstream {client} else {client=Some(from);Some(upstream)};
                    if let Some(target)=target {
                        let bytes=bytes[..n].to_vec();let socket=socket.clone();
                        jobs.spawn(async move {tokio::time::sleep(Duration::from_millis(150)).await;let _=socket.send_to(&bytes,target).await;});
                    }
                }
                _=jobs.join_next(),if !jobs.is_empty()=>{}
            }
        }
    });
    (address, task)
}

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
