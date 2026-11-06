//! Measures the current probe and ciphertext-copy profiles on 1,000 authenticated QUIC transports, including adapter UDP sends [243,263], #201.
//!
//! This is a loopback transport cohort, not 1,000 daemons or kernel mesh nodes.
//! The source-address adapter exercises the real `PathSocket` and `Bindings` paths
//! without introducing a second client socket or an artificial traffic worker.
use super::*;
use infraternal_plugin_remote::{remote_bindings::Bindings, remote_path_socket::PathSocket};
use quinn::{
    AsyncUdpSocket, Runtime as _, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    fmt,
    io::IoSliceMut,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

#[path = "remote_mesh_copy_cost_tests/receive_diagnostic.rs"]
mod receive_diagnostic;
use receive_diagnostic::{DiagnosticWatch, ReceiveDiagnostic};

const CONNECTIONS: usize = 1000;
const WINDOWS: usize = 31;
const WINDOW: Duration = Duration::from_millis(250);

/// Before a fresh alias has selected mesh, enrolled post-handshake traffic can
/// queue dormant alternative replies. No scheduled copy or enrolled recovery
/// may predate the ramp; entry and byte counts remain in the raw receipt.
fn fresh_history_is_dormant(history: [usize; 4]) -> bool {
    history[2] == 0 && history[3] == 0
}

#[test]
fn fresh_admission_accepts_dormant_replies_but_refuses_pending_recovery() {
    assert!(fresh_history_is_dormant([0; 4]));
    assert!(fresh_history_is_dormant([3, 4356, 0, 0]));
    assert!(!fresh_history_is_dormant([1, 32, 1, 0]));
    assert!(!fresh_history_is_dormant([1, 32, 0, 1]));
}

type Watchers = tokio::task::JoinSet<(
    usize,
    io::Result<()>,
    Duration,
    quinn::ConnectionStats,
    u64,
    Option<serde_json::Value>,
)>;

/// Keep the cold admission/warmup failures separate from sampling failures;
/// an exited guard never silently reduces the claimed measured cohort.
fn finished_watchers(watchers: &mut Watchers) -> Vec<serde_json::Value> {
    let mut finished = Vec::new();
    while let Some(result) = watchers.try_join_next() {
        finished.push(match result {
            Ok((index, result, elapsed, stats, mesh_batches, diagnostic)) => {
                let mut receipt = serde_json::json!({
                "connection":index,
                "result":result.as_ref().map_or_else(|error| format!("{:?}", error.kind()), |()| "unexpected_success".into()),
                "probe_failure":result.as_ref().err().and_then(|error|error.get_ref()).and_then(|error|error.downcast_ref::<remote_quic::ProbeFailure>()),
                "lifetime_us":elapsed.as_micros(),
                "rtt_us":stats.path.rtt.as_micros(),
                "authenticated_rx_acks":stats.frame_rx.acks,
                "client_quinn_tx_datagrams":stats.udp_tx.datagrams,
                "client_quinn_rx_datagrams":stats.udp_rx.datagrams,
                "mesh_received_batches":mesh_batches,
                });
                if let Some(diagnostic) = diagnostic {
                    receipt["receive_diagnostic"] = diagnostic;
                }
                receipt
            },
            Err(error) => serde_json::json!({"join_error":error.to_string()}),
        });
    }
    finished
}

/// Read only counters for sockets this cohort owns. Global UDP counters include
/// unrelated services; per-socket drops establish whether this fixture lost
/// packets locally without turning another service's traffic into evidence.
fn owned_udp_drops(server: &[SocketAddr], clients: &[SocketAddr]) -> serde_json::Value {
    let clients: std::collections::HashSet<_> = clients.iter().copied().collect();
    let rows = std::fs::read_to_string("/proc/net/udp").unwrap();
    let mut server_drops = 0_u64;
    let mut client_drops = 0_u64;
    let mut server_sockets = 0;
    let mut client_sockets = 0;
    for row in rows.lines().skip(1) {
        let mut fields = row.split_ascii_whitespace();
        let Some((ip, port)) = fields.nth(1).and_then(|field| field.split_once(':')) else {
            continue;
        };
        let (Ok(ip), Ok(port)) = (u32::from_str_radix(ip, 16), u16::from_str_radix(port, 16))
        else {
            continue;
        };
        let address = SocketAddr::new(Ipv4Addr::from(ip.to_le_bytes()).into(), port);
        let Some(drops) = fields.last().and_then(|field| field.parse::<u64>().ok()) else {
            continue;
        };
        if server.contains(&address) {
            server_sockets += 1;
            server_drops += drops;
        } else if clients.contains(&address) {
            client_sockets += 1;
            client_drops += drops;
        }
    }
    serde_json::json!({"server_drops":server_drops,"client_drops":client_drops,"server_sockets":server_sockets,"client_sockets":client_sockets})
}

#[test]
fn udp_drop_receipt_counts_only_owned_live_sockets() {
    let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let receipt = owned_udp_drops(
        &[server.local_addr().unwrap()],
        &[client.local_addr().unwrap()],
    );
    assert_eq!(receipt["server_sockets"], 1);
    assert_eq!(receipt["client_sockets"], 1);
    assert_eq!(receipt["server_drops"], 0);
    assert_eq!(receipt["client_drops"], 0);
}

fn watch(
    watchers: &mut Watchers,
    index: usize,
    connection: quinn::Connection,
    path: Arc<PathSocket>,
    interval: Duration,
    margin: Duration,
    diagnostic: Option<DiagnosticWatch>,
) {
    watchers.spawn(async move {
        let started = tokio::time::Instant::now();
        let result = remote_quic::path_interrupted(&connection, &path, interval, margin).await;
        (
            index,
            result,
            started.elapsed(),
            connection.stats(),
            path.mesh_datagrams(),
            diagnostic.map(DiagnosticWatch::failure),
        )
    });
}

#[derive(Debug, Default)]
struct Traffic {
    bytes: AtomicU64,
    datagrams: AtomicU64,
    enrolled_bytes: AtomicU64,
    enrolled_datagrams: AtomicU64,
}
impl Traffic {
    fn snapshot(&self) -> (u64, u64) {
        (
            self.bytes.load(Ordering::Relaxed),
            self.datagrams.load(Ordering::Relaxed),
        )
    }
    fn enrolled_snapshot(&self) -> (u64, u64) {
        (
            self.enrolled_bytes.load(Ordering::Relaxed),
            self.enrolled_datagrams.load(Ordering::Relaxed),
        )
    }
}

/// Counts successful physical sends, including copies invisible to Quinn's
/// connection counters. Source selection models one host using two addresses
/// with the same UDP port; only the trusted destination chooses the source.
struct CountedSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    traffic: Arc<Traffic>,
    client: bool,
    record_sends: bool,
}
impl fmt::Debug for CountedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CountedSocket")
            .finish_non_exhaustive()
    }
}
impl AsyncUdpSocket for CountedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.socket.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let source = if self.client {
            let last = match transmit.destination.ip() {
                IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST => 3,
                IpAddr::V4(ip) if ip == Ipv4Addr::new(127, 0, 0, 2) => 4,
                _ => return Err(io::ErrorKind::InvalidInput.into()),
            };
            Some(Ipv4Addr::new(127, 0, 0, last).into())
        } else {
            transmit.src_ip
        };
        self.socket.try_send(&Transmit {
            src_ip: source,
            ..*transmit
        })?;
        if !self.record_sends {
            return Ok(());
        }
        let datagrams = transmit
            .segment_size
            .map_or(1, |segment| transmit.contents.len().div_ceil(segment));
        self.traffic.bytes.fetch_add(
            u64::try_from(transmit.contents.len()).unwrap(),
            Ordering::Relaxed,
        );
        self.traffic
            .datagrams
            .fetch_add(u64::try_from(datagrams).unwrap(), Ordering::Relaxed);
        if matches!(transmit.destination.ip(), IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST || ip == Ipv4Addr::new(127, 0, 0, 3))
        {
            self.traffic.enrolled_bytes.fetch_add(
                u64::try_from(transmit.contents.len()).unwrap(),
                Ordering::Relaxed,
            );
            self.traffic
                .enrolled_datagrams
                .fetch_add(u64::try_from(datagrams).unwrap(), Ordering::Relaxed);
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.socket.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}

fn counted(
    socket: Arc<dyn AsyncUdpSocket>,
    traffic: &Arc<Traffic>,
    client: bool,
    record_sends: bool,
) -> Arc<dyn AsyncUdpSocket> {
    Arc::new(CountedSocket {
        socket,
        traffic: traffic.clone(),
        client,
        record_sends,
    })
}

/// Keep physical counters below the production path adapter, including copies,
/// while using the same fresh-socket registration as an outgoing host.
#[derive(Debug)]
struct CountedRuntime {
    delegate: Arc<dyn quinn::Runtime>,
    traffic: Arc<Traffic>,
    record_sends: bool,
}
impl quinn::Runtime for CountedRuntime {
    fn now(&self) -> std::time::Instant {
        self.delegate.now()
    }
    fn new_timer(&self, at: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        self.delegate.new_timer(at)
    }
    fn spawn(&self, task: Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        self.delegate.spawn(task);
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Ok(counted(
            self.delegate.wrap_udp_socket(socket)?,
            &self.traffic,
            true,
            self.record_sends,
        ))
    }
}

fn counted_server(
    socket: Arc<dyn AsyncUdpSocket>,
    traffic: &Arc<Traffic>,
    diagnostic: Option<&Arc<ReceiveDiagnostic>>,
    index: usize,
    record_sends: bool,
) -> Arc<dyn AsyncUdpSocket> {
    let socket = counted(socket, traffic, false, record_sends);
    diagnostic.map_or_else(
        || socket.clone(),
        |diagnostic| diagnostic.wrap(socket.clone(), index),
    )
}

fn system_unit(name: &str) -> u64 {
    std::str::from_utf8(
        &std::process::Command::new("getconf")
            .arg(name)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .parse()
    .unwrap()
}

#[tokio::test]
async fn physical_counters_include_both_source_paths() {
    for record_sends in [true, false] {
        physical_counter_paths(record_sends).await;
    }
}

/// Accounting modes preserve the exact datagrams and physical source mapping.
async fn physical_counter_paths(record_sends: bool) {
    let enrolled = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mesh = tokio::net::UdpSocket::bind(SocketAddr::new(
        Ipv4Addr::new(127, 0, 0, 2).into(),
        enrolled.local_addr().unwrap().port(),
    ))
    .await
    .unwrap();
    let traffic = Arc::new(Traffic::default());
    let socket = counted(
        quinn::TokioRuntime
            .wrap_udp_socket(std::net::UdpSocket::bind("0.0.0.0:0").unwrap())
            .unwrap(),
        &traffic,
        true,
        record_sends,
    );
    let mut writable = socket.clone().create_io_poller();
    for (receiver, source) in [
        (&enrolled, Ipv4Addr::new(127, 0, 0, 3)),
        (&mesh, Ipv4Addr::new(127, 0, 0, 4)),
    ] {
        let transmit = Transmit {
            destination: receiver.local_addr().unwrap(),
            contents: b"ciphertext",
            ecn: None,
            segment_size: None,
            src_ip: None,
        };
        std::future::poll_fn(|cx| {
            loop {
                match socket.try_send(&transmit) {
                    Ok(()) => return Poll::Ready(Ok(())),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        match writable.as_mut().poll_writable(cx) {
                            Poll::Ready(Ok(())) => {}
                            other => return other,
                        }
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        })
        .await
        .unwrap();
        let mut bytes = [0; 32];
        let (length, address) =
            tokio::time::timeout(Duration::from_secs(5), receiver.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&bytes[..length], b"ciphertext");
        assert_eq!(address.ip(), IpAddr::V4(source));
        assert_eq!(address.port(), socket.local_addr().unwrap().port());
    }
    assert_eq!(
        traffic.snapshot(),
        if record_sends { (20, 2) } else { (0, 0) }
    );
    assert_eq!(
        traffic.enrolled_snapshot(),
        if record_sends { (10, 1) } else { (0, 0) }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Optimized transport-only measurement on the perf VM under its shared benchmark lock."]
async fn mesh_probe_and_copy_cost_at_one_thousand_transports() {
    measure_mesh_probe_and_copy_cost(&[false, true], false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Separate fresh-copy cohort on the perf VM under its shared benchmark lock."]
async fn fresh_copy_from_admission_at_one_thousand_transports() {
    measure_mesh_probe_and_copy_cost(&[true], true, None).await;
}

/// An explicit socket-capacity trial never changes the ordinary production-profile gates.
#[derive(Clone, Copy)]
struct SocketTrial {
    client_gro: bool,
    server_receive_request: usize,
    server_receive_force: bool,
    probe_interval_ms: u64,
    probe_margin_ms: u64,
    record_sends: bool,
}
impl SocketTrial {
    fn capacity(self, socket: &std::net::UdpSocket) -> usize {
        let state = quinn::udp::UdpSocketState::new(socket.into()).unwrap();
        if self.server_receive_request != 0 {
            if self.server_receive_force {
                // This privileged, socket-local control never changes a host
                // sysctl. Record the actual doubled kernel accounting below.
                nix::sys::socket::setsockopt(
                    socket,
                    nix::sys::socket::sockopt::RcvBufForce,
                    &self.server_receive_request,
                )
                .expect("explicit socket-force diagnostic requires CAP_NET_ADMIN");
            } else {
                state
                    .set_recv_buffer_size(socket.into(), self.server_receive_request)
                    .unwrap();
            }
        }
        state.recv_buffer_size(socket.into()).unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Explicit socket-configuration diagnostic on the perf VM; ordinary scale gates stay unchanged."]
async fn socket_configuration_trial_at_one_thousand_transports() {
    assert!(std::env::var_os("INFRATERNAL_MESH_TRIAL_RUNTIME").is_none());
    run_socket_configuration_trial().await;
}

/// Compare scheduling configurations without changing the ordinary scale gates.
#[test]
#[ignore = "Explicit runtime scheduling control on the perf VM; ordinary runtime and guards unchanged."]
fn runtime_configuration_trial_at_one_thousand_transports() {
    let mode = std::env::var("INFRATERNAL_MESH_TRIAL_RUNTIME").unwrap();
    let mut builder = match mode.as_str() {
        "current_thread" => tokio::runtime::Builder::new_current_thread(),
        "split_server" | "split_server_fair" | "split_direct_mesh_no_aliases" => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(3);
            builder
        }
        "four_workers_default" | "four_workers_fair" | "direct_mesh_no_aliases" => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(4);
            builder
        }
        _ => panic!("explicit supported runtime control required"),
    };
    if matches!(mode.as_str(), "four_workers_fair" | "split_server_fair") {
        builder.global_queue_interval(1).event_interval(1);
    }
    builder
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_socket_configuration_trial());
}

/// Parse only explicit diagnostic parameters; the transport measurement owns all guards.
async fn run_socket_configuration_trial() {
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        "infraternal-perf-test"
    );
    let client_gro = match std::env::var("INFRATERNAL_MESH_TRIAL_CLIENT_GRO").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        _ => panic!("explicit trial client receive aggregation required"),
    };
    let server_receive_request =
        match std::env::var("INFRATERNAL_MESH_TRIAL_SERVER_RECEIVE").as_deref() {
            Ok("0") => 0,
            Ok("212992") => 212_992,
            Ok("1048576") => 1_048_576,
            Ok("2097152") => 2_097_152,
            _ => panic!("explicit bounded trial server receive capacity required"),
        };
    let server_receive_force = match std::env::var("INFRATERNAL_MESH_TRIAL_SERVER_FORCE").as_deref()
    {
        Err(_) | Ok("0") => false,
        Ok("1") => true,
        _ => panic!("explicit socket-local force mode required"),
    };
    assert!(server_receive_request <= 212_992 || server_receive_force);
    let (probe_interval_ms, probe_margin_ms) =
        match std::env::var("INFRATERNAL_MESH_TRIAL_PROBE_PROFILE").as_deref() {
            Err(_) | Ok("15-30") => (15, 30),
            Ok("20-25") => (20, 25),
            Ok("25-20") => (25, 20),
            Ok("30-15") => (30, 15),
            _ => panic!("explicit same-envelope probe profile required"),
        };
    let record_sends = match std::env::var("INFRATERNAL_MESH_TRIAL_RECORD_SENDS").as_deref() {
        Err(_) | Ok("1") => true,
        Ok("0") => false,
        _ => panic!("explicit counter-accounting mode required"),
    };
    let trial = Some(SocketTrial {
        client_gro,
        server_receive_request,
        server_receive_force,
        probe_interval_ms,
        probe_margin_ms,
        record_sends,
    });
    match std::env::var("INFRATERNAL_MESH_TRIAL_COHORT").as_deref() {
        Ok("fresh") => measure_mesh_probe_and_copy_cost(&[true], true, trial).await,
        Ok("fresh-no-copy") => measure_mesh_probe_and_copy_cost(&[false], true, trial).await,
        Ok("retained") => measure_mesh_probe_and_copy_cost(&[false, true], false, trial).await,
        _ => panic!("explicit fresh or retained socket trial cohort required"),
    }
}

/// Keep server IO and its tasks on one owned current-thread reactor. The
/// split control uses three client workers plus this one server worker, the
/// same four-worker budget as the shared control. Nothing survives the cohort.
struct OwnedServerRuntime {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl OwnedServerRuntime {
    async fn start<T: Send + 'static>(make: impl FnOnce() -> T + Send + 'static) -> (Self, T) {
        let (sent, ready) = tokio::sync::oneshot::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                // Socket registration must happen here, not on the client
                // reactor before moving the accepting future to this thread.
                assert!(sent.send(make()).is_ok(), "server setup receipt refused");
                let _ = stopped.await;
            });
        });
        let owner = Self {
            stop: Some(stop),
            thread: Some(thread),
        };
        let resources = ready
            .await
            .expect("owned server reactor failed during setup");
        (owner, resources)
    }
}
impl Drop for OwnedServerRuntime {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
            && !std::thread::panicking()
        {
            panic!("owned server reactor failed during the cohort");
        }
    }
}

/// Retain the original same-cohort diagnostic and measure a separately labelled
/// fresh cohort without changing its connections, windows, or health criteria.
async fn measure_mesh_probe_and_copy_cost(
    profiles: &[bool],
    fresh_copy: bool,
    socket_trial: Option<SocketTrial>,
) {
    let direct_mesh_control = socket_trial.is_some()
        && std::env::var("INFRATERNAL_MESH_TRIAL_RUNTIME").is_ok_and(|mode| {
            matches!(
                mode.as_str(),
                "direct_mesh_no_aliases" | "split_direct_mesh_no_aliases"
            )
        });
    assert!(
        !direct_mesh_control || profiles == [false],
        "direct control cannot enable server copies"
    );
    let diagnostic = ReceiveDiagnostic::from_environment();
    let record_sends = socket_trial.is_none_or(|trial| trial.record_sends);
    let ca = root();
    let server_identity = leaf(&ca, true);
    let client_identity = leaf(&ca, false);
    let ticks_per_second = system_unit("CLK_TCK");
    let page_size = system_unit("PAGESIZE");
    let (_, baseline_pages) = usage();
    let client_traffic = Arc::new(Traffic::default());
    let server_traffic = Arc::new(Traffic::default());
    let primary = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let primary_capacity = socket_trial.map(|trial| trial.capacity(&primary));
    let enrolled = primary.local_addr().unwrap();
    let mesh = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), enrolled.port());
    if let Some(diagnostic) = &diagnostic {
        diagnostic.server_addresses(&[enrolled, mesh]);
    }
    let mesh_socket = std::net::UdpSocket::bind(mesh).unwrap();
    let mesh_capacity = socket_trial.map(|trial| trial.capacity(&mesh_socket));
    let server_config =
        remote_quic::server_config(&server_identity, std::slice::from_ref(&ca.certificate))
            .unwrap();
    let server_diagnostic = diagnostic.clone();
    let server_counter = server_traffic.clone();
    let make_server = move || {
        let bindings = Bindings::new(counted_server(
            quinn::TokioRuntime.wrap_udp_socket(primary).unwrap(),
            &server_counter,
            server_diagnostic.as_ref(),
            0,
            record_sends,
        ));
        let lease = bindings
            .lease(counted_server(
                quinn::TokioRuntime.wrap_udp_socket(mesh_socket).unwrap(),
                &server_counter,
                server_diagnostic.as_ref(),
                1,
                record_sends,
            ))
            .unwrap();
        let server = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            bindings.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let listener = server.clone();
        let accepting = tokio::spawn(async move {
            let mut handshakes = tokio::task::JoinSet::new();
            let mut connections = Vec::new();
            while connections.len() < CONNECTIONS {
                tokio::select! {
                    incoming = listener.accept(), if handshakes.len() < 64 => {
                        handshakes.spawn(async move { incoming.unwrap().await.unwrap() });
                    }
                    result = handshakes.join_next(), if !handshakes.is_empty() => connections.push(result.unwrap().unwrap()),
                }
            }
            connections
        });
        (bindings, lease, server, accepting)
    };
    let separate_server = socket_trial.is_some()
        && std::env::var("INFRATERNAL_MESH_TRIAL_RUNTIME").is_ok_and(|mode| {
            matches!(
                mode.as_str(),
                "split_server" | "split_server_fair" | "split_direct_mesh_no_aliases"
            )
        });
    let (_server_runtime, resources) = if separate_server {
        let (owner, resources) = OwnedServerRuntime::start(make_server).await;
        (Some(owner), resources)
    } else {
        (None, make_server())
    };
    let (bindings, lease, server, accepting) = resources;
    let config =
        remote_quic::client_config(&client_identity, std::slice::from_ref(&ca.certificate))
            .unwrap();
    let mut dialing = tokio::task::JoinSet::new();
    let mut connections = Vec::new();
    let mut clients = Vec::new();
    let mut paths = Vec::new();
    let mut drivers = Vec::new();
    let mut peers = Vec::new();
    for index in 0..CONNECTIONS {
        let driver = DialRuntime::new();
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let runtime = CountedRuntime {
            delegate: driver.runtime(),
            traffic: client_traffic.clone(),
            record_sends,
        };
        let path = if socket_trial.is_some_and(|trial| trial.client_gro) {
            PathSocket::new(runtime.wrap_udp_socket(socket).unwrap(), enrolled)
        } else {
            PathSocket::from_udp(socket, enrolled, &runtime).unwrap()
        };
        if direct_mesh_control {
            // Begin on this one physical path during TLS. This control does
            // not test migration or use the server's peer-alias/history layer.
            path.use_mesh(mesh);
        }
        let mut client = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            path.clone(),
            driver.runtime(),
        )
        .unwrap();
        client.set_default_client_config(config.clone());
        let pending = client.connect(enrolled, "localhost").unwrap();
        if !fresh_copy && !direct_mesh_control {
            peers.push(
                bindings
                    .route_peer(
                        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), port),
                        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 4).into(), port),
                    )
                    .unwrap(),
            );
        }
        clients.push(client);
        paths.push(path);
        drivers.push(driver);
        dialing.spawn(async move { (index, pending.await.unwrap()) });
        if dialing.len() >= 8 {
            connections.push(dialing.join_next().await.unwrap().unwrap());
        }
    }
    while let Some(connection) = dialing.join_next().await {
        connections.push(connection.unwrap());
    }
    let accepted = accepting.await.unwrap();
    // This transport-only fixture owns admitted TLS peers directly. Match the
    // production link's responder lifetime before proving any physical path.
    let _proofs: Vec<_> = accepted
        .iter()
        .map(|connection| bindings.connection_proof(connection).unwrap())
        .collect();
    // Completion order differs from socket creation order. Path watchers must
    // own the socket with the connection's actual local UDP port.
    connections.sort_by_key(|(index, _)| *index);
    let connections: Vec<_> = connections
        .into_iter()
        .map(|(_, connection)| connection)
        .collect();
    assert_eq!(accepted.len(), CONNECTIONS);
    if fresh_copy && !direct_mesh_control {
        // All mutual TLS handshakes have completed. Create each fresh alias and
        // enable its existing negotiated-copy flag synchronously before any
        // mesh selection or probe can populate its retained history.
        for path in &paths {
            let port = path.local_addr().unwrap().port();
            let peer = bindings
                .route_peer(
                    SocketAddr::new(Ipv4Addr::new(127, 0, 0, 3).into(), port),
                    SocketAddr::new(Ipv4Addr::new(127, 0, 0, 4).into(), port),
                )
                .unwrap();
            peer.set_backup(true);
            peers.push(peer);
        }
    }
    let mut reports = Vec::new();
    let mut healthy = true;
    let client_addresses: Vec<_> = paths
        .iter()
        .map(|path| path.local_addr().unwrap())
        .collect();
    if let Some(diagnostic) = &diagnostic {
        diagnostic.sample_ports(&client_addresses);
    }
    for &backup in profiles {
        if let Some(diagnostic) = &diagnostic {
            diagnostic.stage(backup, "before");
        }
        // Observe the physical ramp separately: failed guards stop generating
        // probes before steady windows, hiding a startup transmission burst.
        let traffic_before = serde_json::json!({"client":client_traffic.snapshot(),"server":server_traffic.snapshot(),"client_enrolled":client_traffic.enrolled_snapshot(),"server_enrolled":server_traffic.enrolled_snapshot()});
        let udp_drops_before = owned_udp_drops(&[enrolled, mesh], &client_addresses);
        let history_before = bindings.retained_history().unwrap();
        if fresh_copy {
            assert!(
                fresh_history_is_dormant(history_before),
                "fresh peers must have no scheduled copies or enrolled recovery: {history_before:?}"
            );
        }
        for peer in &peers {
            peer.set_backup(backup);
        }
        let ordinary = if backup {
            (Duration::from_millis(15), Duration::from_millis(30))
        } else {
            (Duration::from_millis(100), Duration::from_millis(50))
        };
        // Explicit trials hold cadence constant across copy/no-copy arms;
        // ordinary production-profile measurements retain their own defaults.
        let (interval, margin) = socket_trial.map_or(ordinary, |trial| {
            (
                Duration::from_millis(trial.probe_interval_ms),
                Duration::from_millis(trial.probe_margin_ms),
            )
        });
        let mut watchers = Watchers::new();
        let mut proving = tokio::task::JoinSet::new();
        let mut proof_results = Vec::new();
        let mut proof_failures = 0;
        let admission_started = tokio::time::Instant::now();
        // Match the production lifecycle: a path must return authenticated
        // traffic before its ongoing watchdog starts. Bound the same setup
        // concurrency as TLS joining rather than bursting 1,000 migrations.
        // A successful path starts its guard immediately; ramp-up and warmup
        // failures remain evidence, not a reason to reset or forgive its guard.
        for (index, (connection, path)) in connections.iter().zip(&paths).enumerate() {
            let connection = connection.clone();
            let path = path.clone();
            let since = tokio::time::Instant::now();
            path.use_mesh(mesh);
            path.set_backup(backup);
            remote_quic::probe_liveness(&connection);
            proving.spawn(async move {
                let proved =
                    crate::remote_client::server_path::answered(&connection, &path, since, true)
                        .await;
                (index, proved, since.elapsed(), connection, path)
            });
            if proving.len() >= 8 {
                let (index, proved, elapsed, connection, path) =
                    proving.join_next().await.unwrap().unwrap();
                proof_results.push(serde_json::json!({"connection":index,"proved":proved,"elapsed_us":elapsed.as_micros(),"rtt_us":connection.rtt().as_micros(),"mesh_received_batches":path.mesh_datagrams()}));
                if proved {
                    let observation = diagnostic.as_ref().map(|diagnostic| {
                        diagnostic.watch(index, path.local_addr().unwrap().port(), &accepted)
                    });
                    watch(
                        &mut watchers,
                        index,
                        connection,
                        path,
                        interval,
                        margin,
                        observation,
                    );
                } else {
                    proof_failures += 1;
                }
            }
        }
        while let Some(result) = proving.join_next().await {
            let (index, proved, elapsed, connection, path) = result.unwrap();
            proof_results.push(serde_json::json!({"connection":index,"proved":proved,"elapsed_us":elapsed.as_micros(),"rtt_us":connection.rtt().as_micros(),"mesh_received_batches":path.mesh_datagrams()}));
            if proved {
                let observation = diagnostic.as_ref().map(|diagnostic| {
                    diagnostic.watch(index, path.local_addr().unwrap().port(), &accepted)
                });
                watch(
                    &mut watchers,
                    index,
                    connection,
                    path,
                    interval,
                    margin,
                    observation,
                );
            } else {
                proof_failures += 1;
            }
        }
        let admission_elapsed = admission_started.elapsed();
        let ramp_interruptions = finished_watchers(&mut watchers);
        let traffic_after_ramp = serde_json::json!({"client":client_traffic.snapshot(),"server":server_traffic.snapshot(),"client_enrolled":client_traffic.enrolled_snapshot(),"server_enrolled":server_traffic.enrolled_snapshot()});
        let udp_drops_after_ramp = owned_udp_drops(&[enrolled, mesh], &client_addresses);
        let history_after_ramp = bindings.retained_history().unwrap();
        if let Some(diagnostic) = &diagnostic {
            diagnostic.stage(backup, "after_ramp");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let warmup_interruptions = finished_watchers(&mut watchers);
        let traffic_after_warmup = serde_json::json!({"client":client_traffic.snapshot(),"server":server_traffic.snapshot(),"client_enrolled":client_traffic.enrolled_snapshot(),"server_enrolled":server_traffic.enrolled_snapshot()});
        let udp_drops_after_warmup = owned_udp_drops(&[enrolled, mesh], &client_addresses);
        let history_after_warmup = bindings.retained_history().unwrap();
        if let Some(diagnostic) = &diagnostic {
            diagnostic.stage(backup, "after_warmup");
        }
        let steady_cohort_valid = proof_failures == 0
            && ramp_interruptions.is_empty()
            && warmup_interruptions.is_empty()
            && watchers.len() == CONNECTIONS;
        let load_before = std::fs::read_to_string("/proc/loadavg").unwrap();
        let mut samples = Vec::new();
        let mut false_interruptions = ramp_interruptions.len() + warmup_interruptions.len();
        for window in 0..WINDOWS {
            let (before_ticks, _) = usage();
            let client_before = client_traffic.snapshot();
            let server_before = server_traffic.snapshot();
            let client_enrolled_before = client_traffic.enrolled_snapshot();
            let server_enrolled_before = server_traffic.enrolled_snapshot();
            let started = tokio::time::Instant::now();
            tokio::time::sleep(WINDOW).await;
            let elapsed = started.elapsed();
            let (after_ticks, pages) = usage();
            let client_after = client_traffic.snapshot();
            let server_after = server_traffic.snapshot();
            let client_enrolled_after = client_traffic.enrolled_snapshot();
            let server_enrolled_after = server_traffic.enrolled_snapshot();
            let interruptions = finished_watchers(&mut watchers);
            if let Some(diagnostic) = &diagnostic {
                diagnostic.stage(backup, &format!("window_{window}"));
            }
            false_interruptions += interruptions.len();
            samples.push(serde_json::json!({"window":window,"elapsed_us":elapsed.as_micros(),"cpu_ticks":after_ticks-before_ticks,"resident_bytes":pages*page_size,"resident_delta_bytes":pages.saturating_sub(baseline_pages)*page_size,"client_udp_payload_bytes":client_after.0-client_before.0,"client_udp_datagrams":client_after.1-client_before.1,"server_udp_payload_bytes":server_after.0-server_before.0,"server_udp_datagrams":server_after.1-server_before.1,"client_enrolled_udp_payload_bytes":client_enrolled_after.0-client_enrolled_before.0,"client_enrolled_udp_datagrams":client_enrolled_after.1-client_enrolled_before.1,"server_enrolled_udp_payload_bytes":server_enrolled_after.0-server_enrolled_before.0,"server_enrolled_udp_datagrams":server_enrolled_after.1-server_enrolled_before.1,"false_interruptions":interruptions,"watchers_remaining":watchers.len()}));
        }
        let live = connections
            .iter()
            .filter(|connection| connection.close_reason().is_none())
            .count();
        healthy &= steady_cohort_valid && false_interruptions == 0 && live == CONNECTIONS;
        reports.push(serde_json::json!({"profile":if backup { "copy_enabled_authenticated_transport" } else { "no_copy_probe" },"probe_interval_ms":interval.as_millis(),"probe_margin_ms":margin.as_millis(),"copy_delay_ms":if backup { 10 } else { 0 },"retained_server_history":{"units":["entries","payload_bytes","armed_entries","returning_entries"],"before":history_before,"after_ramp":history_after_ramp,"after_warmup":history_after_warmup,"after_windows":bindings.retained_history().unwrap(),"observation":"aggregate_existing_fields_outside_timed_windows"},"load_before":load_before.trim(),"load_after":std::fs::read_to_string("/proc/loadavg").unwrap().trim(),"live":live,"false_interruptions":false_interruptions,"steady_cohort_valid_at_start":steady_cohort_valid,"owned_udp_drops":{"before":udp_drops_before,"after_ramp":udp_drops_after_ramp,"after_warmup":udp_drops_after_warmup,"after_windows":owned_udp_drops(&[enrolled,mesh],&client_addresses),"observation":"four_per_profile_outside_timed_windows"},"startup":{"physical_traffic_before":traffic_before,"physical_traffic_after_ramp":traffic_after_ramp,"physical_traffic_after_warmup":traffic_after_warmup,"physical_traffic_units":"cumulative_payload_bytes_and_successful_udp_datagrams_including_GSO_segments","proof_concurrency":8,"production_authenticated_path_proof":true,"rebind":false,"admission_elapsed_us":admission_elapsed.as_micros(),"proof_failures":proof_failures,"proofs":proof_results,"ramp_watchdog_interruptions":ramp_interruptions,"warmup_ms":1000,"warmup_watchdog_interruptions":warmup_interruptions},"samples":samples}));
        watchers.abort_all();
        while watchers.join_next().await.is_some() {}
        for path in &paths {
            path.set_backup(false);
        }
        for peer in &peers {
            peer.set_backup(false);
        }
    }
    let mut report = serde_json::json!({"scope":"1000_authenticated_quic_transports_loopback_not_daemons_or_kernel_mesh_nodes","connections":CONNECTIONS,"windows_per_profile":WINDOWS,"window_ms":WINDOW.as_millis(),"clock_ticks_per_second":ticks_per_second,"page_size_bytes":page_size,"machine":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim(),"load":std::fs::read_to_string("/proc/loadavg").unwrap().trim(),"udp_counters":"successful_physical_adapter_sends_including_primary_and_copy_payloads_GSO_segments","udp_bytes_exclude_ip_udp_headers":true,"instrumentation":"process_proc_reads_once_per_window_and_two_relaxed_counter_updates_per_send_plus_two_for_enrolled","baseline_watcher":"current_path_interrupted_with_previous_100ms_probe_constants_not_old_adaptive_watcher","backup_enable":"explicit_peer_and_path_API_flags_after_real_mutual_TLS_not_daemon_Hello_negotiation","profile_order":if fresh_copy && profiles == [false] { "fresh_no_copy_only_new_cohort" } else if fresh_copy { "fresh_copy_only_new_cohort" } else { "no_copy_then_copy_same_retained_cohort" },"fresh_copy_cohort":fresh_copy && profiles.contains(&true),"fresh_alias_cohort":fresh_copy && !direct_mesh_control,"explicit_fresh_no_copy_control":fresh_copy && profiles == [false],"peer_binding_birth":if direct_mesh_control { "none; direct mesh TLS only, not migration or switch acceptance" } else if fresh_copy { "after_all_mutual_TLS_before_any_mesh_selection_backup_enabled_immediately" } else { "before_TLS_with_profile_flags_later" },"limitations":["loopback_without_injected_latency_or_loss_or_kernel_mesh",if fresh_copy { "correlated_windows_of_one_fresh_cohort_no_previous_profile" } else { "correlated_windows_of_one_cohort_in_fixed_order_RSS_retains_prior_allocations" },"CPU_includes_both_ends_and_adapter_counter_instrumentation"],"profiles":reports,"result":if healthy { "PASS" } else { "FAIL" }});
    report["physical_send_counters_enabled"] = serde_json::json!(record_sends);
    report["direct_mesh_handshake_control"] = serde_json::json!(direct_mesh_control);
    report["server_peer_aliases_enabled"] = serde_json::json!(!direct_mesh_control);
    let client_workers = if separate_server {
        3
    } else if std::env::var("INFRATERNAL_MESH_TRIAL_RUNTIME").as_deref() == Ok("current_thread") {
        1
    } else {
        4
    };
    report["runtime_ownership"] = serde_json::json!({
        "separate_server":separate_server,
        "server_runtime":if separate_server { "owned_current_thread" } else { "shared_with_clients" },
        "configured_workers":client_workers+usize::from(separate_server),
        "client_workers":client_workers,
        "server_workers":usize::from(separate_server),
        "scope":"explicit split diagnostic; ordinary shared controls unchanged"
    });
    report["explicit_runtime_control"] = serde_json::json!(
        std::env::var("INFRATERNAL_MESH_TRIAL_RUNTIME")
            .unwrap_or_else(|_| "four_workers_macro".into())
    );
    if !record_sends {
        report["instrumentation"] = serde_json::json!(
            "health-only control: no global send accounting; physical traffic fields omitted; per-window process snapshots and source mapping remain"
        );
        report.as_object_mut().unwrap().remove("udp_counters");
        report
            .as_object_mut()
            .unwrap()
            .remove("udp_bytes_exclude_ip_udp_headers");
        for profile in report["profiles"].as_array_mut().unwrap() {
            for sample in profile["samples"].as_array_mut().unwrap() {
                sample
                    .as_object_mut()
                    .unwrap()
                    .retain(|key, _| !key.contains("_udp_"));
            }
            let startup = profile["startup"].as_object_mut().unwrap();
            for key in [
                "physical_traffic_before",
                "physical_traffic_after_ramp",
                "physical_traffic_after_warmup",
                "physical_traffic_units",
            ] {
                startup.remove(key);
            }
        }
    }
    report["socket_configuration_trial"] = socket_trial.map(|trial| serde_json::json!({
        "scope":"explicit diagnostic socket parameters; not the ordinary production-profile gate",
        "client_gro_enabled":trial.client_gro,
        "physical_send_counters_enabled":trial.record_sends,
        "probe_interval_ms":trial.probe_interval_ms,
        "probe_margin_ms":trial.probe_margin_ms,
        "nominal_detection_over_rtt_ms":trial.probe_interval_ms+trial.probe_margin_ms,
        "server_receive_request_bytes":trial.server_receive_request,"privileged_socket_local_receive_force":trial.server_receive_force,
        "effective_kernel_accounting_bytes":[primary_capacity,mesh_capacity],
        "host_setting_changes":false
    })).into();
    report["client_max_receive_segments_min"] =
        serde_json::json!(paths.iter().map(|path| path.max_receive_segments()).min());
    report["client_max_receive_segments_max"] =
        serde_json::json!(paths.iter().map(|path| path.max_receive_segments()).max());
    report["client_single_segment_sockets"] = serde_json::json!(
        paths
            .iter()
            .filter(|path| path.max_receive_segments() == 1)
            .count()
    );
    let scratch = PathBuf::from(
        std::env::var_os("INFRATERNAL_MESH_PROOF_SCRATCH")
            .expect("set external proof evidence directory"),
    );
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::write(
        scratch.join(if fresh_copy {
            "mesh-fresh-copy-cost-1000.json"
        } else {
            "mesh-probe-copy-cost-1000.json"
        }),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    if let Some(diagnostic) = &diagnostic {
        std::fs::write(
            scratch.join(if fresh_copy {
                "mesh-fresh-copy-receive-diagnostic.json"
            } else {
                "mesh-probe-copy-receive-diagnostic.json"
            }),
            serde_json::to_vec_pretty(&diagnostic.report()).unwrap(),
        )
        .unwrap();
    }
    let startup: Vec<_> = report["profiles"].as_array().unwrap().iter().map(|profile| serde_json::json!({"profile":profile["profile"],"startup":profile["startup"],"steady_cohort_valid_at_start":profile["steady_cohort_valid_at_start"]})).collect();
    std::fs::write(
        scratch.join(if fresh_copy {
            "mesh-fresh-copy-startup-1000.json"
        } else {
            "mesh-probe-copy-startup-1000.json"
        }),
        serde_json::to_vec_pretty(&startup).unwrap(),
    )
    .unwrap();
    println!(
        "METRIC mesh_probe_copy_cost {}",
        serde_json::to_string(&report).unwrap()
    );
    for client in clients {
        client.close(0_u32.into(), b"");
    }
    server.close(0_u32.into(), b"");
    drop((connections, accepted, drivers, peers, lease));
    assert!(
        healthy,
        "healthy authenticated path watchers must remain live throughout every requested profile"
    );
}
