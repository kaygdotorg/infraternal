//! Measure relay-only RSS under a QUIC pre-hello connection or DATAGRAM flood.
//!
//! Run this release binary on the perf VM inside a disposable network namespace.
//! The child process owns only the relay; the parent
//! owns the load generator and samples the child's `/proc` RSS high-water mark.
//! `--handshake-flood` opens concurrent connections from 128 loopback source IPs
//! and withholds the authenticated control hello.

use bytes::{BufMut, Bytes, BytesMut};
use infraternal_plugin_relay::{
    client::Client,
    quinn::{self, AsyncUdpSocket, UdpPoller, udp},
    relay::{Limits, Relay},
    testing::{self, Authority, Purpose},
    tls,
    wire::{HostId, LinkId, Notice},
};
use std::{
    error::Error,
    fs, io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// The server name in the relay's test certificate, used by every client.
const NAME: &str = "relay-memory.mesh.test";
/// How many linked host pairs the datagram flood uses (so twice as many hosts).
const PAIRS: usize = 256;
/// How many datagrams each host sends in the datagram flood.
const DATAGRAMS_PER_HOST: usize = 256;
/// Payload size of each flooded datagram, in bytes.
const PACKET_BYTES: usize = 1_400;
/// How long a client may take to connect to the relay.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// How long a pair may take to receive its link notices.
const LINK_DEADLINE: Duration = Duration::from_secs(10);
/// Number of distinct loopback source addresses used by the handshake flood.
const HANDSHAKE_FLOOD_SOURCE_IPS: u8 = 128;
/// Connection attempts started from each source address.
const HANDSHAKES_PER_SOURCE_IP: usize = 8;
/// How long after starting the handshake flood the relay's memory is sampled.
const HANDSHAKE_FLOOD_SAMPLE_AFTER: Duration = Duration::from_secs(2);

/// Entry point. With no argument it runs the datagram flood; `--handshake-flood`
/// runs the pre-hello connection flood; `--server <dir>` is used internally for
/// the child process that hosts the relay.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let mode = args.next();
    if mode.as_deref().is_some_and(|arg| arg == "--server") {
        let directory = args.next().ok_or("server mode needs a private directory")?;
        run_server(Path::new(&directory)).await?;
        return Ok(());
    }
    if mode
        .as_deref()
        .is_some_and(|arg| arg == "--handshake-flood")
    {
        run_handshake_flood().await?;
        return Ok(());
    }

    run_driver().await
}

/// Child-process mode: runs a relay on a random loopback port using the
/// certificates in `directory`, writes its address to `directory/ready`, and
/// stops when `directory/stop` appears.
async fn run_server(directory: &Path) -> Result<(), Box<dyn Error>> {
    let certificate = fs::read_to_string(directory.join("relay.pem"))?;
    let key = fs::read_to_string(directory.join("relay-key.pem"))?;
    let root = fs::read_to_string(directory.join("root.pem"))?;
    let credentials = testing::credentials_from_pem(&certificate, &key, &root);
    let relay = Relay::start(
        "127.0.0.1:0".parse()?,
        credentials,
        Limits::default(),
        Arc::new(|_| true),
    )?;
    fs::write(directory.join("ready"), relay.local_addr()?.to_string())?;

    while !directory.join("stop").exists() {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    relay.close().await;
    Ok(())
}

/// Datagram flood: connects 512 hosts, links them in pairs, makes every host
/// send a burst of datagrams, and prints the relay process's idle and peak
/// memory as `METRIC` lines.
async fn run_driver() -> Result<(), Box<dyn Error>> {
    let directory = Scratch::create()?;
    let mut authority = Authority::new();
    let (certificate, key) = authority.issue_pem(Purpose::Relay(NAME));
    fs::write(directory.path.join("relay.pem"), certificate)?;
    fs::write(directory.path.join("relay-key.pem"), key)?;
    fs::write(directory.path.join("root.pem"), authority.pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            directory.path.join("relay-key.pem"),
            fs::Permissions::from_mode(0o600),
        )?;
    }

    let server = ServerProcess::start(&directory.path)?;
    let address = server.address;
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    let mut clients = Vec::with_capacity(PAIRS * 2);
    for index in 0..(PAIRS * 2) {
        let host = host_id(index as u64 + 1);
        let credentials = authority.issue(Purpose::Host(host));
        let config = tls::client_config(credentials)?;
        let (client, notices) =
            Client::connect(&endpoint, config, address, NAME, CONNECT_DEADLINE).await?;
        clients.push((host, client, notices));
    }

    let mut pairs = Vec::with_capacity(PAIRS);
    for index in 0..PAIRS {
        let a = index * 2;
        let b = a + 1;
        let a_host = clients[a].0;
        let b_host = clients[b].0;
        clients[a].1.link(b_host).await?;
        clients[b].1.link(a_host).await?;
        let (first_clients, second_clients) = clients.split_at_mut(b);
        let (a_notice, b_notice) = tokio::time::timeout(LINK_DEADLINE, async {
            tokio::join!(first_clients[a].2.next(), second_clients[0].2.next())
        })
        .await?;
        let Notice::Linked { id, .. } = a_notice.ok_or("first link notice ended")? else {
            return Err("first link notice had the wrong kind".into());
        };
        if b_notice != Some(Notice::Linked { peer: a_host, id }) {
            return Err("pair did not receive the same link id".into());
        }
        pairs.push((
            clients[a].1.connection().clone(),
            clients[b].1.connection().clone(),
            id,
        ));
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    let idle_kib = rss_kib(server.pid)?;
    let idle_hwm_kib = hwm_kib(server.pid)?;
    println!("METRIC name=relay_pairs value={PAIRS}");
    println!("METRIC name=relay_hosts value={}", PAIRS * 2);
    println!("METRIC name=relay_idle_rss_kib value={idle_kib}");
    println!("METRIC name=relay_idle_hwm_kib value={idle_hwm_kib}");

    let payload = vec![0x5a; PACKET_BYTES];
    let started = Instant::now();
    let mut send_tasks = tokio::task::JoinSet::new();
    for (first, second, id) in pairs {
        let frame = frame(id, &payload);
        let first_frame = frame.clone();
        send_tasks.spawn(async move { flood(&first, first_frame, DATAGRAMS_PER_HOST).await });
        send_tasks.spawn(async move { flood(&second, frame, DATAGRAMS_PER_HOST).await });
    }
    let mut accepted = 0_u64;
    let mut blocked = 0_u64;
    while let Some(result) = send_tasks.join_next().await {
        let (sent, refused) = result?;
        accepted += sent;
        blocked += refused;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let current_kib = rss_kib(server.pid)?;
    let peak_kib = hwm_kib(server.pid)?;
    println!(
        "METRIC name=relay_flood_attempted value={}",
        PAIRS * 2 * DATAGRAMS_PER_HOST
    );
    println!("METRIC name=relay_flood_accepted_by_clients value={accepted}");
    println!("METRIC name=relay_flood_blocked_at_clients value={blocked}");
    println!(
        "METRIC name=relay_flood_elapsed_ms value={}",
        started.elapsed().as_millis()
    );
    println!("METRIC name=relay_flood_rss_kib value={current_kib}");
    println!("METRIC name=relay_flood_peak_rss_kib value={peak_kib}");
    println!(
        "METRIC name=relay_flood_peak_over_idle_kib value={}",
        peak_kib.saturating_sub(idle_hwm_kib)
    );
    Ok(())
}

/// Handshake flood: opens many QUIC connections from many source addresses and
/// never sends the authenticated hello, then prints the relay process's memory
/// as `METRIC` lines.
async fn run_handshake_flood() -> Result<(), Box<dyn Error>> {
    let directory = Scratch::create()?;
    let mut authority = Authority::new();
    let (certificate, key) = authority.issue_pem(Purpose::Relay(NAME));
    fs::write(directory.path.join("relay.pem"), certificate)?;
    fs::write(directory.path.join("relay-key.pem"), key)?;
    fs::write(directory.path.join("root.pem"), authority.pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory.path, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(
            directory.path.join("relay-key.pem"),
            fs::Permissions::from_mode(0o600),
        )?;
    }

    let server = ServerProcess::start(&directory.path)?;
    let address = server.address;
    let config = tls::client_config(authority.issue(Purpose::Host(host_id(1))))?;
    let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let idle_kib = rss_kib(server.pid)?;
    let idle_hwm_kib = hwm_kib(server.pid)?;
    let mut connects = tokio::task::JoinSet::new();
    let started = Instant::now();
    for source in 1..=HANDSHAKE_FLOOD_SOURCE_IPS {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, source)), 0);
        let socket = runtime.wrap_udp_socket(std::net::UdpSocket::bind(local)?)?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            Arc::new(BlackholeSocket { inner: socket }),
            runtime.clone(),
        )?;
        for _ in 0..HANDSHAKES_PER_SOURCE_IP {
            let endpoint = endpoint.clone();
            let config = config.clone();
            connects.spawn(async move {
                let Ok(connecting) = endpoint.connect_with(config, address, NAME) else {
                    return;
                };
                tokio::select! {
                    () = tokio::time::sleep(HANDSHAKE_FLOOD_SAMPLE_AFTER + Duration::from_secs(1)) => {}
                    _ = connecting => {}
                }
            });
        }
    }

    let attempted = usize::from(HANDSHAKE_FLOOD_SOURCE_IPS) * HANDSHAKES_PER_SOURCE_IP;
    tokio::time::sleep(HANDSHAKE_FLOOD_SAMPLE_AFTER).await;
    let elapsed = started.elapsed();

    let flood_kib = rss_kib(server.pid)?;
    let flood_hwm_kib = hwm_kib(server.pid)?;
    println!("METRIC name=handshake_flood_source_ips value={HANDSHAKE_FLOOD_SOURCE_IPS}");
    println!("METRIC name=handshake_flood_per_source value={HANDSHAKES_PER_SOURCE_IP}");
    println!("METRIC name=handshake_flood_attempted value={attempted}");
    println!(
        "METRIC name=handshake_flood_elapsed_ms value={}",
        elapsed.as_millis()
    );
    println!("METRIC name=relay_idle_rss_kib value={idle_kib}");
    println!("METRIC name=relay_idle_hwm_kib value={idle_hwm_kib}");
    println!("METRIC name=relay_handshake_flood_rss_kib value={flood_kib}");
    println!("METRIC name=relay_handshake_flood_peak_rss_kib value={flood_hwm_kib}");

    // Keep the successful handshakes open, without an IFR1 hello, through sampling.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let peak_hwm_kib = hwm_kib(server.pid)?;
    println!(
        "METRIC name=relay_handshake_flood_peak_over_idle_kib value={}",
        peak_hwm_kib.saturating_sub(idle_hwm_kib)
    );
    connects.abort_all();
    while connects.join_next().await.is_some() {}
    Ok(())
}

/// Lets outbound Initials reach the relay while discarding every server packet.
#[derive(Debug)]
struct BlackholeSocket {
    inner: Arc<dyn AsyncUdpSocket>,
}

impl AsyncUdpSocket for BlackholeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit<'_>) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let count = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(count)) => count,
        };
        for item in meta.iter_mut().take(count) {
            item.len = 0;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Sends `count` copies of `packet` as datagrams on `connection`. Returns how
/// many the client accepted and how many it refused locally.
async fn flood(connection: &quinn::Connection, packet: Bytes, count: usize) -> (u64, u64) {
    let mut accepted = 0;
    let mut blocked = 0;
    for _ in 0..count {
        match connection.send_datagram(packet.clone()) {
            Ok(()) => accepted += 1,
            Err(_) => blocked += 1,
        }
        tokio::task::yield_now().await;
    }
    (accepted, blocked)
}

/// A relay datagram: the 4-byte link id followed by `payload`.
fn frame(id: LinkId, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + payload.len());
    out.put_u32(id.0);
    out.put_slice(payload);
    out.freeze()
}

/// A distinct, well-spread host id derived from `index`.
fn host_id(index: u64) -> HostId {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    bytes[8..].copy_from_slice(&index.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    HostId(bytes)
}

/// Current resident memory of process `pid`, in KiB.
fn rss_kib(pid: u32) -> io::Result<u64> {
    proc_status_kib(pid, "VmRSS:")
}

/// Peak resident memory (high-water mark) of process `pid`, in KiB.
fn hwm_kib(pid: u32) -> io::Result<u64> {
    proc_status_kib(pid, "VmHWM:")
}

/// Reads a KiB field such as `VmRSS:` from `/proc/<pid>/status`.
fn proc_status_kib(pid: u32, field: &str) -> io::Result<u64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, field))?;
    value
        .split_whitespace()
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, field))?
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// A private scratch directory that is deleted when dropped.
struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Creates a new, uniquely named directory in the system temp directory.
    fn create() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("relay-rss-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The relay running in a child process, so its memory can be measured from
/// outside. Dropping it asks the child to stop and waits briefly, then kills it.
struct ServerProcess {
    child: Child,
    directory: PathBuf,
    pid: u32,
    address: SocketAddr,
}

impl ServerProcess {
    /// Starts the child and waits up to ten seconds for it to report its address.
    fn start(directory: &Path) -> io::Result<Self> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--server")
            .arg(directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let pid = child.id();
        let ready = directory.join("ready");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(address) = fs::read_to_string(&ready) {
                let address = match address.parse() {
                    Ok(address) => address,
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                    }
                };
                return Ok(Self {
                    child,
                    directory: directory.to_path_buf(),
                    pid,
                    address,
                });
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "relay child did not bind",
                ));
            }
            if let Some(status) = child.try_wait()? {
                return Err(io::Error::other(format!(
                    "relay child exited early: {status}"
                )));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        let _ = fs::write(self.directory.join("stop"), b"stop");
        if self.child.try_wait().ok().flatten().is_none() {
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
