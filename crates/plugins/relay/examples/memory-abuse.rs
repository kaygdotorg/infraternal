//! Measure relay-only RSS while many linked pairs flood QUIC DATAGRAMs.
//!
//! Run this release binary on the perf VM inside a disposable network namespace
//! and a shaped loopback link. The child process owns only the relay; the parent
//! owns the load generator and samples the child's `/proc` RSS high-water mark.

use bytes::{BufMut, Bytes, BytesMut};
use infraternal_plugin_relay::{
    client::Client,
    quinn,
    relay::{Limits, Relay},
    testing::{self, Authority, Purpose},
    tls,
    wire::{HostId, LinkId, Notice},
};
use std::{
    error::Error,
    fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const NAME: &str = "relay-memory.mesh.test";
const PAIRS: usize = 256;
const DATAGRAMS_PER_HOST: usize = 256;
const PACKET_BYTES: usize = 1_400;
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
const LINK_DEADLINE: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|arg| arg == "--server") {
        let directory = args.next().ok_or("server mode needs a private directory")?;
        run_server(Path::new(&directory)).await?;
        return Ok(());
    }

    run_driver().await
}

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

fn frame(id: LinkId, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + payload.len());
    out.put_u32(id.0);
    out.put_slice(payload);
    out.freeze()
}

fn host_id(index: u64) -> HostId {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&index.to_be_bytes());
    bytes[8..].copy_from_slice(&index.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes());
    HostId(bytes)
}

fn rss_kib(pid: u32) -> io::Result<u64> {
    proc_status_kib(pid, "VmRSS:")
}

fn hwm_kib(pid: u32) -> io::Result<u64> {
    proc_status_kib(pid, "VmHWM:")
}

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

struct Scratch {
    path: PathBuf,
}

impl Scratch {
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

struct ServerProcess {
    child: Child,
    directory: PathBuf,
    pid: u32,
    address: SocketAddr,
}

impl ServerProcess {
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
