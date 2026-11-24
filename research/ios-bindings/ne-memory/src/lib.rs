//! Memory footprint of a GotaTun device on Apple platforms (J1158, #580).
//!
//! The question: does the mesh engine fit in an iOS packet tunnel extension,
//! which iOS kills when its physical footprint passes a fixed limit? This
//! program runs the "phone" side of a tunnel the way the macOS mesh node
//! does (one current-thread tokio runtime, the product's GotaTun fork with
//! the `ring` backend) and samples its own `phys_footprint`, the number the
//! iOS memory limit is enforced against.
//!
//! Layout, all inside one machine:
//!
//! ```text
//!  phone process                                peer process (child)
//!  generator ─▶ GotaTun ══ UDP 127.0.0.1 ══▶ GotaTun ─▶ reflector
//!  sink ◀────── device  ◀═════════════════════ device ◀──┘ (src/dst swapped)
//! ```
//!
//! The TUN on both sides is in memory: no interface, route or DNS setting is
//! touched, and the only packets on a real socket are WireGuard datagrams
//! between two loopback ports. Inner addresses (10.99.0.1/.2) exist only
//! inside the encrypted tunnel. Extra idle peers (`--peers N`) have no
//! endpoint, so they never send anything; they measure per-peer state.
//!
//! Usage: `ne-memory [--peers N] [--secs S] [--idle S] [--size BYTES]
//! [--window PACKETS]`. Output is one JSON object per run on stdout.
//!
//! The crate is a library with two entry points: `src/main.rs` for macOS,
//! and the exported C symbol `ne_memory_main` for the iOS Simulator, where
//! the executable is linked by Xcode's toolchain around the static library.

use std::io::{BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use gotatun::device::{DeviceBuilder, Peer};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use gotatun::x25519::{PublicKey, StaticSecret};
use ipnetwork::{IpNetwork, Ipv4Network};
use tokio::sync::{Notify, mpsc};

/// Loopback UDP port of the phone's WireGuard socket.
const PHONE_PORT: u16 = 47_101;
/// Loopback UDP port of the peer's WireGuard socket.
const PEER_PORT: u16 = 47_102;
/// Tunnel address of the phone (inside the tunnel only).
const PHONE_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 1);
/// Tunnel address of the peer (inside the tunnel only).
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
/// The MTU both in-memory TUNs report, the product's mesh fallback MTU.
const MTU: u16 = 1280;

/// Command-line settings for one measurement.
struct Settings {
    /// Configured peers without an endpoint, on top of the one live peer.
    idle_peers: u32,
    /// Seconds of load.
    secs: u64,
    /// Seconds to sample after the load stops.
    idle_secs: u64,
    /// Inner IP packet size in bytes.
    size: usize,
    /// Packets the generator may have in flight before it waits for echoes.
    window: u64,
}

/// Entry point for C callers (the iOS Simulator launcher): runs with the
/// process arguments and returns 0.
#[unsafe(no_mangle)]
pub extern "C" fn ne_memory_main() -> i32 {
    run();
    0
}

/// Runs the phone or, with the first argument `peer`, the peer side.
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("peer") {
        run_peer();
        return;
    }
    let mut settings = Settings { idle_peers: 0, secs: 20, idle_secs: 10, size: 1280, window: 256 };
    let mut it = args.iter().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().and_then(|v| v.parse::<u64>().ok()).expect("flag needs a number");
        match flag.as_str() {
            "--peers" => settings.idle_peers = value as u32,
            "--secs" => settings.secs = value,
            "--idle" => settings.idle_secs = value,
            "--size" => settings.size = value as usize,
            "--window" => settings.window = value,
            _ => panic!("unknown flag {flag}"),
        }
    }
    assert!(settings.size >= 28 && settings.size <= MTU as usize, "size must fit the MTU");
    run_phone(&settings);
}

// ---------------------------------------------------------------- phone side

/// Shared counters between the generator, the sink and the sampler.
#[derive(Default)]
struct Counters {
    /// Packets the generator handed to the device.
    sent: AtomicU64,
    /// Echoed packets the sink received back.
    received: AtomicU64,
    /// Bytes the sink received back.
    received_bytes: AtomicU64,
    /// Set to 1 while the generator should produce load.
    load_on: AtomicU64,
}

/// The phone's in-memory TUN, receive half: produces IPv4/UDP packets from
/// the phone to the peer while load is on, keeping at most `window` packets
/// unanswered.
struct Generator {
    counters: Arc<Counters>,
    wake: Arc<Notify>,
    size: usize,
    window: u64,
}

impl IpRecv for Generator {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> std::io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let c = &self.counters;
            let in_flight = c.sent.load(Ordering::Relaxed) - c.received.load(Ordering::Relaxed);
            if c.load_on.load(Ordering::Relaxed) == 1 && in_flight < self.window {
                let n = (self.window - in_flight).min(32);
                let mut batch = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let mut p = pool.get();
                    p.truncate(self.size);
                    write_ipv4_udp(&mut p.buf_mut()[..], PHONE_IP, PEER_IP);
                    batch.push(p.try_into_ip().expect("valid IPv4 packet"));
                }
                c.sent.fetch_add(n, Ordering::Relaxed);
                return Ok(batch.into_iter());
            }
            self.wake.notified().await;
        }
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(MTU)
    }
}

/// The phone's in-memory TUN, send half: counts the echoed packets and wakes
/// the generator so it can refill its window.
struct Sink {
    counters: Arc<Counters>,
    wake: Arc<Notify>,
}

impl IpSend for Sink {
    async fn send(&mut self, packet: Packet<Ip>) -> std::io::Result<()> {
        let len = packet.into_bytes().buf_mut().len() as u64;
        self.counters.received.fetch_add(1, Ordering::Relaxed);
        self.counters.received_bytes.fetch_add(len, Ordering::Relaxed);
        self.wake.notify_one();
        Ok(())
    }
}

/// Runs the phone side: starts the peer child, builds the device, then
/// reports footprint before the device exists, idle after the handshake,
/// during load, and idle after load.
fn run_phone(settings: &Settings) {
    let baseline = Footprint::now();
    let phone_secret = random_secret();
    let peer_secret = random_secret();
    let phone_public = PublicKey::from(&phone_secret);
    let peer_public = PublicKey::from(&peer_secret);

    // The peer gets its keys on stdin, never in argv.
    let exe = std::env::current_exe().expect("own path");
    let mut child = Command::new(exe)
        .arg("peer")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the peer process");
    {
        let mut stdin = child.stdin.take().expect("peer stdin");
        writeln!(stdin, "{}", hex(&peer_secret.to_bytes())).unwrap();
        writeln!(stdin, "{}", hex(phone_public.as_bytes())).unwrap();
    }
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().expect("peer stdout"))
        .read_line(&mut ready)
        .expect("peer ready line");
    assert_eq!(ready.trim(), "ready", "peer did not start");

    // The macOS mesh node runs its device on one current-thread runtime.
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let counters = Arc::new(Counters::default());
    let wake = Arc::new(Notify::new());
    let generator = Generator { counters: counters.clone(), wake: wake.clone(), size: settings.size, window: settings.window };
    let sink = Sink { counters: counters.clone(), wake: wake.clone() };

    let mut peers = vec![Peer::new(peer_public)
        .with_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, PEER_PORT)))
        .with_allowed_ip(IpNetwork::V4(Ipv4Network::new(PEER_IP, 32).unwrap()))];
    for i in 0..settings.idle_peers {
        // No endpoint: these peers exist only as configured state.
        let ip = Ipv4Addr::new(10, 98, (i >> 8) as u8, (i & 0xff) as u8);
        peers.push(
            Peer::new(PublicKey::from(&random_secret()))
                .with_allowed_ip(IpNetwork::V4(Ipv4Network::new(ip, 32).unwrap())),
        );
    }

    runtime.block_on(async {
        let device = DeviceBuilder::new()
            .with_default_udp()
            .with_private_key(phone_secret)
            .with_listen_port(PHONE_PORT)
            .with_ip_pair(sink, generator)
            .with_peers(peers)
            .build()
            .await
            .expect("phone device");

        // A short burst brings the handshake up before the idle sample.
        counters.load_on.store(1, Ordering::Relaxed);
        wake.notify_one();
        let start = Instant::now();
        while counters.received.load(Ordering::Relaxed) == 0 {
            assert!(start.elapsed() < Duration::from_secs(10), "no echo within 10 s");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        counters.load_on.store(0, Ordering::Relaxed);
        let handshake_ms = start.elapsed().as_millis();
        tokio::time::sleep(Duration::from_secs(settings.idle_secs)).await;
        let idle = Footprint::now();

        // Load: the generator keeps `window` packets in flight.
        let before = counters.received_bytes.load(Ordering::Relaxed);
        counters.load_on.store(1, Ordering::Relaxed);
        wake.notify_one();
        let mut peak = Footprint::now();
        let load_start = Instant::now();
        while load_start.elapsed() < Duration::from_secs(settings.secs) {
            tokio::time::sleep(Duration::from_millis(100)).await;
            peak = peak.max(Footprint::now());
        }
        counters.load_on.store(0, Ordering::Relaxed);
        let bytes = counters.received_bytes.load(Ordering::Relaxed) - before;
        let secs = load_start.elapsed().as_secs_f64();
        let after_load = Footprint::now();

        tokio::time::sleep(Duration::from_secs(settings.idle_secs)).await;
        let settled = Footprint::now();
        device.stop().await;

        println!(
            "{{\"idle_peers\":{},\"size\":{},\"window\":{},\"handshake_ms\":{},\
             \"baseline\":{},\"idle\":{},\"load_peak\":{},\"after_load\":{},\"settled\":{},\
             \"echo_mbit_s\":{:.1},\"lifetime_peak_mib\":{:.2}}}",
            settings.idle_peers,
            settings.size,
            settings.window,
            handshake_ms,
            baseline.json(),
            idle.json(),
            peak.json(),
            after_load.json(),
            settled.json(),
            bytes as f64 * 8.0 / secs / 1e6,
            Footprint::now().lifetime_peak as f64 / 1048576.0,
        );
    });
    let _ = child.kill();
    let _ = child.wait();
}

// ----------------------------------------------------------------- peer side

/// The peer's in-memory TUN: every packet the device delivers is turned
/// around (source and destination swapped) and handed back to the device.
struct Reflector {
    tx: mpsc::Sender<Packet<Ip>>,
}

impl IpSend for Reflector {
    async fn send(&mut self, packet: Packet<Ip>) -> std::io::Result<()> {
        let mut bytes = packet.into_bytes();
        let buf = bytes.buf_mut();
        if buf.len() >= 20 {
            let (src, dst) = (u32::from_be_bytes(buf[12..16].try_into().unwrap()), u32::from_be_bytes(buf[16..20].try_into().unwrap()));
            buf[12..16].copy_from_slice(&dst.to_be_bytes());
            buf[16..20].copy_from_slice(&src.to_be_bytes());
            if let Ok(ip) = bytes.try_into_ip() {
                let _ = self.tx.send(ip).await;
            }
        }
        Ok(())
    }
}

/// Receive half of the peer's TUN: the reflected packets.
struct Reflected {
    rx: mpsc::Receiver<Packet<Ip>>,
}

impl IpRecv for Reflected {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> std::io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let first = self.rx.recv().await.ok_or_else(|| std::io::Error::other("closed"))?;
        let mut batch = vec![first];
        while batch.len() < 32 {
            match self.rx.try_recv() {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
        }
        Ok(batch.into_iter())
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(MTU)
    }
}

/// Runs the peer: reads its private key and the phone's public key from
/// stdin, serves until the parent kills it.
fn run_peer() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
    let mut lines = input.lines();
    let secret = StaticSecret::from(unhex(lines.next().unwrap()));
    let phone = PublicKey::from(unhex(lines.next().unwrap()));
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    runtime.block_on(async {
        let (tx, rx) = mpsc::channel(1024);
        let _device = DeviceBuilder::new()
            .with_default_udp()
            .with_private_key(secret)
            .with_listen_port(PEER_PORT)
            .with_ip_pair(Reflector { tx }, Reflected { rx })
            .with_peer(
                Peer::new(phone)
                    .with_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, PHONE_PORT)))
                    .with_allowed_ip(IpNetwork::V4(Ipv4Network::new(PHONE_IP, 32).unwrap())),
            )
            .build()
            .await
            .expect("peer device");
        println!("ready");
        std::io::stdout().flush().unwrap();
        std::future::pending::<()>().await;
    });
}

// ------------------------------------------------------------------- helpers

/// Writes a minimal IPv4/UDP header (with a valid IPv4 checksum) at the start
/// of `buf`, whose length is the whole packet.
fn write_ipv4_udp(buf: &mut [u8], src: Ipv4Addr, dst: Ipv4Addr) {
    let total = buf.len() as u16;
    buf[..28].fill(0);
    buf[0] = 0x45;
    buf[2..4].copy_from_slice(&total.to_be_bytes());
    buf[8] = 64;
    buf[9] = 17;
    buf[12..16].copy_from_slice(&src.octets());
    buf[16..20].copy_from_slice(&dst.octets());
    let mut sum = 0u32;
    for i in (0..20).step_by(2) {
        sum += u32::from(u16::from_be_bytes([buf[i], buf[i + 1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    buf[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    buf[20..22].copy_from_slice(&9000u16.to_be_bytes());
    buf[22..24].copy_from_slice(&9000u16.to_be_bytes());
    buf[24..26].copy_from_slice(&(total - 20).to_be_bytes());
}

/// A fresh X25519 secret from the system's random source.
fn random_secret() -> StaticSecret {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes)).expect("random bytes");
    StaticSecret::from(bytes)
}

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parses 64 hex digits into 32 bytes.
fn unhex(text: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// One memory sample of this process.
#[derive(Clone, Copy)]
struct Footprint {
    /// `phys_footprint`: what the iOS per-process memory limit is checked
    /// against (dirty + compressed memory, IOKit and similar).
    phys: u64,
    /// Resident set size, for comparison with Linux numbers.
    resident: u64,
    /// The kernel's own record of the highest `phys_footprint` so far.
    lifetime_peak: u64,
}

impl Footprint {
    /// Samples the current process.
    fn now() -> Self {
        let info = task_vm_info();
        Footprint { phys: info.phys_footprint, resident: info.resident_size, lifetime_peak: info.ledger_phys_footprint_peak as u64 }
    }

    /// The larger of two samples, by `phys_footprint`.
    fn max(self, other: Self) -> Self {
        if other.phys > self.phys { other } else { self }
    }

    /// The sample as a JSON object in MiB.
    fn json(&self) -> String {
        format!("{{\"phys_mib\":{:.2},\"rss_mib\":{:.2}}}", self.phys as f64 / 1048576.0, self.resident as f64 / 1048576.0)
    }
}

/// The leading fields of `task_vm_info_data_t` from `<mach/task_info.h>`,
/// up to `ledger_phys_footprint_peak` (revision 2), plus room for newer
/// revisions so the kernel never writes past the end.
#[repr(C)]
#[derive(Default)]
struct TaskVmInfo {
    virtual_size: u64,
    region_count: i32,
    page_size: i32,
    resident_size: u64,
    resident_size_peak: u64,
    device: u64,
    device_peak: u64,
    internal: u64,
    internal_peak: u64,
    external: u64,
    external_peak: u64,
    reusable: u64,
    reusable_peak: u64,
    purgeable_volatile_pmap: u64,
    purgeable_volatile_resident: u64,
    purgeable_volatile_virtual: u64,
    compressed: u64,
    compressed_peak: u64,
    compressed_lifetime: u64,
    phys_footprint: u64,
    min_address: u64,
    max_address: u64,
    ledger_phys_footprint_peak: i64,
    rest: [u64; 32],
}

unsafe extern "C" {
    /// Mach's `task_info(2)`.
    fn task_info(task: u32, flavor: i32, out: *mut i32, count: *mut u32) -> i32;
    /// The port of the current task; `mach_task_self()` in C is a macro for it.
    static mach_task_self_: u32;
}

/// `TASK_VM_INFO` from `<mach/task_info.h>`.
const TASK_VM_INFO: i32 = 22;

/// Reads `TASK_VM_INFO` for this task.
fn task_vm_info() -> TaskVmInfo {
    let mut info = TaskVmInfo::default();
    let mut count = (std::mem::size_of::<TaskVmInfo>() / 4) as u32;
    // SAFETY: `info` is a plain C struct at least as large as `count` words.
    let rc = unsafe { task_info(mach_task_self_, TASK_VM_INFO, (&raw mut info).cast(), &mut count) };
    assert_eq!(rc, 0, "task_info failed");
    info
}
