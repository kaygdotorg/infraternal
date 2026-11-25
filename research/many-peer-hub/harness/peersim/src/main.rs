//! `peersim`: thousands of simulated WireGuard peers in one process, plus a UDP sink.
//!
//! Part of the many-peer hub measurement (#260, J1234). It runs only inside a network namespace
//! that has no route to the uplink; every peer owns one UDP socket on the underlay address, so
//! the hub sees N distinct endpoints. Peers speak the real WireGuard protocol (boringtun's
//! `Tunn`), so the hub does real handshakes and real decryption for every one of them.
//!
//! Subcommands:
//!
//! - `keys <n> <keys.bin> <peers.json> <mode>`: make `n` key pairs; `keys.bin` holds the private keys
//!   (never leaves the namespace host), `peers.json` the public list the hub reads.
//! - `sim <keys.bin> <fifo> <out> <hub-underlay-ip> <hub-port> <mode>`: serve commands from `fifo`,
//!   append one JSON line per command to `out`. Commands (one per line):
//!   `identity <hex>` (hub public key), `connect <n> <handshakes-per-s|0>`,
//!   `keepalive <seconds|0>` (each connected peer sends an empty keepalive at that interval,
//!   with a random phase), `send <k> <secs> <payload-bytes> <total-mbit|0>`, `storm`, `probe <peer>
//!   <secs>` (one 1 kHz numbered datagram stream from one peer), `exit`.
//!   `mode` picks the peers' source addresses: `single` (all share 10.220.0.2, a whole site behind one
//!   NAT), `spread` (each peer its own /24 inside 10.64.0.0/12, ephemeral port) or `known` (as `spread`,
//!   fixed port 51820, which the hub is told as the peer's endpoint). The harness adds the addresses.
//! - `sink <port> <probe-source-ip>`: count UDP datagrams on `port`; print one JSON line per
//!   second with packets, bytes, distinct sources and the longest gap of the probe source.
#![allow(clippy::too_many_lines)]
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use mio::{net::UdpSocket, Events, Interest, Poll, Token};
use std::{
    collections::HashSet,
    io::{BufRead as _, Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

/// UDP port of the sink inside the hub namespace.
const SINK_PORT: u16 = 5601;
/// The hub's mesh address (the destination of every inner packet).
const HUB_MESH: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 1);
/// The underlay address every simulated peer binds.
const SIM_UNDERLAY: Ipv4Addr = Ipv4Addr::new(10, 220, 0, 2);

/// Mesh address of peer `id` (ids start at 1); matches the hub bench file.
fn mesh_addr(id: u64) -> Ipv4Addr {
    Ipv4Addr::new(10, 254, u8::try_from(1 + id / 256).unwrap(), u8::try_from(id % 256).unwrap())
}

/// The fixed port `known` mode binds, and the harness hands the hub as the peer's endpoint.
const KNOWN_PORT: u16 = 51820;

/// Underlay address of peer `index` in `spread` and `known` modes: one /24 per peer, so no two
/// peers share the hub's per-source or per-network handshake budget.
fn spread_addr(index: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, u8::try_from(64 + (index >> 8)).unwrap(), u8::try_from(index & 255).unwrap(), 1)
}

/// A cheap seeded PRNG (xorshift), enough for key material in a throwaway namespace and for
/// keepalive phase; keys are made from `/dev/urandom` instead.
struct Xor(u64);
impl Xor {
    /// Next 64 random bits.
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Lower-case hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Write `n` key pairs.
fn make_keys(n: u64, keys_path: &str, list_path: &str, mode: &str) {
    let mut urandom = std::fs::File::open("/dev/urandom").unwrap();
    let mut keys = Vec::new();
    let mut list = Vec::new();
    for id in 1..=n {
        let mut secret = [0_u8; 32];
        urandom.read_exact(&mut secret).unwrap();
        let public = PublicKey::from(&StaticSecret::from(secret));
        keys.extend_from_slice(&secret);
        let mut entry = serde_json::json!({"id": id, "key": hex(public.as_bytes())});
        if mode == "known" {
            entry["endpoint"] = format!("{}:{KNOWN_PORT}", spread_addr(usize::try_from(id - 1).unwrap())).into();
        }
        if mode != "single" {
            entry["underlay"] = spread_addr(usize::try_from(id - 1).unwrap()).to_string().into();
        }
        list.push(entry);
    }
    std::fs::write(keys_path, keys).unwrap();
    std::fs::write(list_path, serde_json::to_vec(&list).unwrap()).unwrap();
}

/// One simulated peer.
struct Peer {
    id: u64,
    tunn: Tunn,
    socket: UdpSocket,
    /// When the current handshake attempt began, if the peer is not yet established.
    started: Option<Instant>,
    /// When the peer first asked for this session; retries do not move it, so the measured
    /// handshake time includes every retry the hub's admission control caused.
    first_started: Option<Instant>,
    /// Initiations sent for the current session (1 = answered at once).
    attempts: u32,
    /// How long the last completed handshake took.
    took: Option<Duration>,
    established: bool,
    next_keepalive: Option<Instant>,
}

/// CPU seconds (user + system) this process has used so far.
fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after = stat.rsplit(')').next().unwrap();
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After the closing paren: state is field 0, utime is field 11, stime field 12.
    let ticks: f64 = fields[11].parse::<f64>().unwrap() + fields[12].parse::<f64>().unwrap();
    ticks / 100.0
}

/// The simulator state.
struct Sim {
    peers: Vec<Peer>,
    poll: Poll,
    hub: SocketAddr,
    hub_public: Option<PublicKey>,
    secrets: Vec<[u8; 32]>,
    buf: Vec<u8>,
    rx: Vec<u8>,
    /// Inner datagrams the hub never confirmed are not tracked; only wire counts.
    rng: Xor,
    keepalive: Option<Duration>,
    /// `single`, `spread` or `known` (see the module docs).
    mode: String,
    wire_tx: u64,
    wire_rx: u64,
}

impl Sim {
    /// Make sure the first `n` peers exist (sockets bound, `Tunn` ready).
    fn ensure(&mut self, n: usize) {
        let hub_public = self.hub_public.expect("identity first");
        while self.peers.len() < n {
            let index = self.peers.len();
            let id = index as u64 + 1;
            let secret = StaticSecret::from(self.secrets[index]);
            let bind = match self.mode.as_str() {
                "single" => SocketAddr::new(SIM_UNDERLAY.into(), 0),
                "spread" => SocketAddr::new(spread_addr(index).into(), 0),
                _ => SocketAddr::new(spread_addr(index).into(), KNOWN_PORT),
            };
            let mut socket = UdpSocket::bind(bind).unwrap();
            self.poll
                .registry()
                .register(&mut socket, Token(index), Interest::READABLE)
                .unwrap();
            let tunn = Tunn::new(secret, hub_public, None, None, u32::try_from(index).unwrap(), None).unwrap();
            self.peers.push(Peer {
                id,
                tunn,
                socket,
                started: None,
                first_started: None,
                attempts: 0,
                took: None,
                established: false,
                next_keepalive: None,
            });
        }
    }

    /// Send one handshake initiation for peer `index`.
    fn initiate(&mut self, index: usize, force: bool) {
        let peer = &mut self.peers[index];
        if let TunnResult::WriteToNetwork(packet) =
            peer.tunn.format_handshake_initiation(&mut self.buf, force)
        {
            let _ = peer.socket.send_to(packet, self.hub);
            self.wire_tx += 1;
        }
        peer.started = Some(Instant::now());
        peer.attempts += 1;
        peer.established = false;
    }

    /// Forget the previous session's timing so the next `initiate` starts a fresh measurement.
    fn begin_session(&mut self, index: usize) {
        let peer = &mut self.peers[index];
        peer.first_started = Some(Instant::now());
        peer.attempts = 0;
        peer.took = None;
    }

    /// Drain every readable socket; process replies. Returns datagrams read.
    fn pump(&mut self, events: &mut Events, wait: Duration) -> usize {
        self.poll.poll(events, Some(wait)).unwrap();
        let mut count = 0;
        let tokens: Vec<usize> = events.iter().map(|event| event.token().0).collect();
        for index in tokens {
            loop {
                let peer = &mut self.peers[index];
                let Ok((len, _)) = peer.socket.recv_from(&mut self.rx) else {
                    break;
                };
                count += 1;
                self.wire_rx += 1;
                let mut input: &[u8] = &self.rx[..len];
                loop {
                    match peer.tunn.decapsulate(None, input, &mut self.buf) {
                        TunnResult::WriteToNetwork(reply) => {
                            let _ = peer.socket.send_to(reply, self.hub);
                            self.wire_tx += 1;
                            // The documented way to flush queued output: call again with no input.
                            input = &[];
                            // The keepalive a peer sends straight after processing the hub's
                            // handshake response is the sign that the response arrived.
                            if !peer.established && peer.started.is_some() {
                                peer.established = true;
                                peer.took = peer.first_started.map(|at| at.elapsed());
                            }
                        }
                        TunnResult::WriteToTunnelV4(..) | TunnResult::WriteToTunnelV6(..) => break,
                        TunnResult::Done | TunnResult::Err(_) => break,
                    }
                }
            }
        }
        count
    }

    /// Send keepalives that are due, and retry handshakes unanswered for 5 s (WireGuard's
    /// `REKEY_TIMEOUT`, plus up to 1 s of jitter so retries do not stay in lockstep).
    fn housekeeping(&mut self) {
        let now = Instant::now();
        for index in 0..self.peers.len() {
            let peer = &mut self.peers[index];
            if !peer.established {
                if peer.started.is_some_and(|at| now.duration_since(at) > Duration::from_millis(5000 + (peer.id * 37 % 1000))) {
                    self.initiate(index, true);
                }
                continue;
            }
            if let (Some(due), Some(interval)) = (peer.next_keepalive, self.keepalive) {
                if now >= due {
                    if let TunnResult::WriteToNetwork(packet) = peer.tunn.encapsulate(&[], &mut self.buf) {
                        let _ = peer.socket.send_to(packet, self.hub);
                        self.wire_tx += 1;
                    }
                    peer.next_keepalive = Some(now + interval);
                }
            }
        }
    }
}

/// An inner IPv4/UDP datagram from `id` to the sink, `payload` bytes long, carrying `seq`.
fn inner_packet(id: u64, payload: usize, seq: u64, out: &mut Vec<u8>) {
    out.clear();
    let total = 20 + 8 + payload;
    out.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0]);
    out.extend_from_slice(&mesh_addr(id).octets());
    out.extend_from_slice(&HUB_MESH.octets());
    let mut sum: u32 = 0;
    for pair in out.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let checksum = !(sum as u16);
    out[10..12].copy_from_slice(&checksum.to_be_bytes());
    let udp_len = 8 + payload;
    out.extend_from_slice(&40000_u16.to_be_bytes());
    out.extend_from_slice(&SINK_PORT.to_be_bytes());
    out.extend_from_slice(&u16::try_from(udp_len).unwrap().to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.resize(total, 0);
    out[28..36].copy_from_slice(&seq.to_be_bytes());
}

/// Run the command loop.
fn run_sim(keys_path: &str, fifo: &str, out_path: &str, hub_ip: &str, hub_port: u16, mode: &str) {
    let raw = std::fs::read(keys_path).unwrap();
    let secrets: Vec<[u8; 32]> = raw.chunks(32).map(|chunk| chunk.try_into().unwrap()).collect();
    let mut sim = Sim {
        peers: Vec::new(),
        poll: Poll::new().unwrap(),
        hub: SocketAddr::new(hub_ip.parse().unwrap(), hub_port),
        hub_public: None,
        secrets,
        buf: vec![0; 4096],
        rx: vec![0; 4096],
        rng: Xor(0x9e37_79b9_7f4a_7c15 ^ std::process::id() as u64),
        keepalive: None,
        mode: mode.to_owned(),
        wire_tx: 0,
        wire_rx: 0,
    };
    let mut out = std::fs::OpenOptions::new().create(true).append(true).open(out_path).unwrap();
    let mut events = Events::with_capacity(1024);
    let reader = std::io::BufReader::new(std::fs::File::open(fifo).unwrap());
    let mut scratch = Vec::with_capacity(2048);
    for line in reader.lines() {
        let line = line.unwrap();
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(&command) = words.first() else { continue };
        let number = |at: usize| -> f64 { words.get(at).and_then(|word| word.parse().ok()).unwrap_or(0.0) };
        let mut result = serde_json::json!({"cmd": command});
        let cpu0 = cpu_seconds();
        match command {
            "identity" => {
                let mut key = [0_u8; 32];
                for (index, byte) in key.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&words[1][index * 2..index * 2 + 2], 16).unwrap();
                }
                sim.hub_public = Some(PublicKey::from(key));
            }
            "connect" | "storm" => {
                let n = if command == "connect" { number(1) as usize } else { sim.peers.len() };
                let rate = number(2);
                let old = sim.peers.len();
                sim.ensure(n);
                let begin = Instant::now();
                for index in 0..n {
                    if command == "storm" || index >= old {
                        // Pace by schedule when a rate is given; rate 0 means everyone at once.
                        if rate > 0.0 {
                            let due = begin + Duration::from_secs_f64(index as f64 / rate);
                            while Instant::now() < due {
                                sim.pump(&mut events, Duration::from_millis(1));
                            }
                        }
                        sim.begin_session(index);
                        sim.initiate(index, true);
                    }
                }
                let mut last_progress = Instant::now();
                let mut done = 0;
                while done < n && begin.elapsed() < Duration::from_secs(120) {
                    sim.pump(&mut events, Duration::from_millis(5));
                    sim.housekeeping();
                    let now_done = sim.peers[..n].iter().filter(|p| p.established).count();
                    if now_done != done {
                        done = now_done;
                        last_progress = Instant::now();
                    }
                    if last_progress.elapsed() > Duration::from_secs(30) {
                        break;
                    }
                }
                let mut times: Vec<f64> = sim.peers[..n]
                    .iter()
                    .filter_map(|p| p.took.map(|t| t.as_secs_f64() * 1e3))
                    .collect();
                times.sort_by(f64::total_cmp);
                let pick = |q: f64| times.get(((times.len() as f64 - 1.0) * q) as usize).copied();
                result["peers"] = n.into();
                result["established"] = done.into();
                result["wall_ms"] = (begin.elapsed().as_secs_f64() * 1e3).into();
                result["hs_p50_ms"] = pick(0.5).into();
                result["hs_p99_ms"] = pick(0.99).into();
                result["hs_max_ms"] = times.last().copied().into();
                let retried = sim.peers[..n].iter().filter(|p| p.attempts > 1).count();
                let max_attempts = sim.peers[..n].iter().map(|p| p.attempts).max().unwrap_or(0);
                result["peers_retried"] = retried.into();
                result["max_attempts"] = max_attempts.into();
            }
            "keepalive" => {
                let seconds = number(1);
                if seconds > 0.0 {
                    let interval = Duration::from_secs_f64(seconds);
                    sim.keepalive = Some(interval);
                    for peer in &mut sim.peers {
                        let phase = (sim.rng.next() % 1_000_000) as f64 / 1e6;
                        peer.next_keepalive = Some(Instant::now() + interval.mul_f64(phase));
                    }
                } else {
                    sim.keepalive = None;
                }
            }
            "hold" => {
                // Keep serving replies and keepalives for a number of seconds (idle windows).
                let end = Instant::now() + Duration::from_secs_f64(number(1));
                while Instant::now() < end {
                    sim.pump(&mut events, Duration::from_millis(50));
                    sim.housekeeping();
                }
            }
            "send" | "probe" => {
                let (active, secs, payload, mbit): (Vec<usize>, f64, usize, f64) = if command == "send" {
                    ((0..number(1) as usize).collect(), number(2), number(3) as usize, number(4))
                } else {
                    (vec![number(1) as usize - 1], number(2), 16, 0.0)
                };
                let probe = command == "probe";
                let begin = Instant::now();
                let end = begin + Duration::from_secs_f64(secs);
                let mut sent = 0_u64;
                let mut bytes = 0_u64;
                let mut turn = 0;
                let wire = (payload + 28 + 32) as f64 * 8.0;
                while Instant::now() < end {
                    let index = active[turn % active.len()];
                    turn += 1;
                    if probe {
                        // 1 kHz numbered stream, paced by schedule.
                        let due = begin + Duration::from_millis(sent);
                        while Instant::now() < due {
                            sim.pump(&mut events, Duration::from_micros(200));
                            sim.housekeeping();
                        }
                    } else if mbit > 0.0 {
                        let due = begin + Duration::from_secs_f64(sent as f64 * wire / (mbit * 1e6));
                        while Instant::now() < due {
                            std::hint::spin_loop();
                        }
                    }
                    inner_packet(sim.peers[index].id, payload, sent, &mut scratch);
                    let peer = &mut sim.peers[index];
                    if let TunnResult::WriteToNetwork(packet) = peer.tunn.encapsulate(&scratch, &mut sim.buf) {
                        if peer.socket.send_to(packet, sim.hub).is_ok() {
                            bytes += scratch.len() as u64;
                        }
                        sim.wire_tx += 1;
                    }
                    sent += 1;
                    if sent % 64 == 0 {
                        sim.pump(&mut events, Duration::ZERO);
                    }
                }
                let took = begin.elapsed().as_secs_f64();
                result["sent"] = sent.into();
                result["inner_mbit"] = (bytes as f64 * 8.0 / took / 1e6).into();
                result["secs"] = took.into();
                result["active"] = active.len().into();
            }
            "exit" => {
                writeln!(out, "{result}").unwrap();
                return;
            }
            _ => result["error"] = "unknown command".into(),
        }
        result["sim_cpu_s"] = (cpu_seconds() - cpu0).into();
        result["wire_tx"] = sim.wire_tx.into();
        result["wire_rx"] = sim.wire_rx.into();
        writeln!(out, "{result}").unwrap();
        out.flush().unwrap();
    }
}

/// The sink: counts datagrams and watches one source for gaps.
fn run_sink(port: u16, probe_ip: &str) {
    let socket = std::net::UdpSocket::bind((HUB_MESH, port)).unwrap();
    let fd = std::os::fd::AsRawFd::as_raw_fd(&socket);
    // A big receive buffer so the sink is not what drops packets.
    unsafe {
        let size: libc::c_int = 32 << 20;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, std::ptr::addr_of!(size).cast(), 4);
    }
    let probe: Ipv4Addr = probe_ip.parse().unwrap();
    const BATCH: usize = 64;
    let mut buffers = vec![[0_u8; 2048]; BATCH];
    let mut iov: Vec<libc::iovec> = buffers
        .iter_mut()
        .map(|b| libc::iovec { iov_base: b.as_mut_ptr().cast(), iov_len: 2048 })
        .collect();
    let mut names: Vec<libc::sockaddr_in> = vec![unsafe { std::mem::zeroed() }; BATCH];
    // Datagrams carry the inner packet's own source only inside the payload header we built, so the
    // sink reads the sender from the socket: the hub delivers from the peer's mesh address.
    let mut headers: Vec<libc::mmsghdr> = (0..BATCH)
        .map(|i| {
            let mut header: libc::mmsghdr = unsafe { std::mem::zeroed() };
            header.msg_hdr.msg_iov = &mut iov[i];
            header.msg_hdr.msg_iovlen = 1;
            header.msg_hdr.msg_name = std::ptr::addr_of_mut!(names[i]).cast();
            header.msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
            header
        })
        .collect();
    let timeout = libc::timeval { tv_sec: 0, tv_usec: 200_000 };
    unsafe {
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, std::ptr::addr_of!(timeout).cast(), 16);
    }
    let mut sources: HashSet<u32> = HashSet::new();
    let (mut packets, mut bytes) = (0_u64, 0_u64);
    let mut last_probe: Option<Instant> = None;
    let mut max_gap = Duration::ZERO;
    let mut window = Instant::now();
    let mut stdout = std::io::stdout();
    loop {
        let got = unsafe { libc::recvmmsg(fd, headers.as_mut_ptr(), BATCH as u32, 0, std::ptr::null_mut()) };
        let now = Instant::now();
        if got < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                eprintln!("recvmmsg failed: {error}");
            }
        }
        if got > 0 {
            for i in 0..got as usize {
                packets += 1;
                bytes += u64::from(headers[i].msg_len);
                let source = u32::from_be(names[i].sin_addr.s_addr);
                sources.insert(source);
                if Ipv4Addr::from(source) == probe {
                    if let Some(prev) = last_probe {
                        max_gap = max_gap.max(now.duration_since(prev));
                    }
                    last_probe = Some(now);
                }
                headers[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
            }
        }
        if now.duration_since(window) >= Duration::from_secs(1) {
            // A probe silent for the whole window counts as a gap of that long.
            if let Some(prev) = last_probe {
                max_gap = max_gap.max(now.duration_since(prev));
            }
            let line = serde_json::json!({
                "t": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64(),
                "packets": packets, "bytes": bytes, "sources": sources.len(),
                "probe_max_gap_ms": max_gap.as_secs_f64() * 1e3,
            });
            writeln!(stdout, "{line}").unwrap();
            stdout.flush().unwrap();
            max_gap = Duration::ZERO;
            window = now;
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keys") => make_keys(args[2].parse().unwrap(), &args[3], &args[4], &args[5]),
        Some("sim") => run_sim(&args[2], &args[3], &args[4], &args[5], args[6].parse().unwrap(), &args[7]),
        Some("sink") => run_sink(args[2].parse().unwrap(), &args[3]),
        _ => {
            eprintln!("usage: peersim keys|sim|sink ...");
            std::process::exit(2);
        }
    }
}
