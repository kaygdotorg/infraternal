//! Mesh data-plane probes: one server and three clients, identical for every
//! system under test, so only the tunnel differs between runs.
//!
//! - `net-server`: on one address, a TCP sink (`S`), a TCP echo (`E`) and a UDP
//!   reflector that stamps its receive and send times into each probe.
//! - `net-tput`: N TCP flows for a fixed time; the receiver's byte count is the
//!   result, and whole-machine CPU is sampled across the same window.
//! - `net-lat`: paced UDP probes of a fixed payload size; RTT and both one-way
//!   delays (shared CLOCK_MONOTONIC, see `clock`).
//! - `net-wait`: probe until the first reply, for time-to-first-packet.
use crate::args::{Args, die};
use crate::clock::{ms_since, now_ns};
use crate::procstat;
use crate::stats::{loss_aware_summary, summary};
use serde_json::json;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Identify probe datagrams shared by the sender and reflector.
const MAGIC: u32 = 0x4832_4821;
/// Reserve bytes for the marker, sequence, and three monotonic timestamps.
const HEADER: usize = 32;

/// Bind TCP and UDP probe services at `--bind` and print readiness.
pub fn server(args: &Args) {
    let addr: SocketAddr = args.str("bind").parse().unwrap_or_else(|_| die("bad --bind"));
    let listener = TcpListener::bind(addr).unwrap_or_else(|e| die(&format!("tcp bind: {e}")));
    let udp = UdpSocket::bind(addr).unwrap_or_else(|e| die(&format!("udp bind: {e}")));
    thread::spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, peer)) = udp.recv_from(&mut buf) else { continue };
            let rx = now_ns();
            if n < HEADER || u32::from_le_bytes(buf[0..4].try_into().unwrap()) != MAGIC {
                continue;
            }
            buf[16..24].copy_from_slice(&rx.to_le_bytes());
            buf[24..32].copy_from_slice(&now_ns().to_le_bytes());
            let _ = udp.send_to(&buf[..n], peer);
        }
    });
    println!("ready");
    let _ = std::io::stdout().flush();
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        thread::spawn(move || {
            let mut mode = [0u8; 1];
            if stream.read_exact(&mut mode).is_err() {
                return;
            }
            let mut buf = vec![0u8; 256 * 1024];
            match mode[0] {
                b'S' => {
                    let mut total: u64 = 0;
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => total += n as u64,
                        }
                    }
                    let _ = stream.write_all(&total.to_le_bytes());
                }
                b'E' => {
                    let _ = stream.set_nodelay(true);
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        });
    }
}

/// Run the requested number of TCP flows and report bytes, CPU, and peak memory.
pub fn tput(args: &Args) {
    let to: SocketAddr = args.str("to").parse().unwrap_or_else(|_| die("bad --to"));
    let flows: usize = args.num("flows", 1);
    let seconds: f64 = args.num("seconds", 10.0);
    let watch = procstat::Selection::from_args(args);
    let stop = Arc::new(AtomicBool::new(false));
    let mut conns = Vec::new();
    for _ in 0..flows {
        let mut s = TcpStream::connect_timeout(&to, Duration::from_secs(10))
            .unwrap_or_else(|e| die(&format!("connect: {e}")));
        s.write_all(b"S").unwrap();
        conns.push(s);
    }
    let cpu0 = procstat::cpu_jiffies();
    let ticks0 = watch.cpu_ticks();
    let start = now_ns();
    let handles: Vec<_> = conns
        .into_iter()
        .map(|mut s| {
            let stop = stop.clone();
            thread::spawn(move || {
                let block = vec![0x5au8; 128 * 1024];
                while !stop.load(Ordering::Relaxed) {
                    if s.write_all(&block).is_err() {
                        break;
                    }
                }
                let _ = s.shutdown(Shutdown::Write);
                let mut count = [0u8; 8];
                let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
                s.read_exact(&mut count).map(|_| u64::from_le_bytes(count)).unwrap_or(0)
            })
        })
        .collect();
    // Sample memory of the watched processes while the load runs (peak).
    let mut peak = procstat::MemTotals::default();
    let deadline = start + (seconds * 1e9) as u64;
    while now_ns() < deadline {
        thread::sleep(Duration::from_millis(250));
        peak = peak.max(watch.mem());
    }
    stop.store(true, Ordering::Relaxed);
    let bytes: u64 = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();
    let elapsed = ms_since(start) / 1000.0;
    let cpu1 = procstat::cpu_jiffies();
    let ticks1 = watch.cpu_ticks();
    let gbit = bytes as f64 * 8.0 / elapsed / 1e9;
    let busy_s = cpu1.0.saturating_sub(cpu0.0) as f64 / procstat::hz();
    println!(
        "{}",
        json!({
            "flows": flows,
            "seconds": elapsed,
            "bytes": bytes,
            "gbit_per_s": (gbit * 1000.0).round() / 1000.0,
            "machine_cpu_busy_s": busy_s,
            "machine_cpu_s_per_gbit": if gbit > 0.0 { busy_s / (gbit * elapsed) } else { 0.0 },
            "machine_cores_busy": busy_s / elapsed,
            "watched_cpu_s": ticks1.saturating_sub(ticks0) as f64 / procstat::hz(),
            "watched_rss_kb_peak": peak.rss_kb,
            "watched_pss_kb_peak": peak.pss_kb,
        })
    );
}

/// Stamp one UDP probe with its sequence and monotonic send time.
fn probe(buf: &mut [u8], seq: u32) {
    buf[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    buf[4..8].copy_from_slice(&seq.to_le_bytes());
    buf[8..16].copy_from_slice(&now_ns().to_le_bytes());
}

/// Send paced UDP RTT probes and report loss-aware latency percentiles.
pub fn lat(args: &Args) {
    lat_measure(args, false);
}

/// Send unpaced UDP probes and report both delivered packet rate and loss-aware RTT.
pub fn pps(args: &Args) {
    lat_measure(args, true);
}

/// Run one fixed-count UDP probe series, paced for latency or unpaced for packet rate.
fn lat_measure(args: &Args, unpaced: bool) {
    let to: SocketAddr = args.str("to").parse().unwrap_or_else(|_| die("bad --to"));
    let size: usize = args.num("size", 64).max(HEADER);
    let count: usize = args.num("count", 1000);
    let interval_us: u64 = if unpaced { 0 } else { args.num("interval-us", 1000) };
    let bind: SocketAddr = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).unwrap();
    sock.connect(to).unwrap();
    let rx = sock.try_clone().unwrap();
    let receiver = thread::spawn(move || {
        let mut got: Vec<Option<(f64, f64, f64)>> = vec![None; count];
        let mut buf = vec![0u8; 65536];
        rx.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut idle_since = now_ns();
        let mut received = 0;
        while received < count {
            match rx.recv(&mut buf) {
                Ok(n) if n >= HEADER => {
                    let now = now_ns();
                    let seq = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
                    let sent = u64::from_le_bytes(buf[8..16].try_into().unwrap());
                    let srx = u64::from_le_bytes(buf[16..24].try_into().unwrap());
                    let stx = u64::from_le_bytes(buf[24..32].try_into().unwrap());
                    if seq < count && got[seq].is_none() {
                        got[seq] = Some((
                            (now - sent) as f64 / 1e6,
                            srx.saturating_sub(sent) as f64 / 1e6,
                            now.saturating_sub(stx) as f64 / 1e6,
                        ));
                        received += 1;
                    }
                    idle_since = now;
                }
                _ => {
                    // Probes still in flight after 3 s of silence count as lost.
                    if ms_since(idle_since) > 3000.0 {
                        break;
                    }
                }
            }
        }
        got
    });
    let mut buf = vec![0u8; size];
    let start = now_ns();
    for seq in 0..count {
        let due = start + seq as u64 * interval_us * 1000;
        while now_ns() < due {
            let left = due.saturating_sub(now_ns());
            if left > 200_000 {
                thread::sleep(Duration::from_nanos(left - 100_000));
            } else {
                std::hint::spin_loop();
            }
        }
        probe(&mut buf, seq as u32);
        let _ = sock.send(&buf);
    }
    let send_end = now_ns();
    let got = receiver.join().unwrap();
    let ok: Vec<_> = got.iter().filter_map(|v| *v).collect();
    let rtt: Vec<f64> = ok.iter().map(|v| v.0).collect();
    let fwd: Vec<f64> = ok.iter().map(|v| v.1).collect();
    let rev: Vec<f64> = ok.iter().map(|v| v.2).collect();
    let send_elapsed_s = (send_end.saturating_sub(start) as f64 / 1e9).max(1e-9);
    let received = ok.len();
    if let Some(path) = args.opt("raw-path") {
        let file = File::create(&path).unwrap_or_else(|e| die(&format!("cannot create raw probe log {path}: {e}")));
        let mut raw = BufWriter::new(file);
        for (seq, sample) in got.iter().enumerate() {
            match sample {
                Some((rtt_ms, fwd_ms, rev_ms)) => {
                    writeln!(raw, "{}", json!({"seq":seq,"received":true,"rtt_ms":rtt_ms,"one_way_fwd_ms":fwd_ms,"one_way_rev_ms":rev_ms}))
                        .unwrap_or_else(|e| die(&format!("cannot write raw probe log {path}: {e}")));
                }
                None => {
                    writeln!(raw, "{}", json!({"seq":seq,"received":false}))
                        .unwrap_or_else(|e| die(&format!("cannot write raw probe log {path}: {e}")));
                }
            }
        }
        raw.flush().unwrap_or_else(|e| die(&format!("cannot flush raw probe log {path}: {e}")));
    }
    let rtt_loss_aware = loss_aware_summary(&rtt, count);
    let loss = count.saturating_sub(received);
    let payload_gbit_per_s = received as f64 * size as f64 * 8.0 / send_elapsed_s / 1e9;
    println!(
        "{}",
        json!({
            "payload_bytes": size,
            "sent": count,
            "received": received,
            "lost": loss,
            "interval_us": interval_us,
            "send_elapsed_s": send_elapsed_s,
            "tx_pps": count as f64 / send_elapsed_s,
            "rx_pps": received as f64 / send_elapsed_s,
            "payload_gbit_per_s": payload_gbit_per_s,
            "rtt_ms": summary(&rtt),
            "loss_aware_rtt_ms": rtt_loss_aware,
            "one_way_fwd_ms": summary(&fwd),
            "one_way_rev_ms": summary(&rev),
        })
    );
}

/// Probe until the first UDP reply arrives or the requested deadline expires.
pub fn wait(args: &Args) {
    let to: SocketAddr = args.str("to").parse().unwrap_or_else(|_| die("bad --to"));
    let since: u64 = args.num("since-ns", now_ns());
    let timeout_ms: f64 = args.num("timeout-s", 120.0) * 1000.0;
    let bind: SocketAddr = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    let sock = UdpSocket::bind(bind).unwrap();
    sock.connect(to).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
    let mut buf = vec![0u8; 64];
    let mut attempts = 0u32;
    loop {
        if ms_since(since) > timeout_ms {
            println!("{}", json!({"ok": false, "attempts": attempts, "elapsed_ms": ms_since(since)}));
            std::process::exit(1);
        }
        probe(&mut buf, attempts);
        attempts += 1;
        let _ = sock.send(&buf);
        let mut reply = [0u8; 64];
        if let Ok(n) = sock.recv(&mut reply) {
            if n >= HEADER {
                println!("{}", json!({"ok": true, "attempts": attempts, "elapsed_ms": ms_since(since)}));
                return;
            }
        }
    }
}
