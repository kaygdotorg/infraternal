//! Terminal measurements that run unchanged against every system.
//!
//! A `TermIo` is one attached viewer: a PTY running a multiplexer client
//! (`pty`), or a native infraternal leg-A client (`ix`). The procedures here
//! only send keystrokes and read bytes, so tmux, Zellij, tmux over SSH and
//! infraternal go through the same code.
//!
//! The probe program (`echo-inner`) runs inside every session. It answers each
//! byte it reads with a unique token `{n}`, so an echo is matched by its own
//! sequence number, never by text a redraw happens to repeat.
use crate::args::{Args, die};
use crate::clock::{ms_since, now_ns};
use crate::stats::summary;
use crate::vt::Stripper;
use serde_json::json;
use std::io::{Read, Write};
use std::time::Duration;

/// Common byte and lifecycle operations for each terminal viewer transport.
pub trait TermIo {
    /// Send input bytes to the attached terminal session.
    fn send(&mut self, bytes: &[u8]);
    /// Raw bytes the viewer received, or `None` after `timeout` of silence.
    fn recv(&mut self, timeout: Duration) -> Option<Vec<u8>>;
    /// Release the viewer and its transport after a measurement.
    fn close(self: Box<Self>);
    /// Keepalive probes the viewer answered (zero where the transport has none).
    fn probes(&self) -> u64 {
        0
    }
}

/// Accumulates printed text and counts delivered bytes.
pub struct Screen {
    io: Box<dyn TermIo>,
    strip: Stripper,
    text: Vec<u8>,
    pub bytes: u64,
}

impl Screen {
    /// Wrap one viewer transport with output filtering and byte accounting.
    pub fn new(io: Box<dyn TermIo>) -> Self {
        Self { io, strip: Stripper::default(), text: Vec::new(), bytes: 0 }
    }

    /// Read one viewer chunk, update counters, and return whether bytes arrived.
    fn pump(&mut self, timeout: Duration) -> bool {
        match self.io.recv(timeout) {
            Some(raw) => {
                self.bytes += raw.len() as u64;
                self.strip.feed(&raw, &mut self.text);
                if self.text.len() > 1 << 20 {
                    self.text.drain(..self.text.len() - 4096);
                }
                true
            }
            None => false,
        }
    }

    /// Read until `quiet_ms` pass with no output (or `max_ms` in total).
    pub fn settle(&mut self, quiet_ms: u64, max_ms: f64) {
        let start = now_ns();
        while ms_since(start) < max_ms && self.pump(Duration::from_millis(quiet_ms)) {}
    }

    /// Forget printable output while keeping cumulative received-byte accounting.
    pub fn clear(&mut self) {
        self.text.clear();
    }

    /// Wait until `needle` has been printed; milliseconds from `since`.
    pub fn wait_for(&mut self, needle: &str, since: u64, timeout_ms: f64) -> f64 {
        let needle = needle.as_bytes();
        let mut scanned = 0usize;
        loop {
            let from = scanned.saturating_sub(needle.len());
            if self.text.len() >= needle.len() && self.text[from..].windows(needle.len()).any(|w| w == needle) {
                return ms_since(since);
            }
            scanned = self.text.len();
            if ms_since(since) > timeout_ms {
                die(&format!("timed out waiting for {:?}", String::from_utf8_lossy(needle)));
            }
            let len_before = self.text.len();
            self.pump(Duration::from_millis(50));
            // The buffer may have been trimmed; rescan its tail.
            if self.text.len() < len_before {
                scanned = 0;
            }
        }
    }

    /// Send input bytes through the selected viewer transport.
    pub fn send(&mut self, bytes: &[u8]) {
        self.io.send(bytes);
    }

    /// Close the underlying viewer transport and its child resources.
    pub fn close(self) {
        self.io.close();
    }
}

/// Type a line into the session's shell and wait for its marker.
pub fn type_line(screen: &mut Screen, line: &str, marker: Option<&str>, timeout_ms: f64) -> f64 {
    screen.clear();
    let start = now_ns();
    screen.send(format!("{line}\r").as_bytes());
    marker.map(|m| screen.wait_for(m, start, timeout_ms)).unwrap_or(0.0)
}

/// Convert the command-line `\\r` and `\\n` spellings to control characters.
fn unescape(s: &str) -> String {
    s.replace("\\r", "\r").replace("\\n", "\n")
}

/// `term-echo`: keystroke-to-echo latency through the whole path.
pub fn echo(args: &Args, mut screen: Screen) {
    let samples: usize = args.num("samples", 200);
    let warmup: usize = args.num("warmup", 10);
    let gap_ms: u64 = args.num("gap-ms", 20);
    let timeout_ms: f64 = args.num("timeout-s", 30.0) * 1000.0;
    screen.settle(400, 15_000.0);
    type_line(&mut screen, &args.str("inner"), Some("H2H_READY"), timeout_ms);
    screen.settle(300, 5_000.0);
    let mut out = Vec::with_capacity(samples);
    for i in 0..warmup + samples {
        screen.clear();
        let start = now_ns();
        screen.send(b"k");
        let ms = screen.wait_for(&format!("{{{i}}}"), start, timeout_ms);
        if i >= warmup {
            out.push(ms);
        }
        std::thread::sleep(Duration::from_millis(gap_ms));
    }
    // Ctrl-D ends the probe and returns the shell.
    screen.send(b"\x04");
    screen.settle(200, 3_000.0);
    println!("{}", json!({"echo_ms": summary(&out), "bytes_received": screen.bytes}));
    screen.close();
}

/// `term-flood`: run an output-heavy command; time until its end marker shows.
pub fn flood(args: &Args, mut screen: Screen) {
    let timeout_ms: f64 = args.num("timeout-s", 300.0) * 1000.0;
    let marker = args.str("marker");
    screen.settle(400, 15_000.0);
    let before = screen.bytes;
    let ms = type_line(&mut screen, &args.str("command"), Some(&marker), timeout_ms);
    let delivered = screen.bytes - before;
    screen.settle(500, 30_000.0);
    println!("{}", json!({"seconds_to_marker": ms / 1000.0, "bytes_delivered": delivered}));
    screen.close();
}

/// `term-type`: type one line, optionally wait for a marker (setup steps).
pub fn type_cmd(args: &Args, mut screen: Screen) {
    screen.settle(400, 15_000.0);
    let ms = type_line(&mut screen, &unescape(&args.str("text")), args.opt("marker").as_deref(), 60_000.0);
    screen.settle(300, 5_000.0);
    println!("{}", json!({"ms": ms}));
    screen.close();
}

/// `term-attach`: open a fresh viewer and time until `marker` is on screen.
pub fn attach(args: &Args, open: &dyn Fn() -> Screen) {
    let samples: usize = args.num("samples", 20);
    let marker = args.str("marker");
    let mut out = Vec::new();
    for _ in 0..samples {
        let start = now_ns();
        let mut screen = open();
        out.push(screen.wait_for(&marker, start, 30_000.0));
        screen.settle(100, 2_000.0);
        screen.close();
        std::thread::sleep(Duration::from_millis(200));
    }
    println!("{}", json!({"attach_ms": summary(&out)}));
}

/// `term-hold`: stay attached and idle for `--seconds`; reports what an idle
/// viewer received (redraws, keepalives). Run `proc-idle` alongside it.
pub fn hold(args: &Args, mut screen: Screen) {
    let seconds: f64 = args.num("seconds", 30.0);
    screen.settle(500, 15_000.0);
    let before = screen.bytes;
    let probes_before = screen.io.probes();
    let start = now_ns();
    while ms_since(start) < seconds * 1000.0 {
        screen.pump(Duration::from_millis(100));
    }
    println!(
        "{}",
        json!({"seconds": seconds, "bytes_received": screen.bytes - before,
               "keepalive_probes_per_s": (screen.io.probes() - probes_before) as f64 / seconds})
    );
    screen.close();
}

/// `echo-inner`: the probe program run inside every session.
pub fn echo_inner() {
    // SAFETY: plain termios calls on our controlling terminal (fd 0).
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut t) != 0 {
            die("stdin is not a terminal");
        }
        let saved = t;
        libc::cfmakeraw(&mut t);
        libc::tcsetattr(0, libc::TCSANOW, &t);
        saved
    };
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(b"\x1b[H\x1b[2JH2H_READY\r\n");
    let _ = stdout.flush();
    let mut stdin = std::io::stdin().lock();
    let mut buf = [0u8; 64];
    let mut n: u64 = 0;
    'outer: loop {
        let Ok(read) = stdin.read(&mut buf) else { break };
        if read == 0 {
            break;
        }
        let mut reply = Vec::new();
        for &b in &buf[..read] {
            if b == 0x04 {
                break 'outer;
            }
            reply.extend_from_slice(format!("{{{n}}}").as_bytes());
            n += 1;
            if n % 16 == 0 {
                reply.extend_from_slice(b"\r\n");
            }
        }
        let _ = stdout.write_all(&reply);
        let _ = stdout.flush();
    }
    let _ = stdout.write_all(b"\r\n");
    let _ = stdout.flush();
    // SAFETY: restore the terminal mode saved above.
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
}
