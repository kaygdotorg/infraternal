//! Acceptance probe for #146 (J1116): one viewer's video over a slow link, through the real server session code.
//!
//! What is real: the server's [`Session`] and [`Viewer`] (the recent-frame window, gap repair and
//! pressure reports), a viewer write loop with the same one-frame-in-flight rule and 1 s write limit
//! as the server's socket adapter, and a real TCP connection through whatever link the runner sets
//! up (a disposable network namespace with netem, see `research/app-windows/j1116/`).
//!
//! What is modelled: the Mac's encoder. It produces a frame every 1/120 s (steady scrolling, the
//! heaviest case on #146) of `bit rate / 120` bytes, a keyframe of 250 KB scaled by the current
//! bit rate (J1078 measured 249–251 KB at 1.56 MP and the full rate) whenever the session asks for
//! one, and adapts its rate exactly like `AdaptiveBitrate` in `native/CaptureState.swift`: a pressure
//! report cuts it to 70 % (at most every 0.5 s, never below 500 kbit/s), eight healthy frames raise
//! it by 5 % (at most every second, never above width × height × 3).
//!
//! The reader at `PROBE_ADDR` echoes each frame's sequence and capture time (16 bytes) as soon as
//! the frame has fully arrived; the echo path is not shaped. Latency is capture to arrival at the
//! reader: it leaves out the fixed capture, encode, decode and paint stages.
//!
//! Run: `PROBE_ADDR=host:port PROBE_SECONDS=60 <test binary> --ignored --exact slow_link_probe
//! --nocapture`. It prints `METRIC` lines. For a before/after comparison on a tree without
//! pressure reports, delete the two marked ranges of after-only code: run.sh's comment gives
//! the exact `sed` command.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Rates, sizes and percentiles are modelled in floating point; every value is far inside the
// integer ranges it is converted to.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
use infraternal_plugin_desktop::session::{AccessRules, HostCommand, Session, Video};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Lets everyone view and control: access is not under test here.
struct Everyone;
impl AccessRules for Everyone {
    fn may_view(&self, _user: &str, _host: &str, _owner: &str) -> bool {
        true
    }
    fn may_control(&self, _user: &str, _host: &str, _owner: &str) -> bool {
        true
    }
}

/// The encoder's bit-rate controller, ported from `AdaptiveBitrate` (CaptureState.swift).
struct Bitrate {
    /// Highest rate, bits per second.
    maximum: f64,
    /// Rate in use, bits per second.
    current: f64,
    /// When the rate last changed.
    last: Option<Instant>,
    /// Healthy frames in a row, capped at 8.
    healthy: u32,
    /// When the rate was last cut.
    last_cut: Option<Instant>,
    /// Experiment (`PROBE_AIMD_SPLIT=1`): a cut waits 0.5 s after the last
    /// cut only, not after the last increase as the Swift controller does.
    split: bool,
}
impl Bitrate {
    /// Starts at `maximum` (at least 500 kbit/s).
    fn new(maximum: f64) -> Self {
        let maximum = maximum.max(500_000.0);
        Self {
            maximum,
            current: maximum,
            last: None,
            healthy: 0,
            last_cut: None,
            split: std::env::var_os("PROBE_AIMD_SPLIT").is_some(),
        }
    }
    /// Reports one frame's outcome, as the Swift controller does.
    fn feedback(&mut self, now: Instant, congested: bool) {
        let since = self
            .last
            .map_or(f64::INFINITY, |last| (now - last).as_secs_f64());
        if congested {
            self.healthy = 0;
            let since_cut = self
                .last_cut
                .map_or(f64::INFINITY, |last| (now - last).as_secs_f64());
            if (if self.split { since_cut } else { since }) >= 0.5 {
                self.current = (self.current * 0.7).max(500_000.0);
                self.last = Some(now);
                self.last_cut = Some(now);
            }
        } else {
            self.healthy = (self.healthy + 1).min(8);
            if self.healthy == 8 && since >= 1.0 {
                self.current =
                    (self.current + (self.current / 20.0).max(50_000.0)).min(self.maximum);
                self.last = Some(now);
                self.healthy = 0;
            }
        }
    }
}

/// Counters from the encoder model.
#[derive(Default, Debug)]
struct Produced {
    frames: u64,
    keyframes: u64,
    bytes: u64,
    repairs_asked: u64,
    pressure_reports: u64,
    min_rate: f64,
    rate_sum: f64,
}

/// The value at `quantile` (0..=1) of sorted `values`.
fn percentile(values: &[f64], quantile: f64) -> f64 {
    if values.is_empty() {
        return f64::NAN;
    }
    let rank = (quantile * (values.len() - 1) as f64).round() as usize;
    values[rank.min(values.len() - 1)]
}

/// Streams modelled scrolling video to `PROBE_ADDR` for `PROBE_SECONDS` and prints the result.
// One thread is enough at 3 Mbit/s, and the `server` feature alone has no multi-thread runtime.
#[tokio::test]
#[ignore = "needs PROBE_ADDR: a reader behind a shaped link (research/app-windows/j1116)"]
async fn slow_link_probe() {
    let address = std::env::var("PROBE_ADDR").expect("PROBE_ADDR");
    let seconds: u64 = std::env::var("PROBE_SECONDS").map_or(60, |s| s.parse().unwrap());
    let fps = 120.0;
    let (width, height) = (1520.0, 1026.0);
    let duration = Duration::from_secs(seconds);
    let (session, mut commands) =
        Session::new([7; 16], "mac".into(), "owner".into(), Arc::new(Everyone));
    let mut viewer = session.attach("owner".into()).unwrap();
    let socket = tokio::net::TcpStream::connect(&address).await.unwrap();
    socket.set_nodelay(true).unwrap();
    let (mut read, mut write) = socket.into_split();
    let epoch = Instant::now();

    let encoder_session = Arc::clone(&session);
    let encoder = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / fps));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut rate = Bitrate::new(width * height * 3.0);
        let mut stats = Produced {
            min_rate: rate.current,
            ..Produced::default()
        };
        let mut force = true;
        let mut sequence = 0;
        let trace = std::env::var_os("PROBE_TRACE").is_some();
        while epoch.elapsed() < duration {
            tick.tick().await;
            let now = Instant::now();
            while let Ok(command) = commands.try_recv() {
                match command {
                    HostCommand::Keyframe => {
                        force = true;
                        stats.repairs_asked += 1;
                    }
                    // after-only begin
                    HostCommand::Pressure { .. } => {
                        stats.pressure_reports += 1;
                        rate.feedback(now, true);
                    }
                    // after-only end
                    _ => {}
                }
            }
            let keyframe = std::mem::take(&mut force);
            let share = rate.current / rate.maximum;
            let size = if keyframe {
                (250_000.0 * share).max(41_000.0)
            } else {
                (rate.current / fps / 8.0).max(400.0)
            } as usize;
            sequence += 1;
            encoder_session
                .publish(Video {
                    sequence,
                    capture_ns: u64::try_from(epoch.elapsed().as_nanos()).unwrap(),
                    keyframe,
                    bytes: vec![0; size].into(),
                })
                .unwrap();
            stats.frames += 1;
            stats.keyframes += u64::from(keyframe);
            stats.bytes += size as u64;
            rate.feedback(now, false);
            stats.min_rate = stats.min_rate.min(rate.current);
            stats.rate_sum += rate.current;
            if trace && stats.frames % 120 == 0 {
                println!(
                    "TRACE t={:.0}s rate_mbit_s={:.2} repairs={} pressure={}",
                    epoch.elapsed().as_secs_f64(),
                    rate.current / 1e6,
                    stats.repairs_asked,
                    stats.pressure_reports
                );
            }
        }
        encoder_session.close();
        stats
    });

    let sent = Arc::new(Mutex::new((0_u64, 0_u64, 0_u64, 0_u64)));
    let writer_sent = Arc::clone(&sent);
    let writer = tokio::spawn(async move {
        let mut wire = Vec::new();
        let mut last_write = Duration::ZERO;
        // after-only begin
        // Experiment knob: the lag that reports pressure (the server uses 50 ms).
        let pressure_at = Duration::from_millis(
            std::env::var("PROBE_PRESSURE_MS").map_or(50, |ms| ms.parse().unwrap()),
        );
        // after-only end
        while let Ok(frame) = viewer.next().await {
            // after-only begin
            // As the server's viewer loop: the frame lag or the last write time.
            let lag = viewer.take_lag().max(std::mem::take(&mut last_write));
            if lag >= pressure_at {
                let _ = viewer.report_pressure(lag);
            }
            // after-only end
            wire.clear();
            wire.extend_from_slice(&u32::try_from(frame.bytes.len()).unwrap().to_be_bytes());
            wire.extend_from_slice(&frame.sequence.to_be_bytes());
            wire.extend_from_slice(&frame.capture_ns.to_be_bytes());
            wire.push(u8::from(frame.keyframe));
            wire.extend_from_slice(&frame.bytes);
            let began = Instant::now();
            let written =
                tokio::time::timeout(Duration::from_secs(1), write.write_all(&wire)).await;
            last_write = began.elapsed();
            let mut sent = writer_sent.lock().unwrap();
            if let Ok(Ok(())) = written {
                sent.0 += 1;
                sent.1 += u64::from(frame.keyframe);
                sent.2 += wire.len() as u64;
            } else {
                // The server ends a viewer whose write takes over 1 s.
                sent.3 += 1;
                break;
            }
        }
    });

    let mut latencies = Vec::new();
    let mut echo = [0_u8; 16];
    while tokio::time::timeout(Duration::from_secs(3), read.read_exact(&mut echo))
        .await
        .is_ok_and(|read| read.is_ok())
    {
        let capture = u64::from_be_bytes(echo[8..].try_into().unwrap());
        let arrived = u64::try_from(epoch.elapsed().as_nanos()).unwrap();
        latencies.push(arrived.saturating_sub(capture) as f64 / 1e6);
        if epoch.elapsed() > duration + Duration::from_secs(2) {
            break;
        }
    }
    let produced = encoder.await.unwrap();
    let _ = writer.await;
    let (frames, keyframes, bytes, failed) = *sent.lock().unwrap();
    latencies.sort_by(f64::total_cmp);
    let minutes = seconds as f64 / 60.0;
    println!(
        "METRIC produced_frames={} produced_keyframes={} produced_bytes={} repairs_asked={} pressure_reports={}",
        produced.frames,
        produced.keyframes,
        produced.bytes,
        produced.repairs_asked,
        produced.pressure_reports
    );
    println!(
        "METRIC sent_frames={frames} sent_keyframes={keyframes} sent_bytes={bytes} write_timeouts={failed} keyframes_per_min={:.1} sent_mbit_s={:.2} delivered_fps={:.1}",
        keyframes as f64 / minutes,
        bytes as f64 * 8.0 / 1e6 / seconds as f64,
        latencies.len() as f64 / seconds as f64
    );
    println!(
        "METRIC rate_min_mbit_s={:.2} rate_mean_mbit_s={:.2}",
        produced.min_rate / 1e6,
        produced.rate_sum / produced.frames.max(1) as f64 / 1e6
    );
    println!(
        "METRIC latency_ms n={} p50={:.1} p95={:.1} p99={:.1} max={:.1}",
        latencies.len(),
        percentile(&latencies, 0.5),
        percentile(&latencies, 0.95),
        percentile(&latencies, 0.99),
        latencies.last().copied().unwrap_or(f64::NAN)
    );
}
