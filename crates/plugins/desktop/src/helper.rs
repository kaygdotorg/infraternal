//! Independent control and capture workers prevent snapshot/encode latency from delaying input [D200,D203,D208].
#[cfg(any(target_os = "macos", test))]
use crate::capture::{Capture, CapturedFrame};
#[cfg(any(target_os = "macos", test))]
use crate::macos::MacCapture;
use crate::{
    capture::Rect,
    native::Native,
    protocol::{self, Kind, Size, Start},
};
#[cfg(any(target_os = "macos", test))]
use std::hash::Hasher;
#[cfg(any(target_os = "macos", test))]
#[derive(serde::Deserialize)]
struct Clock {
    capture_ticks: u64,
    // Older clock replies omit this diagnostic field; capture still uses ticks.
    #[serde(default)]
    capture_ns: u64,
}
use std::{
    io::{self, Read},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

struct DeadlineReader {
    stream: UnixStream,
    deadline: Option<Instant>,
}
impl Read for DeadlineReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let timeout = self
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()));
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Desktop control deadline elapsed.",
            ));
        }
        self.stream.set_read_timeout(timeout)?;
        let count = self.stream.read(buffer)?;
        if count > 0 && self.deadline.is_none() {
            self.deadline = Some(Instant::now() + Duration::from_secs(3));
        }
        Ok(count)
    }
}
fn actual(payload: &[u8]) -> io::Result<Rect> {
    #[derive(serde::Deserialize)]
    struct Geometry {
        capture_rect: Rect,
    }
    let geometry: Geometry = serde_json::from_slice(payload)?;
    if !geometry.capture_rect.valid() {
        return Err(io::Error::other("Invalid desktop geometry."));
    }
    Ok(geometry.capture_rect)
}

struct Worker {
    size: Size,
    rect: Rect,
    pending: Arc<Mutex<Option<(Size, Rect)>>>,
    stop: Arc<AtomicBool>,
    force_keyframe: Arc<AtomicBool>,
    congested: Arc<AtomicBool>,
    screen: bool,
    frames: mpsc::Receiver<io::Result<Vec<u8>>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Worker {
    fn start(start: &Start, rect: Rect, native_path: PathBuf, wake: Arc<Wake>) -> io::Result<Self> {
        // Capture belongs to the stable companion that owns its permissions.
        // Retain owned pixels only for explicit diagnostics; normal capture
        // never takes the full-image copy/hash/pipe or polling path.
        let surface = std::env::var_os("INFRATERNAL_DESKTOP_OWNED").is_none();
        #[cfg(any(target_os = "macos", test))]
        let capture = if surface {
            None
        } else {
            Some(MacCapture::start(&start.target, start.size, rect)?)
        };
        #[cfg(not(any(target_os = "macos", test)))]
        let capture = {
            if !surface {
                return Err(io::Error::other(
                    "Owned-pixel desktop capture is available only on macOS.",
                ));
            }
            None::<()>
        };
        let pending = Arc::new(Mutex::new(None));
        let update = Arc::clone(&pending);
        let stop = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::clone(&stop);
        let force_keyframe = Arc::new(AtomicBool::new(false));
        let force = Arc::clone(&force_keyframe);
        let congested = Arc::new(AtomicBool::new(false));
        let pressure = Arc::clone(&congested);
        let (sender, frames) = mpsc::sync_channel(1);
        let size = start.size;
        let screen = matches!(start.target, protocol::Target::Screen { .. });
        let start = start.clone();
        let thread = thread::spawn(move || {
            #[cfg(any(target_os = "macos", test))]
            let result = if let Some(capture) = capture {
                produce(
                    capture,
                    size,
                    &native_path,
                    Production {
                        pending: &update,
                        stop: &cancelled,
                        force_keyframe: &force,
                        congested: &pressure,
                        frames: &sender,
                        wake: &wake,
                    },
                )
            } else {
                produce_surface(
                    start,
                    rect,
                    &native_path,
                    Production {
                        pending: &update,
                        stop: &cancelled,
                        force_keyframe: &force,
                        congested: &pressure,
                        frames: &sender,
                        wake: &wake,
                    },
                )
            };
            #[cfg(not(any(target_os = "macos", test)))]
            let result = {
                let _ = capture;
                produce_surface(
                    start,
                    rect,
                    &native_path,
                    Production {
                        pending: &update,
                        stop: &cancelled,
                        force_keyframe: &force,
                        congested: &pressure,
                        frames: &sender,
                        wake: &wake,
                    },
                )
            };
            if let Err(error) = result {
                let _ = sender.try_send(Err(error));
            }
            wake.notify();
        });
        Ok(Self {
            size,
            rect,
            pending,
            stop,
            force_keyframe,
            congested,
            screen,
            frames,
            thread: Some(thread),
        })
    }
    fn update(&mut self, size: Size, rect: Rect) {
        self.size = size;
        self.rect = rect;
        if let Ok(mut pending) = self.pending.lock() {
            *pending = Some((size, rect));
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
// Both capture paths share coalesced control flags and one bounded frame slot.
// These borrows stay inside the owning worker thread; retirement joins it.
#[derive(Clone, Copy)]
struct Production<'a> {
    pending: &'a Mutex<Option<(Size, Rect)>>,
    stop: &'a Arc<AtomicBool>,
    force_keyframe: &'a AtomicBool,
    congested: &'a AtomicBool,
    frames: &'a mpsc::SyncSender<io::Result<Vec<u8>>>,
    wake: &'a Wake,
}

/// Coalesces repair signals and retries only while an IDR is still missing.
/// The 300 ms floor matches the browser repair throttle without idle requests.
struct SurfaceRecovery {
    waiting_keyframe: bool,
    repair_pending: bool,
    last_request: Option<Instant>,
}

impl SurfaceRecovery {
    const REPAIR_INTERVAL: Duration = Duration::from_millis(300);

    fn new() -> Self {
        Self {
            waiting_keyframe: true,
            repair_pending: false,
            last_request: None,
        }
    }

    fn request(&mut self) {
        self.waiting_keyframe = true;
        self.repair_pending = true;
    }

    fn request_due(&mut self, now: Instant) -> bool {
        if !self.repair_pending
            || self
                .last_request
                .is_some_and(|last| now.saturating_duration_since(last) < Self::REPAIR_INTERVAL)
        {
            return false;
        }
        self.last_request = Some(now);
        true
    }

    fn admit(&mut self, keyframe: bool) -> bool {
        if self.waiting_keyframe && !keyframe {
            self.request();
            return false;
        }
        if keyframe {
            self.waiting_keyframe = false;
            self.repair_pending = false;
            self.last_request = None;
        }
        true
    }
}

#[cfg(any(target_os = "macos", test))]
fn produce(
    mut capture: MacCapture,
    mut size: Size,
    native_path: &Path,
    signals: Production<'_>,
) -> io::Result<()> {
    let Production {
        pending,
        stop,
        force_keyframe,
        congested,
        frames,
        wake,
    } = signals;
    let mut encoder = Native::spawn_encoder(native_path)?;
    encoder.cancel_on(Arc::clone(stop));
    let mut last_change = Instant::now();
    let mut refreshed = false;
    let mut latest = None;
    let mut next_frame = Instant::now();
    let mut needs_keyframe = true;
    let mut fingerprint = None;
    while !stop.load(Ordering::Acquire) {
        if congested.swap(false, Ordering::AcqRel) {
            let _ = encoder.call(Kind::Congested, b"{}")?;
        }
        // Repair is a coalesced producer flag, independent of GUI control and
        // native encoding latency. A dropped IDR retains needs_keyframe below.
        needs_keyframe |= force_keyframe.swap(false, Ordering::AcqRel);
        if let Some((new_size, new_rect)) = pending.lock().ok().and_then(|mut p| p.take()) {
            capture.resize(new_size, new_rect)?;
            size = new_size;
            latest = None;
            refreshed = false;
            fingerprint = None;
        }
        if Instant::now() < next_frame {
            thread::sleep(
                next_frame
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(5)),
            );
            continue;
        }
        if let Some(frame) = capture.take_latest() {
            latest = Some(frame);
        } else if (refreshed && !needs_keyframe)
            || last_change.elapsed() < Duration::from_millis(250)
        {
            thread::sleep(Duration::from_millis(20));
            continue;
        }
        let Some(frame) = &latest else {
            // Yield while the framework starts instead of polling an empty slot.
            thread::sleep(Duration::from_millis(5));
            continue;
        };
        let _ = frame.capture_ticks();
        let (_, clock) = encoder.call(Kind::Status, b"{}")?;
        let clock: Clock = serde_json::from_slice(&clock)?;
        let begin = Instant::now();
        crate::measurement::record("fallback_copy_begin", clock.capture_ns, 0, 0);
        let pixels = capture.copy_pixels()?;
        crate::measurement::record("fallback_copy_end", clock.capture_ns, 0, pixels.len());
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        hash.write(&pixels);
        let current = hash.finish();
        crate::measurement::record("fallback_hash_end", clock.capture_ns, 0, pixels.len());
        if fingerprint != Some(current) {
            fingerprint = Some(current);
            last_change = Instant::now();
            refreshed = false;
        }
        let sharp = !refreshed && last_change.elapsed() >= Duration::from_millis(250);
        if refreshed && !needs_keyframe {
            next_frame = Instant::now() + Duration::from_millis(100);
            continue;
        }
        let (kind, body) = encoder.encode(
            &pixels,
            size.width,
            size.height,
            clock.capture_ticks,
            sharp || needs_keyframe,
        )?;
        if std::env::var_os("INFRATERNAL_DESKTOP_MEASURE").is_some() {
            eprintln!(
                "METRIC capture_encode_ns={} sharp={sharp}",
                begin.elapsed().as_nanos()
            );
        }
        if kind != Kind::Video {
            return Err(io::Error::other("Desktop encoding unavailable."));
        }
        crate::measurement::helper_frame("helper_native_read", &body);
        // At most one compressed frame waits for the local writer. Never wait on a
        // slow reader here. After an encoded drop the next delivered frame must be an
        // IDR: a P-frame that references an undelivered frame would corrupt decoding.
        match frames.try_send(Ok(body)) {
            Ok(()) => {
                needs_keyframe = false;
                wake.notify();
            }
            Err(mpsc::TrySendError::Full(_)) => needs_keyframe = true,
            Err(mpsc::TrySendError::Disconnected(_)) => break,
        }
        refreshed |= sharp;
        // The owned-pixel fallback is bounded by capture/copy cost, not an extra
        // 30 fps scheduler. The companion path takes the native source rate.
        next_frame = begin;
    }
    capture.stop()
}

#[cfg(test)]
mod startup_recovery_tests {
    //! Exercises the real native-surface producer with a scripted companion that misses its startup keyframe.
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::AtomicU64};

    static NEXT: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn delta_before_startup_keyframe_requests_repair_before_delivery() {
        let root = std::env::temp_dir().join(format!(
            "infraternal-desktop-first-picture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create private test directory");
        let native_path = root.join("surface-native");
        fs::write(
            &native_path,
            include_bytes!("../tests/fixtures/surface-first-picture.py"),
        )
        .expect("write scripted companion");
        fs::set_permissions(&native_path, fs::Permissions::from_mode(0o700))
            .expect("make scripted companion executable");

        let start = Start {
            target: protocol::Target::Screen { display_id: 1 },
            size: Size {
                width: 64,
                height: 48,
                canvas_width: 64.0,
                canvas_height: 48.0,
                backing_scale: 1.0,
            },
        };
        let rect = Rect {
            x: 0.0,
            y: 0.0,
            width: 64.0,
            height: 48.0,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(Mutex::new(None));
        let force_keyframe = Arc::new(AtomicBool::new(false));
        let congested = Arc::new(AtomicBool::new(false));
        let (frames, received) = mpsc::sync_channel(1);
        let wake = Arc::new(Wake::default());
        let worker_stop = Arc::clone(&stop);
        let worker_pending = Arc::clone(&pending);
        let worker_force = Arc::clone(&force_keyframe);
        let worker_congested = Arc::clone(&congested);
        let worker_wake = Arc::clone(&wake);
        let worker_path = native_path.clone();
        let worker = thread::spawn(move || {
            produce_surface(
                start,
                rect,
                &worker_path,
                Production {
                    pending: &worker_pending,
                    stop: &worker_stop,
                    force_keyframe: &worker_force,
                    congested: &worker_congested,
                    frames: &frames,
                    wake: &worker_wake,
                },
            )
        });

        let first = received.recv_timeout(Duration::from_secs(2));
        stop.store(true, Ordering::Release);
        let _ = worker.join();
        let requests =
            fs::read_to_string(format!("{}.requests", native_path.display())).unwrap_or_default();
        let _ = fs::remove_dir_all(&root);

        let frame = first
            .expect("startup delta must trigger a repair keyframe")
            .unwrap();
        assert_eq!(
            frame.get(8),
            Some(&1),
            "only a keyframe can start this stream"
        );
        assert_eq!(
            requests.lines().count(),
            1,
            "one startup gap needs one repair request"
        );
    }

    #[test]
    fn surface_repair_is_coalesced_rate_limited_and_idle_when_recovered() {
        let start = Instant::now();
        let mut recovery = SurfaceRecovery::new();

        assert!(
            !recovery.request_due(start),
            "startup alone is not a repair"
        );
        assert!(!recovery.admit(false), "a delta cannot start the stream");
        recovery.request();
        assert!(
            recovery.request_due(start),
            "first observed gap repairs now"
        );
        assert!(
            !recovery.admit(false),
            "deltas remain unusable until an IDR"
        );
        assert!(!recovery.request_due(start + Duration::from_millis(299)));
        assert!(recovery.request_due(start + Duration::from_millis(300)));

        assert!(recovery.admit(true), "an IDR ends the recovery episode");
        assert!(!recovery.request_due(start + Duration::from_secs(1)));
        assert!(recovery.admit(false), "healthy deltas remain deliverable");
        assert!(!recovery.request_due(start + Duration::from_secs(1)));
    }
}

fn produce_surface(
    mut start: Start,
    mut rect: Rect,
    native_path: &Path,
    signals: Production<'_>,
) -> io::Result<()> {
    let Production {
        pending,
        stop,
        force_keyframe,
        congested,
        frames,
        wake,
    } = signals;
    let open = |start: &Start, rect: Rect| -> io::Result<Native> {
        let mut native = Native::spawn_surface(native_path)?;
        native.cancel_on(Arc::clone(stop));
        let mut request = serde_json::to_value(start)?;
        request["capture_rect"] = serde_json::to_value(rect)?;
        let (kind, _) = native.call(Kind::Start, &serde_json::to_vec(&request)?)?;
        if kind != Kind::Geometry {
            return Err(io::Error::other("Desktop surface capture unavailable."));
        }
        Ok(native)
    };
    let mut native = open(&start, rect)?;
    let mut recovery = SurfaceRecovery::new();
    while !stop.load(Ordering::Acquire) {
        if congested.swap(false, Ordering::AcqRel) {
            let _ = native.call(Kind::Congested, b"{}")?;
        }
        if let Some((size, changed)) = pending.lock().ok().and_then(|mut p| p.take()) {
            let _ = native.call(Kind::Stop, b"{}");
            // A fresh private process seals the old geometry/encoder before new
            // pictures. It owns no AX resize/restore work; the control child does.
            drop(native);
            start.size = size;
            rect = changed;
            native = open(&start, rect)?;
            recovery = SurfaceRecovery::new();
        }
        if force_keyframe.swap(false, Ordering::AcqRel) {
            recovery.request();
        }
        if native.take_surface_gap() {
            recovery.request();
        }
        if recovery.request_due(Instant::now()) {
            let (kind, _) = native.call(Kind::Keyframe, b"{}")?;
            if kind == Kind::Error {
                return Err(io::Error::other("Desktop surface repair unavailable."));
            }
        }
        let Some(body) = native.surface_video()? else {
            continue;
        };
        crate::measurement::helper_frame("helper_native_read", &body);
        let keyframe = body.get(8) == Some(&1);
        if !recovery.admit(keyframe) {
            continue;
        }
        match frames.try_send(Ok(body)) {
            Ok(()) => {
                wake.notify();
            }
            Err(mpsc::TrySendError::Full(_)) => {
                recovery.request();
            }
            Err(mpsc::TrySendError::Disconnected(_)) => break,
        }
    }
    Ok(())
}

/// # Errors
/// Ends on framing, admission, capture, companion or output deadline failure.
pub fn session(
    mut socket: UnixStream,
    native: &mut Native,
    native_path: &Path,
    stopping: &Arc<AtomicBool>,
) -> io::Result<()> {
    crate::socket::admit(&socket)?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let shutdown = socket.try_clone()?;
    let mut reader = DeadlineReader {
        stream: socket.try_clone()?,
        deadline: None,
    };
    let (sender, receiver) = mpsc::sync_channel(4);
    let wake = Arc::new(Wake::default());
    let reader_wake = Arc::clone(&wake);
    let reader_thread = thread::spawn(move || {
        loop {
            reader.deadline = None;
            let message = protocol::read(&mut reader);
            if let Ok((kind, _)) = &message {
                crate::measurement::control("helper_control_receive", *kind);
            }
            let failed = message.is_err();
            let sent = sender.send(message);
            reader_wake.notify();
            if sent.is_err() || failed {
                break;
            }
        }
    });
    let result = run(&mut socket, native, native_path, &receiver, stopping, &wake);
    let _ = shutdown.shutdown(Shutdown::Both);
    drop(receiver);
    let _ = reader_thread.join();
    result
}
fn run(
    socket: &mut UnixStream,
    native: &mut Native,
    native_path: &Path,
    requests: &mpsc::Receiver<io::Result<(Kind, Vec<u8>)>>,
    stopping: &AtomicBool,
    wake: &Arc<Wake>,
) -> io::Result<()> {
    let mut stream: Option<Worker> = None;
    let mut reconcile = Instant::now();
    let result = (|| {
        loop {
            // Snapshot before inspecting either queue. A producer racing those
            // reads changes the generation, so waiting cannot lose its wakeup.
            let generation = wake.generation()?;
            if stopping.load(Ordering::Acquire) {
                break;
            }
            let request = requests.try_recv();
            let had_request = request.is_ok();
            match request {
                Ok(request) => {
                    let (kind, payload) = request?;
                    protocol::validate_command(kind, &payload)?;
                    if kind == Kind::Start && stream.is_some() {
                        protocol::write(
                            socket,
                            Kind::Error,
                            br#"{"error":"Stop the current desktop stream first."}"#,
                        )?;
                        continue;
                    }
                    // Restore/release control before waiting for a framework capture
                    // to retire: native capture callbacks can take their bounded timeout.
                    let (reply, body) = if matches!(kind, Kind::Keyframe | Kind::Congested) {
                        capture_request(stream.as_ref(), kind)
                    } else {
                        crate::measurement::control("helper_native_begin", kind);
                        let reply = native.call(kind, &payload)?;
                        crate::measurement::control("helper_native_end", kind);
                        reply
                    };
                    if kind == Kind::Stop {
                        stream.take();
                    }
                    if kind == Kind::Start && reply == Kind::Geometry {
                        let start: Start = serde_json::from_slice(&payload)?;
                        stream = Some(Worker::start(
                            &start,
                            actual(&body)?,
                            native_path.to_owned(),
                            Arc::clone(wake),
                        )?);
                    } else if kind == Kind::Resize
                        && reply == Kind::Geometry
                        && let Some(stream) = &mut stream
                    {
                        stream.update(serde_json::from_slice(&payload)?, actual(&body)?);
                    }
                    protocol::write(socket, reply, &body)?;
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            let Some(stream) = &mut stream else {
                if !had_request {
                    wake.wait(generation, None)?;
                }
                continue;
            };
            if Instant::now() >= reconcile {
                crate::measurement::record("helper_reconcile_begin", 0, 0, 0);
                let (_, geometry) = native.call(Kind::Status, b"{}")?;
                crate::measurement::record("helper_reconcile_end", 0, 0, 0);
                let rect = actual(&geometry)?;
                if rect != stream.rect {
                    stream.update(stream.size, rect);
                    protocol::write(socket, Kind::Geometry, &geometry)?;
                }
                reconcile = Instant::now() + Duration::from_millis(100);
            }
            let frame = stream.frames.try_recv();
            let had_frame = frame.is_ok();
            match frame {
                Ok(frame) => {
                    let frame = frame?;
                    crate::measurement::helper_frame("helper_socket_begin", &frame);
                    protocol::write(socket, Kind::Video, &frame)?;
                    crate::measurement::helper_frame("helper_socket_end", &frame);
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("Desktop capture stopped."));
                }
            }
            // Window following still reconciles at its existing deadline. An
            // idle whole-display capture sleeps until input, damage or EOF;
            // it performs no 5 ms socket/frame polling.
            if !had_request && !had_frame {
                wake.wait(
                    generation,
                    (!stream.screen).then(|| reconcile.saturating_duration_since(Instant::now())),
                )?;
            }
        }
        Ok(())
    })();
    let _ = native.call(Kind::Stop, b"{}");
    stream.take();
    result
}

// Repair and quality flags target capture, never the independent GUI child.
fn capture_request(stream: Option<&Worker>, kind: Kind) -> (Kind, Vec<u8>) {
    let Some(stream) = stream else {
        return (
            Kind::Error,
            br#"{"error":"Desktop capture is unavailable."}"#.to_vec(),
        );
    };
    if kind == Kind::Keyframe {
        stream.force_keyframe.store(true, Ordering::Release);
        (
            Kind::State,
            br#"{"state":"on","keyframe_requested":true}"#.to_vec(),
        )
    } else {
        stream.congested.store(true, Ordering::Release);
        (Kind::State, br#"{"state":"on"}"#.to_vec())
    }
}

#[derive(Default)]
struct Wake {
    generation: Mutex<u64>,
    changed: Condvar,
}
impl Wake {
    fn notify(&self) {
        if let Ok(mut generation) = self.generation.lock() {
            *generation = generation.wrapping_add(1);
            self.changed.notify_one();
        }
    }
    fn generation(&self) -> io::Result<u64> {
        self.generation
            .lock()
            .map(|value| *value)
            .map_err(|_| io::Error::other("Desktop wake unavailable."))
    }
    fn wait(&self, previous: u64, timeout: Option<Duration>) -> io::Result<()> {
        let generation = self
            .generation
            .lock()
            .map_err(|_| io::Error::other("Desktop wake unavailable."))?;
        if let Some(timeout) = timeout {
            drop(
                self.changed
                    .wait_timeout_while(generation, timeout, |value| *value == previous)
                    .map_err(|_| io::Error::other("Desktop wake unavailable."))?,
            );
        } else {
            drop(
                self.changed
                    .wait_while(generation, |value| *value == previous)
                    .map_err(|_| io::Error::other("Desktop wake unavailable."))?,
            );
        }
        Ok(())
    }
}
