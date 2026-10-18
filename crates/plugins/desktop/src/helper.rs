//! Independent control and capture workers prevent snapshot/encode latency from delaying input [D200,D203,D208].
use crate::{
    capture::{Capture, CapturedFrame, Rect},
    macos::MacCapture,
    native::Native,
    protocol::{self, Kind, Size, Start},
};
use std::hash::Hasher;
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
        let surface = std::env::var_os("INFRATERNAL_DESKTOP_SURFACE").is_some();
        let capture = if surface {
            None
        } else {
            Some(MacCapture::start(&start.target, start.size, rect)?)
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
        // 30 fps scheduler. The opt-in surface path takes the native source rate.
        next_frame = begin;
    }
    capture.stop()
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
    let mut waiting_keyframe = true;
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
            waiting_keyframe = true;
        }
        if force_keyframe.swap(false, Ordering::AcqRel) {
            let (kind, _) = native.call(Kind::Keyframe, b"{}")?;
            if kind == Kind::Error {
                return Err(io::Error::other("Desktop surface repair unavailable."));
            }
            waiting_keyframe = true;
        }
        if native.take_surface_gap() && !waiting_keyframe {
            waiting_keyframe = true;
            force_keyframe.store(true, Ordering::Release);
        }
        let Some(body) = native.surface_video()? else {
            continue;
        };
        crate::measurement::helper_frame("helper_native_read", &body);
        let keyframe = body.get(8) == Some(&1);
        if waiting_keyframe && !keyframe {
            continue;
        }
        match frames.try_send(Ok(body)) {
            Ok(()) => {
                waiting_keyframe = false;
                wake.notify();
            }
            Err(mpsc::TrySendError::Full(_)) => {
                waiting_keyframe = true;
                force_keyframe.store(true, Ordering::Release);
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
                        native.call(kind, &payload)?
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
