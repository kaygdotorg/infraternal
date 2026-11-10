//! A dedicated thread that reads the Mac node's utun and hands packets to `GotaTun` in batches.
//!
//! **Why a thread (#260, J461).** The Mac node used to read utun from a tokio task: wait for
//! kqueue readiness, wake a runtime worker, read one packet, go back to waiting. Every outgoing
//! packet paid that readiness round trip before it could be encrypted, and the Mac-send cell of
//! the D378 comparison lost to an engine that parks a dedicated thread on the device instead.
//! Here one OS thread sleeps in `poll(2)` on the utun descriptor and a private stop pipe, drains
//! every frame that is ready (up to [`READ_BATCH`]) as soon as the kernel queues it, and passes
//! the whole batch to the async side in one channel send.
//!
//! **Backpressure.** The hand-off channel holds at most [`QUEUE_BATCHES`] batches. When `GotaTun`
//! falls behind, the thread blocks in its send, stops reading, and the backlog stays in the
//! kernel's utun queue, where macOS flow-controls the local TCP senders. At most
//! `QUEUE_BATCHES × READ_BATCH` packets wait here, plus the one batch the thread holds.
//!
//! **Shutdown.** Dropping the [`UtunReader`] closes the channel and the stop pipe, which wakes the
//! thread from either wait, and then joins it, so no thread outlives its reader.
//!
//! **Device gone.** End of file, a closed or invalid descriptor, or a read error that means the
//! interface went away ends the thread after it delivers that error once. Every later call to
//! [`UtunReader::next_batch`] waits forever instead of failing again: `GotaTun`'s receive task
//! retries non-fatal errors in a loop, so repeating the error would spin it. The device's own
//! cancellation still stops that task.
//!
//! The descriptor stays non-blocking because the utun writer shares it; the thread blocks in
//! `poll`, never in `read`. The module is plain Unix code, so its tests also run in the Linux
//! gate on socket pairs.

use gotatun::packet::{Ip, Packet, PacketBufPool};
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, fcntl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    unistd::{pipe, read},
};
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    sync::Arc,
    thread::JoinHandle,
    time::Duration,
};
use tokio::sync::mpsc;

/// Most frames the thread reads per wake-up before it hands them over.
pub(crate) const READ_BATCH: usize = 64;

/// Most batches waiting in the hand-off channel (8 × 64 = 512 packets, ~5 ms at 1 Gbit/s).
pub(crate) const QUEUE_BATCHES: usize = 8;

/// Pause after a read error that does not end the device, so a descriptor that keeps failing
/// costs at most a hundred wake-ups a second instead of a busy loop.
const ERROR_PAUSE: Duration = Duration::from_millis(10);

/// Turns one raw frame read from the device into an IP packet, or rejects it.
///
/// The Mac node strips and checks the utun address-family header here. A rejected frame is
/// reported to `GotaTun` as a non-fatal error, as before; the reader keeps going.
pub(crate) type Decode = Box<dyn FnMut(Packet<[u8]>) -> io::Result<Packet<Ip>> + Send + 'static>;

/// What the thread hands to the async side.
enum Delivery {
    /// Packets in device order, at most one read batch.
    Batch(Vec<Packet<Ip>>),
    /// One frame or read failed; the thread carries on.
    Rejected(io::Error),
    /// The device is gone; this is the thread's last message.
    Ended(io::Error),
}

/// Counts frames the thread has read, so the tests can check the backpressure bound.
#[cfg(test)]
#[derive(Clone, Default)]
struct ReadCount(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl ReadCount {
    /// Record one more frame read from the device.
    fn add_one(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Owns the reader thread for one device descriptor; drop it to stop and join the thread.
pub(crate) struct UtunReader {
    /// Batches from the thread. `None` once dropped, so the thread's send fails and it exits.
    batches: Option<mpsc::Receiver<Delivery>>,
    /// Write end of the stop pipe. Closing it wakes the thread's `poll`.
    stop: Option<OwnedFd>,
    /// The thread, joined on drop.
    thread: Option<JoinHandle<()>>,
    /// The device is gone (or the thread ended) and that was already reported once.
    finished: bool,
    /// Frames read so far, shared with the thread (tests only).
    #[cfg(test)]
    count: ReadCount,
}

impl UtunReader {
    /// Start a reader thread on `device`, a non-blocking descriptor that yields one frame per
    /// `read`. Buffers come from `pool`; `decode` turns each frame into a packet.
    ///
    /// `queue_batches` and `read_batch` bound the hand-off (the Mac node passes
    /// [`QUEUE_BATCHES`] and [`READ_BATCH`]; tests pass small values). Both are at least 1.
    /// # Errors
    /// Returns failures to create the stop pipe or the thread.
    pub(crate) fn spawn<F: AsFd + Send + Sync + 'static>(
        device: Arc<F>,
        pool: PacketBufPool,
        decode: Decode,
        queue_batches: usize,
        read_batch: usize,
    ) -> io::Result<Self> {
        let (stop_read, stop_write) = pipe().map_err(io::Error::from)?;
        for end in [&stop_read, &stop_write] {
            fcntl(end, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(io::Error::from)?;
        }
        let (tx, rx) = mpsc::channel(queue_batches.max(1));
        #[cfg(test)]
        let count = ReadCount::default();
        #[cfg(test)]
        let thread_count = count.clone();
        let read_batch = read_batch.max(1);
        let thread = std::thread::Builder::new()
            .name("mesh-utun-reader".into())
            .spawn(move || {
                let mut reader = ThreadSide {
                    device: device.as_fd(),
                    stop: stop_read.as_fd(),
                    pool: &pool,
                    decode,
                    tx: &tx,
                    read_batch,
                    #[cfg(test)]
                    count: &thread_count,
                };
                reader.run();
            })?;
        Ok(Self {
            batches: Some(rx),
            stop: Some(stop_write),
            thread: Some(thread),
            finished: false,
            #[cfg(test)]
            count,
        })
    }

    /// Wait for the next batch of packets.
    ///
    /// Returns the device-gone error once; after that it never returns (see the module docs).
    /// # Errors
    /// A rejected frame (non-fatal) or the error that ended the device.
    pub(crate) async fn next_batch(&mut self) -> io::Result<Vec<Packet<Ip>>> {
        if !self.finished {
            let next = match self.batches.as_mut() {
                Some(batches) => batches.recv().await,
                None => None,
            };
            match next {
                Some(Delivery::Batch(batch)) => return Ok(batch),
                Some(Delivery::Rejected(error)) => return Err(error),
                Some(Delivery::Ended(error)) => {
                    self.finished = true;
                    return Err(error);
                }
                // The thread stopped without saying why (it panicked): treat it as gone.
                None => {
                    self.finished = true;
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "utun reader thread stopped",
                    ));
                }
            }
        }
        std::future::pending().await
    }

    /// The shared count of frames the thread has read so far.
    #[cfg(test)]
    fn frames_read(&self) -> usize {
        self.count.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for UtunReader {
    /// Stop the thread from either of its waits, then join it.
    fn drop(&mut self) {
        // A thread blocked handing over a batch sees the channel close.
        self.batches.take();
        // A thread parked in `poll` sees the stop pipe hang up.
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Whether a read error means the device went away rather than one bad read.
fn ends_device(error: Errno) -> bool {
    matches!(
        error,
        Errno::EBADF
            | Errno::ENXIO
            | Errno::ENODEV
            | Errno::ENOTCONN
            | Errno::EPIPE
            | Errno::ECONNRESET
    )
}

/// Everything the reader thread borrows while it runs.
struct ThreadSide<'a> {
    /// The non-blocking device descriptor.
    device: std::os::fd::BorrowedFd<'a>,
    /// Read end of the stop pipe.
    stop: std::os::fd::BorrowedFd<'a>,
    pool: &'a PacketBufPool,
    /// Owned by the thread: the Mac decoder reads a live MTU watcher, which needs `&mut`.
    decode: Decode,
    tx: &'a mpsc::Sender<Delivery>,
    read_batch: usize,
    /// Frames read so far (tests only).
    #[cfg(test)]
    count: &'a ReadCount,
}

impl ThreadSide<'_> {
    /// Wait in `poll`, drain what is ready, hand it over; return when stopped or the device ends.
    fn run(&mut self) {
        loop {
            let mut fds = [
                PollFd::new(self.device, PollFlags::POLLIN),
                PollFd::new(self.stop, PollFlags::POLLIN),
            ];
            match poll(&mut fds, PollTimeout::NONE) {
                Ok(_) => {}
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    self.send(Delivery::Ended(error.into()));
                    return;
                }
            }
            // Any event on the stop pipe (its writer closed) means the reader was dropped.
            if fds[1].revents().is_some_and(|events| !events.is_empty()) {
                return;
            }
            if fds[0]
                .revents()
                .is_some_and(|events| events.contains(PollFlags::POLLNVAL))
            {
                self.send(Delivery::Ended(Errno::EBADF.into()));
                return;
            }
            if !self.drain() {
                return;
            }
        }
    }

    /// Read every ready frame (up to one batch) and hand it over in order.
    ///
    /// Returns `false` when the thread must exit: the device ended or the reader was dropped.
    fn drain(&mut self) -> bool {
        let mut batch = Vec::with_capacity(self.read_batch);
        while batch.len() < self.read_batch {
            let mut packet = self.pool.get();
            match read(self.device, &mut packet[..]) {
                Ok(0) => {
                    self.finish(&mut batch, io::ErrorKind::UnexpectedEof.into());
                    return false;
                }
                Ok(length) => {
                    #[cfg(test)]
                    self.count.add_one();
                    packet.truncate(length);
                    match (self.decode)(packet) {
                        Ok(packet) => batch.push(packet),
                        // Keep device order: what came before goes first, then the rejection.
                        Err(error) => {
                            if !self.flush(&mut batch) || !self.send(Delivery::Rejected(error)) {
                                return false;
                            }
                        }
                    }
                }
                Err(Errno::EAGAIN) => break,
                Err(Errno::EINTR) => {}
                Err(error) if ends_device(error) => {
                    self.finish(&mut batch, error.into());
                    return false;
                }
                Err(error) => {
                    if !self.flush(&mut batch) || !self.send(Delivery::Rejected(error.into())) {
                        return false;
                    }
                    // sleep: pace a descriptor that keeps failing (see `ERROR_PAUSE`)
                    std::thread::sleep(ERROR_PAUSE);
                    break;
                }
            }
        }
        self.flush(&mut batch)
    }

    /// The device is gone: hand over what was read, then the error, as the last messages.
    fn finish(&self, batch: &mut Vec<Packet<Ip>>, error: io::Error) {
        if self.flush(batch) {
            self.send(Delivery::Ended(error));
        }
    }

    /// Hand over the batch if it has packets. `false` once the reader is gone.
    fn flush(&self, batch: &mut Vec<Packet<Ip>>) -> bool {
        if batch.is_empty() {
            return true;
        }
        let full = std::mem::replace(batch, Vec::with_capacity(self.read_batch));
        self.send(Delivery::Batch(full))
    }

    /// Block until the hand-off queue has room. `false` once the reader is gone.
    fn send(&self, delivery: Delivery) -> bool {
        self.tx.blocking_send(delivery).is_ok()
    }
}

#[cfg(test)]
mod tests {
    //! Pins the reader's ordering, batching, backpressure bound, shutdown and device-gone
    //! rules on Unix socket pairs, so they also run in the Linux gate.
    #![allow(clippy::expect_used)]
    use super::*;
    use std::{
        io::Write,
        os::unix::net::{UnixDatagram, UnixStream},
        sync::mpsc as std_mpsc,
        time::{Duration, Instant},
    };

    /// A minimal IPv4 header (20 bytes) whose identification field carries `n`, so order and
    /// loss are visible after the round trip.
    fn frame(n: u16) -> Vec<u8> {
        let mut f = vec![0u8; 20];
        f[0] = 0x45;
        f[2..4].copy_from_slice(&20u16.to_be_bytes());
        f[4..6].copy_from_slice(&n.to_be_bytes());
        f[8] = 64;
        f
    }

    /// The test decoder: frames are plain IPv4 packets, no utun header.
    fn decode() -> Decode {
        Box::new(|packet: Packet<[u8]>| {
            packet
                .try_into_ip()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
        })
    }

    /// Read the identification field back out of a delivered packet.
    fn id(packet: Packet<Ip>) -> u16 {
        let bytes = packet.into_bytes();
        let bytes: &[u8] = bytes.as_ref();
        u16::from_be_bytes([bytes[4], bytes[5]])
    }

    /// A non-blocking datagram pair: `(device end for the reader, test end)`.
    fn datagram_pair() -> (Arc<UnixDatagram>, UnixDatagram) {
        let (device, peer) = UnixDatagram::pair().expect("socket pair");
        device
            .set_nonblocking(true)
            .expect("non-blocking device end");
        (Arc::new(device), peer)
    }

    /// Run `f` on a helper thread and fail the test if it takes longer than `limit`.
    fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std_mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(limit).expect("finished in time")
    }

    /// Wait up to `limit` for the reader's next delivery. The timer is created inside the
    /// runtime, which tokio requires.
    fn next_within(
        rt: &tokio::runtime::Runtime,
        reader: &mut UtunReader,
        limit: Duration,
    ) -> Result<io::Result<Vec<Packet<Ip>>>, tokio::time::error::Elapsed> {
        rt.block_on(async { tokio::time::timeout(limit, reader.next_batch()).await })
    }

    /// Sends numbered frames into the test end from its own thread, so tests can push more
    /// than the socket buffer holds. macOS gives a datagram pair a small buffer and answers a
    /// full one with `ENOBUFS` instead of blocking, so a full buffer is retried. Dropping the
    /// feeder stops it and joins the thread.
    struct Feeder {
        stop: Arc<std::sync::atomic::AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl Feeder {
        /// Start sending frames `range`, in order, into `peer`.
        fn start(peer: UnixDatagram, range: std::ops::Range<u16>) -> Self {
            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stopping = stop.clone();
            let thread = std::thread::spawn(move || {
                for n in range {
                    loop {
                        if stopping.load(std::sync::atomic::Ordering::SeqCst) {
                            return;
                        }
                        match peer.send(&frame(n)) {
                            Ok(_) => break,
                            Err(e)
                                if e.raw_os_error() == Some(libc_enobufs())
                                    || e.kind() == io::ErrorKind::WouldBlock =>
                            {
                                // sleep: the reader drains the buffer; retry shortly
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            Err(e) => panic!("send frame {n}: {e}"),
                        }
                    }
                }
            });
            Self {
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for Feeder {
        /// Stop sending and join the thread.
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// `ENOBUFS`, the "socket buffer full" error macOS returns for datagram pairs.
    fn libc_enobufs() -> i32 {
        nix::errno::Errno::ENOBUFS as i32
    }

    /// A current-thread runtime with timers, like the Mac node's packet worker.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime")
    }

    /// The Mac node's hand-off holds at most 512 packets, the same bound as `GotaTun`'s macOS
    /// queue cap (#260), so the reader never reintroduces a deep queue in front of the engine.
    #[test]
    fn production_bound_is_512_packets() {
        assert_eq!(QUEUE_BATCHES * READ_BATCH, 512);
    }

    /// Frames arrive in order and grouped into batches no larger than the read batch.
    #[test]
    fn delivers_frames_in_order_in_bounded_batches() {
        let (device, peer) = datagram_pair();
        let mut reader =
            UtunReader::spawn(device, PacketBufPool::new(0), decode(), 4, 8).expect("spawn");
        let _feeder = Feeder::start(peer, 0..50);
        let rt = runtime();
        let mut seen = Vec::new();
        while seen.len() < 50 {
            let batch = next_within(&rt, &mut reader, Duration::from_secs(5))
                .expect("batch in time")
                .expect("no error");
            assert!(
                !batch.is_empty() && batch.len() <= 8,
                "batch of {}",
                batch.len()
            );
            seen.extend(batch.into_iter().map(id));
        }
        assert_eq!(seen, (0..50).collect::<Vec<_>>());
    }

    /// Dropping an idle reader wakes its thread from `poll` and joins it promptly.
    #[test]
    fn drop_stops_an_idle_reader_promptly() {
        let (device, _peer) = datagram_pair();
        let reader = UtunReader::spawn(device.clone(), PacketBufPool::new(0), decode(), 4, 8)
            .expect("spawn");
        // sleep: let the thread park in poll
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        within(Duration::from_secs(2), move || drop(reader));
        assert!(started.elapsed() < Duration::from_secs(1));
        // The thread released its handle on the descriptor.
        assert_eq!(Arc::strong_count(&device), 1);
    }

    /// Dropping a reader whose thread is blocked on a full hand-off queue also joins promptly.
    #[test]
    fn drop_stops_a_reader_blocked_on_a_full_queue() {
        let (device, peer) = datagram_pair();
        let reader = UtunReader::spawn(device.clone(), PacketBufPool::new(0), decode(), 1, 2)
            .expect("spawn");
        let feeder = Feeder::start(peer, 0..20);
        let deadline = Instant::now() + Duration::from_secs(2);
        while reader.frames_read() < 4 && Instant::now() < deadline {
            // sleep: wait for the queue to fill
            std::thread::sleep(Duration::from_millis(5));
        }
        within(Duration::from_secs(2), move || drop(reader));
        drop(feeder);
        assert_eq!(Arc::strong_count(&device), 1);
    }

    /// With nobody consuming, the thread stops reading at the bound and leaves the rest queued
    /// in the device; once consumed, every frame still arrives, in order.
    #[test]
    fn full_queue_stops_reading_at_the_bound() {
        let (device, peer) = datagram_pair();
        let (queue_batches, read_batch) = (2, 4);
        let mut reader = UtunReader::spawn(
            device,
            PacketBufPool::new(0),
            decode(),
            queue_batches,
            read_batch,
        )
        .expect("spawn");
        let _feeder = Feeder::start(peer, 0..60);
        // sleep: let the thread fill the queue
        std::thread::sleep(Duration::from_millis(300));
        // Queued batches plus the one batch the blocked thread holds.
        let bound = (queue_batches + 1) * read_batch;
        let read = reader.frames_read();
        assert!(read <= bound, "read {read} frames, bound {bound}");
        assert!(
            read >= queue_batches * read_batch,
            "read only {read} frames"
        );
        let rt = runtime();
        let mut seen = Vec::new();
        while seen.len() < 60 {
            let batch = next_within(&rt, &mut reader, Duration::from_secs(5))
                .expect("batch in time")
                .expect("no error");
            seen.extend(batch.into_iter().map(id));
        }
        assert_eq!(seen, (0..60).collect::<Vec<_>>());
    }

    /// When the device ends, the reader reports it once, then waits instead of failing again,
    /// and its thread is gone.
    #[test]
    fn device_gone_is_reported_once_then_pends() {
        let (device, peer) = UnixStream::pair().expect("stream pair");
        device
            .set_nonblocking(true)
            .expect("non-blocking device end");
        let device = Arc::new(device);
        let mut reader = UtunReader::spawn(device.clone(), PacketBufPool::new(0), decode(), 4, 8)
            .expect("spawn");
        let mut peer = peer;
        peer.write_all(&frame(7)).expect("send frame");
        drop(peer);
        let rt = runtime();
        let mut error = None;
        for _ in 0..4 {
            match next_within(&rt, &mut reader, Duration::from_secs(5)).expect("a delivery in time")
            {
                Ok(batch) => assert!(batch.into_iter().all(|p| id(p) == 7)),
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        let error = error.expect("device-gone error");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let again = next_within(&rt, &mut reader, Duration::from_millis(200));
        assert!(again.is_err(), "a second call must wait, not fail again");
        let deadline = Instant::now() + Duration::from_secs(2);
        while Arc::strong_count(&device) > 1 && Instant::now() < deadline {
            // sleep: wait for the thread to exit
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(Arc::strong_count(&device), 1, "the thread must have exited");
        within(Duration::from_secs(2), move || drop(reader));
    }

    /// A frame the decoder rejects is reported as one error, and reading carries on.
    #[test]
    fn a_rejected_frame_does_not_stop_the_reader() {
        let (device, peer) = datagram_pair();
        let mut reader =
            UtunReader::spawn(device, PacketBufPool::new(0), decode(), 4, 8).expect("spawn");
        peer.send(&[0u8; 3]).expect("send junk");
        peer.send(&frame(1)).expect("send frame");
        let rt = runtime();
        let mut errors = 0;
        let mut seen = Vec::new();
        while seen.is_empty() {
            match next_within(&rt, &mut reader, Duration::from_secs(5)).expect("a delivery in time")
            {
                Ok(batch) => seen.extend(batch.into_iter().map(id)),
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::InvalidData);
                    errors += 1;
                }
            }
        }
        assert_eq!((errors, seen), (1, vec![1]));
    }
}
