//! Owns the private native companion with one deadline for writing and receiving; EOF triggers cleanup [D203].
use crate::protocol::{self, Kind};
use std::{
    io::{self, Write},
    os::fd::AsFd,
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Reply = io::Result<(Kind, Vec<u8>)>;
pub struct Native {
    child: Option<Child>,
    input: Option<ChildStdin>,
    replies: Option<Receiver<Reply>>,
    reader: Option<JoinHandle<()>>,
    cancellation: Option<Arc<AtomicBool>>,
    retirement: Option<JoinHandle<()>>,
    encoder: bool,
    surface: bool,
    video: Option<Vec<u8>>,
    video_gap: bool,
}
impl Native {
    /// # Errors
    /// Reports launch failure or unavailable inherited pipes.
    pub fn spawn(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, false, false)
    }
    /// # Errors
    /// Starts only encoding; it cannot create a control indicator or inject input.
    pub fn spawn_encoder(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, true, false)
    }
    /// # Errors
    /// Starts same-process companion capture, keeping H.264 on the public path.
    pub fn spawn_surface(executable: &Path) -> io::Result<Self> {
        Self::spawn_mode(executable, false, true)
    }
    fn spawn_mode(executable: &Path, encoder: bool, surface: bool) -> io::Result<Self> {
        // The native entrypoint uses a responsibility-disclaimed SETEXEC before
        // AppKit or capture access. It preserves this owned PID and both pipes.
        let mut command = Command::new(executable);
        if encoder {
            command.arg("--encoder");
        }
        if surface {
            command.arg("--surface-capture");
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("Desktop companion input unavailable."))?;
        // A bounded reply wait is insufficient if a full pipe blocks the write.
        // Nonblocking writes preserve the owned pixel slice without another copy.
        let flags = nix::fcntl::fcntl(&input, nix::fcntl::FcntlArg::F_GETFL)?;
        nix::fcntl::fcntl(
            &input,
            nix::fcntl::FcntlArg::F_SETFL(
                nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK,
            ),
        )?;
        let mut output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("Desktop companion output unavailable."))?;
        let (sender, replies) = mpsc::sync_channel(1);
        let reader = thread::spawn(move || {
            loop {
                let reply = protocol::read(&mut output);
                let failed = reply.is_err();
                // Once the receiver is sealed, drain final replies until EOF.
                // Keeping stdout open lets control cleanup finish without SIGPIPE.
                let _ = sender.send(reply);
                if failed {
                    break;
                }
            }
        });
        Ok(Self {
            child: Some(child),
            input: Some(input),
            replies: Some(replies),
            reader: Some(reader),
            cancellation: None,
            retirement: None,
            encoder,
            surface,
            video: None,
            video_gap: false,
        })
    }
    /// Stop in-flight writes/replies when the owning capture worker is cancelled.
    pub fn cancel_on(&mut self, cancellation: Arc<AtomicBool>) {
        self.cancellation = Some(cancellation);
    }
    /// # Errors
    /// Reports companion errors or a three-second deadline covering write and reply.
    pub fn call(&mut self, kind: Kind, payload: &[u8]) -> Reply {
        let deadline = Instant::now() + Duration::from_secs(3);
        let result = protocol::write(&mut self.writer(deadline)?, kind, payload);
        if let Err(error) = result {
            self.stop_now();
            return Err(error);
        }
        self.response(deadline, !self.encoder)
    }
    /// # Errors
    /// Requires one bounded owned BGRA image and a responsive encoder.
    pub fn encode(
        &mut self,
        pixels: &[u8],
        width: u32,
        height: u32,
        capture_ticks: u64,
        sharp: bool,
    ) -> Reply {
        if u64::from(width) * u64::from(height) > 4 * 1024 * 1024
            || pixels.len() as u64 != u64::from(width) * u64::from(height) * 4
        {
            return Err(io::Error::other("Desktop pixel bounds exceeded."));
        }
        let metadata = serde_json::to_vec(
            &serde_json::json!({"width":width,"height":height,"capture_ticks":capture_ticks,"sharp":sharp}),
        )?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let length = u32::try_from(2 + 4 + metadata.len() + pixels.len())
            .map_err(|_| io::Error::other("Desktop pixel bounds exceeded."))?;
        let meta_length = u32::try_from(metadata.len())
            .map_err(|_| io::Error::other("Desktop pixel bounds exceeded."))?;
        let result = (|| {
            let mut input = self.writer(deadline)?;
            input.write_all(&length.to_be_bytes())?;
            input.write_all(&[protocol::VERSION, 101])?;
            input.write_all(&meta_length.to_be_bytes())?;
            input.write_all(&metadata)?;
            input.write_all(pixels)
        })();
        if let Err(error) = result {
            // A partial packet cannot be reused. Cancellation must also release
            // the child before Worker::drop joins the capture thread.
            self.stop_now();
            return Err(error);
        }
        self.response(deadline, false)
    }
    fn writer(&mut self, deadline: Instant) -> io::Result<DeadlineWriter<'_>> {
        Ok(DeadlineWriter {
            input: self
                .input
                .as_mut()
                .ok_or_else(|| io::Error::other("Desktop companion stopped."))?,
            deadline,
            cancellation: self.cancellation.as_deref(),
        })
    }
    fn stop_now(&mut self) {
        self.replies.take();
        self.input.take();
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
        }
    }
    fn retire_control(&mut self) {
        self.replies.take();
        self.input.take();
        if let Some(child) = self.child.take() {
            // Seal the old exchange immediately, but preserve EOF restoration.
            // Cleanup runs outside the operation deadline and remains owned:
            // Drop joins it before the helper can report complete shutdown.
            self.retirement = Some(thread::spawn(move || retire_child(child)));
        }
    }
    fn response(&mut self, deadline: Instant, graceful: bool) -> Reply {
        let reply = loop {
            match self.receive_response(deadline) {
                Ok((Kind::Video, body)) if self.surface => {
                    // A newer IDR repairs any skipped references. Replacing an
                    // encoded frame with a delta cannot hide the gap from the
                    // worker: private video has no sequence numbers of its own.
                    if body.get(8) == Some(&1) {
                        self.video_gap = false;
                    } else {
                        self.video_gap |= self.video.is_some();
                    }
                    self.video = Some(body);
                }
                reply => break reply,
            }
        };
        if reply.is_err() {
            // The private protocol has no request IDs. Once a request fails,
            // queued or delayed replies must never answer a subsequent command.
            if graceful
                && !reply
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::ConnectionAborted)
            {
                self.retire_control();
            } else {
                self.stop_now();
            }
        }
        reply
    }
    /// An overwritten encoded delta requires a new IDR at the forwarding boundary.
    pub fn take_surface_gap(&mut self) -> bool {
        std::mem::take(&mut self.video_gap)
    }
    /// # Errors
    /// Returns only native video; bounded idle waits let the owning worker observe retirement.
    pub fn surface_video(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(video) = self.video.take() {
            return Ok(Some(video));
        }
        match self.receive_response(Instant::now() + Duration::from_millis(100)) {
            Ok((Kind::Video, body)) => Ok(Some(body)),
            Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(None),
            _ => Err(io::Error::other("Desktop surface capture unavailable.")),
        }
    }
    fn receive_response(&self, deadline: Instant) -> Reply {
        let replies = self
            .replies
            .as_ref()
            .ok_or_else(|| io::Error::other("Desktop companion stopped."))?;
        loop {
            let timeout = remaining(deadline, self.cancellation.as_deref())?;
            match replies.recv_timeout(timeout) {
                Ok(reply) => return reply,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Desktop companion stopped.",
                    ));
                }
            }
        }
    }
}

fn remaining(deadline: Instant, cancellation: Option<&AtomicBool>) -> io::Result<Duration> {
    if cancellation.is_some_and(|stop| stop.load(Ordering::Acquire)) {
        // write_all retries Interrupted automatically; cancellation must end it.
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Desktop capture stopped.",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Desktop companion operation timed out.",
        ));
    }
    Ok(if cancellation.is_some() {
        remaining.min(Duration::from_millis(20))
    } else {
        remaining
    })
}

struct DeadlineWriter<'a> {
    input: &'a mut ChildStdin,
    deadline: Instant,
    cancellation: Option<&'a AtomicBool>,
}
impl Write for DeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            let timeout = remaining(self.deadline, self.cancellation)?;
            match self.input.write(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let mut ready = [nix::poll::PollFd::new(
                        self.input.as_fd(),
                        nix::poll::PollFlags::POLLOUT,
                    )];
                    let timeout =
                        nix::poll::PollTimeout::try_from(timeout).map_err(io::Error::other)?;
                    match nix::poll::poll(&mut ready, timeout) {
                        Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => return result,
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for Native {
    fn drop(&mut self) {
        // Closing stdin lets control restore before exit. A cancelled encoder
        // was already stopped, so its drop cannot wait on a blocked pixel writer.
        self.replies.take();
        self.input.take();
        if let Some(child) = self.child.take() {
            retire_child(child);
        }
        if let Some(retirement) = self.retirement.take() {
            let _ = retirement.join();
        }
        // The receiver is closed before joining, so a full response slot cannot
        // block the reader while it drains the child's final cleanup response.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn retire_child(mut child: Child) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while matches!(child.try_wait(), Ok(None)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
}
