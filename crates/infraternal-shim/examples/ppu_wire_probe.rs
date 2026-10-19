//! Native frozen-wire echo observer for synthetic perf-VM fixtures [D270].
//! Additional viewers use a distinct durable writer. No shell command is
//! inferred from real sessions; generated octal markers fence actual PTY output.
//! The caller must record this observer's extra connections separately from
//! the original soak. It never substitutes for that suite's admission result.
use infraternal_shim::frame::{Decoder, Frame, FrameRef, MAX_FRAME, MULTI_WRITER, SEQUENCED_INPUT};
use nix::poll::{PollFd, PollFlags, poll};
use std::{
    fmt::Write as _,
    io::{self, Read, Write},
    os::{fd::AsFd, unix::net::UnixStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "ppu_wire_probe/passive.rs"]
mod passive;

struct Peer {
    stream: UnixStream,
    decoder: Decoder,
    head: u64,
    wire: Vec<u8>,
    written: usize,
    marker: Vec<u8>,
    tail: Vec<u8>,
    started: Instant,
    elapsed: Option<Duration>,
    watch: Option<passive::Observer>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn frame(stream: &mut UnixStream) -> io::Result<Frame> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_le_bytes(length)).map_err(io::Error::other)?;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid("frame length outside frozen bounds"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Frame::decode(&bytes)
}

impl Peer {
    fn connect(path: &Path, writer: u32, index: usize, number: usize) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let Frame::Hello { head, .. } = frame(&mut stream)? else {
            return Err(invalid("expected frozen Hello"));
        };
        for request in [
            Frame::Attach(SEQUENCED_INPUT | MULTI_WRITER),
            Frame::SelectWriter(writer),
            Frame::InputStateRequest,
        ] {
            stream.write_all(&request.encode()?)?;
        }
        let accepted = loop {
            match frame(&mut stream)? {
                Frame::InputState(_, accepted) => break accepted,
                Frame::Error(_, message) => return Err(invalid(&message)),
                _ => {}
            }
        };
        stream.write_all(&Frame::ReadFrom(head).encode()?)?;
        // Literal marker text is absent from the command, so command echo
        // cannot satisfy this observer even if a fixture loses stty -echo.
        let marker = format!("native-probe-{index}-{number}").into_bytes();
        let mut command = String::from("printf '");
        for byte in &marker {
            write!(&mut command, "\\{byte:03o}").map_err(io::Error::other)?;
        }
        command.push_str("\\n'\n");
        let wire = Frame::SequencedInput(accepted, command.into_bytes()).encode()?;
        stream.set_nonblocking(true)?;
        Ok(Self {
            stream,
            decoder: Decoder::default(),
            head,
            wire,
            written: 0,
            marker,
            tail: Vec::new(),
            started: Instant::now(),
            elapsed: None,
            watch: None,
        })
    }

    fn output(&mut self, seq: u64, bytes: &[u8]) -> io::Result<()> {
        if seq != self.head {
            return Err(invalid("output gap or duplicate"));
        }
        self.head = self
            .head
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| invalid("offset exhausted"))?;
        if let Some(watch) = &mut self.watch {
            return watch.feed(bytes);
        }
        self.tail.extend_from_slice(bytes);
        if self.elapsed.is_none()
            && self
                .tail
                .windows(self.marker.len())
                .any(|part| part == self.marker)
        {
            self.elapsed = Some(self.started.elapsed());
        }
        let keep = self.marker.len().saturating_sub(1);
        if self.tail.len() > keep {
            self.tail.drain(..self.tail.len() - keep);
        }
        Ok(())
    }

    fn step(&mut self, flags: PollFlags) -> io::Result<()> {
        if flags.contains(PollFlags::POLLOUT) && self.written < self.wire.len() {
            match self.stream.write(&self.wire[self.written..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => self.written += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            let mut bytes = [0; 16384];
            let count = match self.stream.read(&mut bytes) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            };
            let mut decoder = std::mem::take(&mut self.decoder);
            let result = decoder.feed_with(&bytes[..count], |frame| match frame {
                FrameRef::Output(seq, bytes) => self.output(seq, bytes),
                FrameRef::Owned(Frame::InputAck(_)) => Ok(()),
                FrameRef::Owned(Frame::Error(_, message)) => Err(invalid(&message)),
                _ => Err(invalid("unexpected observer frame")),
            });
            self.decoder = decoder;
            result?;
        }
        if flags.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
            return Err(invalid("observer socket failed"));
        }
        Ok(())
    }
}

fn session_path(state: &Path, origin: u128, index: usize) -> io::Result<PathBuf> {
    let id = origin
        .checked_add(index as u128)
        .ok_or_else(|| invalid("session identity exhausted"))?;
    Ok(state.join("sessions").join(format!("{id:032x}.sock")))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|mode| mode == "watch") {
        return passive::run(&arguments[1..]);
    }
    if arguments.len() != 6 {
        return Err("usage: ppu_wire_probe STATE ORIGIN_HEX FIRST COUNT NUMBER WRITER".into());
    }
    let origin = u128::from_str_radix(&arguments[1], 16)?;
    let first: usize = arguments[2].parse()?;
    let count: usize = arguments[3].parse()?;
    let number: usize = arguments[4].parse()?;
    let writer: u32 = arguments[5].parse()?;
    if count == 0 || count > 1000 || writer == 0 {
        return Err("observer count/writer outside bounds".into());
    }
    let mut peers = Vec::with_capacity(count);
    for index in first..first.checked_add(count).ok_or("index exhausted")? {
        peers.push(Peer::connect(
            &session_path(Path::new(&arguments[0]), origin, index)?,
            writer,
            index,
            number,
        )?);
    }
    // Connection/setup and command encoding precede every measured start.
    for peer in &mut peers {
        peer.started = Instant::now();
        peer.step(PollFlags::POLLOUT)?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while peers.iter().any(|peer| peer.elapsed.is_none()) {
        if Instant::now() >= deadline {
            return Err("native observer deadline".into());
        }
        let mut descriptors: Vec<_> = peers
            .iter()
            .map(|peer| {
                let mut flags = PollFlags::POLLIN;
                if peer.written < peer.wire.len() {
                    flags |= PollFlags::POLLOUT;
                }
                PollFd::new(peer.stream.as_fd(), flags)
            })
            .collect();
        match poll(&mut descriptors, 1000_u16) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let ready: Vec<_> = descriptors
            .iter()
            .map(|fd| fd.revents().unwrap_or_else(PollFlags::empty))
            .collect();
        drop(descriptors);
        for (peer, flags) in peers.iter_mut().zip(ready) {
            peer.step(flags)?;
        }
    }
    print!("[");
    for (index, peer) in peers.iter().enumerate() {
        if index > 0 {
            print!(",");
        }
        print!(
            "{:.6}",
            peer.elapsed.ok_or("missing observer result")?.as_secs_f64() * 1000.0
        );
    }
    println!("]");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("native wire observer: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    //! The observer fences real output, retains split markers and checks offsets.
    use super::*;

    #[test]
    fn first_session_uses_the_inclusive_host_origin() -> io::Result<()> {
        assert_eq!(
            session_path(Path::new("state"), 0x1234, 0)?,
            Path::new("state/sessions/00000000000000000000000000001234.sock")
        );
        assert!(session_path(Path::new("state"), u128::MAX, 1).is_err());
        Ok(())
    }
    #[test]
    fn marker_spans_frames_and_wrong_output_offset_is_refused() -> io::Result<()> {
        let (stream, _other) = UnixStream::pair()?;
        let mut peer = Peer {
            stream,
            decoder: Decoder::default(),
            head: 10,
            wire: Vec::new(),
            written: 0,
            marker: b"probe-marker".to_vec(),
            tail: Vec::new(),
            started: Instant::now(),
            elapsed: None,
            watch: None,
        };
        peer.output(10, b"noise probe-")?;
        assert!(peer.elapsed.is_none());
        let head = peer.head;
        assert!(peer.output(head + 1, b"marker").is_err());
        assert_eq!(peer.head, head);
        peer.output(head, b"marker suffix")?;
        assert!(peer.elapsed.is_some());
        assert!(peer.tail.len() < peer.marker.len());
        Ok(())
    }
}
