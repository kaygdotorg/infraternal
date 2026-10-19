//! Observe existing synthetic probe output without adding shell input or writer switches [D270].
//! Extra viewers still add fan-out; this diagnostic never replaces the original soak admission.
use super::{Peer, invalid, session_path};
use nix::poll::{PollFd, PollFlags, poll};
use std::{
    io::{self, Read, Write},
    os::fd::AsFd,
    path::Path,
    time::{Duration, Instant},
};

pub(super) struct Observer {
    prefix: Vec<u8>,
    tail: Vec<u8>,
    expected: usize,
    records: Vec<(usize, u64)>,
}
impl Observer {
    fn new(index: usize, expected: usize) -> Self {
        Self {
            prefix: format!("probe-{index}-").into_bytes(),
            tail: Vec::new(),
            expected,
            records: Vec::with_capacity(expected),
        }
    }
    pub(super) fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.feed_at(bytes, monotonic_ns()?)
    }
    fn feed_at(&mut self, bytes: &[u8], stamp: u64) -> io::Result<()> {
        self.tail.extend_from_slice(bytes);
        for start in 0..self.tail.len().saturating_sub(self.prefix.len() - 1) {
            if !self.tail[start..].starts_with(&self.prefix) {
                continue;
            }
            let rest = &self.tail[start + self.prefix.len()..];
            let digits = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
            let Some(delimiter) = rest.get(digits) else {
                continue;
            };
            if digits == 0 || !matches!(delimiter, b'\r' | b'\n') {
                continue;
            }
            if digits > 1 && rest[0] == b'0' {
                return Err(invalid("noncanonical probe number"));
            }
            let number = rest[..digits].iter().try_fold(0_usize, |value, byte| {
                value
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(usize::from(*byte - b'0')))
                    .ok_or_else(|| invalid("probe number overflow"))
            })?;
            if number < self.records.len() {
                // A suffix can include an already recorded complete marker.
                continue;
            }
            if number != self.records.len() || number >= self.expected {
                return Err(invalid("probe sequence gap or excess"));
            }
            self.records.push((number, stamp));
        }
        // Preserve a split prefix/decimal/newline, never the bulk output body.
        let keep = self.prefix.len() + 21;
        if self.tail.len() > keep {
            self.tail.drain(..self.tail.len() - keep);
        }
        Ok(())
    }
    fn complete(&self) -> bool {
        self.records.len() == self.expected
    }
}

/// Instant is opaque; the controller needs the same kernel clock across processes.
#[allow(unsafe_code)]
fn monotonic_ns() -> io::Result<u64> {
    let mut value = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the initialized timespec is writable throughout this synchronous
    // call. The kernel retains no pointer; both supported Linux ABIs use it.
    if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &raw mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(value.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(u64::try_from(value.tv_nsec).ok()?))
        .ok_or_else(|| invalid("monotonic clock outside bounds"))
}

pub(super) fn run(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if arguments.len() != 6 {
        return Err("usage: watch STATE ORIGIN_HEX FIRST COUNT PROBES WRITER".into());
    }
    let origin = u128::from_str_radix(&arguments[1], 16)?;
    let first: usize = arguments[2].parse()?;
    let count: usize = arguments[3].parse()?;
    let probes: usize = arguments[4].parse()?;
    let writer: u32 = arguments[5].parse()?;
    if count == 0
        || first.checked_add(count).is_none_or(|end| end > 1000)
        || !(1..=7200).contains(&probes)
        || writer == 0
    {
        return Err(invalid("observer count/writer outside bounds").into());
    }
    let mut peers = Vec::with_capacity(count);
    for index in first..first + count {
        let mut peer = Peer::connect(
            &session_path(Path::new(&arguments[0]), origin, index)?,
            writer,
            index,
            0,
        )?;
        // Reuse the frozen handshake and output-offset checks. Never send the
        // active observer's generated command: the original writer stays active.
        peer.wire = Vec::new();
        peer.marker = Vec::new();
        peer.watch = Some(Observer::new(index, probes));
        peers.push(peer);
    }
    println!("{{\"kind\":\"passive-ready\",\"viewers\":{count},\"probes\":{probes}}}");
    io::stdout().flush()?;
    let deadline = Instant::now() + Duration::from_mins(125);
    while peers
        .iter()
        .any(|peer| !peer.watch.as_ref().is_some_and(Observer::complete))
    {
        if Instant::now() >= deadline {
            return Err(invalid("passive observer deadline").into());
        }
        let mut descriptors: Vec<_> = peers
            .iter()
            .map(|peer| PollFd::new(peer.stream.as_fd(), PollFlags::POLLIN))
            .collect();
        match poll(&mut descriptors, 1000_u16) {
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let flags: Vec<_> = descriptors
            .iter()
            .map(|fd| fd.revents().unwrap_or_else(PollFlags::empty))
            .collect();
        drop(descriptors);
        for (peer, flags) in peers.iter_mut().zip(flags) {
            peer.step(flags)?;
        }
    }
    // Defer large result serialization until the controller's measured probes
    // and survivor census finish, so receipt I/O cannot delay its final reader.
    println!("{{\"kind\":\"passive-complete\"}}");
    io::stdout().flush()?;
    let mut release = [0; 1];
    io::stdin().read_exact(&mut release)?;
    if release != [1] {
        return Err(invalid("passive result barrier refused").into());
    }
    println!("{{\"kind\":\"passive-records\",\"rows\":[");
    let mut separator = "";
    for (offset, peer) in peers.iter().enumerate() {
        let watch = peer
            .watch
            .as_ref()
            .ok_or_else(|| invalid("observer missing"))?;
        for &(number, stamp) in &watch.records {
            print!("{separator}[{},{number},{stamp}]", first + offset);
            separator = ",";
        }
    }
    println!("]}}");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Exact sequence accounting across every marker split; no new input is generated.
    use super::*;

    #[test]
    fn every_split_keeps_all_existing_probe_markers_once() -> io::Result<()> {
        let bytes = b"noise probe-901-0\r\nprobe-900-0\r\ntext probe-900-1\r\n";
        for split in 0..=bytes.len() {
            let mut observer = Observer::new(900, 2);
            observer.feed_at(&bytes[..split], 10)?;
            observer.feed_at(&bytes[split..], 20)?;
            assert_eq!(
                observer.records.iter().map(|row| row.0).collect::<Vec<_>>(),
                [0, 1]
            );
            assert!(observer.complete());
            assert!(observer.tail.len() <= observer.prefix.len() + 21);
        }
        Ok(())
    }
    #[test]
    fn gaps_excess_overflow_and_noncanonical_numbers_are_refused() -> io::Result<()> {
        for bytes in [
            b"probe-2-1\n".as_slice(),
            b"probe-2-0\nprobe-2-1\n".as_slice(),
            b"probe-2-999999999999999999999999\n".as_slice(),
            b"probe-2-00\n".as_slice(),
        ] {
            assert!(Observer::new(2, 1).feed_at(bytes, 10).is_err());
        }
        let mut observer = Observer::new(2, 1);
        observer.feed_at(b"probe-2-0suffix\n", 10)?;
        assert!(!observer.complete());
        observer.feed_at(b"probe-2-0\n", 20)?;
        observer.feed_at(b"probe-2-0\n", 30)?;
        assert_eq!(observer.records, [(0, 20)]);
        Ok(())
    }
    #[test]
    fn cross_process_clock_is_monotonic() -> io::Result<()> {
        assert!(monotonic_ns()? <= monotonic_ns()?);
        Ok(())
    }
}
