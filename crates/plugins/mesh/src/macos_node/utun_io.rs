//! Owns the macOS utun descriptor and adapts its packets to GotaTun.

use crate::macos_utun_reader::{self as reader, Decode, UtunReader};
use bytes::Buf;
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::socket::{
        AddressFamily, SockFlag, SockProtocol, SockType, SysControlAddr, connect, getsockopt,
        socket, sockopt::UtunIfname,
    },
    unistd::write,
};
use std::{
    io,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};
use tokio::{
    io::{Interest, unix::AsyncFd},
    sync::watch,
};

/// The address-family marker that macOS prepends to an IPv4 utun packet.
const UTUN_AF_INET: u32 = 2;
/// The address-family marker that macOS prepends to an IPv6 utun packet.
const UTUN_AF_INET6: u32 = 30;
/// The kernel control socket name used to request a fresh utun interface.
const UTUN_CONTROL: &str = "com.apple.net.utun_control";

/// Holds a freshly allocated utun control socket until the node registers it.
pub(super) struct OpenUtun {
    fd: OwnedFd,
    name: String,
}

impl OpenUtun {
    /// Ask the kernel for one fresh utun and read back the assigned interface unit.
    /// # Errors
    /// Returns socket-control or interface lookup failures.
    pub(super) fn open() -> io::Result<Self> {
        let fd = socket(
            AddressFamily::System,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::KextControl,
        )
        .map_err(|error| utun_setup_error("PF_SYSTEM socket", error))?;
        fcntl(&fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .map_err(|error| utun_setup_error("nonblocking setup", error))?;
        fcntl(&fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .map_err(|error| utun_setup_error("close-on-exec setup", error))?;
        let control = SysControlAddr::from_name(fd.as_raw_fd(), UTUN_CONTROL, 0)
            .map_err(|error| utun_setup_error("control lookup", error))?;
        connect(fd.as_raw_fd(), &control)
            .map_err(|error| utun_setup_error("control connect", error))?;
        let name = getsockopt(&fd, UtunIfname)
            .map_err(|error| utun_setup_error("interface name lookup", error))?
            .into_string()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "utun interface name is not valid UTF-8.",
                )
            })?;
        if !valid_utun_name(&name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun interface name is invalid.",
            ));
        }
        Ok(Self { fd, name })
    }
}

/// Add the utun setup stage to a kernel error so startup failures have useful context.
fn utun_setup_error(stage: &str, error: nix::errno::Errno) -> io::Error {
    let error = io::Error::from(error);
    io::Error::new(error.kind(), format!("utun {stage}: {error}"))
}

/// Owns one dynamically assigned utun control socket and its exact interface name.
#[derive(Clone)]
pub(super) struct MacUtun {
    fd: Arc<AsyncFd<OwnedFd>>,
    name: Arc<str>,
    mtu: watch::Sender<u16>,
}

impl MacUtun {
    /// Register one previously opened utun descriptor with this daemon's tokio runtime.
    /// # Errors
    /// Returns readiness registration failures.
    pub(super) fn from_open(open: OpenUtun) -> io::Result<Self> {
        // Tokio's safe constructor is deprecated but remains the only safe API;
        // the replacement requires unsafe code, which this crate forbids.
        // Write readiness only: reads happen on the dedicated reader thread
        // (`macos_utun_reader`), so read events would only wake the runtime for nothing.
        #[allow(deprecated)]
        let fd = AsyncFd::with_interest(open.fd, Interest::WRITABLE)?;
        let (mtu, _) = watch::channel(crate::mesh_mtu::IPV6_MINIMUM_MTU);
        Ok(Self {
            fd: Arc::new(fd),
            name: Arc::from(open.name),
            mtu,
        })
    }

    /// Return the interface name assigned to this utun.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Build the send adapter with a watcher for this utun's current shared interface MTU.
    pub(super) fn sender(&self) -> MacUtunTx {
        MacUtunTx {
            fd: self.fd.clone(),
            mtu: self.mtu.subscribe().into(),
            frame: Vec::with_capacity(usize::from(crate::mesh_mtu::IPV6_MINIMUM_MTU) + 4),
        }
    }

    /// Build the receive adapter with a watcher for this utun's current shared interface MTU.
    ///
    /// Its reader thread starts on the first receive and stops when the adapter is dropped.
    pub(super) fn receiver(&self) -> MacUtunRx {
        MacUtunRx {
            fd: self.fd.clone(),
            mtu: self.mtu.subscribe().into(),
            reader: None,
            start_failed: false,
        }
    }

    /// Publish an MTU change to the utun send and receive packet workers.
    pub(super) fn set_mtu(&self, mtu: u16) {
        self.mtu.send_replace(mtu);
    }
}

/// Sends packets from GotaTun to one owned utun using its live interface MTU.
pub(super) struct MacUtunTx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
    frame: Vec<u8>,
}

impl IpSend for MacUtunTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = packet.into_bytes();
        let family = utun_family(packet.as_ref())?;
        if packet.len() > usize::from(self.mtu.get()) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.frame.clear();
        self.frame.extend_from_slice(&family.to_be_bytes());
        self.frame.extend_from_slice(packet.as_ref());
        loop {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|fd| write(fd.get_ref(), &self.frame).map_err(io::Error::from)) {
                Err(_) => continue,
                Ok(Err(error)) => return Err(error),
                Ok(Ok(written)) if written == self.frame.len() => return Ok(()),
                Ok(Ok(_)) => return Err(io::ErrorKind::WriteZero.into()),
            }
        }
    }
}

/// Receives packets from one owned utun and rejects frames above its live interface MTU.
///
/// A dedicated thread reads the utun and hands packets over in bounded batches (#260, J461):
/// see [`crate::macos_utun_reader`] for why, and for its backpressure and shutdown rules.
pub(super) struct MacUtunRx {
    fd: Arc<AsyncFd<OwnedFd>>,
    mtu: MtuWatcher,
    /// The reader thread, started on the first receive with `GotaTun`'s packet pool.
    reader: Option<UtunReader>,
    /// Starting the thread failed and that was reported once; later receives wait forever,
    /// because `GotaTun` retries non-fatal errors in a loop and repeating one would spin it.
    start_failed: bool,
}

impl MacUtunRx {
    /// Start the reader thread, decoding each frame against this utun's live MTU.
    /// # Errors
    /// Returns stop-pipe or thread creation failures.
    fn start_reader(&self, pool: &PacketBufPool) -> io::Result<UtunReader> {
        let mut mtu = self.mtu.clone();
        let decode: Decode = Box::new(move |mut packet: Packet<[u8]>| {
            parse_utun_payload(packet.as_ref(), mtu.get())?;
            packet.buf_mut().advance(4);
            packet
                .try_into_ip()
                .map_err(|_| io::ErrorKind::InvalidData.into())
        });
        UtunReader::spawn(
            self.fd.clone(),
            pool.clone(),
            decode,
            reader::QUEUE_BATCHES,
            reader::READ_BATCH,
        )
    }
}

/// What [`MacUtunRx::recv`] yields: one reader batch, in device order.
type UtunBatch = std::vec::IntoIter<Packet<Ip>>;

impl IpRecv for MacUtunRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        if self.start_failed {
            return std::future::pending::<io::Result<UtunBatch>>().await;
        }
        if self.reader.is_none() {
            match self.start_reader(pool) {
                Ok(started) => self.reader = Some(started),
                Err(error) => {
                    self.start_failed = true;
                    return Err(error);
                }
            }
        }
        let Some(reader) = self.reader.as_mut() else {
            return std::future::pending::<io::Result<UtunBatch>>().await;
        };
        reader.next_batch().await.map(Vec::into_iter)
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

/// Check that an interface name has the exact shape returned for a macOS utun.
pub(super) fn valid_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|unit| !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Select the address-family header macOS requires for a complete IP packet.
/// # Errors
/// Rejects empty packets and unsupported IP versions.
pub(super) fn utun_family(packet: &[u8]) -> io::Result<u32> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Ok(UTUN_AF_INET),
        Some(6) => Ok(UTUN_AF_INET6),
        _ => Err(io::ErrorKind::InvalidData.into()),
    }
}

/// Validate and strip the network-order address-family header from one utun frame.
///
/// `mtu` is the live shared interface limit reported to the GotaTun packet workers.
/// # Errors
/// Rejects truncated, unsupported, oversized or family-mismatched frames.
pub(super) fn parse_utun_payload(frame: &[u8], mtu: u16) -> io::Result<&[u8]> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(io::ErrorKind::InvalidData)?
        .try_into()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    let payload = frame.get(4..).ok_or(io::ErrorKind::InvalidData)?;
    let family = u32::from_be_bytes(prefix);
    if payload.is_empty() || payload.len() > usize::from(mtu) || utun_family(payload)? != family {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(payload)
}
