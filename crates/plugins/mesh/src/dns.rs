//! Serves one node's accepted, policy-filtered mesh name snapshot on its mesh address [#266].
//!
//! A node's own snapshot contains only names it may reach. Queries from another source are treated
//! as nonexistent inside the zone, so this listener never reveals names from its broader view.
//!
//! Every query that parses gets an answer, never silence (#580, J1183): a name outside the mesh
//! zones gets `REFUSED`, so a client's stub resolver moves on at once instead of waiting out its
//! timeout. A message that parses but is not one plain question gets `FORMERR` or `NOTIMP`. Only
//! bytes that do not parse as DNS, oversized packets and response messages (which must never be
//! answered, or two resolvers could bounce replies forever) are dropped; each drop is counted in a
//! rate-limited log line that names no queried name (see [`DropLog`]).
use crate::dataplane::Config;
/// Parsed names shared by the host socket and tunnel resolvers.
pub(crate) use infraternal_mesh_node::dns::Records;
/// Name records and direct packet replies from the node DNS engine.
pub use infraternal_mesh_node::dns::response;
use infraternal_mesh_node::dns::{DropReason, MAX_PACKET, is_protocol_error, response_for_source};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    io::{self, Read as _, Write as _},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    os::{fd::AsFd, unix::net::UnixStream},
    sync::{Arc, Mutex, RwLock},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// The UDP port the resolver listens on. It is a high port so no privilege is
/// needed; the host's split-DNS setup sends queries for the mesh suffix here.
pub const DNS_PORT: u16 = 1053;
/// The standard DNS port used by `NetworkManager`'s split-DNS forwarding.
pub const DNS_SYSTEM_PORT: u16 = 53;
/// Maximum number of TCP DNS clients held by the resolver at once.
const TCP_CONNECTION_LIMIT: usize = 64;
/// Maximum number of TCP DNS clients held for one source address.
const TCP_SOURCE_CONNECTION_LIMIT: usize = 8;
/// Maximum time a TCP DNS client may remain idle between reads or writes.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum time from accept (or the previous complete answer) to read one whole DNS frame.
const TCP_MESSAGE_TIMEOUT: Duration = Duration::from_secs(2);
/// Malformed DNS messages are counted for the lifetime of a connection.
const TCP_MALFORMED_FRAME_LIMIT: usize = 16;
/// Maximum number of queued TCP accepts serviced before polling clients again.
const TCP_ACCEPT_BUDGET: usize = 64;
/// Shortest time between two "dropped queries" log lines. Drops in between are counted and
/// reported by the next line, so a flood of junk costs one line a minute, not one per packet.
const DROP_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Counts dropped queries and logs them at most once per [`DROP_LOG_INTERVAL`].
///
/// The first drop is logged at once, so an operator sees the problem while reproducing it.
/// Later drops inside the interval are only counted; the next line after the interval reports
/// how many there were. Both protocol workers share one log through an [`Arc`].
#[derive(Default)]
struct DropLog {
    window: Mutex<DropWindow>,
}

/// The mutable part of [`DropLog`]: when it last logged and what it has counted since.
#[derive(Default)]
struct DropWindow {
    logged_at: Option<Instant>,
    unreported: u64,
}

impl DropLog {
    /// Records one drop for `reason` and writes the log line when the interval allows it.
    fn record(&self, reason: DropReason) {
        if let Some(dropped) = self.note(Instant::now()) {
            tracing::info!(
                dropped,
                reason = reason.as_str(),
                "mesh DNS dropped queries it could not answer"
            );
        }
    }

    /// Counts one drop at `now`. Returns the number of drops to report when a line is due
    /// (this one included), or `None` while the previous line is younger than the interval.
    fn note(&self, now: Instant) -> Option<u64> {
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        window.unreported += 1;
        if window
            .logged_at
            .is_some_and(|logged_at| now.saturating_duration_since(logged_at) < DROP_LOG_INTERVAL)
        {
            return None;
        }
        window.logged_at = Some(now);
        Some(std::mem::take(&mut window.unreported))
    }
}

/// Bounded state for one TCP client, including one in-flight DNS frame in each direction.
struct TcpClient {
    stream: TcpStream,
    source: SocketAddr,
    input: Vec<u8>,
    expected_message_length: Option<usize>,
    output: Vec<u8>,
    output_offset: usize,
    last_activity: Instant,
    frame_deadline: Option<Instant>,
    malformed_frames: usize,
}

impl TcpClient {
    /// Reserves at most one capped DNS request frame for a newly accepted stream.
    fn new(stream: TcpStream, source: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            stream,
            source,
            input: Vec::with_capacity(MAX_PACKET + 2),
            expected_message_length: None,
            output: Vec::new(),
            output_offset: 0,
            last_activity: now,
            frame_deadline: Some(now + TCP_MESSAGE_TIMEOUT),
            malformed_frames: 0,
        }
    }

    /// Clears the in-flight request after it receives no local answer.
    fn clear_request(&mut self) {
        self.input.clear();
        self.expected_message_length = None;
    }

    /// Returns the earlier of the idle timeout and the whole-frame deadline.
    fn deadline(&self) -> Instant {
        let idle_deadline = self.last_activity + TCP_IDLE_TIMEOUT;
        self.frame_deadline.map_or(idle_deadline, |frame_deadline| {
            frame_deadline.min(idle_deadline)
        })
    }

    /// Reports whether this connection has exhausted either bounded wait.
    fn expired_at(&self, now: Instant) -> bool {
        self.deadline() <= now
    }
}

/// Selects the next TCP deadline, blocking indefinitely when no clients are connected.
fn tcp_poll_timeout(clients: &[TcpClient]) -> PollTimeout {
    let now = Instant::now();
    clients
        .iter()
        .map(|client| client.deadline().saturating_duration_since(now))
        .min()
        .map_or(PollTimeout::NONE, |remaining| {
            PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX)
        })
}

/// Accepts a bounded batch so a flood of TCP handshakes cannot starve UDP queries.
///
/// A connection over the global or per-source limit is closed at once and counted in `drops`.
fn accept_tcp_connections(
    listener: &TcpListener,
    clients: &mut Vec<TcpClient>,
    drops: &DropLog,
) -> io::Result<()> {
    for _ in 0..TCP_ACCEPT_BUDGET {
        match listener.accept() {
            Ok((stream, source)) => {
                let source_connections = clients
                    .iter()
                    .filter(|client| client.source.ip() == source.ip())
                    .count();
                if clients.len() >= TCP_CONNECTION_LIMIT
                    || source_connections >= TCP_SOURCE_CONNECTION_LIMIT
                {
                    drops.record(DropReason::ConnectionLimit);
                    continue;
                }
                if stream.set_nonblocking(true).is_err() {
                    continue;
                }
                clients.push(TcpClient::new(stream, source));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Reads at most one capped, length-prefixed query fragment and queues its UDP-equivalent answer.
///
/// Returns `false` when the connection should close. A frame that gets no answer is counted in
/// `drops`; too many of them on one connection close it.
fn read_tcp_request(
    client: &mut TcpClient,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
) -> bool {
    let mut buffer = [0_u8; MAX_PACKET + 2];
    let target_length = client
        .expected_message_length
        .map_or(2, |message_length| message_length + 2);
    let remaining = target_length - client.input.len();
    let read_length = remaining.min(buffer.len());
    match client.stream.read(&mut buffer[..read_length]) {
        Ok(0) => false,
        Ok(length) => {
            client.last_activity = Instant::now();
            client.input.extend_from_slice(&buffer[..length]);
            if client.expected_message_length.is_none() && client.input.len() == 2 {
                let message_length =
                    usize::from(u16::from_be_bytes([client.input[0], client.input[1]]));
                if !(12..=MAX_PACKET).contains(&message_length) {
                    drops.record(DropReason::Oversized);
                    return false;
                }
                client.expected_message_length = Some(message_length);
            }

            let Some(message_length) = client.expected_message_length else {
                return true;
            };
            if client.input.len() < message_length + 2 {
                return true;
            }

            let response = {
                let snapshot = records
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                response_for_source(&client.input[2..], &snapshot, client.source.ip())
            };
            client.clear_request();
            match response {
                Ok(response) if response.len() <= MAX_PACKET => {
                    // FORMERR and NOTIMP are answered, but still spend the malformed-frame
                    // budget, so a stream of junk headers is cut off as before.
                    if is_protocol_error(&response) {
                        client.malformed_frames += 1;
                        if client.malformed_frames >= TCP_MALFORMED_FRAME_LIMIT {
                            return false;
                        }
                    }
                    let Ok(response_length) = u16::try_from(response.len()) else {
                        return false;
                    };
                    client.output.clear();
                    client
                        .output
                        .extend_from_slice(&response_length.to_be_bytes());
                    client.output.extend_from_slice(&response);
                    client.output_offset = 0;
                    client.frame_deadline = None;
                    true
                }
                Ok(_) => {
                    drops.record(DropReason::AnswerTooLarge);
                    false
                }
                Err(reason) => {
                    drops.record(reason);
                    client.malformed_frames += 1;
                    if client.malformed_frames >= TCP_MALFORMED_FRAME_LIMIT {
                        return false;
                    }
                    client.frame_deadline = Some(Instant::now() + TCP_MESSAGE_TIMEOUT);
                    true
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => true,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => true,
        Err(_) => false,
    }
}

/// Writes a queued length-prefixed response without blocking the shared DNS worker.
fn write_tcp_response(client: &mut TcpClient) -> bool {
    while client.output_offset < client.output.len() {
        match client.stream.write(&client.output[client.output_offset..]) {
            Ok(0) => return false,
            Ok(length) => {
                client.output_offset += length;
                client.last_activity = Instant::now();
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
            Err(_) => return false,
        }
    }
    client.output.clear();
    client.output_offset = 0;
    client.frame_deadline = Some(Instant::now() + TCP_MESSAGE_TIMEOUT);
    true
}

/// Applies one poll result to a TCP client, preserving a half-closed client's pending answer.
fn service_tcp_client(
    client: &mut TcpClient,
    ready: PollFlags,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
) -> bool {
    if ready.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return false;
    }
    if client.output.is_empty() {
        if ready.contains(PollFlags::POLLIN) && !read_tcp_request(client, records, drops) {
            return false;
        }
    } else if ready.contains(PollFlags::POLLOUT) && !write_tcp_response(client) {
        return false;
    }
    !(ready.contains(PollFlags::POLLHUP) && client.output.is_empty())
}

/// Serves UDP on its own worker so TCP framing and clients cannot delay datagrams.
///
/// Every datagram that gets no reply is counted in `drops`.
fn run_udp_worker(
    sockets: &[UdpSocket],
    shutdown_reader: &UnixStream,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
) {
    let mut query = [0_u8; MAX_PACKET + 1];
    'worker: loop {
        let shutdown_index = sockets.len();
        let mut descriptors = Vec::with_capacity(shutdown_index + 1);
        descriptors.extend(
            sockets
                .iter()
                .map(|socket| PollFd::new(socket.as_fd(), PollFlags::POLLIN)),
        );
        descriptors.push(PollFd::new(shutdown_reader.as_fd(), PollFlags::POLLIN));
        match poll(&mut descriptors, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
        }
        let ready = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or_else(PollFlags::empty))
            .collect::<Vec<_>>();
        drop(descriptors);
        if ready[shutdown_index]
            .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            break;
        }
        for (index, socket) in sockets.iter().enumerate() {
            if !ready[index].contains(PollFlags::POLLIN) {
                continue;
            }
            let (length, source) = match socket.recv_from(&mut query) {
                Ok(result) => result,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(_) => break 'worker,
            };
            if length > MAX_PACKET {
                drops.record(DropReason::Oversized);
                continue;
            }
            let response = {
                let snapshot = records
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                response_for_source(&query[..length], &snapshot, source.ip())
            };
            match response {
                Ok(reply) => {
                    let _ = socket.send_to(&reply, source);
                }
                Err(reason) => drops.record(reason),
            }
        }
    }
}

/// Serves TCP independently, with bounded accepts, reads and per-connection state.
fn run_tcp_worker(
    listeners: &[TcpListener],
    shutdown_reader: &UnixStream,
    records: &Arc<RwLock<Records>>,
    drops: &DropLog,
) {
    let mut clients = Vec::<TcpClient>::new();
    'worker: loop {
        let now = Instant::now();
        clients.retain(|client| !client.expired_at(now));
        let clients_start = listeners.len();
        let polled_client_count = clients.len();
        let shutdown_index = clients_start + polled_client_count;
        let mut descriptors = Vec::with_capacity(shutdown_index + 1);
        descriptors.extend(
            listeners
                .iter()
                .map(|listener| PollFd::new(listener.as_fd(), PollFlags::POLLIN)),
        );
        descriptors.extend(clients.iter().map(|client| {
            let flags = if client.output.is_empty() {
                PollFlags::POLLIN
            } else {
                PollFlags::POLLOUT
            };
            PollFd::new(client.stream.as_fd(), flags)
        }));
        descriptors.push(PollFd::new(shutdown_reader.as_fd(), PollFlags::POLLIN));
        match poll(&mut descriptors, tcp_poll_timeout(&clients)) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break 'worker,
        }
        let ready = descriptors
            .iter()
            .map(|descriptor| descriptor.revents().unwrap_or_else(PollFlags::empty))
            .collect::<Vec<_>>();
        drop(descriptors);
        if ready[shutdown_index]
            .intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
        {
            break;
        }
        // One read per ready client per poll turn bounds parser work and lets other clients run.
        for index in (0..polled_client_count).rev() {
            if !service_tcp_client(
                &mut clients[index],
                ready[clients_start + index],
                records,
                drops,
            ) {
                clients.swap_remove(index);
            }
        }
        for (index, listener) in listeners.iter().enumerate() {
            if ready[index].contains(PollFlags::POLLIN)
                && accept_tcp_connections(listener, &mut clients, drops).is_err()
            {
                break 'worker;
            }
        }
        // The poll can return immediately while hostile TCP clients stay ready.
        thread::yield_now();
    }
}

/// The mesh DNS server of one node.
///
/// By default it listens on UDP and TCP port [`DNS_PORT`] of the node's mesh IPv4 address, with separate
/// `mesh-dns-udp` and `mesh-dns-tcp` workers. TCP clients have bounded connection state and share
/// the UDP source-privacy rules. Queries from another source receive the same NXDOMAIN as an
/// absent name, and names outside the mesh zones receive `REFUSED` (see [`response`]). Names can be replaced while it runs; each query sees a whole
/// snapshot, never a half-updated one. Dropping the resolver stops both workers and waits for them.
pub struct Resolver {
    address: Ipv4Addr,
    records: Arc<RwLock<Records>>,
    udp_shutdown: UnixStream,
    tcp_shutdown: UnixStream,
    udp_worker: Option<JoinHandle<()>>,
    tcp_worker: Option<JoinHandle<()>>,
}

impl Resolver {
    /// Starts serving the names in `config` on the node's mesh address.
    ///
    /// # Errors
    /// Fails if the names are invalid, if the port is already in use, or if the
    /// mesh address is not available on this host yet.
    pub fn bind(config: &Config) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        Self::bind_records(config.addresses.ipv4, records, false)
    }

    /// Serves the snapshot through already-bound UDP and TCP sockets, taking ownership of both.
    ///
    /// Callers may bind each protocol to port zero and read its assigned destination before
    /// handing it over. Ports may differ; both sockets must use the snapshot's mesh IPv4 address.
    /// No socket is closed and rebound, so a concurrent listener cannot steal a reserved port.
    /// This constructor does not add the optional standard-port listeners.
    ///
    /// # Errors
    /// Rejects invalid records or socket addresses that differ from the snapshot's address,
    /// and reports failures configuring the listener or starting either worker.
    pub fn from_sockets(
        config: &Config,
        socket: UdpSocket,
        listener: TcpListener,
    ) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        let address = IpAddr::V4(config.addresses.ipv4);
        if socket.local_addr()?.ip() != address || listener.local_addr()?.ip() != address {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS sockets must bind the configured mesh IPv4 address",
            ));
        }
        Self::serve_sockets(records, socket, listener, None)
    }

    /// Starts serving one node snapshot and, on root Linux nodes, also claims port 53 when free.
    ///
    /// Port 53 is optional because host DNS forwarding can target [`DNS_PORT`] directly. A root
    /// Linux node also offers it as a compatibility listener when the address and port are free.
    /// # Errors
    /// Fails if the high mesh DNS port cannot be bound or the snapshot is invalid.
    pub fn bind_for_node(config: &Config) -> io::Result<Self> {
        let records = Records::from_config(config)?;
        #[cfg(target_os = "linux")]
        {
            Self::bind_records(config.addresses.ipv4, records, system_port_for_node())
        }
        #[cfg(target_os = "macos")]
        {
            Self::bind_records(config.addresses.ipv4, records, false)
        }
    }

    /// Starts serving on `address` with no names, so both protocols and eligible ports are held before publish.
    #[cfg(target_os = "linux")]
    pub(crate) fn bind_empty_for_node(address: Ipv4Addr) -> io::Result<Self> {
        Self::bind_records(address, Records::empty(address), system_port_for_node())
    }

    /// The mesh address the resolver is bound to on Linux.
    #[cfg(target_os = "linux")]
    pub(crate) const fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Binds the UDP and TCP sockets and starts independent protocol workers.
    ///
    /// UDP gets its own poll loop. TCP state is capped by global and per-source connection count,
    /// frame size, whole-message time and idle time; each ready client gets one bounded read per
    /// poll turn. Packets over the size limit and bytes that do not parse get no reply and are
    /// logged (rate-limited); malformed TCP messages also count toward closing that connection.
    fn bind_records(
        address: Ipv4Addr,
        initial: Records,
        try_system_port: bool,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from((address, DNS_PORT)))?;
        let listener = TcpListener::bind(SocketAddr::from((address, DNS_PORT)))?;
        #[cfg(target_os = "linux")]
        let system_pair = if try_system_port {
            match (
                UdpSocket::bind(SocketAddr::from((address, DNS_SYSTEM_PORT))),
                TcpListener::bind(SocketAddr::from((address, DNS_SYSTEM_PORT))),
            ) {
                (Ok(system_socket), Ok(system_listener))
                    if system_listener.set_nonblocking(true).is_ok() =>
                {
                    Some((system_socket, system_listener))
                }
                _ => None,
            }
        } else {
            None
        };
        #[cfg(target_os = "macos")]
        let system_pair = {
            let _ = try_system_port;
            None::<(UdpSocket, TcpListener)>
        };
        Self::serve_sockets(initial, socket, listener, system_pair)
    }

    /// Starts workers with continuous ownership of all bound sockets and joins them on shutdown.
    fn serve_sockets(
        initial: Records,
        socket: UdpSocket,
        listener: TcpListener,
        system_pair: Option<(UdpSocket, TcpListener)>,
    ) -> io::Result<Self> {
        let address = initial.local_address();
        listener.set_nonblocking(true)?;
        let mut worker_sockets = vec![socket];
        let mut worker_listeners = vec![listener];
        if let Some((system_socket, system_listener)) = system_pair {
            worker_sockets.push(system_socket);
            worker_listeners.push(system_listener);
        }
        let (mut udp_shutdown, udp_shutdown_reader) = UnixStream::pair()?;
        let (tcp_shutdown, tcp_shutdown_reader) = UnixStream::pair()?;
        let records = Arc::new(RwLock::new(initial));
        // One drop log for both workers, so its rate limit covers the whole resolver.
        let drops = Arc::new(DropLog::default());
        let udp_records = Arc::clone(&records);
        let udp_drops = Arc::clone(&drops);
        let udp_worker = thread::Builder::new()
            .name("mesh-dns-udp".to_owned())
            .spawn(move || {
                run_udp_worker(
                    &worker_sockets,
                    &udp_shutdown_reader,
                    &udp_records,
                    &udp_drops,
                );
            })?;
        let tcp_records = Arc::clone(&records);
        let tcp_worker = match thread::Builder::new()
            .name("mesh-dns-tcp".to_owned())
            .spawn(move || {
                run_tcp_worker(
                    &worker_listeners,
                    &tcp_shutdown_reader,
                    &tcp_records,
                    &drops,
                );
            }) {
            Ok(worker) => worker,
            Err(error) => {
                let _ = udp_shutdown.write(&[0]);
                let _ = udp_worker.join();
                return Err(error);
            }
        };
        Ok(Self {
            address,
            records,
            udp_shutdown,
            tcp_shutdown,
            udp_worker: Some(udp_worker),
            tcp_worker: Some(tcp_worker),
        })
    }

    /// Swaps in the names of a newly accepted snapshot. Takes effect for the
    /// next query.
    ///
    /// # Errors
    /// Rejects malformed names, references to absent peers and duplicate
    /// names, and returns `Unsupported` if the node's mesh address changed:
    /// that needs a new resolver. The old names stay active on error.
    pub fn replace(&self, config: &Config) -> io::Result<()> {
        if config.addresses.ipv4 != self.address {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mesh DNS address changes require resolver replacement",
            ));
        }
        let next = Records::from_config(config)?;
        *self
            .records
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        Ok(())
    }

    /// Swaps in records that are already validated.
    pub(crate) fn publish(&self, records: Records) {
        *self
            .records
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = records;
    }
}

/// Root Linux nodes also offer the optional port 53 compatibility listener.
#[cfg(target_os = "linux")]
fn system_port_for_node() -> bool {
    nix::unistd::Uid::effective().is_root()
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // The independent pipes wake both poll loops without touching DNS sockets.
        let _ = self.udp_shutdown.write(&[0]);
        let _ = self.tcp_shutdown.write(&[0]);
        if let Some(worker) = self.udp_worker.take() {
            let _ = worker.join();
        }
        if let Some(worker) = self.tcp_worker.take() {
            let _ = worker.join();
        }
    }
}

/// Checks the host resolver's rate limit for reporting dropped queries.
#[cfg(test)]
mod source_tests {
    use super::*;

    /// The first drop is logged at once; drops inside the interval are counted and reported by
    /// the first line after it, so a flood writes one line a minute.
    #[test]
    fn drop_log_reports_the_first_drop_then_one_count_per_interval() {
        let log = DropLog::default();
        let start = Instant::now();
        assert_eq!(log.note(start), Some(1));
        for second in 1..=59 {
            assert_eq!(log.note(start + Duration::from_secs(second)), None);
        }
        assert_eq!(log.note(start + DROP_LOG_INTERVAL), Some(60));
        assert_eq!(log.note(start + DROP_LOG_INTERVAL), None);
    }
}
