//! Opt-in, bounded fixture observations. These intentionally add observer cost;
//! they attribute receive progress and never relax the cohort's health checks.
use super::*;
use std::sync::Mutex;

const SAMPLES: usize = 8;
const BINS: usize = 18;

#[derive(Default)]
struct Socket {
    polls: u64,
    ready: u64,
    pending: u64,
    errors: u64,
    datagrams: u64,
    last_us: Option<u64>,
    was_ready: bool,
    after_ready: [u64; BINS],
    after_pending: [u64; BINS],
    sampled: [(u64, u64); SAMPLES],
}
#[derive(Default)]
struct State {
    sockets: [Socket; 2],
    ports: Vec<u16>,
    addresses: Vec<SocketAddr>,
    stages: Vec<serde_json::Value>,
}
pub(super) struct ReceiveDiagnostic {
    origin: std::time::Instant,
    state: Mutex<State>,
}
impl ReceiveDiagnostic {
    pub(super) fn from_environment() -> Option<Arc<Self>> {
        (std::env::var("INFRATERNAL_MESH_RECEIVE_DIAGNOSTIC").as_deref() == Ok("1")).then(|| {
            Arc::new(Self {
                origin: std::time::Instant::now(),
                state: Mutex::new(State::default()),
            })
        })
    }
    fn now(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_micros()).unwrap()
    }
    pub(super) fn server_addresses(&self, addresses: &[SocketAddr]) {
        self.state.lock().unwrap().addresses = addresses.to_vec();
    }
    pub(super) fn sample_ports(&self, addresses: &[SocketAddr]) {
        self.state.lock().unwrap().ports = addresses
            .iter()
            .step_by((CONNECTIONS / SAMPLES).max(1))
            .take(SAMPLES)
            .map(SocketAddr::port)
            .collect();
    }
    pub(super) fn wrap(
        self: &Arc<Self>,
        socket: Arc<dyn AsyncUdpSocket>,
        index: usize,
    ) -> Arc<dyn AsyncUdpSocket> {
        Arc::new(ReceiveSocket {
            socket,
            diagnostic: self.clone(),
            index,
        })
    }
    pub(super) fn received(
        &self,
        index: usize,
        result: &Poll<io::Result<usize>>,
        meta: &[RecvMeta],
    ) {
        let now = self.now();
        let mut state = self.state.lock().unwrap();
        let State { sockets, ports, .. } = &mut *state;
        let socket = &mut sockets[index];
        socket.polls += 1;
        if let Some(previous) = socket.last_us {
            let bin = gap_bin(now.saturating_sub(previous));
            if socket.was_ready {
                socket.after_ready[bin] += 1;
            } else {
                socket.after_pending[bin] += 1;
            }
        }
        socket.last_us = Some(now);
        socket.was_ready = matches!(result, Poll::Ready(Ok(_)));
        match result {
            Poll::Pending => socket.pending += 1,
            Poll::Ready(Err(_)) => socket.errors += 1,
            Poll::Ready(Ok(count)) => {
                socket.ready += 1;
                for packet in &meta[..*count] {
                    let count = if packet.stride == 0 {
                        1
                    } else {
                        packet.len.div_ceil(packet.stride)
                    } as u64;
                    socket.datagrams += count;
                    if let Some(sample) = ports.iter().position(|port| *port == packet.addr.port())
                    {
                        socket.sampled[sample].0 += count;
                        socket.sampled[sample].1 = now;
                    }
                }
            }
        }
    }
    fn snapshot(state: &State, now: u64) -> serde_json::Value {
        let sockets: Vec<_> = state.sockets.iter().enumerate().map(|(index, socket)| serde_json::json!({
            "path":if index == 0 {"enrolled"} else {"mesh"}, "polls":socket.polls,"ready":socket.ready,"pending":socket.pending,"errors":socket.errors,"datagrams":socket.datagrams,
            "last_poll_us":socket.last_us,"previous_poll_ready":socket.was_ready,
            "ready_to_next_poll_gap_bins":socket.after_ready,"pending_to_next_poll_gap_bins":socket.after_pending,
            "sampled_ports":state.ports.iter().enumerate().map(|(index,port)|serde_json::json!({"port":port,"datagrams":socket.sampled[index].0,"last_receive_us":socket.sampled[index].1})).collect::<Vec<_>>()
        })).collect();
        serde_json::json!({"at_us":now,"sockets":sockets})
    }
    pub(super) fn stage(&self, backup: bool, name: &str) {
        let mut state = self.state.lock().unwrap();
        let mut snapshot = Self::snapshot(&state, self.now());
        snapshot["socket_drops"] = serde_json::Value::Array(
            state
                .addresses
                .iter()
                .map(|address| owned_udp_drops(&[*address], &[]))
                .collect(),
        );
        snapshot["backup"] = backup.into();
        snapshot["stage"] = name.into();
        // The fixture has two profiles, each with three boundaries and 31 windows.
        assert!(state.stages.len() < 2 * (WINDOWS + 3));
        state.stages.push(snapshot);
    }
    pub(super) fn watch(
        self: &Arc<Self>,
        index: usize,
        port: u16,
        accepted: &[quinn::Connection],
    ) -> DiagnosticWatch {
        let sampled = self.state.lock().unwrap().ports.contains(&port);
        let server = sampled.then(|| {
            accepted
                .iter()
                .find(|connection| connection.remote_address().port() == port)
                .unwrap()
                .clone()
        });
        let before = server.as_ref().map(|server| {
            let stats = server_stats(server);
            serde_json::json!({"at_us":self.now(),"server":stats,"socket_snapshot":Self::snapshot(&self.state.lock().unwrap(),self.now())})
        });
        DiagnosticWatch {
            diagnostic: self.clone(),
            index,
            port,
            server,
            before,
        }
    }
    pub(super) fn report(&self) -> serde_json::Value {
        let state = self.state.lock().unwrap();
        serde_json::json!({"scope":"observer_cost_diagnostic_not_acceptance_CPU","origin":"fixture_start_monotonic_microseconds","gap_bin_upper_exclusive_us":(0..BINS).map(|bin|if bin+1==BINS {u64::MAX} else {1_u64<<bin}).collect::<Vec<_>>(),"limitations":["pending_poll_gaps_can_include_idle_time","raw_ingress_includes_duplicates_and_ACK_only_packets","failure_connection_stats_sampled_outside_UDP_callbacks","snapshots_add_observer_cost"],"stages":state.stages})
    }
}
fn gap_bin(gap: u64) -> usize {
    usize::try_from(gap.bit_width()).unwrap().min(BINS - 1)
}

pub(super) struct DiagnosticWatch {
    diagnostic: Arc<ReceiveDiagnostic>,
    index: usize,
    port: u16,
    server: Option<quinn::Connection>,
    before: Option<serde_json::Value>,
}
impl DiagnosticWatch {
    pub(super) fn failure(self) -> serde_json::Value {
        let now = self.diagnostic.now();
        let mut receipt =
            serde_json::json!({"at_us":now,"connection":self.index,"local_port":self.port});
        if let Some(server) = self.server {
            // Quinn's connection mutex is acquired only here, never by socket callbacks.
            receipt["server"] = server_stats(&server);
            receipt["guard_start"] = self.before.unwrap();
            receipt["socket_snapshot"] =
                ReceiveDiagnostic::snapshot(&self.diagnostic.state.lock().unwrap(), now);
        }
        receipt
    }
}

#[test]
fn receive_diagnostic_gap_bins_have_explicit_bounds() {
    assert_eq!(gap_bin(0), 0);
    assert_eq!(gap_bin(1), 1);
    assert_eq!(gap_bin(2), 2);
    assert_eq!(gap_bin(131_071), 17);
    assert_eq!(gap_bin(u64::MAX), 17);
}

#[test]
fn receive_diagnostic_counts_gro_and_only_fixed_sampled_ports() {
    let diagnostic = ReceiveDiagnostic {
        origin: std::time::Instant::now(),
        state: Mutex::new(State::default()),
    };
    diagnostic.sample_ports(&["127.0.0.3:1234".parse().unwrap()]);
    let meta = [RecvMeta {
        addr: "127.0.0.3:1234".parse().unwrap(),
        len: 25,
        stride: 10,
        ..RecvMeta::default()
    }];
    diagnostic.received(1, &Poll::Ready(Ok(1)), &meta);
    diagnostic.received(1, &Poll::Pending, &[]);
    diagnostic.stage(true, "before");
    let report = diagnostic.report();
    let socket = &report["stages"][0]["sockets"][1];
    assert_eq!(socket["datagrams"], 3);
    assert_eq!(socket["polls"], 2);
    assert_eq!(socket["ready"], 1);
    assert_eq!(socket["pending"], 1);
    assert_eq!(socket["sampled_ports"][0]["datagrams"], 3);
    assert_eq!(
        socket["ready_to_next_poll_gap_bins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .sum::<u64>(),
        1
    );
    assert_eq!(report["stages"][0]["sockets"][0]["polls"], 0);
}

fn server_stats(server: &quinn::Connection) -> serde_json::Value {
    let stats = server.stats();
    serde_json::json!({"udp_rx_datagrams":stats.udp_rx.datagrams,"udp_tx_datagrams":stats.udp_tx.datagrams,"rx_acks":stats.frame_rx.acks,"rx_datagrams":stats.frame_rx.datagram,"tx_acks":stats.frame_tx.acks})
}

/// Only opt-in runs install this extra socket layer. The default counter wrapper
/// keeps its original receive callback and pays no diagnostic branch or clock.
struct ReceiveSocket {
    socket: Arc<dyn AsyncUdpSocket>,
    diagnostic: Arc<ReceiveDiagnostic>,
    index: usize,
}
impl fmt::Debug for ReceiveSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiveSocket")
            .finish_non_exhaustive()
    }
}
impl AsyncUdpSocket for ReceiveSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.socket.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        self.socket.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let result = self.socket.poll_recv(cx, bufs, meta);
        self.diagnostic.received(self.index, &result, meta);
        result
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.socket.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.socket.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.socket.may_fragment()
    }
}
