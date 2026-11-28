//! Bind the device's UDP sockets and share admission across their receive halves.

use crate::handshake_admission::{PeerAdmission, PeerAdmissionUdpReceiver};
use gotatun::{
    udp::{
        UdpTransportFactory, UdpTransportFactoryParams,
        socket::{UdpSocket as GotaUdpSocket, UdpSocketFactory},
    },
    x25519::StaticSecret,
};
use std::{io, sync::Arc};
use tokio::sync::RwLock;

/// Holds the already-bound UDP sockets and the live handshake admission state for `GotaTun`.
///
/// Every receive half it hands out runs the shared admission guard (J555 F2), so an initiation
/// from a key this Mac has not installed gets no reply, the same as on Linux. Clones share the
/// listener and the guard.
#[derive(Clone)]
pub struct BoundUdpFactory {
    /// The bound socket used to send encrypted packets.
    pub send: GotaUdpSocket,
    receive: GotaUdpSocket,
    port: u16,
    /// The admission table shared by the device and the worker.
    pub admission: Arc<RwLock<PeerAdmission>>,
}

impl BoundUdpFactory {
    /// Wrap sockets that already own their UDP port.
    #[must_use]
    pub fn from_bound(
        send: GotaUdpSocket,
        receive: GotaUdpSocket,
        port: u16,
        admission: Arc<RwLock<PeerAdmission>>,
    ) -> Self {
        Self {
            send,
            receive,
            port,
            admission,
        }
    }

    /// Bind the Mac node's direct-path probes to this factory's send socket and give the admission
    /// guard its half, as the Linux engine does (#220, D185, J1194).
    ///
    /// Without this the guard has no probes, so a probe-shaped datagram would reach `GotaTun` as
    /// garbage and no ping would ever be answered: a Linux peer measuring its direct path to this
    /// Mac would see a peer that never answers. With it the guard consumes pings from known peer
    /// endpoints (at most 64 pongs a second) and sends nothing on its own, so an idle Mac gains no
    /// wakeups (D81). The Mac has no path owner yet, so the finished answers go nowhere: the
    /// receiver is dropped and the probes never start a round of their own.
    async fn with_probes(
        send: GotaUdpSocket,
        receive: GotaUdpSocket,
        port: u16,
        admission: Arc<RwLock<PeerAdmission>>,
    ) -> Self {
        let (probes, _answers) =
            crate::direct_probe::DirectProbes::new(send.clone(), crate::direct_probe::token_seed());
        admission.write().await.set_probes(probes);
        Self {
            send,
            receive,
            port,
            admission,
        }
    }
}

impl UdpTransportFactory for BoundUdpFactory {
    type Send = GotaUdpSocket;
    type Recv = PeerAdmissionUdpReceiver;

    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl std::future::Future<Output = io::Result<(Self::Send, Self::Recv)>> {
        if params.addr.is_some() || params.port != self.port {
            return std::future::ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        std::future::ready(Ok((
            self.send.clone(),
            PeerAdmissionUdpReceiver::new(self.receive.clone(), Arc::clone(&self.admission)),
        )))
    }

    /// The second socket for small data datagrams (#260, J1211): an ephemeral port beside the mesh
    /// port, with the same family set-up. Its receive half runs the same admission guard as the
    /// main one, so a stranger cannot use the second port to skip it. The direct-path probes stay
    /// on the main socket.
    async fn bind_side(
        &mut self,
        main: &Self::Send,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<Option<(Self::Send, Self::Recv)>> {
        if params.addr.is_some() || params.port != self.port {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let Some((send, receive)) = UdpSocketFactory::default().bind_side(main, params).await?
        else {
            return Ok(None);
        };
        Ok(Some((
            send,
            PeerAdmissionUdpReceiver::new(receive, Arc::clone(&self.admission)),
        )))
    }
}

/// Bind the requested Mac UDP port, using one automatic fallback when that listener is occupied.
///
/// The bound socket remains owned by the worker, and the returned port is persisted and advertised
/// so coordinator peers target the actual listener. An explicit operator override stays exact.
/// The returned factory carries a handshake admission guard for `private_key` with no peers
/// yet; the worker installs its peers before the device receives anything.
/// # Errors
/// Returns socket errors, rejects the reserved kernel `WireGuard` port, or reports allocation failure.
pub async fn bind_udp(
    request: crate::listen_port::Request,
    private_key: StaticSecret,
    mac_connected: bool,
) -> io::Result<(BoundUdpFactory, u16)> {
    if request.port == 51_820 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let admission = Arc::new(RwLock::new(PeerAdmission::new(private_key)));
    // The product's S choice, the same one the worker starts its route listener with.
    let mut factory = UdpSocketFactory {
        mac_connected: Some(mac_connected),
        ..UdpSocketFactory::default()
    };
    if request.port != 0 {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: request.port,
        };
        match factory.bind(&params).await {
            Ok((send, receive)) => {
                let port = send.local_addr()?.port();
                if port == 0 || port == 51_820 {
                    return Err(io::ErrorKind::AddrInUse.into());
                }
                return Ok((
                    BoundUdpFactory::with_probes(send, receive, port, admission).await,
                    port,
                ));
            }
            Err(error) if request.allow_fallback && error.kind() == io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error),
        }
    }
    for _ in 0..16 {
        let params = UdpTransportFactoryParams {
            addr: None,
            port: 0,
        };
        let (send, receive) = factory.bind(&params).await?;
        let port = send.local_addr()?.port();
        if port != 0 && port != 51_820 {
            return Ok((
                BoundUdpFactory::with_probes(send, receive, port, admission).await,
                port,
            ));
        }
    }
    Err(io::ErrorKind::AddrInUse.into())
}
