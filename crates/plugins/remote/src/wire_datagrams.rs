//! Shares one lazy QUIC datagram read among admitted plugin lanes without an idle task [D198,D232].
use bytes::Bytes;
use infraternal_plugin_api::{
    Operation,
    datagrams::{AdmissionError, DatagramHub, DatagramReceiver, DatagramRetirement},
    streams::{DatagramLane, WireStreamDef},
};
use std::sync::Arc;
use tokio::sync::{Mutex, watch};

/// Metadata only: construction starts no reader, timer or listener. The read
/// mutex lets an active consumer demultiplex packets for all admitted lanes.
/// Cancelling the last consumer drops the sole pending read; there is no task
/// to outlive runtime disable or retain the authenticated connection on its own.
pub struct NativeDatagrams {
    connection: quinn::Connection,
    hub: DatagramHub,
    read: Mutex<()>,
}
impl NativeDatagrams {
    /// Creates the demultiplexer for `connection`. It starts no task; packets are read only while some lane is waiting for one.
    #[must_use]
    pub fn new(connection: quinn::Connection) -> Arc<Self> {
        Arc::new(Self {
            connection,
            hub: DatagramHub::default(),
            read: Mutex::new(()),
        })
    }
    /// Call only after reliable binding and immutable host authority admission.
    /// Packet contents cannot create a lane or choose its identity.
    /// # Errors
    /// Refuses unsupported datagrams, duplicate routes and bounded capacity.
    pub fn admit(
        self: &Arc<Self>,
        definition: &'static WireStreamDef,
        identity: [u8; 16],
    ) -> Result<Arc<dyn DatagramLane>, AdmissionError> {
        if self.connection.max_datagram_size().is_none() {
            return Err(AdmissionError::Invalid);
        }
        let receive = self.hub.register(definition, identity)?;
        let retirement = receive.retirement();
        Ok(Arc::new(Lane {
            transport: Arc::clone(self),
            receive: Mutex::new(receive),
            definition,
            identity,
            retirement,
            retired: watch::channel(false).0,
        }))
    }
    /// Reads one datagram from the connection and hands it to the lane it belongs to. Only one reader runs at a time.
    async fn read_packet(&self) -> Result<(), ()> {
        // QUIC's read_datagram consumes one complete packet or waits. It has no
        // partial packet progress to lose when a consumer wins the select below.
        let _read = self.read.lock().await;
        let packet = self.connection.read_datagram().await.map_err(|_| ())?;
        self.hub.push(packet);
        Ok(())
    }
}
/// One admitted datagram lane: a fixed stream definition and 16-byte identity on the shared connection.
struct Lane {
    transport: Arc<NativeDatagrams>,
    receive: Mutex<DatagramReceiver>,
    definition: &'static WireStreamDef,
    identity: [u8; 16],
    retirement: DatagramRetirement,
    retired: watch::Sender<bool>,
}
impl DatagramLane for Lane {
    /// Ends the lane. Pending and later sends and receives fail.
    fn retire(&self) {
        self.retired.send_replace(true);
        self.retirement.retire();
    }
    /// Waits for the next datagram addressed to this lane. Fails if the lane is retired or the connection closes.
    fn receive(&self) -> Operation<'_, Result<Bytes, ()>> {
        Box::pin(async {
            let mut retired = self.retired.subscribe();
            if *retired.borrow() {
                return Err(());
            }
            let mut receive = self.receive.lock().await;
            loop {
                tokio::select! { biased;
                    _ = retired.changed() => return Err(()),
                    packet = receive.receive() => return packet.ok_or(()),
                    result = self.transport.read_packet() => result?,
                }
            }
        })
    }
    /// Sends one datagram. Refused unless it fits the connection's maximum, and carries this lane's own identity, so a lane cannot send as another.
    fn send<'a>(&'a self, packet: &'a [u8]) -> Operation<'a, Result<(), ()>> {
        Box::pin(async move {
            let mut retired = self.retired.subscribe();
            if self
                .max_payload()
                .is_none_or(|maximum| packet.len() > maximum)
                || self
                    .definition
                    .datagram_identity
                    .is_none_or(|decode| decode(packet) != Some(self.identity))
            {
                return Err(());
            }
            tokio::select! { biased;
                _ = retired.changed() => Err(()),
                result = self.transport
                .connection
                .send_datagram_wait(Bytes::copy_from_slice(packet))
                => result.map_err(|_| ()),
            }
        })
    }
    /// Largest datagram payload the connection currently accepts; `None` after retirement or if datagrams are unsupported.
    fn max_payload(&self) -> Option<usize> {
        if *self.retired.borrow() {
            None
        } else {
            self.transport.connection.max_datagram_size()
        }
    }
}

#[cfg(test)]
#[path = "wire_datagrams_tests.rs"]
mod tests;
