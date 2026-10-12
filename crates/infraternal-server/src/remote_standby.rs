//! Parks one ledger-admitted fallback per host without retaining handshake permits or replacing the active terminal actor [128,198,215], #129.
use crate::remote_guard::AuthorityGuard;
use infraternal_agent::{
    channel::Channel,
    transport::{Receive, Transmit},
};
use infraternal_protocol::{Frame, encode_muxed_frame_into};
use std::{
    collections::HashSet,
    io,
    sync::{Arc, Mutex},
};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

const MAX_PARKED: usize = 1000;

#[derive(Default)]
pub(crate) struct Slots(Mutex<HashSet<Uuid>>);

pub(crate) struct Parking {
    slots: Arc<Slots>,
    host: Uuid,
}
impl Drop for Parking {
    fn drop(&mut self) {
        self.slots
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.host);
    }
}
impl Slots {
    fn reserve(self: &Arc<Self>, host: Uuid) -> io::Result<Parking> {
        let mut slots = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots.len() >= MAX_PARKED || !slots.insert(host) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(Parking {
            slots: self.clone(),
            host,
        })
    }
}

/// Handshake ownership transfers to a bounded identity slot only after admission.
pub(crate) struct Admission {
    pub(crate) authority: AuthorityGuard,
    permits: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
    slots: Arc<Slots>,
    pub(crate) priming: Option<Priming>,
}

/// A primed connection keeps its identity slot until actor promotion or drop.
pub(crate) struct Priming {
    _parking: Parking,
    pub(crate) activation: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

pub(crate) use crate::remote_standby_request::{activation, wants_prime};

impl Admission {
    pub(crate) fn new(
        authority: AuthorityGuard,
        permits: (OwnedSemaphorePermit, OwnedSemaphorePermit),
        slots: Arc<Slots>,
    ) -> Self {
        Self {
            authority,
            permits: Some(permits),
            slots,
            priming: None,
        }
    }

    /// Basic parking owns no actor/terminal; native priming transfers its slot
    /// into the same host actor. Both retain revocation and ledger checks.
    pub(crate) async fn hello<C: Channel>(
        &mut self,
        channel: &C,
        receive: &mut Receive,
        prime: bool,
    ) -> io::Result<Vec<u8>> {
        if prime && channel.native_stream_id().is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let parking = self.slots.reserve(self.authority.identity.host)?;
        self.authority.admit_operation().await?;
        self.permits.take();
        {
            let _permit = self.authority.write_permit().await?;
            tokio::select! {
                biased;
                () = self.authority.cancelled() => return Err(io::ErrorKind::PermissionDenied.into()),
                sent = async {
                let mut transmit = Transmit::default();
                transmit
                    .send(
                        channel,
                        0,
                        &Frame::Result {
                            call_id: 0,
                            ok: true,
                            json: b"{}",
                        },
                    )
                    .await?;
                transmit
                    .send(
                        channel,
                        0,
                        &Frame::Hello {
                            version: 1,
                            caps: infraternal_plugin_api::channel::REMOTE_WRITER_BINDING
                                | infraternal_plugin_api::channel::REMOTE_STANDBY
                                | if prime { infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS } else { 0 },
                            client_info: "infraternal server",
                        },
                    )
                    .await?;
                    Ok::<(), io::Error>(())
                } => sent?,
            }
        }
        let mut prefix = Vec::new();
        tokio::select! {
            biased;
            () = self.authority.cancelled() => return Err(io::ErrorKind::PermissionDenied.into()),
            hello = receive.next(channel) => {
                let hello = hello?;
                if hello.stream_id != 0 || !matches!(hello.frame, Frame::Hello { version: 1, caps, .. } if !prime || caps & infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS != 0) {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                encode_muxed_frame_into(0, &hello.frame, &mut prefix).map_err(io::Error::other)?;
            }
        }
        self.authority.admit_operation().await?;
        if prime {
            self.priming = Some(Priming {
                _parking: parking,
                activation: Mutex::new(None),
            });
        }
        Ok(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parking_is_per_identity_bounded_and_released_on_drop() {
        let slots = Arc::new(Slots::default());
        let mut parked = Vec::new();
        for _ in 0..MAX_PARKED {
            parked.push(slots.reserve(Uuid::new_v4()).unwrap());
        }
        assert!(slots.reserve(parked[0].host).is_err());
        assert!(slots.reserve(Uuid::new_v4()).is_err());
        let first = parked.remove(0).host;
        let again = slots.reserve(first).unwrap();
        assert_eq!(slots.0.lock().unwrap().len(), MAX_PARKED);
        drop(again);
        assert_eq!(slots.0.lock().unwrap().len(), MAX_PARKED - 1);
    }
}
