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

/// Most hosts that may hold a parked fallback connection at once.
const MAX_PARKED: usize = 1000;

/// Set of hosts that currently have a parked connection. A host can hold at most one.
#[derive(Default)]
pub(crate) struct Slots(Mutex<HashSet<Uuid>>);

/// Proof that a host holds its slot. Dropping it frees the slot.
pub(crate) struct Parking {
    /// Table the slot is returned to on drop.
    slots: Arc<Slots>,
    host: Uuid,
}
impl Drop for Parking {
    /// Frees this host's slot.
    fn drop(&mut self) {
        self.slots
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.host);
    }
}
impl Slots {
    /// Claims the slot for `host`. Fails with `WouldBlock` if that host already has one or the table is full.
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
    /// Revocation and ledger checks for the connected host, kept for the whole parked lifetime.
    pub(crate) authority: AuthorityGuard,
    /// Handshake permits, returned as soon as the connection is admitted so a parked one does not hold them.
    permits: Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)>,
    /// Shared slot table the connection will park in.
    slots: Arc<Slots>,
    /// Set once a native-priming hello succeeded; keeps the slot until the connection is promoted or dropped.
    pub(crate) priming: Option<Priming>,
}

/// A primed connection keeps its identity slot until actor promotion or drop.
pub(crate) struct Priming {
    _parking: Parking,
    /// Sends the signal that promotes the primed connection to the active one. Taken at most once.
    pub(crate) activation: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

pub(crate) use crate::remote_standby_request::{activation, wants_prime};

impl Admission {
    /// Starts an admission from the checked `authority`, the handshake `permits` and the shared `slots`.
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
                                | if prime { infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS } else { 0 }
                                | if channel.native_stream_id().is_some() { infraternal_plugin_api::channel::REMOTE_PATH_BACKUP | infraternal_plugin_api::channel::REMOTE_PATH_PROOF } else { 0 },
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
    //! Checks strict parking admission and cancellation ownership before actor polling.
    use super::*;
    #[test]
    fn cancelled_queue_admission_releases_parking_before_actor_poll() {
        let slots = Arc::new(Slots::default());
        let host = Uuid::new_v4();
        let (activation, receiver) = tokio::sync::oneshot::channel();
        let state = Arc::new(Mutex::new(Some(Priming {
            _parking: slots.reserve(host).unwrap(),
            activation: Mutex::new(Some(activation)),
        })));
        let queued = state.clone();
        drop(crate::remote_link::PrimingAdmission {
            state,
            connection: None,
            admitted: false,
        });
        assert!(queued.lock().unwrap().is_none());
        assert!(slots.reserve(host).is_ok());
        assert!(receiver.blocking_recv().is_err());
    }

    #[test]
    fn bounded_standby_options_reject_ambiguous_or_unrecognized_fields() {
        assert!(!wants_prime(b"{}").unwrap());
        assert!(!wants_prime(br#"{"prime":false}"#).unwrap());
        assert!(wants_prime(br#"{"prime":true}"#).unwrap());
        for malformed in [
            br#"{"prime":true,"prime":false}"#.as_slice(),
            br#"{"prime":true,"writer":2}"#,
            br#"{"prime":1}"#,
            br"[]",
            br"{}{}",
        ] {
            assert!(wants_prime(malformed).is_err());
        }
        let mut oversized = br#"{"prime":true}"#.to_vec();
        oversized.resize(65, b' ');
        assert!(wants_prime(&oversized).is_err());
    }

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
