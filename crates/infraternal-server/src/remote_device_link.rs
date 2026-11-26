//! The server's end of a device's leg-B link (#580, slice 1): admit an
//! iPhone's certificate with the device guard, exchange Hellos, and hold a
//! link that serves nothing.
//!
//! A `device` is a phone that joins the mesh. It has no uid and runs no
//! infraternal agent, so nothing here may ever give it a terminal, a session,
//! a login, host facts, SSH or a mesh action. That is enforced by
//! construction rather than by checks spread over the host code:
//! - the device is admitted only by [`EnrollmentStore::admit_device`], which
//!   returns a [`DeviceAuthority`] (no uid, no mode). The host guard
//!   ([`crate::remote_guard::AuthorityGuard`]) never sees it;
//! - the link is never published into [`crate::remote_runtime::RemoteHosts`],
//!   so no server code that opens terminals, lists sessions or calls host
//!   actions can find it;
//! - after the two Hellos the only frame the device may send is `Ping`, which
//!   gets its `Pong`. Any other frame, any further stream and any datagram
//!   closes the link with [`close::REFUSED`]. Nothing is answered first.
//!
//! What ends a held link, and how promptly:
//! - the device's removal (or any cut of its host in the shared revocation
//!   scope): at once, through the cut signal registered for the link;
//! - the certificate's `notAfter`: at that instant (a timer);
//! - a revocation of the certificate alone (the old certificate after an
//!   identity rotation): within [`RECHECK`], when the next `admit_device`
//!   read fails;
//! - the same device opening a newer link: at once, with [`close::REPLACED`];
//! - a ledger read that fails, or does not answer within [`LEDGER_DEADLINE`]:
//!   the link closes with [`close::UNAVAILABLE`], so that a stuck store can
//!   never keep a revoked device's link and can never look like a revocation.
//!
//! [`close::REVOKED`] is sent only for a cut or for a ledger that answered
//! "no" ([`NotAdmitted`]). The codes and what a device does with them are
//! documented in [`infraternal_link::device::close`].
//!
//! (Tests shorten [`RECHECK`]; its production value is 10 s.)
//!
//! Limits: one live link per device (the newest wins), and at most
//! [`MAX_DEVICE_LINKS`] in all. Before admission a device uses the same
//! handshake lanes and per-source slots as every host; they are released
//! once the Hellos are done.

use crate::{
    enrollment::{DeviceAuthority, EnrollmentError, EnrollmentStore},
    remote_guard::Revocation,
};
use infraternal_agent::{
    remote_native::NativeChannel,
    transport::{Receive, Transmit},
};
use infraternal_link::device::close;
use infraternal_protocol::Frame;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, atomic::AtomicU64},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use uuid::Uuid;

/// How often a held link re-reads the device's admission, to notice a
/// revoked certificate. Removal of the device does not wait for this. One
/// indexed read per device every 10 s is about 1,000 reads a second at the
/// 10,000-link cap. Tests use a short period so they can wait for it.
pub(crate) const RECHECK: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(10)
};

/// How long one ledger read may take (the host path's 5 s) before the server
/// gives up on checking the device.
const LEDGER_DEADLINE: Duration = Duration::from_secs(5);

/// How long a device has, after its handshake, to open the control stream
/// and send its Hello.
const HELLO_DEADLINE: Duration = Duration::from_secs(5);

/// Most device links held at once, across every device.
pub(crate) const MAX_DEVICE_LINKS: usize = 10_000;

/// The uid half of a device link's revocation epoch. A device has no uid;
/// `u32::MAX` is `(uid_t)-1`, which no account can have, so this epoch
/// can never be a host's. Cutting the host (its removal) cuts every epoch
/// with its id, this one included.
pub(crate) const DEVICE_EPOCH_UID: u32 = u32::MAX;

/// The device links currently held, one per device.
#[derive(Default)]
pub(crate) struct DeviceLinks {
    /// Each device's live link: its generation and its connection.
    live: Mutex<HashMap<Uuid, (u64, quinn::Connection)>>,
    /// The next generation; tells a link apart from its replacement.
    next: AtomicU64,
}

impl DeviceLinks {
    /// Hold `connection` as `device`'s link, closing the one it replaces.
    /// Returns the new link's generation, or `None` at the global cap.
    fn insert(&self, device: Uuid, connection: &quinn::Connection) -> Option<u64> {
        let generation = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if live.len() >= MAX_DEVICE_LINKS && !live.contains_key(&device) {
            return None;
        }
        if let Some((_, older)) = live.insert(device, (generation, connection.clone())) {
            older.close(close::REPLACED.into(), b"");
        }
        Some(generation)
    }

    /// Forget `device`'s link if it is still generation `generation`.
    fn remove(&self, device: Uuid, generation: u64) {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if live
            .get(&device)
            .is_some_and(|(held, _)| *held == generation)
        {
            live.remove(&device);
        }
    }

    /// Whether `device` has a held link now.
    #[cfg(test)]
    pub(crate) fn holds(&self, device: Uuid) -> bool {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(&device)
    }

    /// How many device links are held now.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

/// Unix seconds now.
fn unix_now() -> io::Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?;
    i64::try_from(elapsed.as_secs()).map_err(io::Error::other)
}

/// Why a device was not admitted. The device is told which of the two it was,
/// because only one of them says anything about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NotAdmitted {
    /// The ledger answered, or a removal cut the device: it may not link.
    Refused,
    /// The server could not check: the ledger read failed or missed
    /// [`LEDGER_DEADLINE`], or there was no room to watch the link.
    Unavailable,
}

impl NotAdmitted {
    /// The close code that tells the device why its link ends.
    fn close_code(self) -> u32 {
        match self {
            Self::Refused => close::REVOKED,
            Self::Unavailable => close::UNAVAILABLE,
        }
    }
}

/// Admit `fingerprint` as a device now, or say why not.
/// # Errors
/// [`NotAdmitted::Refused`] when the certificate is not a live device's;
/// [`NotAdmitted::Unavailable`] when the ledger could not be read.
pub(crate) async fn admit(
    store: &EnrollmentStore,
    fingerprint: &[u8; 32],
) -> Result<DeviceAuthority, NotAdmitted> {
    let now = unix_now().map_err(|_| NotAdmitted::Unavailable)?;
    store
        .admit_device(fingerprint, now)
        .await
        .map_err(|error| match error {
            EnrollmentError::Denied => NotAdmitted::Refused,
            EnrollmentError::Storage(_) => NotAdmitted::Unavailable,
        })
}

/// [`admit`] under [`LEDGER_DEADLINE`]: a stalled read counts as
/// [`NotAdmitted::Unavailable`], so a stuck store never holds a link open.
/// # Errors
/// As [`admit`].
async fn admit_within(
    store: &EnrollmentStore,
    fingerprint: &[u8; 32],
) -> Result<DeviceAuthority, NotAdmitted> {
    tokio::time::timeout(LEDGER_DEADLINE, admit(store, fingerprint))
        .await
        .unwrap_or(Err(NotAdmitted::Unavailable))
}

/// Register the cut signal for an admitted device, then read the ledger once
/// more (as the host guard does): a removal between `admit` and the
/// registration either shows in this read or finds the signal and cuts it.
/// Without the second read the link would stay up until the next recheck.
/// The read fails closed on [`LEDGER_DEADLINE`].
/// # Errors
/// [`NotAdmitted::Refused`] when the device is cut, no longer admitted, or
/// admitted as something else; [`NotAdmitted::Unavailable`] at the signal cap
/// or when the ledger could not be read.
pub(crate) async fn watch_admitted(
    store: &EnrollmentStore,
    authority: &DeviceAuthority,
    fingerprint: &[u8; 32],
) -> Result<(Arc<Revocation>, tokio::sync::watch::Receiver<bool>), NotAdmitted> {
    let signal = store
        .1
        .register(authority.host, DEVICE_EPOCH_UID)
        .map_err(|_| NotAdmitted::Unavailable)?;
    let mut cut = signal.cut_receiver();
    let live = admit_within(store, fingerprint).await;
    // A cut is a removal in progress, whatever the read managed to say.
    if *cut.borrow_and_update() || live? != *authority {
        return Err(NotAdmitted::Refused);
    }
    Ok((signal, cut))
}

/// Serve one admitted device's link until something ends it (see the module
/// docs). `handshake` holds the connection's handshake lane and source slots;
/// they are released once the Hellos are done. The connection is always
/// closed when this returns.
/// # Errors
/// The reason the link ended early: a missing or malformed Hello, the cap,
/// or an admission that no longer stands (`PermissionDenied`) or could not be
/// checked (`WouldBlock`).
pub(crate) async fn serve<H: Send>(
    connection: quinn::Connection,
    authority: DeviceAuthority,
    fingerprint: [u8; 32],
    store: EnrollmentStore,
    links: Arc<DeviceLinks>,
    handshake: H,
) -> io::Result<()> {
    let (signal, mut cut) = match watch_admitted(&store, &authority, &fingerprint).await {
        Ok(watched) => watched,
        Err(reason) => {
            connection.close(reason.close_code().into(), b"");
            return Err(match reason {
                NotAdmitted::Refused => io::ErrorKind::PermissionDenied,
                NotAdmitted::Unavailable => io::ErrorKind::WouldBlock,
            }
            .into());
        }
    };
    let (control, mut receive) = match hello(&connection).await {
        Ok(opened) => opened,
        Err(error) => {
            connection.close(close::REFUSED.into(), b"");
            return Err(error);
        }
    };
    let Some(generation) = links.insert(authority.host, &connection) else {
        connection.close(close::REFUSED.into(), b"");
        return Err(io::ErrorKind::WouldBlock.into());
    };
    drop(handshake);
    let code = hold(
        &connection,
        &control,
        &mut receive,
        &mut cut,
        &authority,
        &fingerprint,
        &store,
    )
    .await;
    if let Some(code) = code {
        connection.close(code.into(), b"");
    }
    links.remove(authority.host, generation);
    drop(signal);
    Ok(())
}

/// Accept control stream 0 and read the device's version-1 Hello, then send
/// the server's: version 1, no capabilities.
async fn hello(connection: &quinn::Connection) -> io::Result<(NativeChannel, Receive)> {
    tokio::time::timeout(HELLO_DEADLINE, async {
        let (send, receive) = connection.accept_bi().await.map_err(io::Error::other)?;
        let control = NativeChannel::control(send, receive)?;
        let mut receive = Receive::default();
        let first = receive.next(&control).await?;
        if first.stream_id != 0 || !matches!(first.frame, Frame::Hello { version: 1, .. }) {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Transmit::default()
            .send(
                &control,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: 0,
                    client_info: "infraternal-server",
                },
            )
            .await?;
        Ok((control, receive))
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Hold the link: answer Pings, refuse everything else, and watch the cut,
/// the certificate's expiry and its admission. Returns the close code, or
/// `None` when the connection ended by itself.
async fn hold(
    connection: &quinn::Connection,
    control: &NativeChannel,
    receive: &mut Receive,
    cut: &mut tokio::sync::watch::Receiver<bool>,
    authority: &DeviceAuthority,
    fingerprint: &[u8; 32],
    store: &EnrollmentStore,
) -> Option<u32> {
    // The expiry instant, to the sub-second: the timer must not fire before
    // the wall clock reaches `notAfter`, nor a second after it. A clock that
    // cannot be read ends the link, since expiry could not be kept.
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return Some(close::EXPIRED);
    };
    let not_after = Duration::from_secs(u64::try_from(authority.not_after).unwrap_or(0));
    let expires = Instant::now() + not_after.saturating_sub(now);
    let mut recheck = tokio::time::interval_at(Instant::now() + RECHECK, RECHECK);
    let mut transmit = Transmit::default();
    loop {
        tokio::select! {
            biased;
            _ = cut.changed() => return Some(close::REVOKED),
            () = tokio::time::sleep_until(expires) => return Some(close::EXPIRED),
            _ = recheck.tick() => {
                if let Err(reason) = admit_within(store, fingerprint).await {
                    // Admission also ends at `notAfter`; name that as expiry.
                    let past_end = unix_now().is_ok_and(|now| now >= authority.not_after);
                    return Some(if past_end { close::EXPIRED } else { reason.close_code() });
                }
            }
            _ = connection.closed() => return None,
            _ = connection.accept_bi() => return Some(close::REFUSED),
            _ = connection.accept_uni() => return Some(close::REFUSED),
            _ = connection.read_datagram() => return Some(close::REFUSED),
            frame = receive.next(control) => {
                let Ok(frame) = frame else { return Some(close::REFUSED) };
                let Frame::Ping { nonce, sent_us } = frame.frame else {
                    return Some(close::REFUSED);
                };
                if transmit
                    .send(control, 0, &Frame::Pong { nonce, sent_us })
                    .await
                    .is_err()
                {
                    return Some(close::REFUSED);
                }
            }
        }
    }
}
