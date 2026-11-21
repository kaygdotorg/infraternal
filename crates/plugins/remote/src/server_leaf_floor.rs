//! Refuses a server leaf older than the newest one this host has already accepted (#559).
//!
//! The server's leg-B TLS certificate (its "leaf") is reissued from the CA
//! while the CA is unlocked, and each new leaf starts later than the one it
//! replaces. Chain and name verification alone would still accept every
//! older leaf the CA ever signed until it expires, so a copy of an old server
//! state directory could pose as the server. This floor closes that window:
//! after the TLS handshake the infraternal agent compares the presented
//! leaf's `notBefore` with the newest one it has seen, refuses anything
//! older, and remembers anything newer.
//!
//! How to use it: build one [`ServerLeafFloor`] per enrollment, with the
//! enrollment's durable [`ServerLeafStore`], and call
//! [`ServerLeafFloor::admit`] on every verified server leaf before any
//! application byte is sent or read. A leaf with the same `notBefore` as the
//! floor is accepted: that is the current leaf presented again.
//!
//! Invariants:
//! - The in-memory floor only ever rises. A durable write that fails still
//!   raises it in memory, so this process keeps refusing older leaves; the
//!   connection itself is not refused, because a full disk must not take the
//!   host offline. The only loss is that a restart before the next successful
//!   write starts from the older durable value.
//! - The check runs after chain, name and expiry verification, never instead
//!   of them. It adds ordering, not trust.
use openssl::x509::X509;
use std::{
    io,
    sync::{Arc, Mutex},
};

/// Durable storage for the newest accepted server-leaf `notBefore`.
///
/// Implemented by the installation (it knows where enrollment state lives).
/// `remember` is called only when the value rises, which is once per server
/// leaf rotation, so it may write and fsync synchronously.
pub trait ServerLeafStore: Send + Sync {
    /// Persist `not_before` (Unix seconds) as the newest accepted server leaf.
    /// # Errors
    /// Storage failure. The caller keeps the raised value in memory.
    fn remember(&self, not_before: i64) -> io::Result<()>;
}

/// The newest server leaf this host has accepted, shared by every dial path
/// (QUIC, TCP/TLS fallback, mesh paths and certificate recovery).
pub struct ServerLeafFloor {
    /// Newest accepted `notBefore`, in Unix seconds. `i64::MIN` means none yet.
    newest: Mutex<i64>,
    /// Where a raised floor is persisted; `None` keeps it in memory only.
    store: Option<Arc<dyn ServerLeafStore>>,
}

impl Default for ServerLeafFloor {
    /// A floor with no history and no storage: the first leaf sets it. Used by
    /// tests and by callers that have no enrollment state directory.
    fn default() -> Self {
        Self {
            newest: Mutex::new(i64::MIN),
            store: None,
        }
    }
}

impl ServerLeafFloor {
    /// Start from the durable value `newest` (or `None` when nothing was
    /// recorded yet) and persist every raise through `store`.
    #[must_use]
    pub fn new(newest: Option<i64>, store: Arc<dyn ServerLeafStore>) -> Self {
        Self {
            newest: Mutex::new(newest.unwrap_or(i64::MIN)),
            store: Some(store),
        }
    }

    /// The newest accepted `notBefore`, if any leaf was accepted yet.
    #[must_use]
    pub fn newest(&self) -> Option<i64> {
        self.newest
            .lock()
            .ok()
            .map(|newest| *newest)
            .filter(|newest| *newest != i64::MIN)
    }

    /// Accept `leaf` if it is not older than the newest accepted leaf, and
    /// raise the floor when it is newer.
    /// # Errors
    /// `InvalidData` for an older leaf, an unreadable `notBefore` or a
    /// poisoned lock. The message names no certificate detail. The kind is
    /// deliberately not `PermissionDenied`: that kind means "the server
    /// refused this host's identity" and starts certificate recovery and the
    /// predecessor fallback, which a stale server must not trigger.
    pub fn admit(&self, leaf: &X509) -> io::Result<()> {
        let not_before = not_before_seconds(leaf)?;
        let mut newest = self.newest.lock().map_err(|_| refused())?;
        if not_before < *newest {
            return Err(refused());
        }
        if not_before > *newest {
            *newest = not_before;
            if let Some(store) = &self.store {
                // See the module invariants: storage failure keeps the raised
                // in-memory floor and does not refuse a verified, newer leaf.
                let _ = store.remember(not_before);
            }
        }
        Ok(())
    }

    /// Check the verified server leaf of an established QUIC connection.
    /// # Errors
    /// No usable peer certificate, or the refusals of [`Self::admit`].
    pub fn admit_quic(&self, connection: &quinn::Connection) -> io::Result<()> {
        self.admit(&crate::remote_quic::peer_leaf(connection).map_err(|_| refused())?)
    }
}

/// A leaf's `notBefore` as Unix seconds.
/// # Errors
/// Times before 1970 or outside `i64` are refused.
pub fn not_before_seconds(leaf: &X509) -> io::Result<i64> {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).map_err(|_| refused())?;
    let difference = epoch.diff(leaf.not_before()).map_err(|_| refused())?;
    let seconds = i64::from(difference.days)
        .checked_mul(86_400)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or_else(refused)?;
    if seconds < 0 {
        return Err(refused());
    }
    Ok(seconds)
}

/// The one refusal this module returns; it says nothing about the leaf.
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "remote infraternal server certificate refused",
    )
}

/// Tests for leaf ordering and persistence.
#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, x509::X509NameBuilder};

    /// A self-signed certificate whose only meaningful field is `notBefore`.
    fn leaf(not_before: i64) -> X509 {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "leaf").unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::from_unix(not_before).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(not_before + 86_400).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::null()).unwrap();
        builder.build()
    }

    /// Records every persisted value, and can be told to fail.
    #[derive(Default)]
    struct Recorder {
        values: Mutex<Vec<i64>>,
        fail: bool,
    }
    impl ServerLeafStore for Recorder {
        fn remember(&self, not_before: i64) -> io::Result<()> {
            self.values.lock().unwrap().push(not_before);
            if self.fail {
                Err(io::Error::other("storage unavailable"))
            } else {
                Ok(())
            }
        }
    }

    /// Newer and equal leaves pass; an older one is refused once a newer one was seen.
    #[test]
    fn older_leaf_is_refused_after_a_newer_one() {
        let floor = ServerLeafFloor::default();
        assert_eq!(floor.newest(), None);
        floor.admit(&leaf(1_800_000_000)).unwrap();
        floor.admit(&leaf(1_800_000_000)).unwrap();
        floor.admit(&leaf(1_800_086_400)).unwrap();
        assert_eq!(floor.newest(), Some(1_800_086_400));
        let error = floor.admit(&leaf(1_800_000_000)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(floor.newest(), Some(1_800_086_400));
    }

    /// Only a rise is persisted, and the durable start value is honoured.
    #[test]
    fn durable_floor_starts_from_storage_and_records_only_rises() {
        let store = Arc::new(Recorder::default());
        let floor = ServerLeafFloor::new(Some(1_800_000_000), store.clone());
        assert!(floor.admit(&leaf(1_799_999_999)).is_err());
        floor.admit(&leaf(1_800_000_000)).unwrap();
        floor.admit(&leaf(1_800_000_100)).unwrap();
        floor.admit(&leaf(1_800_000_100)).unwrap();
        assert_eq!(*store.values.lock().unwrap(), vec![1_800_000_100]);
    }

    /// A failed write keeps the raised floor in memory and still accepts the newer leaf.
    #[test]
    fn storage_failure_keeps_the_raised_floor_in_memory() {
        let store = Arc::new(Recorder {
            fail: true,
            ..Recorder::default()
        });
        let floor = ServerLeafFloor::new(None, store);
        floor.admit(&leaf(1_800_000_100)).unwrap();
        assert!(floor.admit(&leaf(1_800_000_000)).is_err());
    }
}
