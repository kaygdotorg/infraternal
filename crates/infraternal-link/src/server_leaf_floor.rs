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
//! The floor reads `notBefore` straight from the leaf's DER, so it needs no
//! X.509 library and builds for every client (#580). It only ever sees leaves
//! that the TLS stack has already verified, and it takes only the strict
//! forms RFC 5280 requires (and rustls's verifier requires too): DER lengths
//! in minimal form, `UTCTime` or `GeneralizedTime` with seconds and `Z`.
//!
//! Invariants:
//! - The in-memory floor only ever rises. A durable write that fails still
//!   raises it in memory, so this process keeps refusing older leaves; the
//!   connection itself is not refused, because a full disk must not take the
//!   host offline. The only loss is that a restart before the next successful
//!   write starts from the older durable value.
//! - The check runs after chain, name and expiry verification, never instead
//!   of them. It adds ordering, not trust.
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

    /// Accept the leaf certificate `leaf_der` if it is not older than the
    /// newest accepted leaf, and raise the floor when it is newer.
    /// # Errors
    /// `InvalidData` for an older leaf, an unreadable `notBefore` or a
    /// poisoned lock. The message names no certificate detail. The kind is
    /// deliberately not `PermissionDenied`: that kind means "the server
    /// refused this host's identity" and starts certificate recovery and the
    /// predecessor fallback, which a stale server must not trigger.
    pub fn admit(&self, leaf_der: &[u8]) -> io::Result<()> {
        let not_before = not_before_seconds(leaf_der)?;
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
    #[cfg(feature = "quic")]
    pub fn admit_quic(&self, connection: &quinn::Connection) -> io::Result<()> {
        let identity = connection.peer_identity().ok_or_else(refused)?;
        let chain = identity
            .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
            .map_err(|_| refused())?;
        self.admit(chain.first().ok_or_else(refused)?)
    }
}

/// A leaf's `notBefore` as Unix seconds, read from its DER.
/// # Errors
/// A malformed certificate, a time that is not in the strict DER form, or a
/// time before 1970.
pub fn not_before_seconds(leaf_der: &[u8]) -> io::Result<i64> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (certificate, _) = element(leaf_der, SEQUENCE)?;
    // TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber,
    //   signature, issuer, validity, ... }
    let (tbs, _) = element(certificate, SEQUENCE)?;
    let mut rest = tbs;
    if rest.first() == Some(&VERSION) {
        rest = element(rest, VERSION)?.1;
    }
    rest = element(rest, INTEGER)?.1;
    rest = element(rest, SEQUENCE)?.1;
    rest = element(rest, SEQUENCE)?.1;
    // Validity ::= SEQUENCE { notBefore Time, notAfter Time }
    let (validity, _) = element(rest, SEQUENCE)?;
    let seconds = match validity.first() {
        Some(&UTC_TIME) => {
            let (text, _) = element(validity, UTC_TIME)?;
            // RFC 5280 4.1.2.5.1: two-digit years 50-99 are 19xx, 00-49 are 20xx.
            let short = digits(text, 0, 2)?;
            let year = if short >= 50 {
                1900 + short
            } else {
                2000 + short
            };
            civil_seconds(year, text, 2, 13)?
        }
        Some(&GENERALIZED_TIME) => {
            let (text, _) = element(validity, GENERALIZED_TIME)?;
            civil_seconds(digits(text, 0, 4)?, text, 4, 15)?
        }
        _ => return Err(refused()),
    };
    if seconds < 0 {
        return Err(refused());
    }
    Ok(seconds)
}

/// DER tag of a SEQUENCE.
const SEQUENCE: u8 = 0x30;
/// DER tag of an INTEGER (the serial number).
const INTEGER: u8 = 0x02;
/// DER tag of the explicit `[0]` version field.
const VERSION: u8 = 0xa0;
/// DER tag of a `UTCTime`.
const UTC_TIME: u8 = 0x17;
/// DER tag of a `GeneralizedTime`.
const GENERALIZED_TIME: u8 = 0x18;

/// Splits the DER element at the start of `bytes`, which must have tag
/// `tag`, into its contents and whatever follows it. Lengths must be in
/// minimal DER form; the indefinite form and lengths over four bytes are
/// refused, and contents may not run past the input.
fn element(bytes: &[u8], tag: u8) -> io::Result<(&[u8], &[u8])> {
    let (&found, rest) = bytes.split_first().ok_or_else(refused)?;
    if found != tag {
        return Err(refused());
    }
    let (&first, mut rest) = rest.split_first().ok_or_else(refused)?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return Err(refused());
        }
        let (octets, after) = rest.split_at(count);
        rest = after;
        // Minimal form: no leading zero octet, and the long form only for 128 or more.
        if octets[0] == 0 {
            return Err(refused());
        }
        let length = octets
            .iter()
            .fold(0usize, |length, octet| (length << 8) | usize::from(*octet));
        if length < 0x80 {
            return Err(refused());
        }
        length
    };
    if rest.len() < length {
        return Err(refused());
    }
    Ok(rest.split_at(length))
}

/// The decimal number written by `count` ASCII digits at `at` in `text`.
fn digits(text: &[u8], at: usize, count: usize) -> io::Result<i64> {
    let field = text.get(at..at + count).ok_or_else(refused)?;
    field.iter().try_fold(0i64, |value, byte| {
        if byte.is_ascii_digit() {
            Ok(value * 10 + i64::from(byte - b'0'))
        } else {
            Err(refused())
        }
    })
}

/// Seconds since 1970 for `year` and the `MMDDHHMMSSZ` that starts at `at` in
/// `text`, which must be exactly `length` bytes long. Every field is range
/// checked, including the day against the month's length.
fn civil_seconds(year: i64, text: &[u8], at: usize, length: usize) -> io::Result<i64> {
    if text.len() != length || text[length - 1] != b'Z' {
        return Err(refused());
    }
    let month = digits(text, at, 2)?;
    let day = digits(text, at + 2, 2)?;
    let hour = digits(text, at + 4, 2)?;
    let minute = digits(text, at + 6, 2)?;
    let second = digits(text, at + 8, 2)?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(refused()),
    };
    if day < 1 || day > month_days || hour > 23 || minute > 59 || second > 59 {
        return Err(refused());
    }
    // Days from 1970-01-01 in the proleptic Gregorian calendar, counted in
    // 400-year eras that start on 1 March, so the leap day ends each year.
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Ok(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

/// The one refusal this module returns; it says nothing about the leaf.
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "remote infraternal server certificate refused",
    )
}

/// Tests for the DER time reader on hand-built certificate skeletons. The
/// ordering and persistence tests run in `infraternal-plugin-remote`, where
/// real certificates are built, and also compare this reader with OpenSSL's.
#[cfg(test)]
mod tests {
    use super::*;

    /// A DER element with `tag` around `contents`, in minimal length form.
    fn der(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let length = contents.len();
        if length < 0x80 {
            out.push(u8::try_from(length).unwrap());
        } else if length < 0x100 {
            out.extend([0x81, u8::try_from(length).unwrap()]);
        } else {
            out.extend([
                0x82,
                u8::try_from(length >> 8).unwrap(),
                u8::try_from(length & 0xff).unwrap(),
            ]);
        }
        out.extend_from_slice(contents);
        out
    }

    /// A certificate skeleton whose validity starts with the time element `time`.
    fn certificate(time: &[u8], version: bool) -> Vec<u8> {
        let mut tbs = Vec::new();
        if version {
            tbs.extend(der(VERSION, &der(INTEGER, &[2])));
        }
        tbs.extend(der(INTEGER, &[1]));
        tbs.extend(der(SEQUENCE, &[]));
        tbs.extend(der(SEQUENCE, &[0x31, 0x00]));
        let mut validity = time.to_vec();
        validity.extend(der(UTC_TIME, b"491231235959Z"));
        tbs.extend(der(SEQUENCE, &validity));
        let mut certificate = der(SEQUENCE, &tbs);
        certificate.extend(der(SEQUENCE, &[]));
        der(SEQUENCE, &certificate)
    }

    /// Known instants in both time forms, with and without the version field.
    #[test]
    fn reads_both_time_forms() {
        for (time, expected) in [
            (der(UTC_TIME, b"700101000000Z"), 0),
            (der(UTC_TIME, b"270115083000Z"), 1_800_001_800),
            (der(UTC_TIME, b"491231235959Z"), 2_524_607_999),
            (der(UTC_TIME, b"500101000000Z"), -631_152_000),
            (der(GENERALIZED_TIME, b"20500101000000Z"), 2_524_608_000),
            (der(GENERALIZED_TIME, b"20240229120000Z"), 1_709_208_000),
            (der(GENERALIZED_TIME, b"99991231235959Z"), 253_402_300_799),
        ] {
            for version in [false, true] {
                let result = not_before_seconds(&certificate(&time, version));
                if expected < 0 {
                    assert!(result.is_err(), "pre-1970 times are refused");
                } else {
                    assert_eq!(result.unwrap(), expected);
                }
            }
        }
    }

    /// Times outside the strict form and impossible dates are refused.
    #[test]
    fn refuses_loose_or_impossible_times() {
        for time in [
            der(UTC_TIME, b"2701150830Z"),
            der(UTC_TIME, b"270115083000+0100"),
            der(UTC_TIME, b"270115083000"),
            der(UTC_TIME, b"27011508300aZ"),
            der(UTC_TIME, b"271315083000Z"),
            der(UTC_TIME, b"270230083000Z"),
            der(UTC_TIME, b"230229000000Z"),
            der(UTC_TIME, b"270115243000Z"),
            der(UTC_TIME, b"270115086000Z"),
            der(UTC_TIME, b"270115083060Z"),
            der(GENERALIZED_TIME, b"20270115083000.5Z"),
            der(INTEGER, b"270115083000Z"),
        ] {
            assert!(not_before_seconds(&certificate(&time, true)).is_err());
        }
    }

    /// Truncated input, non-minimal and indefinite lengths are refused.
    #[test]
    fn refuses_malformed_der() {
        let good = certificate(&der(UTC_TIME, b"270115083000Z"), true);
        for cut in 0..good.len() {
            assert!(not_before_seconds(&good[..cut]).is_err());
        }
        assert!(element(&[0x30, 0x80, 0x00, 0x00], SEQUENCE).is_err());
        assert!(element(&[0x30, 0x81, 0x05, 0, 0, 0, 0, 0], SEQUENCE).is_err());
        assert!(element(&[0x30, 0x82, 0x00, 0x80], SEQUENCE).is_err());
        assert!(element(&[0x30, 0x85, 1, 0, 0, 0, 0], SEQUENCE).is_err());
        assert_eq!(
            element(&[0x30, 0x01, 7, 9], SEQUENCE).unwrap(),
            (&[7][..], &[9][..])
        );
    }
}
