//! Produces public-only CA expiry and lock status for HTTP, the local socket and CLI (#285).

use crate::{ca::CaKeySource, clock_health::ClockHealth};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::{asn1::Asn1Time, hash::MessageDigest, x509::X509};
use serde::{Deserialize, Serialize};

const DAY: i64 = 86_400;
const MAX_TRUST_ROOTS: usize = 2;

/// Public certificate metadata. It contains no signing material or host-specific data.
#[derive(Deserialize, Serialize)]
pub struct RootStatus {
    /// Root generation used by the trust bundle.
    pub generation: u64,
    /// Stable SHA-256 fingerprint of the root DER.
    pub fingerprint: String,
    /// Base64url DER; public trust only.
    pub certificate_der: String,
    /// Root certificate's exclusive expiry as Unix seconds.
    pub not_after: i64,
    /// Remaining server-clock lifetime, unavailable while time is uncertain.
    pub remaining_seconds: Option<i64>,
    /// The nearest configured warning threshold, or `unknown` without a healthy clock.
    pub warning_level: String,
}

/// Public CA state shared by browser status and the same-UID local status path.
#[derive(Deserialize, Serialize)]
pub struct CaStatus {
    /// Whether the server supplied a status source.
    pub available: bool,
    /// Whether retained public trust exists.
    pub initialized: bool,
    /// Signing state; `null` means it could not be read.
    pub locked: Option<bool>,
    /// The server has a clock sample sequence within the accepted bound.
    pub clock_healthy: bool,
    /// Current and next public roots when a source exposes them.
    pub roots: Vec<RootStatus>,
}

impl CaStatus {
    /// An unavailable local status channel is never represented as an unlocked CA.
    #[must_use]
    pub fn unavailable() -> Self {
        Self {
            available: false,
            initialized: false,
            locked: None,
            clock_healthy: false,
            roots: Vec::new(),
        }
    }
}

/// Read only public roots and the lock watch; a missing watch remains unknown.
///
/// # Errors
/// Returns an error if the public root set is ambiguous or certificate metadata is malformed.
pub fn from_source(
    source: Option<&dyn CaKeySource>,
    clock: Option<&ClockHealth>,
) -> Result<CaStatus, crate::ca::CaError> {
    let Some(source) = source else {
        return Ok(CaStatus::unavailable());
    };
    let locked = source.subscribe_locked().map(|state| *state.borrow());
    from_roots(&source.public_roots(), locked, clock)
}

/// Build an authenticated status response from one legacy public issuer.
///
/// # Errors
/// Returns an error if the issuer certificate metadata is malformed.
pub fn from_issuer(
    issuer: Option<X509>,
    locked: Option<bool>,
    clock: Option<&ClockHealth>,
) -> Result<CaStatus, crate::ca::CaError> {
    let roots = issuer.map(|issuer| vec![(1, issuer)]).unwrap_or_default();
    from_roots(&roots, locked, clock)
}

/// Build public-only status for the current and optional next root.
///
/// # Errors
/// Refuses an oversized or ambiguous root set and malformed certificate metadata.
pub fn from_roots(
    roots: &[(u64, X509)],
    locked: Option<bool>,
    clock: Option<&ClockHealth>,
) -> Result<CaStatus, crate::ca::CaError> {
    if roots.len() > MAX_TRUST_ROOTS
        || roots.iter().any(|(generation, _)| *generation == 0)
        || roots.iter().enumerate().any(|(index, (generation, _))| {
            roots[..index]
                .iter()
                .any(|(earlier, _)| earlier == generation)
        })
    {
        return Err(crate::ca::CaError);
    }
    let now = clock.and_then(ClockHealth::current_epoch);
    let roots: Vec<RootStatus> = roots
        .iter()
        .map(|(generation, issuer)| root_status(issuer, *generation, now))
        .collect::<Result<_, _>>()?;
    Ok(CaStatus {
        available: true,
        initialized: !roots.is_empty(),
        locked,
        clock_healthy: now.is_some(),
        roots,
    })
}

fn root_status(
    issuer: &X509,
    generation: u64,
    now: Option<i64>,
) -> Result<RootStatus, crate::ca::CaError> {
    let der = issuer.to_der().map_err(|_| crate::ca::CaError)?;
    let digest = issuer
        .digest(MessageDigest::sha256())
        .map_err(|_| crate::ca::CaError)?;
    let fingerprint = hex_fingerprint(&digest);
    let not_after = epoch_seconds(issuer)?;
    let remaining_seconds = now.and_then(|now| not_after.checked_sub(now));
    let warning_level = remaining_seconds.map_or("unknown", warning_level);
    Ok(RootStatus {
        generation,
        fingerprint: format!("sha256:{fingerprint}"),
        certificate_der: B64.encode(der),
        not_after,
        remaining_seconds,
        warning_level: warning_level.to_owned(),
    })
}

fn hex_fingerprint(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().copied() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn epoch_seconds(issuer: &X509) -> Result<i64, crate::ca::CaError> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| crate::ca::CaError)?;
    let difference = epoch
        .diff(issuer.not_after())
        .map_err(|_| crate::ca::CaError)?;
    i64::from(difference.days)
        .checked_mul(DAY)
        .and_then(|days| days.checked_add(i64::from(difference.secs)))
        .ok_or(crate::ca::CaError)
}

fn warning_level(remaining: i64) -> &'static str {
    if remaining <= 0 {
        "expired"
    } else if remaining <= 7 * DAY {
        "7d"
    } else if remaining <= 30 * DAY {
        "30d"
    } else if remaining <= 90 * DAY {
        "90d"
    } else if remaining <= 365 * DAY {
        "365d"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkey::PKey,
        x509::{X509, X509NameBuilder},
    };

    fn root(not_after: i64) -> X509 {
        let key = PKey::generate_ed25519().unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "public status test root")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::from_unix(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::from_unix(not_after).unwrap())
            .unwrap();
        certificate.sign(&key, MessageDigest::null()).unwrap();
        certificate.build()
    }

    #[test]
    fn warning_thresholds_are_inclusive_and_clock_failure_stays_unknown() {
        assert_eq!(warning_level(365 * DAY), "365d");
        assert_eq!(warning_level(90 * DAY), "90d");
        assert_eq!(warning_level(30 * DAY), "30d");
        assert_eq!(warning_level(7 * DAY), "7d");
        assert_eq!(warning_level(0), "expired");
        assert_eq!(warning_level(366 * DAY), "none");
    }

    #[test]
    fn absent_source_never_reports_unlocked_or_initialized() {
        let status = from_source(None, None).unwrap();
        assert!(!status.available);
        assert!(!status.initialized);
        assert_eq!(status.locked, None);
        assert!(status.roots.is_empty());
    }

    #[test]
    fn public_status_retains_both_ordered_roots_without_a_healthy_clock() {
        let current = root(1_900_000_000);
        let next = root(2_000_000_000);
        let roots = vec![(4, current), (5, next)];
        let status = from_roots(&roots, Some(true), None).unwrap();

        assert!(status.available);
        assert!(status.initialized);
        assert_eq!(status.locked, Some(true));
        assert!(!status.clock_healthy);
        assert_eq!(status.roots.len(), 2);
        assert_eq!(status.roots[0].generation, 4);
        assert_eq!(status.roots[1].generation, 5);
        assert_eq!(status.roots[0].warning_level, "unknown");
        assert_eq!(status.roots[0].remaining_seconds, None);
        assert_eq!(status.roots[0].not_after, 1_900_000_000);
        assert_ne!(status.roots[0].certificate_der, "");
    }

    #[test]
    fn public_status_rejects_ambiguous_or_oversized_root_sets() {
        let current = root(1_900_000_000);
        let duplicate = vec![(4, current.clone()), (4, root(2_000_000_000))];
        assert!(from_roots(&duplicate, Some(false), None).is_err());
        let oversized = vec![
            (1, current.clone()),
            (2, root(2_000_000_000)),
            (3, root(2_100_000_000)),
        ];
        assert!(from_roots(&oversized, Some(false), None).is_err());
    }
}
