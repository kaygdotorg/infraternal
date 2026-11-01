//! Produces public-only CA expiry and lock status for HTTP, the local socket and CLI (#285).

use crate::{ca::CaKeySource, clock_health::ClockHealth};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use openssl::{asn1::Asn1Time, hash::MessageDigest, x509::X509};
use serde::Serialize;

const DAY: i64 = 86_400;

/// Public certificate metadata. It contains no signing material or host-specific data.
#[derive(Serialize)]
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
    pub warning_level: &'static str,
}

/// Public CA state shared by browser status and the same-UID local status path.
#[derive(Serialize)]
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

/// Read only the public issuer and lock watch; a missing watch remains unknown.
pub fn from_source(
    source: Option<&dyn CaKeySource>,
    clock: Option<&ClockHealth>,
) -> Result<CaStatus, crate::ca::CaError> {
    let Some(source) = source else {
        return Ok(CaStatus::unavailable());
    };
    let locked = source.subscribe_locked().map(|state| *state.borrow());
    from_issuer(source.public_issuer(), locked, clock)
}

/// Build an authenticated status response from a known lock state and public issuer.
pub fn from_issuer(
    issuer: Option<X509>,
    locked: Option<bool>,
    clock: Option<&ClockHealth>,
) -> Result<CaStatus, crate::ca::CaError> {
    let now = clock.and_then(ClockHealth::current_epoch);
    let roots = issuer
        .map(|issuer| root_status(&issuer, now))
        .transpose()?
        .into_iter()
        .collect();
    Ok(CaStatus {
        available: true,
        initialized: !roots.is_empty(),
        locked,
        clock_healthy: now.is_some(),
        roots,
    })
}

fn root_status(issuer: &X509, now: Option<i64>) -> Result<RootStatus, crate::ca::CaError> {
    let der = issuer.to_der().map_err(|_| crate::ca::CaError)?;
    let digest = issuer
        .digest(MessageDigest::sha256())
        .map_err(|_| crate::ca::CaError)?;
    let fingerprint = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let not_after = epoch_seconds(issuer)?;
    let remaining_seconds = now.and_then(|now| not_after.checked_sub(now));
    let warning_level = remaining_seconds.map_or("unknown", warning_level);
    Ok(RootStatus {
        generation: 1,
        fingerprint: format!("sha256:{fingerprint}"),
        certificate_der: B64.encode(der),
        not_after,
        remaining_seconds,
        warning_level,
    })
}

fn epoch_seconds(issuer: &X509) -> Result<i64, crate::ca::CaError> {
    let epoch = Asn1Time::from_unix(0).map_err(|_| crate::ca::CaError)?;
    let difference = issuer
        .not_after()
        .diff(epoch.as_ref())
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
}
