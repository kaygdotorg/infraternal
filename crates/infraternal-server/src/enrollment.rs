//! Persists remote host-bound join capabilities and public certificate authority [64][133][134].
//!
//! This is storage, not a network authentication adapter. Trusted callers must
//! authorize the owner before issuing invitations, and authenticate the pinned
//! enrollment channel and validate/sign the CSR before redemption. No private
//! key or raw join capability enters SQLite. The certificate record and token
//! consumption commit together; a signing/storage failure leaves the invitation
//! usable. Transport admission must additionally consult the host tombstone.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

#[path = "remote_authority.rs"]
pub(crate) mod authority;
#[path = "bootstrap_retirement.rs"]
mod bootstrap_retirement;
pub use authority::HostAuthority;

pub use infraternal_plugin_remote::enrollment::Mode;

/// Public identity produced by the trusted CSR signer, never supplied by a client.
pub struct CertificateRecord {
    /// SHA-256 of the exact signed certificate DER.
    pub fingerprint: [u8; 32],
    /// SHA-256 of the signing issuer's certificate DER.
    pub issuer_fingerprint: [u8; 32],
    /// The validated CSR's Ed25519 public key.
    pub public_key: [u8; 32],
    /// Inclusive certificate validity start, Unix seconds.
    pub not_before: i64,
    /// Exclusive certificate validity end, exactly seven days later.
    pub not_after: i64,
}

/// A secret capability intentionally lacking Debug, Display and serialization.
pub struct JoinToken(String);

/// Immutable facts for a receipt derived from one approved device-code request.
pub(crate) struct ApprovedJoinReceipt<'a> {
    pub(crate) owner: &'a str,
    pub(crate) host: Uuid,
    pub(crate) mode: Mode,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) now: i64,
    pub(crate) session_hash: &'a str,
    pub(crate) invitation_secret: &'a str,
    pub(crate) expected_key_digest: &'a [u8; 32],
}

impl JoinToken {
    /// Explicitly access the secret for a private stdin/descriptor handoff.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.0
    }
}

/// Content-free errors safe for operator diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    /// Invalid, expired, replaced, consumed or revoked invitation/identity.
    #[error("enrollment refused")]
    Denied,
    /// SQLite failed; no raw capability is embedded in queries or errors.
    #[error("enrollment storage unavailable")]
    Storage(#[from] sqlx::Error),
}

/// Session authority and the SSH-proved public key bound to one invitation.
pub(crate) struct IssueConstraints<'a> {
    pub(crate) session_hash: Option<&'a str>,
    pub(crate) expected_key_digest: Option<&'a [u8; 32]>,
}

/// Storage using the server's existing bounded SQLite pool; no idle worker.
/// Construct once per configured runtime and pass clones to authority writers
/// and transports so committed revocation reaches their shared event scope.
#[derive(Clone)]
pub struct EnrollmentStore(
    pub(crate) SqlitePool,
    pub(crate) std::sync::Arc<crate::remote_guard::Revocations>,
    pub(crate) crate::remote_inventory::InventoryChanges,
);

impl EnrollmentStore {
    /// Bind commit publication to the existing plugin runtime without retaining it.
    /// Clones share this binding with every admitted transport and authority writer.
    pub fn bind_plugins(&self, runtime: &crate::plugins::PluginRuntime) {
        *self
            .1
            .plugins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = runtime.downgrade();
    }
    /// Use an already migrated server database. This creates no listener/timer.
    /// Each construction creates a distinct revocation scope; cloning retains it.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self(
            pool,
            std::sync::Arc::new(crate::remote_guard::Revocations::default()),
            crate::remote_inventory::InventoryChanges::default(),
        )
    }

    /// Cheap public-authority preflight before CSR verification or private signing.
    /// Redemption repeats these checks atomically; this read grants no authority.
    /// # Errors
    /// Refuses noncanonical, stale, consumed, wrong-mode or revoked invitations.
    pub async fn preflight(
        &self,
        secret: &str,
        host: Uuid,
        mode: Mode,
        now: i64,
    ) -> Result<Option<[u8; 32]>, EnrollmentError> {
        if secret.len() != 43 || now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_| EnrollmentError::Denied)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != secret {
            return Err(EnrollmentError::Denied);
        }
        let expected: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT t.expected_key_digest FROM remote_join_tokens t JOIN remote_hosts h ON h.id=t.host_id \
             WHERE t.host_id=? AND t.mode=? AND h.mode=t.mode AND t.digest=? \
             AND t.consumed_at IS NULL AND t.issued_at<=? AND t.expires_at>? AND h.revoked_at IS NULL",
        ).bind(host.as_bytes().as_slice()).bind(mode.as_str())
            .bind(Sha256::digest(secret.as_bytes()).as_slice()).bind(now).bind(now)
            .fetch_optional(&self.0).await?;
        match expected {
            None => Err(EnrollmentError::Denied),
            Some(None) => Ok(None),
            Some(Some(bytes)) => bytes
                .try_into()
                .map(Some)
                .map_err(|_| EnrollmentError::Denied),
        }
    }

    /// Spend a valid invitation after a definitive refusal without publishing authority.
    /// # Errors
    /// Refuses malformed, stale, consumed, replaced or revoked capabilities.
    pub(crate) async fn consume_refused(
        &self,
        secret: &str,
        host: Uuid,
        mode: Mode,
        now: i64,
    ) -> Result<(), EnrollmentError> {
        if secret.len() != 43 || now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_| EnrollmentError::Denied)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != secret {
            return Err(EnrollmentError::Denied);
        }
        let changed = sqlx::query(
            "UPDATE remote_join_tokens SET consumed_at=? \
             WHERE host_id=? AND mode=? AND digest=? AND consumed_at IS NULL \
             AND issued_at<=? AND expires_at>? \
             AND EXISTS (SELECT 1 FROM remote_hosts h WHERE h.id=remote_join_tokens.host_id \
             AND h.mode=remote_join_tokens.mode AND h.revoked_at IS NULL)",
        )
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(mode.as_str())
        .bind(Sha256::digest(secret.as_bytes()).as_slice())
        .bind(now)
        .bind(now)
        .execute(&self.0)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnrollmentError::Denied);
        }
        Ok(())
    }

    /// Replace a host's invitation only for its authorized owner and fixed mode.
    ///
    /// # Errors
    /// Refuses absent/revoked hosts, ownership or mode mismatch and invalid time;
    /// returns storage failure without exposing the newly generated capability.
    pub async fn issue(
        &self,
        owner: &str,
        host: Uuid,
        mode: Mode,
        now: i64,
        expected_key_digest: &[u8; 32],
    ) -> Result<JoinToken, EnrollmentError> {
        self.issue_authorized(owner, host, mode, now, None, Some(expected_key_digest))
            .await
    }

    /// Return the invitation's bound key, falling back to a legacy certificate key.
    /// A missing value covers pending and pre-upgrade invitations, both of which must fail closed.
    pub(crate) async fn host_key_digest(
        &self,
        host: Uuid,
    ) -> Result<Option<[u8; 32]>, EnrollmentError> {
        let stored: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT expected_key_digest FROM remote_join_tokens WHERE host_id=?",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_optional(&self.0)
        .await?;
        if let Some(Some(bytes)) = stored {
            return bytes
                .try_into()
                .map(Some)
                .map_err(|_| EnrollmentError::Denied);
        }
        let public_key: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT public_key FROM remote_certificates WHERE host_id=? ORDER BY not_after DESC LIMIT 1",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_optional(&self.0)
        .await?;
        public_key
            .map(|key| <[u8; 32]>::try_from(key).map_err(|_| EnrollmentError::Denied))
            .transpose()
            .map(|key| key.map(|public| Sha256::digest(public).into()))
    }

    async fn issue_authorized(
        &self,
        owner: &str,
        host: Uuid,
        mode: Mode,
        now: i64,
        session_hash: Option<&str>,
        expected_key_digest: Option<&[u8; 32]>,
    ) -> Result<JoinToken, EnrollmentError> {
        let mut connection = self.0.acquire().await?;
        self.issue_authorized_in(
            owner,
            host,
            mode,
            now,
            IssueConstraints {
                session_hash,
                expected_key_digest,
            },
            &mut connection,
        )
        .await
    }

    /// Issue on the caller's transaction so host metadata and its invitation
    /// either publish together or roll back together, including cancellation.
    /// An undelivered revocation refuses new authority before final retirement.
    pub(crate) async fn issue_authorized_in(
        &self,
        owner: &str,
        host: Uuid,
        mode: Mode,
        now: i64,
        constraints: IssueConstraints<'_>,
        connection: &mut sqlx::SqliteConnection,
    ) -> Result<JoinToken, EnrollmentError> {
        let expires = now
            .checked_add(900)
            .filter(|_| now >= 0)
            .ok_or(EnrollmentError::Denied)?;
        let secret = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let digest = Sha256::digest(secret.as_bytes());
        // INSERT SELECT checks authority in the same write statement as replacement;
        // a concurrent revocation cannot race a separate read/check.
        let changed = sqlx::query(
            "INSERT INTO remote_join_tokens (host_id, mode, digest, issued_at, expires_at, expected_key_digest) \
             SELECT id, mode, ?, ?, ?, ? FROM remote_hosts \
             WHERE id = ? AND owner_id = ? AND mode = ? AND revoked_at IS NULL \
             AND NOT EXISTS (SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=remote_hosts.id AND q.confirmed=0) \
             AND (? IS NULL OR EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id \
             WHERE s.token_hash=? AND s.user_id=remote_hosts.owner_id AND s.unlocked=1 \
             AND s.expires>unixepoch() AND u.owner=1)) \
             ON CONFLICT(host_id) DO UPDATE SET digest=excluded.digest, \
             issued_at=excluded.issued_at, expires_at=excluded.expires_at, consumed_at=NULL, \
             expected_key_digest=excluded.expected_key_digest",
        )
        .bind(digest.as_slice())
        .bind(now)
        .bind(expires)
        .bind(constraints.expected_key_digest.map(<[u8; 32]>::as_slice))
        .bind(host.as_bytes().as_slice())
        .bind(owner)
        .bind(mode.as_str())
        .bind(constraints.session_hash)
        .bind(constraints.session_hash)
        .execute(connection)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnrollmentError::Denied);
        }
        Ok(JoinToken(secret))
    }

    /// Publish the receipt for one passkey-approved request without extending or replacing it.
    /// The derived invitation secret is stable across poll retries and bound to the approved key.
    pub(crate) async fn issue_approved_receipt_in(
        &self,
        receipt: ApprovedJoinReceipt<'_>,
        connection: &mut sqlx::SqliteConnection,
    ) -> Result<JoinToken, EnrollmentError> {
        let ApprovedJoinReceipt {
            owner,
            host,
            mode,
            issued_at,
            expires_at,
            now,
            session_hash,
            invitation_secret,
            expected_key_digest,
        } = receipt;
        if invitation_secret.len() != 43 || issued_at < 0 || issued_at > now || expires_at <= now {
            return Err(EnrollmentError::Denied);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(invitation_secret)
            .map_err(|_| EnrollmentError::Denied)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != invitation_secret {
            return Err(EnrollmentError::Denied);
        }
        let digest = Sha256::digest(invitation_secret.as_bytes());
        // On conflict, only the exact still-live request may read its original receipt.
        // Existing expiry and consumption state are never refreshed by a poll retry.
        let changed = sqlx::query(
            "INSERT INTO remote_join_tokens (host_id, mode, digest, issued_at, expires_at, expected_key_digest) \
             SELECT h.id, h.mode, ?, ?, ?, ? FROM remote_hosts h \
             WHERE h.id = ? AND h.owner_id = ? AND h.mode = ? AND h.revoked_at IS NULL \
             AND EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id \
                 WHERE s.token_hash=? AND s.user_id=h.owner_id AND s.unlocked=1 \
                 AND s.expires>? AND u.owner=1) \
             ON CONFLICT(host_id) DO UPDATE SET digest=excluded.digest \
                 WHERE remote_join_tokens.digest=excluded.digest \
                 AND remote_join_tokens.issued_at=excluded.issued_at \
                 AND remote_join_tokens.expires_at=excluded.expires_at \
                 AND remote_join_tokens.expected_key_digest=excluded.expected_key_digest",
        )
        .bind(digest.as_slice())
        .bind(issued_at)
        .bind(expires_at)
        .bind(expected_key_digest.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(owner)
        .bind(mode.as_str())
        .bind(session_hash)
        .bind(now)
        .execute(connection)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(EnrollmentError::Denied);
        }
        Ok(JoinToken(invitation_secret.to_owned()))
    }

    /// Atomically consume an invitation and retain its signed public identity.
    ///
    /// The caller must derive `certificate` from its own validated CSR signer.
    /// Never use untrusted client-provided certificate fields here.
    /// # Errors
    /// Refuses invalid capability/host/mode/time, concurrent redemption and
    /// revocation. An insert failure rolls back consumption rather than burning
    /// an invitation whose certificate was not durably recorded.
    /// Pending cleanup also refuses redemption without consuming the invitation.
    pub async fn redeem(
        &self,
        secret: &str,
        host: Uuid,
        mode: Mode,
        now: i64,
        certificate: &CertificateRecord,
    ) -> Result<(), EnrollmentError> {
        // Canonical spelling matters: hash only the one URL-safe encoding of
        // exactly 32 bytes, rejecting aliases and oversized inputs before decode.
        if secret.len() != 43 || now < 0 {
            return Err(EnrollmentError::Denied);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_| EnrollmentError::Denied)?;
        if decoded.len() != 32
            || URL_SAFE_NO_PAD.encode(&decoded) != secret
            || certificate.not_before < 0
            || certificate.not_before > now
            || certificate.not_after <= now
            || certificate.not_before.checked_add(604_800) != Some(certificate.not_after)
        {
            return Err(EnrollmentError::Denied);
        }
        let digest = Sha256::digest(secret.as_bytes());
        let mut transaction = self.0.begin().await?;
        // The first operation is a write. SQLite serializes writers, so two
        // redeem transactions cannot both validate an unconsumed invitation.
        let changed = sqlx::query(
            "UPDATE remote_join_tokens SET consumed_at = ? \
             WHERE host_id = ? AND mode = ? AND digest = ? AND expected_key_digest = ? \
             AND consumed_at IS NULL \
             AND issued_at <= ? AND expires_at > ? \
             AND EXISTS (SELECT 1 FROM remote_hosts h WHERE h.id = host_id \
             AND h.mode = remote_join_tokens.mode AND h.revoked_at IS NULL \
             AND NOT EXISTS (SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0))",
        )
        .bind(now)
        .bind(host.as_bytes().as_slice())
        .bind(mode.as_str())
        .bind(digest.as_slice())
        .bind(Sha256::digest(certificate.public_key).as_slice())
        .bind(now)
        .bind(now)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            transaction.rollback().await?;
            return Err(EnrollmentError::Denied);
        }
        sqlx::query(
            "INSERT INTO remote_certificates (fingerprint, host_id, issuer_fingerprint, \
             public_key, not_before, not_after) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(certificate.fingerprint.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(certificate.issuer_fingerprint.as_slice())
        .bind(certificate.public_key.as_slice())
        .bind(certificate.not_before)
        .bind(certificate.not_after)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        self.2.publish();
        Ok(())
    }
}

#[cfg(test)]
#[path = "remote_migration_tests.rs"]
mod migration_tests;
