//! The durable record of upgrading a host to the root infraternal agent
//! (D274, D376, #399; J415's R1, R3, R5 and R7).
//!
//! A host's mode is write-once, with one exception: a *promotion*. Every step of
//! one is a single SQLite write on its `remote_host_promotions` row, and the
//! database itself refuses the steps out of order (see the migration's
//! triggers). In order:
//!
//! 1. [`EnrollmentStore::begin_promotion`]: a host admin's unlocked session,
//!    inside its admin window, opens a row bound to the exact rootless
//!    certificate and link generation it saw (R7). One live row per host.
//! 2. [`EnrollmentStore::reserve_try`]: the 2-try check and the try itself are
//!    one UPDATE (B2), so two tabs can't both spend the last try. A try that
//!    types a password counts until root is reached, so a timeout or failure
//!    after typing counts too (PAM may have counted it).
//! 3. [`EnrollmentStore::settle_try`]: wrong, failed, or root reached.
//! 4. [`EnrollmentStore::issue_successor_token`]: a one-use join token for
//!    the root install, bound to the key the install staged.
//! 5. [`EnrollmentStore::redeem_successor`]: the root infraternal agent joins.
//!    Its certificate gets `role='successor'`, so ordinary admission refuses
//!    it; only [`EnrollmentStore::admit_successor`] admits it, and its result
//!    ([`SuccessorAuthority`]) is a different type the ordinary guard can't take.
//! 6. [`EnrollmentStore::handover`]: one transaction flips the host to root,
//!    revokes every other key of the host, makes the successor's certificate
//!    the host's active one and queues the predecessor's retirement (R3, R5).
//!
//! Any ending other than the handover is [`EnrollmentStore::abandon_promotion`]
//! (or the sweeper, [`EnrollmentStore::sweep_promotions`]). It is one write
//! that also bars the handover forever (the handover requires `enrolled`), and
//! when a successor had joined it queues that successor's uninstall (R5).
//!
//! The 2-try rule counts per account (B9): sudo and doas both check the
//! person's own password, su checks root's. It only sees tries made through
//! infraternal; failures someone typed by hand in a terminal count on the
//! host (`pam_faillock`) but not here, so a wait can come one try early there.
//!
//! Nothing here holds a secret: tokens are stored as SHA-256 digests, and the
//! password never reaches the server at all (it is sealed in the browser).
#[cfg(any(feature = "ssh", test))]
use super::JoinToken;
use super::{CertificateRecord, EnrollmentError, EnrollmentStore};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// How long a promotion may take from begin to handover, in seconds. The
/// sweeper abandons a row still live after it.
#[cfg(any(feature = "ssh", test))]
pub(crate) const LIFETIME: i64 = 15 * 60;
/// Wrong passwords allowed before the wait (D376: under the common 3-try lockout).
#[cfg(any(feature = "ssh", test))]
pub(crate) const TRIES: i64 = 2;
/// How long the wait lasts after the second wrong password, in seconds:
/// `pam_faillock`'s default `fail_interval`, so the host's own count has
/// forgotten both failures by then.
#[cfg(any(feature = "ssh", test))]
pub(crate) const WAIT: i64 = 15 * 60;

/// How the rootless account becomes root (D274's order).
#[cfg(any(feature = "ssh", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    /// sudo without a password: consent only, nothing is typed.
    SudoNoPassword,
    /// sudo with the person's own password.
    Sudo,
    /// doas with the person's own password.
    Doas,
    /// su with root's password.
    Su,
}

#[cfg(any(feature = "ssh", test))]
impl Method {
    /// The stored and wire word.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::SudoNoPassword => "sudo-nopasswd",
            Self::Sudo => "sudo",
            Self::Doas => "doas",
            Self::Su => "su",
        }
    }

    /// Whose password PAM checks, which is what the 2-try rule counts (B9):
    /// sudo and doas check the person's own account, su checks root's.
    pub(crate) const fn account(self) -> &'static str {
        match self {
            Self::Su => "root",
            Self::SudoNoPassword | Self::Sudo | Self::Doas => "person",
        }
    }
}

/// The rootless identity a promotion is bound to, seen at begin (R7).
#[cfg(any(feature = "ssh", test))]
#[derive(Clone, Copy, Debug)]
pub(crate) struct Bound {
    /// The uid the rootless infraternal agent runs as.
    pub(crate) from_uid: u32,
    /// The exact certificate its live link was admitted with.
    pub(crate) from_fingerprint: [u8; 32],
    /// The registry's generation of that link; a replaced link abandons.
    pub(crate) link_generation: Uuid,
}

/// Why a promotion step was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PromotionError {
    /// Not allowed, or the row isn't in the state this step needs.
    #[error("promotion refused")]
    Denied,
    /// Another promotion of this host is live.
    #[cfg(any(feature = "ssh", test))]
    #[error("promotion busy")]
    Busy,
    /// Two wrong passwords: wait this many seconds (D376).
    #[cfg(any(feature = "ssh", test))]
    #[error("promotion waits")]
    Locked {
        /// Seconds until the next try is accepted.
        retry_after: i64,
    },
    /// SQLite failed.
    #[error("promotion storage unavailable")]
    Storage(#[from] sqlx::Error),
}

impl From<EnrollmentError> for PromotionError {
    fn from(error: EnrollmentError) -> Self {
        match error {
            EnrollmentError::Denied => Self::Denied,
            EnrollmentError::Storage(error) => Self::Storage(error),
        }
    }
}

/// How a reserved try ended.
#[cfg(any(feature = "ssh", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Settled {
    /// The password was refused.
    Wrong,
    /// It ended before root for another reason. `typed`: a password had
    /// already been handed to PAM, so the try still counts.
    Failed {
        /// Whether the password reached PAM.
        typed: bool,
    },
    /// Root was reached; the install runs next.
    Rooted,
    /// Root was reached (the password was right), but the host's binary
    /// didn't match this server's payload, so nothing ran as root and the
    /// try ends. It counts as a success for the 2-try rule (J465 P3-2): PAM
    /// counted a success too, so the count starts again.
    Mismatch,
}

/// What an admitted successor may do (R5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SuccessorPurpose {
    /// Its promotion is `enrolled`: answer the proof calls before handover.
    Proof,
    /// Its promotion was abandoned: roll back and uninstall itself, nothing else.
    Uninstall,
}

/// A root upgrade's successor, admitted by its own check
/// ([`EnrollmentStore::admit_successor`]).
///
/// Deliberately not a [`super::HostAuthority`]: the ordinary guard, the host
/// registry and plugin routing only take that type, so a successor can't be
/// mistaken for (or replace) the host's live infraternal agent (J415 R1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SuccessorAuthority {
    /// The host being upgraded.
    pub(crate) host: Uuid,
    /// Its promotion.
    pub(crate) attempt: Uuid,
    /// The successor's exact certificate.
    pub(crate) fingerprint: [u8; 32],
    /// What it may do.
    pub(crate) purpose: SuccessorPurpose,
    /// Unix second after which this admission is void (the promotion's
    /// deadline for proof, the certificate's end for uninstall).
    pub(crate) not_after: i64,
}

/// One successor admission row: attempt, host, state, the promotion's
/// deadline and the certificate's end.
type SuccessorRow = (Vec<u8>, Vec<u8>, String, i64, i64);

/// What the handover changed, for the caller's in-memory follow-up.
#[cfg(any(feature = "ssh", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HandedOver {
    /// The host, now rootful.
    pub(crate) host: Uuid,
    /// The rootless uid whose epoch the caller must now cut (R2).
    pub(crate) from_uid: u32,
}

/// The SQL condition "this host and account are waiting after two wrong
/// passwords", over the bind names `?h` (host), `?a` (account) and `?n` (now).
/// Counted: tries whose password reached PAM and never reached root, since
/// the last try that did. Locked while there are at least [`TRIES`] of them
/// and the newest is less than [`WAIT`] old.
#[cfg(any(feature = "ssh", test))]
const LOCKED: &str = "EXISTS(SELECT 1 FROM (SELECT count(*) AS n, MAX(COALESCE(f.ended_at, f.started_at)) AS last \
    FROM remote_host_promotions f WHERE f.host_id = ?h AND f.account = ?a AND f.tried = 1 AND f.rooted = 0 \
    AND f.started_at >= COALESCE((SELECT MAX(o.started_at) FROM remote_host_promotions o \
        WHERE o.host_id = ?h AND o.account = ?a AND o.rooted = 1), -1)) \
    WHERE n >= 2 AND last + 900 > ?n)";

/// [`LOCKED`] with its placeholders replaced by SQL expressions.
/// The `FROM ... WHERE` of a promotion begin, without the 2-try wait: who
/// may begin (an unlocked owner session inside its admin window, for a live
/// rootless host) and what it binds to (an admissible active certificate of
/// that host and uid). Parameters: `?4` rootless certificate, `?6` now,
/// `?8` host, `?9` uid, `?10` session hash, `?11` admin window.
#[cfg(any(feature = "ssh", test))]
const BEGIN_ALLOWED: &str = "FROM remote_hosts h JOIN sessions s ON s.user_id = h.owner_id \
     JOIN users u ON u.id = s.user_id \
     JOIN remote_certificates c ON c.host_id = h.id AND c.fingerprint = ?4 \
     WHERE h.id = ?8 AND h.mode = 'rootless' AND h.execution_uid = ?9 AND h.revoked_at IS NULL \
     AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id = h.id AND q.confirmed = 0) \
     AND s.token_hash = ?10 AND s.unlocked = 1 AND s.expires > ?6 AND u.owner = 1 \
     AND s.fresh <= ?6 AND ?6 - s.fresh < ?11 \
     AND c.role = 'active' AND c.execution_uid = h.execution_uid AND c.revoked_at IS NULL \
     AND c.not_before <= ?6 AND c.not_after > ?6";

/// An earlier promotion of host `h.id` whose root install may still be on
/// the host: its successor's uninstall is pending and that successor can
/// still be admitted to run it (J569 P2-2). Once its certificate expires it
/// can never uninstall through infraternal, so it stops barring the host.
#[cfg(any(feature = "ssh", test))]
const UNINSTALL_PENDING: &str = "EXISTS(SELECT 1 FROM remote_host_promotions p \
     JOIN remote_certificates sc ON sc.fingerprint = p.successor_fingerprint \
     WHERE p.host_id = h.id AND p.cleanup = 'uninstall' \
     AND sc.revoked_at IS NULL AND sc.not_after > ?6)";

/// The 2-try wait clause ([`LOCKED`]) for the given host, account and time
/// expressions, spliced into a statement's WHERE.
#[cfg(any(feature = "ssh", test))]
fn locked(host: &str, account: &str, now: &str) -> String {
    LOCKED
        .replace("?h", host)
        .replace("?a", account)
        .replace("?n", now)
}

/// The canonical spelling of a 32-byte token, or refused.
fn canonical(secret: &str) -> Result<(), PromotionError> {
    if secret.len() != 43 {
        return Err(PromotionError::Denied);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(secret)
        .map_err(|_| PromotionError::Denied)?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != secret {
        return Err(PromotionError::Denied);
    }
    Ok(())
}

/// Whether `error` is a UNIQUE constraint failure (another live promotion).
#[cfg(any(feature = "ssh", test))]
fn unique_violation(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.is_unique_violation())
}

impl EnrollmentStore {
    /// Open a promotion of `host` for the session `session_hash`.
    ///
    /// SQL fragments are fixed, and every value from the caller is bound.
    /// The authority check and the insert are one statement (R7): the session
    /// must be unlocked, inside its admin window, belong to the host's owner,
    /// who must be the server owner (the only "host admin" until roles
    /// arrive); the host must be live and rootless; and `bound` must name an
    /// admissible active certificate of that host and uid. No message from an
    /// infraternal agent can create or advance a promotion.
    ///
    /// # Errors
    /// [`PromotionError::Busy`] when another promotion of the host is live
    /// or an earlier one's uninstall is pending, [`PromotionError::Locked`]
    /// during the 2-try wait (told only to a caller who may begin),
    /// otherwise `Denied`.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn begin_promotion(
        &self,
        session_hash: &str,
        host: Uuid,
        attempt: Uuid,
        method: Method,
        bound: Bound,
        now: i64,
    ) -> Result<(), PromotionError> {
        if now < 0 {
            return Err(PromotionError::Denied);
        }
        let sql = format!(
            "INSERT INTO remote_host_promotions(attempt, host_id, person, method, account, from_uid, \
             from_fingerprint, link_generation, started_at, expires_at) \
             SELECT ?1, h.id, s.user_id, ?2, ?3, h.execution_uid, ?4, ?5, ?6, ?6 + ?7 \
             {BEGIN_ALLOWED} AND NOT {} AND NOT {UNINSTALL_PENDING}",
            locked("h.id", "?3", "?6")
        );
        let inserted = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(attempt.as_bytes().as_slice())
            .bind(method.word())
            .bind(method.account())
            .bind(bound.from_fingerprint.as_slice())
            .bind(bound.link_generation.as_bytes().as_slice())
            .bind(now)
            .bind(LIFETIME)
            .bind(host.as_bytes().as_slice())
            .bind(i64::from(bound.from_uid))
            .bind(session_hash)
            .bind(infraternal_plugin_api::ADMIN_WINDOW_SECONDS)
            .execute(&self.0)
            .await;
        match inserted {
            Ok(done) if done.rows_affected() == 1 => Ok(()),
            Ok(_) => {
                self.refused_begin(session_hash, host, method, bound, now)
                    .await
            }
            Err(error) if unique_violation(&error) => Err(PromotionError::Busy),
            Err(error) => Err(error.into()),
        }
    }

    /// Why [`Self::begin_promotion`]'s insert added no row, in this order:
    /// - a caller who may not begin at all is `Denied`, and learns nothing
    ///   about the host's state (J569 P3-3: before, a locked session, one
    ///   outside its admin window or another owner was told the 2-try wait);
    /// - an earlier promotion's root install that may still be on the host
    ///   (its uninstall is pending) is `Busy` (J569 P2-2): a new handover
    ///   would revoke that successor's certificate, and its uninstall could
    ///   then never be delivered;
    /// - the 2-try wait is `Locked`;
    /// - anything else (a stale binding) is `Denied`.
    #[cfg(any(feature = "ssh", test))]
    async fn refused_begin(
        &self,
        session_hash: &str,
        host: Uuid,
        method: Method,
        bound: Bound,
        now: i64,
    ) -> Result<(), PromotionError> {
        // The same numbered parameters as the insert; the ones it doesn't
        // use (`?1`–`?3`, `?5`, `?7`) are bound to NULL.
        let sql = format!("SELECT NOT {UNINSTALL_PENDING} {BEGIN_ALLOWED}");
        let unused = None::<i64>;
        let allowed: Option<bool> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
            .bind(unused)
            .bind(unused)
            .bind(unused)
            .bind(bound.from_fingerprint.as_slice())
            .bind(unused)
            .bind(now)
            .bind(unused)
            .bind(host.as_bytes().as_slice())
            .bind(i64::from(bound.from_uid))
            .bind(session_hash)
            .bind(infraternal_plugin_api::ADMIN_WINDOW_SECONDS)
            .fetch_optional(&self.0)
            .await?;
        match allowed {
            None => Err(PromotionError::Denied),
            Some(false) => Err(PromotionError::Busy),
            Some(true) => match self.retry_after(host, method, now).await? {
                Some(retry_after) => Err(PromotionError::Locked { retry_after }),
                None => Err(PromotionError::Denied),
            },
        }
    }

    /// Seconds until `host` accepts another try by `method`'s account, or
    /// `None` when it does now (D376's 2 tries, then wait; B9 per account).
    ///
    /// # Errors
    /// The database could not be read; callers refuse the try.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn retry_after(
        &self,
        host: Uuid,
        method: Method,
        now: i64,
    ) -> Result<Option<i64>, PromotionError> {
        let last: Option<i64> = sqlx::query_scalar(
            "SELECT last + ?3 - ?4 FROM (SELECT count(*) AS n, MAX(COALESCE(f.ended_at, f.started_at)) AS last \
             FROM remote_host_promotions f WHERE f.host_id = ?1 AND f.account = ?2 AND f.tried = 1 AND f.rooted = 0 \
             AND f.started_at >= COALESCE((SELECT MAX(o.started_at) FROM remote_host_promotions o \
                 WHERE o.host_id = ?1 AND o.account = ?2 AND o.rooted = 1), -1)) \
             WHERE n >= ?5 AND last + ?3 > ?4",
        )
        .bind(host.as_bytes().as_slice())
        .bind(method.account())
        .bind(WAIT)
        .bind(now)
        .bind(TRIES)
        .fetch_optional(&self.0)
        .await?;
        Ok(last)
    }

    /// Reserve the try of `attempt` for the session that began it (B2),
    /// still inside its admin window (J465 P3-3).
    ///
    /// One UPDATE moves the row from `open` to `elevating` only if the 2-try
    /// wait doesn't apply, so a concurrent second finish of the same attempt,
    /// or a try racing another, can't both pass. With `typed` (a password is
    /// about to reach PAM) the try counts from this moment until
    /// [`Self::settle_try`] says root was reached.
    ///
    /// # Errors
    /// `Locked` during the wait; `Denied` for a foreign session, an expired
    /// row, or one that isn't `open` (already used).
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn reserve_try(
        &self,
        session_hash: &str,
        attempt: Uuid,
        typed: bool,
        now: i64,
    ) -> Result<(Uuid, Method), PromotionError> {
        let sql = format!(
            "UPDATE remote_host_promotions SET state = 'elevating', tried = ?1 \
             WHERE attempt = ?2 AND state = 'open' AND expires_at > ?3 \
             AND EXISTS(SELECT 1 FROM sessions s WHERE s.token_hash = ?4 \
                 AND s.user_id = remote_host_promotions.person AND s.unlocked = 1 AND s.expires > ?3 \
                 AND s.fresh <= ?3 AND ?3 - s.fresh < ?5) \
             AND NOT {} \
             RETURNING host_id, method",
            locked(
                "remote_host_promotions.host_id",
                "remote_host_promotions.account",
                "?3"
            )
        );
        let row: Option<(Vec<u8>, String)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .bind(i64::from(typed))
            .bind(attempt.as_bytes().as_slice())
            .bind(now)
            .bind(session_hash)
            .bind(infraternal_plugin_api::ADMIN_WINDOW_SECONDS)
            .fetch_optional(&self.0)
            .await?;
        if let Some((host, method)) = row {
            let host = Uuid::from_slice(&host).map_err(|_| PromotionError::Denied)?;
            return Ok((host, parse_method(&method)?));
        }
        let open: Option<(Vec<u8>, String)> = sqlx::query_as(
            "SELECT host_id, method FROM remote_host_promotions WHERE attempt = ? AND state = 'open'",
        )
        .bind(attempt.as_bytes().as_slice())
        .fetch_optional(&self.0)
        .await?;
        if let Some((host, method)) = open
            && let Ok(host) = Uuid::from_slice(&host)
            && let Some(retry_after) = self.retry_after(host, parse_method(&method)?, now).await?
        {
            return Err(PromotionError::Locked { retry_after });
        }
        Err(PromotionError::Denied)
    }

    /// Record how a reserved try ended. Only an `elevating` row moves.
    ///
    /// # Errors
    /// `Denied` when the row isn't `elevating` (it was abandoned meanwhile).
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn settle_try(
        &self,
        attempt: Uuid,
        settled: Settled,
        now: i64,
    ) -> Result<(), PromotionError> {
        let (state, tried, rooted, ended): (&str, Option<i64>, i64, Option<i64>) = match settled {
            // A refused password always counts.
            Settled::Wrong => ("wrong", Some(1), 0, Some(now)),
            // A failure counts only when the password had reached PAM.
            Settled::Failed { typed } => ("failed", Some(i64::from(typed)), 0, Some(now)),
            // Root reached: the try was right and the count starts again.
            Settled::Rooted => ("installing", None, 1, None),
            Settled::Mismatch => ("failed", Some(1), 1, Some(now)),
        };
        let changed = sqlx::query(
            "UPDATE remote_host_promotions SET state = ?1, tried = COALESCE(?2, tried), rooted = ?3, ended_at = ?4 \
             WHERE attempt = ?5 AND state = 'elevating'",
        )
        .bind(state)
        .bind(tried)
        .bind(rooted)
        .bind(ended)
        .bind(attempt.as_bytes().as_slice())
        .execute(&self.0)
        .await?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(PromotionError::Denied)
        }
    }

    /// Issue the successor's one-use join token, bound to the key the root
    /// install staged (`key_digest`, the SHA-256 of its public key).
    ///
    /// Only an `installing` row with no token yet gets one, so a token can't
    /// be replaced; it dies with the row's deadline.
    ///
    /// # Errors
    /// `Denied` otherwise.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn issue_successor_token(
        &self,
        attempt: Uuid,
        key_digest: &[u8; 32],
        now: i64,
    ) -> Result<JoinToken, PromotionError> {
        let secret = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let changed = sqlx::query(
            "UPDATE remote_host_promotions SET token_digest = ?, expected_key_digest = ? \
             WHERE attempt = ? AND state = 'installing' AND token_digest IS NULL AND expires_at > ?",
        )
        .bind(Sha256::digest(secret.as_bytes()).as_slice())
        .bind(key_digest.as_slice())
        .bind(attempt.as_bytes().as_slice())
        .bind(now)
        .execute(&self.0)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(PromotionError::Denied);
        }
        Ok(JoinToken(secret))
    }

    /// The key digest a live successor token is bound to, before the CSR is
    /// signed. Redemption repeats every check in its write; this grants nothing.
    ///
    /// # Errors
    /// `Denied` for any token that isn't a live successor token of `host`.
    pub(crate) async fn preflight_successor(
        &self,
        secret: &str,
        host: Uuid,
        now: i64,
    ) -> Result<[u8; 32], PromotionError> {
        canonical(secret)?;
        let digest: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT p.expected_key_digest FROM remote_host_promotions p JOIN remote_hosts h ON h.id = p.host_id \
             WHERE p.host_id = ? AND p.token_digest = ? AND p.state = 'installing' AND p.expires_at > ? \
             AND p.successor_fingerprint IS NULL AND h.mode = 'rootless' AND h.execution_uid = p.from_uid \
             AND h.revoked_at IS NULL",
        )
        .bind(host.as_bytes().as_slice())
        .bind(Sha256::digest(secret.as_bytes()).as_slice())
        .bind(now)
        .fetch_optional(&self.0)
        .await?;
        digest
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(PromotionError::Denied)
    }

    /// Spend a successor token and record the successor's certificate, in
    /// one transaction: the row becomes `enrolled` and the certificate gets
    /// `role='successor'` for uid 0, which only [`Self::admit_successor`] admits.
    ///
    /// # Errors
    /// `Denied` for a spent, foreign, expired or wrong-key token, or when the
    /// host is no longer the rootless host the promotion began on.
    pub(crate) async fn redeem_successor(
        &self,
        secret: &str,
        host: Uuid,
        now: i64,
        certificate: &CertificateRecord,
    ) -> Result<(), PromotionError> {
        canonical(secret)?;
        // A successor is a root infraternal agent on a Linux or macOS host, so
        // its key is always Ed25519; device keys (#580) never take this path.
        let crate::identity_key::IdentityKey::Ed25519(successor_key) = &certificate.public_key
        else {
            return Err(PromotionError::Denied);
        };
        if certificate.not_before < 0
            || certificate.not_before > now
            || certificate.not_after <= now
            || certificate.not_before.checked_add(604_800) != Some(certificate.not_after)
        {
            return Err(PromotionError::Denied);
        }
        let mut transaction = self.0.begin().await?;
        // The first statement is the write that spends the token, so two
        // redemptions can't both see it unspent.
        let changed = sqlx::query(
            "UPDATE remote_host_promotions SET state = 'enrolled', successor_fingerprint = ?, successor_key = ? \
             WHERE host_id = ? AND token_digest = ? AND state = 'installing' AND expires_at > ? \
             AND successor_fingerprint IS NULL AND expected_key_digest = ? \
             AND EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id = remote_host_promotions.host_id \
                 AND h.mode = 'rootless' AND h.execution_uid = remote_host_promotions.from_uid \
                 AND h.revoked_at IS NULL \
                 AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id = h.id AND q.confirmed = 0))",
        )
        .bind(certificate.fingerprint.as_slice())
        .bind(successor_key.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(Sha256::digest(secret.as_bytes()).as_slice())
        .bind(now)
        .bind(Sha256::digest(successor_key).as_slice())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            transaction.rollback().await?;
            return Err(PromotionError::Denied);
        }
        sqlx::query(
            "INSERT INTO remote_certificates (fingerprint, host_id, issuer_fingerprint, public_key, \
             not_before, not_after, role, execution_uid) VALUES (?, ?, ?, ?, ?, ?, 'successor', 0)",
        )
        .bind(certificate.fingerprint.as_slice())
        .bind(host.as_bytes().as_slice())
        .bind(certificate.issuer_fingerprint.as_slice())
        .bind(successor_key.as_slice())
        .bind(certificate.not_before)
        .bind(certificate.not_after)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Admit a successor's certificate, separately from ordinary admission
    /// (J415 R1). It passes only while its promotion names this exact
    /// certificate and key, and either is `enrolled` and unexpired (proof
    /// calls), or was abandoned with its uninstall still pending (cleanup).
    ///
    /// # Errors
    /// `Denied` for every other certificate, ordinary ones included.
    pub(crate) async fn admit_successor(
        &self,
        fingerprint: &[u8; 32],
        now: i64,
    ) -> Result<SuccessorAuthority, PromotionError> {
        if now < 0 {
            return Err(PromotionError::Denied);
        }
        let row: Option<SuccessorRow> = sqlx::query_as(
            "SELECT p.attempt, p.host_id, p.state, p.expires_at, c.not_after FROM remote_host_promotions p \
             JOIN remote_certificates c ON c.fingerprint = p.successor_fingerprint \
             JOIN remote_hosts h ON h.id = p.host_id \
             WHERE p.successor_fingerprint = ?1 AND c.host_id = p.host_id AND c.public_key = p.successor_key \
             AND c.role = 'successor' AND c.execution_uid = 0 AND c.revoked_at IS NULL \
             AND c.not_before <= ?2 AND c.not_after > ?2 \
             AND ((p.state = 'enrolled' AND p.expires_at > ?2 AND h.mode = 'rootless' \
                   AND h.execution_uid = p.from_uid AND h.revoked_at IS NULL) \
               OR (p.state = 'abandoned' AND p.cleanup = 'uninstall'))",
        )
        .bind(fingerprint.as_slice())
        .bind(now)
        .fetch_optional(&self.0)
        .await?;
        let (attempt, host, state, expires_at, not_after) = row.ok_or(PromotionError::Denied)?;
        let purpose = if state == "enrolled" {
            SuccessorPurpose::Proof
        } else {
            SuccessorPurpose::Uninstall
        };
        Ok(SuccessorAuthority {
            host: Uuid::from_slice(&host).map_err(|_| PromotionError::Denied)?,
            attempt: Uuid::from_slice(&attempt).map_err(|_| PromotionError::Denied)?,
            fingerprint: *fingerprint,
            purpose,
            not_after: if purpose == SuccessorPurpose::Proof {
                expires_at.min(not_after)
            } else {
                not_after
            },
        })
    }

    /// The handover: one transaction makes the successor the host's
    /// infraternal agent (J415 R3).
    ///
    /// In order, all or nothing:
    /// - the host flips from rootless (the promotion's uid) to root, only if
    ///   the promotion is `enrolled`, unexpired, names `successor`, and the
    ///   exact rootless certificate it was bound to is still live (R7); the
    ///   database trigger refuses every other mode change;
    /// - every certificate of the host whose key isn't the successor's is
    ///   revoked, by key, so a renewal that committed meanwhile is covered;
    /// - the successor's certificate becomes the active one;
    /// - the host's rootless join token is dropped;
    /// - the row becomes `handed_over` with the predecessor's retirement queued.
    ///
    /// After the commit it cuts the old epoch (`Revocations::cut_epoch`) and
    /// releases that cut (R2); the returned value says which epoch ended.
    ///
    /// # Errors
    /// `Denied` when any check fails; nothing has changed then.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn handover(
        &self,
        attempt: Uuid,
        successor: &[u8; 32],
        now: i64,
    ) -> Result<HandedOver, PromotionError> {
        let mut transaction = self.0.begin().await?;
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "UPDATE remote_hosts SET mode = 'rootful', execution_uid = 0 \
             WHERE mode = 'rootless' AND revoked_at IS NULL \
             AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id = remote_hosts.id AND q.confirmed = 0) \
             AND id = (SELECT p.host_id FROM remote_host_promotions p \
                 WHERE p.attempt = ?1 AND p.state = 'enrolled' AND p.expires_at > ?2 \
                 AND p.successor_fingerprint = ?3 AND p.from_uid = remote_hosts.execution_uid \
                 AND EXISTS(SELECT 1 FROM remote_certificates c WHERE c.fingerprint = p.from_fingerprint \
                     AND c.host_id = p.host_id AND c.role = 'active' AND c.execution_uid = p.from_uid \
                     AND c.revoked_at IS NULL AND c.not_before <= ?2 AND c.not_after > ?2)) \
             RETURNING id, (SELECT from_uid FROM remote_host_promotions WHERE attempt = ?1)",
        )
        .bind(attempt.as_bytes().as_slice())
        .bind(now)
        .bind(successor.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((host, from_uid)) = row else {
            transaction.rollback().await?;
            return Err(PromotionError::Denied);
        };
        let from_uid = u32::try_from(from_uid).map_err(|_| PromotionError::Denied)?;
        sqlx::query(
            "UPDATE remote_certificates SET revoked_at = COALESCE(revoked_at, ?) WHERE host_id = ? \
             AND public_key <> (SELECT successor_key FROM remote_host_promotions WHERE attempt = ?)",
        )
        .bind(now)
        .bind(host.as_slice())
        .bind(attempt.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await?;
        let activated = sqlx::query(
            "UPDATE remote_certificates SET role = 'active' \
             WHERE fingerprint = ? AND host_id = ? AND role = 'successor' AND revoked_at IS NULL",
        )
        .bind(successor.as_slice())
        .bind(host.as_slice())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let moved = sqlx::query(
            "UPDATE remote_host_promotions SET state = 'handed_over', cleanup = 'retire', ended_at = ? \
             WHERE attempt = ? AND state = 'enrolled'",
        )
        .bind(now)
        .bind(attempt.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if activated != 1 || moved != 1 {
            transaction.rollback().await?;
            return Err(PromotionError::Denied);
        }
        sqlx::query("DELETE FROM remote_join_tokens WHERE host_id = ?")
            .bind(host.as_slice())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        let host = Uuid::from_slice(&host).map_err(|_| PromotionError::Denied)?;
        // R2, in J415's order: commit, then cut the rootless epoch, then
        // release that cut. The old actor's open streams end at the cut; its
        // new operations already fail admission's recheck. The root epoch,
        // which the successor holds, is untouched.
        if self.1.cut_epoch(host, from_uid).is_ok() {
            self.1.tombstoned_epoch(host, from_uid);
        }
        self.2.publish();
        self.publish_revoked_authority().await;
        Ok(HandedOver { host, from_uid })
    }

    /// Give up on a live promotion: one write that bars its handover forever,
    /// and queues the successor's uninstall when one had joined (R5).
    /// Returns whether a live row ended here.
    ///
    /// # Errors
    /// Storage failure only.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn abandon_promotion(
        &self,
        attempt: Uuid,
        now: i64,
    ) -> Result<bool, PromotionError> {
        Ok(sqlx::query(ABANDON_WHERE_ATTEMPT)
            .bind(now)
            .bind(attempt.as_bytes().as_slice())
            .execute(&self.0)
            .await?
            .rows_affected()
            == 1)
    }

    /// Record that the root install was put back: the host is as it was.
    ///
    /// The driver calls this only when nothing reached the host or the
    /// install's rollback was verified. A row still `installing` simply
    /// ends. An `enrolled` row (the successor had joined) ends too, because
    /// that rollback removed the successor: its certificate is revoked in the
    /// same transaction and no uninstall is queued for it (J569 P3-1; before,
    /// such a row was abandoned with an uninstall for a successor that was
    /// already gone, and the certificate stayed admissible for 7 days).
    ///
    /// # Errors
    /// `Denied` when the row is neither `installing` nor `enrolled`.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn rolled_back(&self, attempt: Uuid, now: i64) -> Result<(), PromotionError> {
        let mut transaction = self.0.begin().await?;
        let successor: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "UPDATE remote_host_promotions SET state = 'rolled_back', ended_at = ? \
             WHERE attempt = ? AND state IN ('installing', 'enrolled') RETURNING successor_fingerprint",
        )
        .bind(now)
        .bind(attempt.as_bytes().as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(successor) = successor else {
            return Err(PromotionError::Denied);
        };
        if let Some(fingerprint) = successor {
            sqlx::query(
                "UPDATE remote_certificates SET revoked_at = COALESCE(revoked_at, ?) \
                 WHERE fingerprint = ? AND role = 'successor'",
            )
            .bind(now)
            .bind(fingerprint.as_slice())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// The sweeper: abandon every live promotion past its deadline, and
    /// with `all`, every live one (a server start: no task drives them
    /// any more). Returns how many it ended.
    ///
    /// # Errors
    /// Storage failure only.
    pub(crate) async fn sweep_promotions(
        &self,
        now: i64,
        all: bool,
    ) -> Result<u64, PromotionError> {
        Ok(sqlx::query(
            "UPDATE remote_host_promotions SET state = 'abandoned', ended_at = ?1, \
             cleanup = CASE WHEN successor_fingerprint IS NOT NULL THEN 'uninstall' ELSE cleanup END \
             WHERE state IN ('open', 'elevating', 'installing', 'enrolled') AND (?2 OR expires_at <= ?1)",
        )
        .bind(now)
        .bind(all)
        .execute(&self.0)
        .await?
        .rows_affected())
    }

    /// The abandoned successor confirmed it rolled back and removed itself:
    /// revoke its certificate and retire the outbox entry, in one write.
    ///
    /// # Errors
    /// Storage failure only; a duplicate receipt changes nothing.
    pub(crate) async fn confirm_successor_uninstall(
        &self,
        attempt: Uuid,
        now: i64,
    ) -> Result<(), PromotionError> {
        let mut transaction = self.0.begin().await?;
        let changed = sqlx::query(
            "UPDATE remote_host_promotions SET cleanup = 'done' WHERE attempt = ? AND cleanup = 'uninstall'",
        )
        .bind(attempt.as_bytes().as_slice())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 1 {
            sqlx::query(
                "UPDATE remote_certificates SET revoked_at = COALESCE(revoked_at, ?) \
                 WHERE fingerprint = (SELECT successor_fingerprint FROM remote_host_promotions WHERE attempt = ?)",
            )
            .bind(now)
            .bind(attempt.as_bytes().as_slice())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// The predecessor retirement still owed to `host`'s root infraternal
    /// agent, as (promotion, rootless uid), oldest first (R5).
    ///
    /// # Errors
    /// Storage failure only.
    pub(crate) async fn pending_retirement(
        &self,
        host: Uuid,
    ) -> Result<Option<(Uuid, u32)>, PromotionError> {
        let row: Option<(Vec<u8>, i64)> = sqlx::query_as(
            "SELECT attempt, from_uid FROM remote_host_promotions WHERE host_id = ? AND cleanup = 'retire' \
             ORDER BY ended_at LIMIT 1",
        )
        .bind(host.as_bytes().as_slice())
        .fetch_optional(&self.0)
        .await?;
        row.map(|(attempt, uid)| {
            Ok((
                Uuid::from_slice(&attempt).map_err(|_| PromotionError::Denied)?,
                u32::try_from(uid).map_err(|_| PromotionError::Denied)?,
            ))
        })
        .transpose()
    }

    /// Record the install transaction the relay runs for `attempt` (J465 P1),
    /// once, while the row is live. The uninstall outbox needs it to roll
    /// back a journal the relay left open.
    ///
    /// # Errors
    /// `Denied` when the row isn't live or already has another transaction.
    #[cfg(any(feature = "ssh", test))]
    pub(crate) async fn record_install_transaction(
        &self,
        attempt: Uuid,
        transaction: Uuid,
    ) -> Result<(), PromotionError> {
        let changed = sqlx::query(
            "UPDATE remote_host_promotions SET install_transaction = ? WHERE attempt = ? \
             AND install_transaction IS NULL AND state IN ('installing', 'enrolled')",
        )
        .bind(transaction.as_bytes().as_slice())
        .bind(attempt.as_bytes().as_slice())
        .execute(&self.0)
        .await?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(PromotionError::Denied)
        }
    }

    /// The install transaction recorded for `attempt`, if any.
    ///
    /// # Errors
    /// Storage failure only.
    pub(crate) async fn install_transaction(
        &self,
        attempt: Uuid,
    ) -> Result<Option<Uuid>, PromotionError> {
        let stored: Option<Option<Vec<u8>>> = sqlx::query_scalar(
            "SELECT install_transaction FROM remote_host_promotions WHERE attempt = ?",
        )
        .bind(attempt.as_bytes().as_slice())
        .fetch_optional(&self.0)
        .await?;
        Ok(stored
            .flatten()
            .and_then(|bytes| Uuid::from_slice(&bytes).ok()))
    }

    /// The root infraternal agent confirmed the rootless install is retired.
    ///
    /// # Errors
    /// Storage failure only; a duplicate receipt changes nothing.
    pub(crate) async fn confirm_retirement(&self, attempt: Uuid) -> Result<(), PromotionError> {
        sqlx::query(
            "UPDATE remote_host_promotions SET cleanup = 'done' WHERE attempt = ? AND cleanup = 'retire'",
        )
        .bind(attempt.as_bytes().as_slice())
        .execute(&self.0)
        .await?;
        Ok(())
    }
}

/// Abandon one live promotion (see [`EnrollmentStore::abandon_promotion`]).
/// Shared with host removal, which abandons in its own transaction.
#[cfg(any(feature = "ssh", test))]
pub(crate) const ABANDON_WHERE_ATTEMPT: &str = "UPDATE remote_host_promotions SET state = 'abandoned', ended_at = ?, \
     cleanup = CASE WHEN successor_fingerprint IS NOT NULL THEN 'uninstall' ELSE cleanup END \
     WHERE attempt = ? AND state IN ('open', 'elevating', 'installing', 'enrolled')";

/// Abandon a host's live promotion, for host removal's transaction.
pub(crate) const ABANDON_WHERE_HOST: &str = "UPDATE remote_host_promotions SET state = 'abandoned', ended_at = ?, \
     cleanup = CASE WHEN successor_fingerprint IS NOT NULL THEN 'uninstall' ELSE cleanup END \
     WHERE host_id = ? AND state IN ('open', 'elevating', 'installing', 'enrolled')";

/// The method for a stored word.
#[cfg(any(feature = "ssh", test))]
fn parse_method(word: &str) -> Result<Method, PromotionError> {
    [
        Method::SudoNoPassword,
        Method::Sudo,
        Method::Doas,
        Method::Su,
    ]
    .into_iter()
    .find(|method| method.word() == word)
    .ok_or(PromotionError::Denied)
}

/// Real SQLite proofs of the promotion record.
#[cfg(test)]
#[path = "remote_promotion_tests.rs"]
mod tests;
