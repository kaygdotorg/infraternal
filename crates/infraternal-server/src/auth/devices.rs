//! Single-use device approval and exact-scope API key authorization [27,28].
//!
//! Starting an approval is public, so the rows it creates are bounded (#263):
//! expired rows are deleted on every start, the server holds at most
//! [`MAX_PENDING_APPROVALS`] unexpired approvals, and each source network
//! holds at most its [`SOURCE_CAPS`] share. The caps nest (an IPv6 /64, /56
//! and /48; an IPv4 address and /24), so one ordinary allocation cannot fill
//! the server cap and refuse every other `up` (#263, J134 P2-2). The
//! per-source counts live in memory only, so client addresses are never
//! written to the database. A restart forgets them; the server cap still
//! holds because it counts database rows.
use super::{Auth, B64, Engine, Error, Result, Row, Value, hash, json, random, require_session_tx};
use base64::engine::general_purpose::STANDARD_NO_PAD as FingerprintB64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::IpAddr};
use uuid::Uuid;

/// Most unexpired approvals (sign-in and machine join) the server holds at once.
pub(crate) const MAX_PENDING_APPROVALS: i64 = 1024;
/// Most unexpired approvals each enclosing source network may hold, as
/// (prefix length, cap). A person retrying a sign-in or `up` a few times stays
/// well under the innermost cap. A site's /56 or a tunnel broker's /48 holds
/// at most 32, so filling the server cap needs 32 distinct /48s or /24s.
/// Rejected: evicting the oldest uninspected approval at the server cap. A
/// fast flood would then displace a real code in the seconds before its owner
/// opens it, while caps never remove an approval they admitted.
const SOURCE_CAPS: Caps = Caps {
    v6: [(64, 5), (56, 16), (48, 32)],
    v4: [(32, 5), (24, 32)],
};

/// Nested per-network caps for each address family; see [`SOURCE_CAPS`].
struct Caps {
    v6: [(u8, usize); 3],
    v4: [(u8, usize); 2],
}

/// One enclosing network of a caller: its masked address and prefix length.
type Network = (IpAddr, u8);

impl Caps {
    /// Every network enclosing `source` that has a cap, with that cap.
    /// IPv4-mapped IPv6 addresses count as their IPv4 address.
    fn networks(&self, source: IpAddr) -> impl Iterator<Item = (Network, usize)> + '_ {
        let source = crate::runtime::device_source(source);
        let (v6, v4) = match source {
            IpAddr::V6(address) => (Some(u128::from(address)), None),
            IpAddr::V4(address) => (None, Some(u32::from(address))),
        };
        let v6 = v6.into_iter().flat_map(|bits| {
            self.v6.iter().map(move |&(prefix, cap)| {
                let mask = u128::MAX << (128 - u32::from(prefix));
                ((IpAddr::V6((bits & mask).into()), prefix), cap)
            })
        });
        let v4 = v4.into_iter().flat_map(|bits| {
            self.v4.iter().map(move |&(prefix, cap)| {
                let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                ((IpAddr::V4((bits & mask).into()), prefix), cap)
            })
        });
        v6.chain(v4)
    }
}
/// Approval and receipt lifetime in seconds (D311).
const APPROVAL_LIFETIME: i64 = 600;

/// Expiry times of the approvals started inside each capped source network;
/// a network's entry vanishes with its last unexpired approval. Each expiry
/// was admitted under the server cap and is recorded once per enclosing
/// network (at most three), and a row leaves the table before expiry only when
/// an owner approves and redeems its sign-in, so the map tracks the cap.
#[derive(Default)]
pub(super) struct PendingSources(HashMap<Network, Vec<i64>>);

/// Most approval ceremonies waiting for a passkey at once (each lives
/// for one ceremony lifetime). Each person holds at most
/// [`super::webauthn::PER_PERSON_CEREMONIES`] of them.
const MAX_APPROVAL_CEREMONIES: usize = 1024;

/// Approval passkey ceremonies, keyed by ceremony ID. Each is bound to
/// the session that started it and the code it approves.
#[derive(Default)]
pub(super) struct ApprovalCeremonies(pub(super) HashMap<String, ApprovalCeremony>);

pub(super) struct ApprovalCeremony {
    /// `sign_in` or `join_machine`, read when the ceremony started.
    kind: String,
    session_hash: String,
    pub(super) user_id: String,
    code_hash: String,
    expires: i64,
}

/// Public, bounded machine facts shown before a fresh passkey approves enrollment [#263].
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinMachineRequest {
    pub(crate) host_id: Uuid,
    pub(crate) hostname: String,
    pub(crate) mode: String,
    pub(crate) execution_uid: u32,
    pub(crate) key_fingerprint: String,
}

/// A passkey-approved machine request retained only until its ten-minute receipt expires.
pub(crate) struct ApprovedMachineJoin {
    pub(crate) user_id: String,
    pub(crate) session_hash: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) request: JoinMachineRequest,
}

struct ApprovalDraft<'a> {
    token: &'a str,
    code: &'a str,
    kind: &'a str,
    scopes: &'a str,
    device: &'a str,
    request: Option<&'a str>,
    now: i64,
}

impl JoinMachineRequest {
    pub(crate) fn key_digest(&self) -> Result<[u8; 32]> {
        let encoded = self
            .key_fingerprint
            .strip_prefix("SHA256:")
            .ok_or(Error::Invalid)?;
        let decoded = FingerprintB64.decode(encoded).map_err(|_| Error::Invalid)?;
        if decoded.len() != 32 || FingerprintB64.encode(&decoded) != encoded {
            return Err(Error::Invalid);
        }
        decoded.try_into().map_err(|_| Error::Invalid)
    }

    /// The host name is the one fact the owner reads before approving, so it
    /// is exactly the ASCII set `infraternal up` sends: no bidi, zero-width or
    /// look-alike character can make it read as another machine (#263, J134 P3-3).
    fn validate(&self) -> Result<[u8; 32]> {
        if self.hostname.is_empty()
            || self.hostname.len() > 128
            || !self
                .hostname
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || !matches!(self.mode.as_str(), "system" | "user")
            || (self.mode == "system") != (self.execution_uid == 0)
        {
            return Err(Error::Invalid);
        }
        self.key_digest()
    }

    fn fingerprint(&self) -> Result<String> {
        self.key_digest()?;
        Ok(self.key_fingerprint.clone())
    }

    /// Derive one stable, short-lived invitation capability from its exact approval.
    pub(crate) fn receipt_token(&self, poll_token: &str) -> Result<String> {
        let poll_bytes = B64.decode(poll_token).map_err(|_| Error::Denied)?;
        if poll_bytes.len() != 32 || B64.encode(&poll_bytes) != poll_token {
            return Err(Error::Denied);
        }
        let key_digest = self.key_digest()?;
        let mut digest = Sha256::new();
        digest.update(b"infraternal/device-join-receipt/v1\0");
        digest.update(poll_bytes);
        digest.update(self.host_id.as_bytes());
        digest.update(self.mode.as_bytes());
        digest.update(self.execution_uid.to_be_bytes());
        digest.update(key_digest);
        Ok(B64.encode(digest.finalize()))
    }
}

#[allow(clippy::missing_errors_doc)]
impl Auth {
    /// Start device-code approval. Only the high-entropy polling token can redeem approval.
    /// `source` is the caller's trusted address; it is accounted by network.
    pub async fn device_start(
        &self,
        device: &str,
        scopes: Vec<String>,
        source: IpAddr,
        now: i64,
    ) -> Result<Value> {
        if device.is_empty()
            || device.len() > 128
            || scopes.is_empty()
            || scopes.len() > 32
            || scopes.iter().any(|s| {
                !matches!(
                    s.as_str(),
                    "hosts:read" | "terminal:connect" | "actions:dry-run"
                )
            })
        {
            return Err(Error::Invalid);
        }
        let token = random();
        let code = B64.encode(rand::random::<[u8; 12]>());
        let scopes = serde_json::to_string(&scopes)?;
        self.insert_approval(
            ApprovalDraft {
                token: &token,
                code: &code,
                kind: "sign_in",
                scopes: &scopes,
                device,
                request: None,
                now,
            },
            source,
        )
        .await
    }

    /// Start a D311-style fresh-passkey approval that requests one machine identity [#263].
    pub(crate) async fn device_join_start(
        &self,
        device: &str,
        request: JoinMachineRequest,
        source: IpAddr,
        now: i64,
    ) -> Result<Value> {
        if device.is_empty() || device.len() > 128 || now < 0 {
            return Err(Error::Invalid);
        }
        request.validate()?;
        let token = random();
        let code = B64.encode(rand::random::<[u8; 12]>());
        let request = serde_json::to_string(&request)?;
        self.insert_approval(
            ApprovalDraft {
                token: &token,
                code: &code,
                kind: "join_machine",
                scopes: "[]",
                device,
                request: Some(&request),
                now,
            },
            source,
        )
        .await
    }

    /// Store one approval within the pending caps (module docs), deleting expired rows first.
    async fn insert_approval(&self, approval: ApprovalDraft<'_>, source: IpAddr) -> Result<Value> {
        let now = approval.now;
        let expires = now + APPROVAL_LIFETIME;
        // Held across the transaction: concurrent starts cannot both take the last slot.
        let mut sources = self.device_sources.lock().await;
        sources.0.retain(|_, expiries| {
            expiries.retain(|&expiry| expiry > now);
            !expiries.is_empty()
        });
        if SOURCE_CAPS
            .networks(source)
            .any(|(network, cap)| sources.0.get(&network).map_or(0, Vec::len) >= cap)
        {
            return Err(Error::Throttled);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM approvals WHERE expires<=?")
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let pending: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM approvals")
            .fetch_one(&mut *tx)
            .await?;
        if pending >= MAX_PENDING_APPROVALS {
            tx.commit().await?;
            return Err(Error::Throttled);
        }
        sqlx::query(
            "INSERT INTO approvals(token_hash,code_hash,scopes,device,expires,kind,request_json) \
             VALUES (?,?,?,?,?,?,?)",
        )
        .bind(hash(approval.token))
        .bind(hash(approval.code))
        .bind(approval.scopes)
        .bind(approval.device)
        .bind(expires)
        .bind(approval.kind)
        .bind(approval.request)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        for (network, _) in SOURCE_CAPS.networks(source) {
            sources.0.entry(network).or_default().push(expires);
        }
        Ok(
            json!({"poll_token":approval.token,"user_code":approval.code,"expires_in":APPROVAL_LIFETIME}),
        )
    }

    /// Start the passkey ceremony that approves exactly one pending request
    /// (a CLI sign-in, or an inspected machine join), for this session. A
    /// recent login is never enough. D311 ("approval always needs the
    /// passkey") and D333 (approving a key *is* its tap) want a tap for
    /// *this* approval, so a script in the page cannot approve other pending
    /// requests after any login (#263, J134 P3-2, J145 P3-3). Only the owner
    /// may approve a machine join.
    pub(crate) async fn device_approve_start(
        &self,
        session_token: &str,
        code: &str,
        now: i64,
    ) -> Result<Value> {
        let session = self.session(session_token, now).await?;
        let kind: String = sqlx::query_scalar(
            "SELECT kind FROM approvals WHERE code_hash=? AND expires>? AND user_id IS NULL \
             AND (kind='sign_in' OR (kind='join_machine' AND inspect_attempts>0 \
             AND EXISTS(SELECT 1 FROM users WHERE id=? AND owner=1)))",
        )
        .bind(hash(code))
        .bind(now)
        .bind(&session.user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::Denied)?;
        let mut ceremonies = self.approval_ceremonies.lock().await;
        ceremonies.0.retain(|_, ceremony| ceremony.expires > now);
        // One person holds at most a few; their own oldest makes room, and
        // its passkey ceremony goes with it (#263, J161 P3-2).
        let mut mine: Vec<_> = ceremonies
            .0
            .iter()
            .filter(|(_, ceremony)| ceremony.user_id == session.user_id)
            .map(|(id, ceremony)| (ceremony.expires, id.clone()))
            .collect();
        if mine.len() >= super::webauthn::PER_PERSON_CEREMONIES {
            mine.sort_unstable();
            let excess = mine.len() + 1 - super::webauthn::PER_PERSON_CEREMONIES;
            let mut pending = self.pending.lock().await;
            for (_, id) in &mine[..excess] {
                ceremonies.0.remove(id);
                pending.logins.remove(id);
            }
        }
        if ceremonies.0.len() >= MAX_APPROVAL_CEREMONIES {
            return Err(Error::Throttled);
        }
        let start = self.login_start(&session.user_id, now).await?;
        let id = start["ceremony"].as_str().ok_or(Error::Denied)?.to_owned();
        ceremonies.0.insert(
            id,
            ApprovalCeremony {
                kind,
                session_hash: hash(session_token),
                user_id: session.user_id,
                code_hash: hash(code),
                expires: now + super::CEREMONY,
            },
        );
        Ok(start)
    }

    /// Approve the request this ceremony was started for, with the passkey
    /// proof of that same ceremony. The ceremony is single use.
    pub(crate) async fn device_approve_finish(
        &self,
        session_token: &str,
        code: &str,
        ceremony: &str,
        proof: Value,
        now: i64,
    ) -> Result<()> {
        let entry = {
            let mut ceremonies = self.approval_ceremonies.lock().await;
            let bound = ceremonies.0.get(ceremony).ok_or(Error::Denied)?;
            // Another session or another code cannot spend this ceremony, and
            // a mismatch leaves it for the page that started it.
            if bound.session_hash != hash(session_token) || bound.code_hash != hash(code) {
                return Err(Error::Denied);
            }
            ceremonies.0.remove(ceremony).ok_or(Error::Denied)?
        };
        if entry.expires <= now {
            return Err(Error::Denied);
        }
        let verified = self.verify_passkey(ceremony, proof, now).await?;
        if verified.user() != entry.user_id {
            return Err(Error::Denied);
        }
        self.approve_code(
            session_token,
            &entry.user_id,
            code,
            &entry.kind,
            Some(verified.credential()),
            now,
        )
        .await
    }

    /// Approve with no passkey, for tests of what happens after approval
    /// (redemption, key lifetimes). The ceremony itself has its own tests.
    #[cfg(test)]
    pub(crate) async fn approve_without_passkey_for_tests(
        &self,
        session_token: &str,
        code: &str,
        now: i64,
    ) -> Result<()> {
        let session = self.session(session_token, now).await?;
        let kind: String = sqlx::query_scalar("SELECT kind FROM approvals WHERE code_hash=?")
            .bind(hash(code))
            .fetch_optional(&self.pool)
            .await?
            .ok_or(Error::Denied)?;
        self.approve_code(session_token, &session.user_id, code, &kind, None, now)
            .await
    }

    /// Bind one pending approval of `kind` to this live session's person, in
    /// one writer transaction. For a join, `credential` is the passkey that
    /// just signed the bound ceremony; it must still be registered.
    async fn approve_code(
        &self,
        session_token: &str,
        user: &str,
        code: &str,
        kind: &str,
        credential: Option<&str>,
        now: i64,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET name=name WHERE id=?")
            .bind(user)
            .execute(&mut *tx)
            .await?;
        require_session_tx(&mut tx, &hash(session_token), user, now).await?;
        if let Some(credential) = credential
            && !sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM passkeys WHERE id=? AND user_id=?)",
            )
            .bind(credential)
            .bind(user)
            .fetch_one(&mut *tx)
            .await?
        {
            return Err(Error::Denied);
        }
        sqlx::query_scalar::<_, String>(
            "SELECT kind FROM approvals WHERE code_hash=? AND expires>? AND user_id IS NULL \
             AND kind=? AND (kind='sign_in' OR inspect_attempts>0)",
        )
        .bind(hash(code))
        .bind(now)
        .bind(kind)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::Denied)?;
        if kind == "join_machine"
            && !sqlx::query_scalar::<_, bool>("SELECT owner=1 FROM users WHERE id=?")
                .bind(user)
                .fetch_one(&mut *tx)
                .await?
        {
            return Err(Error::Denied);
        }
        if sqlx::query(
            "UPDATE approvals SET user_id=?,approved_session_hash=? \
             WHERE code_hash=? AND expires>? AND user_id IS NULL",
        )
        .bind(user)
        .bind(hash(session_token))
        .bind(hash(code))
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            != 1
        {
            return Err(Error::Denied);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Inspect requested device and scopes before approval (a code alone never grants access).
    pub async fn device_inspect(&self, token: &str, code: &str, now: i64) -> Result<Value> {
        self.session(token, now).await?;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT device,scopes,kind,request_json FROM approvals \
             WHERE code_hash=? AND expires>? \
             AND (kind='sign_in' OR (kind='join_machine' AND inspect_attempts<5))",
        )
        .bind(hash(code))
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(Error::Denied)?;
        let kind: String = row.get("kind");
        if kind == "join_machine"
            && sqlx::query(
                "UPDATE approvals SET inspect_attempts=inspect_attempts+1 \
                 WHERE code_hash=? AND expires>? AND kind='join_machine' AND inspect_attempts<5",
            )
            .bind(hash(code))
            .bind(now)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                != 1
        {
            return Err(Error::Denied);
        }
        let value = match kind.as_str() {
            "sign_in" => json!({
                "device": row.get::<String, _>("device"),
                "scopes": serde_json::from_str::<Value>(row.get("scopes"))?,
            }),
            "join_machine" => {
                let request_json: Option<String> = row.get("request_json");
                let request: JoinMachineRequest =
                    serde_json::from_str(request_json.as_deref().ok_or(Error::Invalid)?)?;
                json!({
                    "kind": "join_machine",
                    "hostname": request.hostname,
                    "mode": request.mode,
                    "key_fingerprint": request.fingerprint()?,
                })
            }
            _ => return Err(Error::Invalid),
        };
        tx.commit().await?;
        Ok(value)
    }

    /// Redeem approval once. The API key is returned only here and stored as a hash.
    pub async fn device_redeem(&self, token: &str, now: i64) -> Result<String> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("DELETE FROM approvals WHERE token_hash=? AND expires>? AND user_id IS NOT NULL AND kind='sign_in' RETURNING user_id,device,scopes")
            .bind(hash(token)).bind(now).fetch_optional(&mut *tx).await?.ok_or(Error::Denied)?;
        let now = api_key_time(&mut tx, now).await?;
        let key = random();
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at) VALUES (?,?,?,?,?,?+(SELECT api_key_lifetime_days*86400 FROM server_settings WHERE id=1))")
            .bind(hash(&key))
            .bind(row.get::<String, _>("user_id"))
            .bind(row.get::<String, _>("device"))
            .bind(row.get::<String, _>("scopes"))
            .bind(now)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(key)
    }

    /// Whether a polling token names an approved machine request rather than sign-in.
    pub(crate) async fn device_join_approved(&self, token: &str, now: i64) -> Result<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM approvals WHERE token_hash=? AND expires>? \
             AND kind='join_machine' AND user_id IS NOT NULL)",
        )
        .bind(hash(token))
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    /// Read a still-live owner approval without consuming its exact-key recovery receipt.
    pub(crate) async fn approved_device_join(
        &self,
        token: &str,
        now: i64,
    ) -> Result<ApprovedMachineJoin> {
        let row = sqlx::query(
            "SELECT user_id,approved_session_hash,request_json,expires FROM approvals \
             WHERE token_hash=? AND expires>? AND kind='join_machine' AND user_id IS NOT NULL",
        )
        .bind(hash(token))
        .bind(now)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(Error::Denied)?;
        let request_json: Option<String> = row.get("request_json");
        let request: JoinMachineRequest =
            serde_json::from_str(request_json.as_deref().ok_or(Error::Invalid)?)?;
        request.validate()?;
        let expires_at = row.get::<i64, _>("expires");
        let issued_at = expires_at.checked_sub(600).ok_or(Error::Invalid)?;
        Ok(ApprovedMachineJoin {
            user_id: row.get("user_id"),
            session_hash: row
                .get::<Option<String>, _>("approved_session_hash")
                .ok_or(Error::Denied)?,
            issued_at,
            expires_at,
            request,
        })
    }

    /// Validate a CLI/MCP key for one explicit scope; no browser session or fresh-tap privilege.
    pub async fn api_authorize(&self, token: &str, scope: &str) -> Result<String> {
        let token_hash = hash(token);
        // Serialize expiry, policy clamping, renewal and revocation. A dead row
        // remains dead even if the owner subsequently lengthens the policy.
        let mut tx = infraternal_plugin_api::storage::begin_immediate(&self.pool).await?;
        let row = sqlx::query("SELECT user_id,scopes,renewed_at,expires_at,dead,api_key_lifetime_days FROM api_keys CROSS JOIN server_settings WHERE server_settings.id=1 AND token_hash=?")
            .bind(&token_hash).fetch_optional(&mut *tx).await?;
        // Sample only after acquiring the writer and reading the key: pool or
        // lock waits must not carry a pre-expiry timestamp into renewal.
        let now = api_key_time(&mut tx, super::http::current_time(self)?).await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Err(Error::Denied);
        };
        let renewed_at: i64 = row.get("renewed_at");
        let stored_expiry: i64 = row.get("expires_at");
        let lifetime = row.get::<i64, _>("api_key_lifetime_days") * 86400;
        let deadline = stored_expiry.min(renewed_at + lifetime);
        if row.get::<bool, _>("dead") || deadline <= now {
            sqlx::query("UPDATE api_keys SET dead=1,expires_at=? WHERE token_hash=? AND dead=0")
                .bind(deadline)
                .bind(&token_hash)
                .execute(&mut *tx)
                .await?;
            // Denial must commit the tombstone, rather than roll it back.
            tx.commit().await?;
            return Err(Error::Denied);
        }
        let scopes: Vec<String> = serde_json::from_str(row.get("scopes"))?;
        let allowed = scopes.iter().any(|s| s == scope);
        if allowed && now.saturating_sub(renewed_at) >= 3600 {
            sqlx::query(
                "UPDATE api_keys SET renewed_at=?,expires_at=? WHERE token_hash=? AND dead=0",
            )
            .bind(now)
            .bind(now + lifetime)
            .bind(&token_hash)
            .execute(&mut *tx)
            .await?;
        } else if deadline < stored_expiry {
            // A shorter policy is permanent for this key until a valid renewal.
            sqlx::query("UPDATE api_keys SET expires_at=? WHERE token_hash=? AND dead=0")
                .bind(deadline)
                .bind(&token_hash)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        if !allowed {
            return Err(Error::Denied);
        }
        Ok(row.get("user_id"))
    }

    /// Revoke an API key belonging to this user after a fresh tap.
    pub async fn api_revoke(&self, session_token: &str, key_hash: &str, now: i64) -> Result<()> {
        let session = self.session(session_token, now).await?;
        session.require_fresh(now)?;
        sqlx::query("DELETE FROM api_keys WHERE token_hash=? AND user_id=?")
            .bind(key_hash)
            .bind(session.user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// List revocable API key identifiers without returning any bearer secret.
    pub async fn api_list(&self, token: &str, now: i64) -> Result<Value> {
        let session = self.session(token, now).await?;
        let rows = sqlx::query("SELECT token_hash,device,scopes FROM api_keys WHERE user_id=?")
            .bind(session.user_id)
            .fetch_all(&self.pool)
            .await?;
        let keys: Vec<Value> = rows.iter().map(|r| Ok(json!({"id":r.get::<String,_>("token_hash"),"device":r.get::<String,_>("device"),"scopes":serde_json::from_str::<Value>(r.get("scopes"))?}))).collect::<Result<_>>()?;
        Ok(json!(keys))
    }
}

/// The writer transaction serializes the persisted high-water mark with expiry.
/// Only a new maximum writes; rollback and restart cannot make expiry time regress.
pub(super) async fn api_key_time(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    wall: i64,
) -> Result<i64> {
    let recorded: i64 =
        sqlx::query_scalar("SELECT api_key_time_high_water FROM server_settings WHERE id=1")
            .fetch_one(&mut **tx)
            .await?;
    if wall > recorded {
        sqlx::query("UPDATE server_settings SET api_key_time_high_water=? WHERE id=1")
            .bind(wall)
            .execute(&mut **tx)
            .await?;
    }
    Ok(wall.max(recorded))
}
