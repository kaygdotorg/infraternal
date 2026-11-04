//! Single-use registration/login ceremonies, verified metadata and writer-locked counters [24,28].
use super::{
    Auth, Authority, B64, CEREMONY, Engine, Error, Login, LoginState, Passkey, Pending,
    PublicKeyCredential, RegisterPublicKeyCredential, Registration, Result, Row, TapAction, Uuid,
    Value, Wrap, action_tap, constant_prf_input, hash, insert_session, json, prf_salt, put_wrap,
    random, recovery_hash, require_tap_tx, setup::valid_username,
};

// The successful verifier retains its counter transaction until the caller
// publishes a session or commits a proof-only operation. Cancellation rolls it back.
struct VerifiedLogin {
    tx: sqlx::Transaction<'static, sqlx::Sqlite>,
    user: String,
    credential: String,
    expires: i64,
    action: Option<String>,
}

#[allow(clippy::missing_errors_doc)]
impl Auth {
    pub(super) async fn registration(
        &self,
        user: String,
        username: &str,
        display_name: &str,
        authority: Authority,
        rotate: bool,
        now: i64,
    ) -> Result<Value> {
        if !valid_username(username) || display_name.chars().count() > 64 {
            return Err(Error::Invalid);
        }
        let keys = self.passkeys(&user).await?;
        if matches!(authority, Authority::Add(_)) && keys.len() >= 2 {
            return Err(Error::Denied);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_registration(
                Uuid::parse_str(&user).map_err(|_| Error::Invalid)?,
                username,
                display_name,
                Some(keys.iter().map(|k| k.cred_id().clone()).collect()),
            )
            .map_err(|_| Error::Webauthn)?;
        let mut options = serde_json::to_value(options)?;
        // Residence and PRF support are browser properties, not signed security claims.
        // UV, RP, origin, challenge, signature and counters are enforced by webauthn-rs.
        options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
        options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(true);
        options["publicKey"]["extensions"]["prf"] = json!({"eval":{"first":constant_prf_input()}});
        // Recovery entropy is generated only by the browser. Legacy fixtures inject
        // an old hash explicitly in tests; no production ceremony creates words.
        let recovery_hash = None;
        let id = random();
        let mut pending = self.pending.lock().await;
        prune(&mut pending, now);
        if pending.registrations.len() + pending.logins.len() >= 1024 {
            return Err(Error::Denied);
        }
        pending.registrations.insert(
            id.clone(),
            Registration {
                state,
                user: user.clone(),
                username: username.into(),
                display_name: display_name.into(),
                authority,
                recovery_hash,
                rotate_recovery: rotate,
                expires: now + CEREMONY,
                binding: None,
            },
        );
        Ok(
            json!({"ceremony":id,"user_id":user,"options":options,"recovery_words":null,"recovery_version":2}),
        )
    }

    /// Finish registration and atomically install mandatory passkey/recovery envelopes.
    pub async fn registration_finish(
        &self,
        id: &str,
        proof: Value,
        passkey_wrap: Wrap,
        recovery_wrap: Option<Wrap>,
        now: i64,
    ) -> Result<String> {
        self.registration_finish_with_verifier(id, proof, passkey_wrap, recovery_wrap, None, now)
            .await
    }

    /// Install only a browser authentication secret; recovery wrapping material stays local.
    #[allow(clippy::too_many_arguments)]
    pub async fn registration_finish_with_verifier(
        &self,
        id: &str,
        proof: Value,
        passkey_wrap: Wrap,
        recovery_wrap: Option<Wrap>,
        verifier: Option<String>,
        now: i64,
    ) -> Result<String> {
        self.registration_finish_clock(id, proof, passkey_wrap, recovery_wrap, verifier, || Ok(now))
            .await
    }

    // HTTP supplies live authority time; library callers keep deterministic clocks.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)] // Keep all registration authority consumption in one writer transaction.
    pub(super) async fn registration_finish_clock(
        &self,
        id: &str,
        proof: Value,
        passkey_wrap: Wrap,
        recovery_wrap: Option<Wrap>,
        verifier: Option<String>,
        clock: impl Fn() -> Result<i64>,
    ) -> Result<String> {
        let now = clock()?;
        let mut registration = self
            .pending
            .lock()
            .await
            .registrations
            .remove(id)
            .ok_or(Error::Denied)?;
        let setup_consumed = matches!(&registration.authority, Authority::Setup(_));
        if registration.expires <= now {
            return Err(Error::Denied);
        }
        let (key, aaguid) = self.validated_registration(
            &registration,
            proof,
            &passkey_wrap,
            recovery_wrap.as_ref(),
        )?;
        let version = registration.install_verifier(verifier).await?;
        let mut tx = self.pool.begin().await?;
        // A write first obtains SQLite's writer lock before any security-sensitive read.
        sqlx::query("UPDATE setup SET expires=expires WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        // Hashing and writer contention can outlive any admission timestamp. Sample
        // again under the writer lock; SQLite also checks the consuming statement.
        let now: i64 = sqlx::query_scalar("SELECT MAX(?,unixepoch())")
            .bind(clock()?)
            .fetch_one(&mut *tx)
            .await?;
        if registration.expires <= now {
            return Err(Error::Denied);
        }
        match &registration.authority {
            Authority::Setup(token) => {
                if sqlx::query("DELETE FROM setup WHERE token_hash=? AND expires>MAX(?,unixepoch()) AND ?>MAX(?,unixepoch())")
                    .bind(token)
                    .bind(now)
                    .bind(registration.expires)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                    != 1
                {
                    return Err(Error::Denied);
                }
                let username_exists: bool =
                    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username=?)")
                        .bind(&registration.username)
                        .fetch_one(&mut *tx)
                        .await?;
                if username_exists {
                    return Err(Error::Conflict);
                }
                sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name,recovery_version,recovery_wrap_version) VALUES (?,?,1,?,?,?,?,?)")
                    .bind(&registration.user)
                    .bind(&registration.display_name)
                    .bind(registration.recovery_hash.as_ref().ok_or(Error::Invalid)?)
                    .bind(&registration.username)
                    .bind(&registration.display_name)
                    .bind(version).bind(version)
                    .execute(&mut *tx)
                    .await?;
            }
            Authority::Add(session) => {
                // `add_start` spent this session's `passkey.add` tap; the new authenticator may
                // take longer than the tap window, so the finish checks the spend, not freshness.
                action_tap::tap_spent_on_tx(
                    &mut tx,
                    session,
                    &registration.user,
                    &TapAction::AddPasskey,
                    now,
                )
                .await?;
                let count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM passkeys WHERE user_id=?")
                        .bind(&registration.user)
                        .fetch_one(&mut *tx)
                        .await?;
                if count >= 2 {
                    return Err(Error::Denied);
                }
            }
            Authority::Recovery(token) => {
                super::recovery::complete(
                    self,
                    &mut tx,
                    &registration.user,
                    token,
                    registration.recovery_hash.as_ref().ok_or(Error::Invalid)?,
                    version,
                    now,
                    registration.expires,
                )
                .await?;
            }
        }
        let user = &registration.user;
        let key_id = store_passkey(&mut tx, user, &key, aaguid.as_deref()).await?;
        put_wrap(&mut tx, user, "passkey", &key_id, &passkey_wrap).await?;
        if let Some(w) = recovery_wrap {
            put_wrap(&mut tx, user, "recovery", "recovery", &w).await?;
        }
        let token = random();
        insert_session(&mut tx, &token, user, "enrollment", now, Some(&key_id)).await?;
        if matches!(registration.authority, Authority::Recovery(_)) {
            self.recovery_changes
                .commit(tx, user, Some(self.revocations.clone()))
                .await?;
        } else {
            tx.commit().await?;
        }
        if setup_consumed {
            self.setup_consumed.send_replace(());
        }
        Ok(token)
    }

    /// Validate proof and envelope shapes before any database mutation.
    fn validated_registration(
        &self,
        registration: &Registration,
        proof: Value,
        passkey_wrap: &Wrap,
        recovery_wrap: Option<&Wrap>,
    ) -> Result<(Passkey, Option<String>)> {
        reject_prf(&proof)?;
        passkey_wrap.validate()?;
        if let Some(w) = recovery_wrap {
            w.validate()?;
        }
        if registration.rotate_recovery != recovery_wrap.is_some() {
            return Err(Error::Invalid);
        }
        let proof: RegisterPublicKeyCredential = serde_json::from_value(proof)?;
        if proof.type_ != "public-key" {
            return Err(Error::Denied);
        }
        let key = self
            .webauthn
            .finish_passkey_registration(&proof, &registration.state)
            .map_err(|_| Error::Webauthn)?;
        // Metadata is projected only from a proof the verifier has already accepted.
        let aaguid = registration_aaguid(&proof)?;
        Ok((key, aaguid))
    }

    pub(super) async fn passkeys(&self, user: &str) -> Result<Vec<Passkey>> {
        sqlx::query_scalar::<_, String>("SELECT credential FROM passkeys WHERE user_id=?")
            .bind(user)
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|v| serde_json::from_str(&v).map_err(Error::from))
            .collect()
    }

    /// Begin a UV-required login, with no per-action authority.
    pub async fn login_start(&self, user: &str, now: i64) -> Result<Value> {
        self.login_start_for(user, None, now).await
    }

    /// Begin a UV-required login whose tap is also bound to `action` (`action_tap`, D336).
    pub(crate) async fn login_start_for(
        &self,
        user: &str,
        action: Option<&TapAction>,
        now: i64,
    ) -> Result<Value> {
        let action = bound(action)?;
        // One read binds each allowed credential to its wrapping input. Separate reads
        // could race enrollment/recovery and also add an unnecessary storage round trip.
        let inputs = sqlx::query("SELECT id,credential,prf_input FROM passkeys WHERE user_id=?")
            .bind(user)
            .fetch_all(&self.pool)
            .await?;
        let keys: Vec<Passkey> = inputs
            .iter()
            .map(|row| serde_json::from_str(row.get("credential")).map_err(Error::from))
            .collect::<Result<_>>()?;
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&keys)
            .map_err(|_| Error::Denied)?;
        let mut options = serde_json::to_value(options)?;
        let evaluations: serde_json::Map<String, Value> = inputs
            .iter()
            .map(|row| {
                let input = row
                    .get::<Option<String>, _>("prf_input")
                    .unwrap_or_else(|| prf_salt(None));
                (row.get("id"), json!({"first":input}))
            })
            .collect();
        let first = evaluations.values().next().ok_or(Error::Denied)?;
        let prf = if evaluations.values().all(|input| input == first) {
            json!({"eval":first})
        } else {
            // With an identified allow-list WebAuthn permits credential-specific inputs.
            json!({"evalByCredential":evaluations})
        };
        options["publicKey"]["extensions"] = json!({"prf":prf});
        let id = random();
        let mut pending = self.pending.lock().await;
        prune(&mut pending, now);
        if pending.registrations.len() + pending.logins.len() >= 1024 {
            return Err(Error::Denied);
        }
        pending.logins.insert(
            id.clone(),
            Login {
                state: LoginState::Identified(state, user.into()),
                expires: now + CEREMONY,
                binding: None,
                action,
            },
        );
        Ok(json!({"ceremony":id,"options":options}))
    }

    /// Start identity-free UV authentication without publishing any credential list.
    pub async fn discoverable_login_start(&self, now: i64) -> Result<Value> {
        self.discoverable_login_start_for(None, now).await
    }

    /// Identity-free login whose tap is also bound to `action` (`action_tap`, D336).
    pub(crate) async fn discoverable_login_start_for(
        &self,
        action: Option<&TapAction>,
        now: i64,
    ) -> Result<Value> {
        let action = bound(action)?;
        let (options, state) = self
            .webauthn
            .start_discoverable_authentication()
            .map_err(|_| Error::Webauthn)?;
        let mut options = serde_json::to_value(options)?;
        // A button-triggered ceremony uses the normal browser prompt, not conditional UI.
        options
            .as_object_mut()
            .ok_or(Error::Json)?
            .remove("mediation");
        options["publicKey"]["allowCredentials"] = json!([]);
        options["publicKey"]["extensions"] = json!({"prf":{"eval":{"first":constant_prf_input()}}});
        let id = random();
        let mut pending = self.pending.lock().await;
        prune(&mut pending, now);
        if pending.registrations.len() + pending.logins.len() >= 1024 {
            return Err(Error::Denied);
        }
        pending.logins.insert(
            id.clone(),
            Login {
                state: LoginState::Discoverable(state),
                expires: now + CEREMONY,
                binding: None,
                action,
            },
        );
        Ok(json!({"ceremony":id,"options":options}))
    }

    /// Validate a signature and counters before issuing a fresh opaque device session.
    pub async fn login_finish(
        &self,
        id: &str,
        proof: Value,
        device: &str,
        now: i64,
    ) -> Result<String> {
        self.finish_login(id, proof, device, now, false).await
    }

    /// HTTP login grants only envelope access until a successful local unwrap is confirmed.
    pub(super) async fn pending_login_finish(
        &self,
        id: &str,
        proof: Value,
        device: &str,
        now: i64,
    ) -> Result<String> {
        self.finish_login(id, proof, device, now, true).await
    }

    async fn finish_login(
        &self,
        id: &str,
        proof: Value,
        device: &str,
        now: i64,
        pending_unlock: bool,
    ) -> Result<String> {
        let VerifiedLogin {
            mut tx,
            user,
            credential,
            action,
            ..
        } = self.verified_login(id, proof, device, now).await?;
        let token = random();
        insert_session(&mut tx, &token, &user, device, now, Some(&credential)).await?;
        if let Some(action) = action {
            // The new session carries the one action this tap was made for (D336).
            sqlx::query("UPDATE sessions SET tap_action=? WHERE token_hash=?")
                .bind(action)
                .bind(hash(&token))
                .execute(&mut *tx)
                .await?;
        }
        if pending_unlock {
            sqlx::query("UPDATE sessions SET unlocked=0,expires=? WHERE token_hash=?")
                .bind(now + CEREMONY)
                .bind(hash(&token))
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(token)
    }

    // Reuse exactly the signed-proof, registered-credential and monotone-counter
    // checks for operations that must not create a browser session. The caller
    // keeps this writer transaction until committing its own resulting authority.
    async fn verified_login(
        &self,
        id: &str,
        proof: Value,
        device: &str,
        now: i64,
    ) -> Result<VerifiedLogin> {
        let login = self
            .pending
            .lock()
            .await
            .logins
            .remove(id)
            .ok_or(Error::Denied)?;
        if login.expires <= now || device.is_empty() || device.len() > 128 {
            return Err(Error::Denied);
        }
        reject_prf(&proof)?;
        let proof: PublicKeyCredential = serde_json::from_value(proof)?;
        if proof.type_ != "public-key" {
            return Err(Error::Denied);
        }
        let expires = login.expires;
        let action = login.action.clone();
        let user = match &login.state {
            LoginState::Identified(_, user) => {
                if proof.get_user_unique_id().is_some_and(|handle| {
                    Uuid::parse_str(user).map_or(true, |id| handle != id.as_bytes())
                }) {
                    return Err(Error::Denied);
                }
                user.clone()
            }
            LoginState::Discoverable(_) => self
                .webauthn
                .identify_discoverable_authentication(&proof)
                .map_err(|_| Error::Denied)?
                .0
                .to_string(),
        };
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE users SET name=name WHERE id=?")
            .bind(&user)
            .execute(&mut *tx)
            .await?;
        // The unsigned handle selects a candidate only. Under the writer lock require
        // this exact credential to belong to that user before verifying its signature.
        let row = sqlx::query("SELECT id,credential FROM passkeys WHERE user_id=? AND id=?")
            .bind(&user)
            .bind(B64.encode(proof.get_credential_id()))
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(Error::Denied)?;
        let mut key: Passkey = serde_json::from_str(row.get("credential"))?;
        let result = match login.state {
            LoginState::Identified(state, _) => {
                self.webauthn.finish_passkey_authentication(&proof, &state)
            }
            LoginState::Discoverable(state) => {
                self.webauthn
                    .finish_discoverable_authentication(&proof, state, &[(&key).into()])
            }
        }
        .map_err(|_| Error::Denied)?;
        // Nonzero counters are monotonic; synced authenticators legitimately use zero.
        // The pinned verifier serializes this private counter under cred.counter; a schema
        // change fails closed here and must pass the stale-counter regression test.
        let previous = serde_json::to_value(&key)?;
        let counter = previous["cred"]["counter"].as_u64().ok_or(Error::Invalid)?;
        if (counter != 0 || result.counter() != 0) && u64::from(result.counter()) <= counter {
            return Err(Error::Denied);
        }
        key.update_credential(&result).ok_or(Error::Denied)?;
        sqlx::query("UPDATE passkeys SET credential=? WHERE id=?")
            .bind(serde_json::to_string(&key)?)
            .bind(row.get::<String, _>("id"))
            .execute(&mut *tx)
            .await?;
        let credential = row.get("id");
        Ok(VerifiedLogin {
            tx,
            user,
            credential,
            expires,
            action,
        })
    }

    /// Verify a real, single-use passkey proof without creating a browser session.
    /// The result grants no CA or role authority; callers recheck current policy
    /// and the registered credential under their own final writer transaction.
    /// # Errors
    /// Refuses invalid, expired or replayed proofs and stale credential counters.
    pub async fn verify_passkey(
        &self,
        id: &str,
        proof: Value,
        now: i64,
    ) -> Result<super::VerifiedPasskey> {
        self.verify_passkey_clock(id, proof, || {
            let wall = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|time| i64::try_from(time.as_secs()).ok())
                .ok_or(Error::Invalid)?;
            Ok(now.max(wall))
        })
        .await
    }

    // Re-read the clock after awaited writer admission; tests advance this same
    // boundary deterministically instead of waiting for a five-minute ceremony.
    pub(crate) async fn verify_passkey_clock(
        &self,
        id: &str,
        proof: Value,
        clock: impl Fn() -> Result<i64>,
    ) -> Result<super::VerifiedPasskey> {
        let initial = clock()?;
        let VerifiedLogin {
            tx,
            user,
            credential,
            expires,
            // A CA ceremony is started by `ca_administration` with no auth action; any
            // action on a login ceremony is spent only by `login_finish`.
            action: _,
        } = self
            .verified_login(id, proof, "passkey operation", initial)
            .await?;
        let verified_at = clock()?.max(initial);
        if expires <= verified_at {
            return Err(Error::Denied);
        }
        tx.commit().await?;
        Ok(super::VerifiedPasskey {
            user,
            credential,
            verified_at,
            expires,
        })
    }

    /// Enroll the optional second passkey; spends this session's `passkey.add` tap (D336).
    pub async fn add_start(&self, token: &str, now: i64) -> Result<Value> {
        let session = self.session(token, now).await?;
        let mut tx = self.pool.begin().await?;
        require_tap_tx(
            &mut tx,
            &hash(token),
            &session.user_id,
            &TapAction::AddPasskey,
            now,
        )
        .await?;
        tx.commit().await?;
        let identity = sqlx::query("SELECT username,display_name FROM users WHERE id=?")
            .bind(&session.user_id)
            .fetch_one(&self.pool)
            .await?;
        self.registration(
            session.user_id,
            identity.get("username"),
            identity.get("display_name"),
            Authority::Add(hash(token)),
            false,
            now,
        )
        .await
    }
}

/// Validate a ceremony's action and keep only its digest on the pending login.
fn bound(action: Option<&TapAction>) -> Result<Option<String>> {
    action
        .map(|action| action.validate().map(|()| action_tap::digest(action)))
        .transpose()
}

pub(super) fn prune(p: &mut Pending, now: i64) {
    p.registrations.retain(|_, r| r.expires > now);
    p.logins.retain(|_, l| l.expires > now);
}
pub(super) fn reject_prf(proof: &Value) -> Result<()> {
    let object = proof.as_object().ok_or(Error::Invalid)?;
    if object.keys().any(|k| {
        !matches!(
            k.as_str(),
            "id" | "rawId" | "type" | "response" | "extensions" | "clientExtensionResults"
        )
    }) {
        return Err(Error::Invalid);
    }
    let response = proof["response"].as_object().ok_or(Error::Invalid)?;
    if response.keys().any(|k| {
        !matches!(
            k.as_str(),
            "clientDataJSON"
                | "attestationObject"
                | "transports"
                | "authenticatorData"
                | "signature"
                | "userHandle"
        )
    }) {
        return Err(Error::Invalid);
    }
    for field in ["extensions", "clientExtensionResults"] {
        if let Some(e) = proof.get(field)
            && e.as_object()
                .ok_or(Error::Invalid)?
                .keys()
                .any(|k| !matches!(k.as_str(), "credProps" | "appid"))
        {
            return Err(Error::Invalid);
        }
    }
    // Finish requests must omit ALL PRF results, including base64-encoded output.
    if proof.get("extensions").and_then(|e| e.get("prf")).is_some()
        || proof
            .get("clientExtensionResults")
            .and_then(|e| e.get("prf"))
            .is_some()
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// Persist the verifier-owned credential and the exact input used to wrap its DEK.
async fn store_passkey(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    user: &str,
    key: &Passkey,
    aaguid: Option<&str>,
) -> Result<String> {
    let id = B64.encode(key.cred_id().as_ref());
    sqlx::query("INSERT INTO passkeys(id,user_id,credential,prf_input,aaguid) VALUES (?,?,?,?,?)")
        .bind(&id)
        .bind(user)
        .bind(serde_json::to_string(key)?)
        .bind(constant_prf_input())
        .bind(aaguid)
        .execute(&mut **tx)
        .await?;
    Ok(id)
}

/// Extract only after webauthn-rs accepts the complete registration proof.
/// Passkey in pinned webauthn-rs 0.5.5 discards AAGUID for `none` attestation.
/// Zero values are privacy redaction, not a provider identity. This deliberately
/// reuses the existing CBOR engine instead of implementing another CBOR parser.
pub(super) fn registration_aaguid(proof: &RegisterPublicKeyCredential) -> Result<Option<String>> {
    let value: serde_cbor_2::Value =
        serde_cbor_2::from_slice(proof.response.attestation_object.as_ref())
            .map_err(|_| Error::Invalid)?;
    let serde_cbor_2::Value::Map(fields) = value else {
        return Err(Error::Invalid);
    };
    let Some(serde_cbor_2::Value::Bytes(data)) =
        fields.get(&serde_cbor_2::Value::Text("authData".into()))
    else {
        return Err(Error::Invalid);
    };
    // WebAuthn authData: rpIdHash[32], flags[1], signCount[4], AAGUID[16].
    // The verifier already validated AT, credential ID, COSE key and all lengths.
    if data.get(32).is_none_or(|flags| flags & 0x40 == 0) {
        return Err(Error::Invalid);
    }
    let id =
        Uuid::from_slice(data.get(37..53).ok_or(Error::Invalid)?).map_err(|_| Error::Invalid)?;
    Ok((!id.is_nil()).then(|| id.to_string()))
}

impl Registration {
    // Hash outside the writer lock; mandatory recovery envelopes require a verifier.
    async fn install_verifier(&mut self, verifier: Option<String>) -> Result<i64> {
        if let Some(verifier) = verifier {
            if !self.rotate_recovery {
                return Err(Error::Invalid);
            }
            super::crypto::valid_secret(&verifier)?;
            self.recovery_hash = Some(recovery_hash(verifier).await?);
            Ok(2)
        } else {
            // Explicit test-only legacy fixtures can inject an old PHC hash. Every
            // production rotating ceremony instead requires the browser secret.
            if self.rotate_recovery && self.recovery_hash.is_none() {
                return Err(Error::Invalid);
            }
            Ok(1)
        }
    }
}
