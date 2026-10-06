//! Single-use registration/login ceremonies, ownership and writer-locked counters [24,28].
use super::{
    Auth, Authority, B64, CEREMONY, Engine, Error, Login, LoginState, Passkey, Pending,
    PublicKeyCredential, RegisterPublicKeyCredential, Registration, Result, Row, Uuid, Value, Wrap,
    hash, insert_session, json, prf_salt, put_wrap, random, recovery_hash, require_session_tx,
};

#[allow(clippy::missing_errors_doc)]
impl Auth {
    pub(super) async fn registration(
        &self,
        user: String,
        name: &str,
        authority: Authority,
        rotate: bool,
        now: i64,
    ) -> Result<Value> {
        if name.is_empty() || name.len() > 128 {
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
                name,
                name,
                Some(keys.iter().map(|k| k.cred_id().clone()).collect()),
            )
            .map_err(|_| Error::Webauthn)?;
        let mut options = serde_json::to_value(options)?;
        // Residence and PRF support are browser properties, not signed security claims.
        // UV, RP, origin, challenge, signature and counters are enforced by webauthn-rs.
        options["publicKey"]["authenticatorSelection"]["residentKey"] = json!("required");
        options["publicKey"]["authenticatorSelection"]["requireResidentKey"] = json!(true);
        options["publicKey"]["extensions"]["prf"] = json!({"eval":{"first":prf_salt(Some(&user))}});
        let words = if rotate {
            Some(
                bip39::Mnemonic::generate_in(bip39::Language::English, 24)
                    .map_err(|_| Error::Invalid)?
                    .to_string(),
            )
        } else {
            None
        };
        let recovery_hash = match &words {
            Some(w) => Some(recovery_hash(w.clone()).await?),
            None => None,
        };
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
                name: name.into(),
                authority,
                recovery_hash,
                expires: now + CEREMONY,
            },
        );
        Ok(json!({"ceremony":id,"user_id":user,"options":options,"recovery_words":words}))
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
        let registration = self
            .pending
            .lock()
            .await
            .registrations
            .remove(id)
            .ok_or(Error::Denied)?;
        if registration.expires <= now {
            return Err(Error::Denied);
        }
        reject_prf(&proof)?;
        passkey_wrap.validate()?;
        if let Some(w) = &recovery_wrap {
            w.validate()?;
        }
        if registration.recovery_hash.is_some() != recovery_wrap.is_some() {
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
        let mut tx = self.pool.begin().await?;
        // A write first obtains SQLite's writer lock before any security-sensitive read.
        sqlx::query("UPDATE setup SET expires=expires WHERE singleton=1")
            .execute(&mut *tx)
            .await?;
        match &registration.authority {
            Authority::Setup(token) => {
                if sqlx::query("DELETE FROM setup WHERE token_hash=? AND expires>?")
                    .bind(token)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected()
                    != 1
                {
                    return Err(Error::Denied);
                }
                sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES (?,?,1,?)")
                    .bind(&registration.user)
                    .bind(&registration.name)
                    .bind(registration.recovery_hash.as_ref().ok_or(Error::Invalid)?)
                    .execute(&mut *tx)
                    .await?;
            }
            Authority::Add(session) => {
                require_session_tx(&mut tx, session, &registration.user, now).await?;
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
                if sqlx::query("DELETE FROM recovery WHERE user_id=? AND token_hash=? AND ready<=? AND expires>?")
                    .bind(&registration.user).bind(token).bind(now).bind(now).execute(&mut *tx).await?.rows_affected() != 1 { return Err(Error::Denied); }
                for table in ["sessions", "api_keys", "approvals", "passkeys", "wraps"] {
                    sqlx::query(&format!("DELETE FROM {table} WHERE user_id=?"))
                        .bind(&registration.user)
                        .execute(&mut *tx)
                        .await?;
                }
                sqlx::query("UPDATE users SET recovery_hash=? WHERE id=?")
                    .bind(registration.recovery_hash.as_ref().ok_or(Error::Invalid)?)
                    .bind(&registration.user)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        let key_id = store_passkey(&mut tx, &registration.user, &key).await?;
        put_wrap(
            &mut tx,
            &registration.user,
            "passkey",
            &key_id,
            &passkey_wrap,
        )
        .await?;
        if let Some(w) = recovery_wrap {
            put_wrap(&mut tx, &registration.user, "recovery", "recovery", &w).await?;
        }
        let token = random();
        insert_session(&mut tx, &token, &registration.user, "enrollment", now).await?;
        tx.commit().await?;
        Ok(token)
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

    /// Begin a UV-required login (also the fresh-tap ceremony).
    pub async fn login_start(&self, user: &str, now: i64) -> Result<Value> {
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
            },
        );
        Ok(json!({"ceremony":id,"options":options}))
    }

    /// Start identity-free UV authentication without publishing any credential list.
    pub async fn discoverable_login_start(&self, now: i64) -> Result<Value> {
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
        options["publicKey"]["extensions"] = json!({});
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
        let token = random();
        insert_session(&mut tx, &token, &user, device, now).await?;
        tx.commit().await?;
        Ok(token)
    }

    /// Enroll the optional second passkey after a fresh tap.
    pub async fn add_start(&self, token: &str, now: i64) -> Result<Value> {
        let session = self.session(token, now).await?;
        session.require_fresh(now)?;
        let name: String = sqlx::query_scalar("SELECT name FROM users WHERE id=?")
            .bind(&session.user_id)
            .fetch_one(&self.pool)
            .await?;
        self.registration(
            session.user_id,
            &name,
            Authority::Add(hash(token)),
            false,
            now,
        )
        .await
    }
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
) -> Result<String> {
    let id = B64.encode(key.cred_id().as_ref());
    sqlx::query("INSERT INTO passkeys(id,user_id,credential,prf_input) VALUES (?,?,?,?)")
        .bind(&id)
        .bind(user)
        .bind(serde_json::to_string(key)?)
        .bind(prf_salt(Some(user)))
        .execute(&mut **tx)
        .await?;
    Ok(id)
}
