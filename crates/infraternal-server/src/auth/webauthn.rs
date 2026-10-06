//! Single-use registration/login ceremonies, ownership and writer-locked counters [24,28].
use super::{
    Auth, Authority, B64, CEREMONY, Engine, Error, Passkey, Pending, RegisterPublicKeyCredential,
    Registration, Result, Uuid, Value, Wrap, insert_session, json, prf_salt, put_wrap, random,
    recovery_hash,
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
        options["publicKey"]["extensions"]["prf"] = json!({"eval":{"first":prf_salt()}});
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
        if pending.registrations.len() >= 1024 {
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
        let key_id = B64.encode(key.cred_id().as_ref());
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
        }
        sqlx::query("INSERT INTO passkeys(id,user_id,credential) VALUES (?,?,?)")
            .bind(&key_id)
            .bind(&registration.user)
            .bind(serde_json::to_string(&key)?)
            .execute(&mut *tx)
            .await?;
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
}

pub(super) fn prune(p: &mut Pending, now: i64) {
    p.registrations.retain(|_, r| r.expires > now);
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
