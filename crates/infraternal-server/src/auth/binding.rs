//! HTTP transaction binding keeps a signed ceremony in the browser that started it [24,53].
use super::{Auth, Error, Result, hash, random};
use axum::http::{HeaderMap, HeaderValue};

/// Name prefix of the ceremony-binding cookie. The `__Host-` prefix makes browsers
/// accept it only over HTTPS, with `Path=/` and no `Domain`, so a sibling
/// subdomain cannot plant or overwrite it.
const COOKIE: &str = "__Host-infraternal-ceremony=";

/// Returns the binding token the browser sent, or `None` when the cookie is
/// missing, duplicated, or not a well-formed 43-character token. A duplicate is
/// treated as missing so a hidden second cookie cannot choose the value.
fn cookie(headers: &HeaderMap) -> Option<&str> {
    super::cookies::capability(headers, COOKIE)
}

impl Auth {
    /// Reuse a valid browser binding so concurrent starts remain independently usable.
    pub(super) async fn bind_ceremony(&self, id: &str, headers: &HeaderMap) -> Result<HeaderValue> {
        let token = cookie(headers).map_or_else(random, str::to_owned);
        let binding = Some(hash(&token));
        let mut pending = self.pending.lock().await;
        if let Some(login) = pending.logins.get_mut(id) {
            login.binding = binding;
        } else if let Some(registration) = pending.registrations.get_mut(id) {
            registration.binding = binding;
        } else {
            return Err(Error::Denied);
        }
        HeaderValue::from_str(&format!(
            "{COOKIE}{token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=300"
        ))
        .map_err(|_| Error::Invalid)
    }

    /// Binding is checked before consuming the proof; a foreign browser cannot drain it.
    pub(super) async fn require_ceremony_binding(
        &self,
        id: &str,
        headers: &HeaderMap,
    ) -> Result<()> {
        let supplied = hash(cookie(headers).ok_or(Error::Denied)?);
        let pending = self.pending.lock().await;
        let expected = pending
            .logins
            .get(id)
            .and_then(|l| l.binding.as_ref())
            .or_else(|| {
                pending
                    .registrations
                    .get(id)
                    .and_then(|r| r.binding.as_ref())
            })
            .ok_or(Error::Denied)?;
        if !openssl::memcmp::eq(supplied.as_bytes(), expected.as_bytes()) {
            return Err(Error::Denied);
        }
        Ok(())
    }
}
