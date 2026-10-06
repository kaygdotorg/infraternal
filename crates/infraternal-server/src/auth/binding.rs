//! HTTP transaction binding keeps a signed ceremony in the browser that started it [24,53].
use super::{Auth, Error, Result, hash, random};
use axum::http::{HeaderMap, HeaderValue, header};

const COOKIE: &str = "__Host-infraternal-ceremony=";

fn cookie(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|value| value.trim().strip_prefix(COOKIE));
    let value = values.next()?;
    (values.next().is_none()
        && value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
    .then_some(value)
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
