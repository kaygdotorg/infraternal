//! Read browser capabilities across HTTP/1 and HTTP/2 fields.
//!
//! Session cookie names carry a server-issued login sequence and absolute expiry. The browser may
//! return several generations in any order while responses race; selecting by the name is safe
//! because the bearer value is still checked against the live session row before use.
use axum::http::{HeaderMap, header};

/// The single cookie name sessions used before versioned names; still read when no versioned cookie is present.
const LEGACY_SESSION_NAME: &str = "__Host-infraternal";
/// Versioned session cookies are named `<prefix><login sequence>-<absolute expiry>`.
const SESSION_NAME_PREFIX: &str = "__Host-infraternal-session-";

/// One parsed browser session capability and its ordering hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionCookie<'a> {
    pub name: &'a str,
    pub token: &'a str,
    pub login_sequence: i64,
    pub expires: i64,
}

/// HTTP/2 may split Cookie into multiple fields; uniqueness covers the entire request.
/// Fail closed on non-text fields rather than silently ignoring a hidden duplicate.
pub(crate) fn capability<'a>(headers: &'a HeaderMap, prefix: &str) -> Option<&'a str> {
    let mut found = None;
    for field in headers.get_all(header::COOKIE) {
        for value in field.to_str().ok()?.split(';') {
            let Some(value) = value.trim().strip_prefix(prefix) else {
                continue;
            };
            if found.is_some()
                || value.len() != 43
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return None;
            }
            found = Some(value);
        }
    }
    found
}

/// Select the newest versioned session cookie without depending on Cookie field order.
/// A legacy fixed-name cookie is accepted only when no versioned cookie is present.
pub(crate) fn session(headers: &HeaderMap) -> Option<SessionCookie<'_>> {
    let mut selected: Option<SessionCookie<'_>> = None;
    let mut legacy: Option<SessionCookie<'_>> = None;
    for field in headers.get_all(header::COOKIE) {
        for pair in field.to_str().ok()?.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name == LEGACY_SESSION_NAME {
                if !valid_token(value) || legacy.is_some() {
                    return None;
                }
                legacy = Some(SessionCookie {
                    name,
                    token: value,
                    login_sequence: 0,
                    expires: 0,
                });
                continue;
            }
            if !name.starts_with(SESSION_NAME_PREFIX) {
                continue;
            }
            let (login_sequence, expires) = parse_session_name(name)?;
            if !valid_token(value) {
                return None;
            }
            let candidate = SessionCookie {
                name,
                token: value,
                login_sequence,
                expires,
            };
            match selected {
                None => selected = Some(candidate),
                Some(current)
                    if (candidate.login_sequence, candidate.expires)
                        > (current.login_sequence, current.expires) =>
                {
                    selected = Some(candidate);
                }
                Some(current)
                    if (candidate.login_sequence, candidate.expires)
                        == (current.login_sequence, current.expires) =>
                {
                    // The same ordering key with more than one field is ambiguous, even when
                    // the values happen to match. A browser normally stores one value per name.
                    return None;
                }
                Some(_) => {}
            }
        }
    }
    selected.or(legacy)
}

/// Return valid session cookie names observed in this request for safe retirement.
pub(crate) fn observed_session_names(headers: &HeaderMap) -> Vec<&str> {
    let mut names = Vec::new();
    for field in headers.get_all(header::COOKIE) {
        let Ok(field) = field.to_str() else {
            continue;
        };
        for pair in field.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            let valid_name = if name == LEGACY_SESSION_NAME {
                true
            } else {
                parse_session_name(name).is_some()
            };
            if valid_name && valid_token(value) && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// Most distinct session bearers one logout revokes.
///
/// A browser holds one live login generation, plus briefly a newer one while a
/// login races an older request. Eight leaves room for several such races. The
/// cap exists because logout needs no live session: without it, one request with
/// a large Cookie header of made-up bearers would cost one database delete each.
pub(crate) const MAX_LOGOUT_SESSIONS: usize = 8;

/// Return every distinct valid session bearer present in a logout request, or
/// `None` when there are more than [`MAX_LOGOUT_SESSIONS`].
///
/// A browser can send several login generations while an older request is
/// still in flight. Logout revokes all of those capabilities so a delayed
/// response cannot make an older live session usable again. Over the cap the
/// caller revokes none of them: revoking a subset would report success while
/// leaving a presented bearer live. Collection stops at the first bearer over the
/// cap, so parsing cost is bounded too.
pub(crate) fn session_tokens(headers: &HeaderMap) -> Option<Vec<&str>> {
    let mut tokens = Vec::new();
    for field in headers.get_all(header::COOKIE) {
        let Ok(field) = field.to_str() else {
            continue;
        };
        for pair in field.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            let session_name = name == LEGACY_SESSION_NAME
                || (name.starts_with(SESSION_NAME_PREFIX) && parse_session_name(name).is_some());
            if session_name && valid_token(value) && !tokens.contains(&value) {
                if tokens.len() == MAX_LOGOUT_SESSIONS {
                    return None;
                }
                tokens.push(value);
            }
        }
    }
    Some(tokens)
}

/// The login sequence and expiry from a versioned cookie name, only in canonical decimal form.
fn parse_session_name(name: &str) -> Option<(i64, i64)> {
    let suffix = name.strip_prefix(SESSION_NAME_PREFIX)?;
    let (sequence, expires_text) = suffix.split_once('-')?;
    let login_sequence = sequence.parse::<i64>().ok()?;
    let expires = expires_text.parse::<i64>().ok()?;
    if login_sequence < 0
        || expires <= 0
        || login_sequence.to_string() != sequence
        || expires.to_string() != expires_text
    {
        return None;
    }
    Some((login_sequence, expires))
}

/// A session bearer is exactly 43 URL-safe base64 characters.
fn valid_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    const PREFIX: &str = "__Host-infraternal=";
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    /// A bearer for an older login generation.
    const OLDER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF1";
    /// A bearer for a newer login generation.
    const NEWER: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF2";

    #[test]
    fn joined_split_reordered_and_other_cookies() {
        let session = format!("{PREFIX}{TOKEN}");
        for fields in [
            vec![format!("ceremony=unrelated; {session}")],
            vec!["ceremony=unrelated".into(), session.clone()],
            vec![session, "ceremony=unrelated".into()],
        ] {
            let mut headers = HeaderMap::new();
            for field in fields {
                headers.append(header::COOKIE, field.parse().unwrap());
            }
            assert_eq!(capability(&headers, PREFIX), Some(TOKEN));
        }
    }

    #[test]
    fn duplicates_missing_invalid_and_nontext_fail_closed() {
        let session = format!("{PREFIX}{TOKEN}");
        for fields in [
            vec![],
            vec!["other=value".into()],
            vec![format!("{PREFIX}short")],
            vec![format!("{PREFIX}{}!", &TOKEN[..42])],
            vec![session.clone(), session.clone()],
            vec![format!("{session}; {session}")],
            vec![session.clone(), format!("{PREFIX}short")],
            vec![format!("{PREFIX}short"), session.clone()],
        ] {
            let mut headers = HeaderMap::new();
            for field in fields {
                headers.append(header::COOKIE, field.parse().unwrap());
            }
            assert!(capability(&headers, PREFIX).is_none());
        }
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, session.parse().unwrap());
        headers.append(
            header::COOKIE,
            HeaderValue::from_bytes(b"other=\xff").unwrap(),
        );
        assert!(capability(&headers, PREFIX).is_none());
    }

    /// The newest cookie wins by sequence, then expiry, whatever the header order.
    #[test]
    fn session_selection_uses_sequence_then_expiry_across_header_order() {
        let older = format!("{SESSION_NAME_PREFIX}7-1900000000={OLDER}");
        let refreshed = format!("{SESSION_NAME_PREFIX}7-1900000100={OLDER}");
        let later_login = format!("{SESSION_NAME_PREFIX}8-1900000001={NEWER}");
        for joined in [
            format!("{older}; {refreshed}; {later_login}"),
            format!("{later_login}; {refreshed}; {older}"),
            format!("{refreshed}; {older}; {later_login}"),
        ] {
            let mut headers = HeaderMap::new();
            headers.append(header::COOKIE, joined.parse().unwrap());
            let selected = session(&headers).unwrap();
            assert_eq!(selected.token, NEWER);
            assert_eq!(selected.login_sequence, 8);
            assert_eq!(selected.expires, 1_900_000_001);
        }
    }

    /// A legacy cookie is used only without versioned ones, and two cookies with the same newest key are refused.
    #[test]
    fn session_selection_migrates_legacy_and_rejects_ambiguous_latest() {
        let mut legacy = HeaderMap::new();
        legacy.append(header::COOKIE, format!("{PREFIX}{TOKEN}").parse().unwrap());
        assert_eq!(session(&legacy).unwrap().token, TOKEN);

        let mut mixed = HeaderMap::new();
        mixed.append(
            header::COOKIE,
            format!("{PREFIX}{TOKEN}; {SESSION_NAME_PREFIX}1-1900000000={NEWER}")
                .parse()
                .unwrap(),
        );
        assert_eq!(session(&mixed).unwrap().token, NEWER);

        let duplicated = format!("{SESSION_NAME_PREFIX}1-1900000000={NEWER}");
        let mut ambiguous = HeaderMap::new();
        ambiguous.append(header::COOKIE, duplicated.parse().unwrap());
        ambiguous.append(
            header::COOKIE,
            format!("{SESSION_NAME_PREFIX}1-1900000000={OLDER}")
                .parse()
                .unwrap(),
        );
        assert!(session(&ambiguous).is_none());
    }

    /// Only valid session cookie shapes are reported as observed names.
    #[test]
    fn observed_names_only_accept_valid_session_cookie_shapes() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            format!(
                "{PREFIX}{TOKEN}; {SESSION_NAME_PREFIX}2-1900000000={NEWER}; {SESSION_NAME_PREFIX}bad={OLDER}"
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(
            observed_session_names(&headers),
            vec![
                "__Host-infraternal",
                "__Host-infraternal-session-2-1900000000"
            ]
        );
    }
}

#[cfg(test)]
mod measurement {
    use super::*;
    use std::{hint::black_box, time::Instant};

    #[test]
    #[ignore = "local optimized cookie reader measurement at 50 browser sessions"]
    #[allow(clippy::cast_precision_loss)]
    fn cookie_latency_at_50_sessions() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::COOKIE,
            "ceremony=unrelated; __Host-infraternal=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
                .parse()
                .unwrap(),
        );
        let samples = 200_000;
        for strict in [false, true] {
            let start = Instant::now();
            for _ in 0..samples {
                for _ in 0..50 {
                    let headers = black_box(&headers);
                    let token = if strict {
                        capability(headers, "__Host-infraternal=")
                    } else {
                        // The old HTTP reader is the baseline, including its duplicate check.
                        let mut values = headers
                            .get(header::COOKIE)
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .split(';')
                            .filter_map(|c| c.trim().strip_prefix("__Host-infraternal="));
                        let value = values.next().unwrap();
                        (values.next().is_none() && value.len() == 43).then_some(value)
                    };
                    black_box(token);
                }
            }
            println!(
                "COOKIE_READER sessions=50 samples_per_session={samples} strict={strict} ns_per_request={:.2} ns_per_50={:.2} retained_bytes_per_session=0",
                start.elapsed().as_nanos() as f64 / f64::from(samples * 50),
                start.elapsed().as_nanos() as f64 / f64::from(samples)
            );
        }
    }
}
