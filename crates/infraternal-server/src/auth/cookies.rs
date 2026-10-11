//! Read capability cookies across HTTP/1 and HTTP/2 fields without allocating or accepting duplicates.
use axum::http::{HeaderMap, header};

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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    const PREFIX: &str = "__Host-infraternal=";
    const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

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
