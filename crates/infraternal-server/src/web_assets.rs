//! Serves build-time encodings without request CPU and caches only Bun's content-hashed chunks [5][41].
//!
//! Two kinds of file leave here. A hashed `chunk-<hash>.js` never changes under its name, so it is cached for a
//! year. Everything else (the page, `main.js`, the style sheets, the workers) keeps its name across releases, so it
//! is `no-cache`: the browser asks again on every load and must be told reliably whether its copy is still the
//! current release's. That answer is the ETag, and the one the file service computes (file time and size) cannot give
//! it: reproducible bundles carry one fixed file time, so two releases whose `main.js` compress to the same number
//! of bytes have the same ETag, and a browser then reuses the *old* `main.js`, which imports chunk names that no
//! longer exist (#500, J538). [`headers`] therefore replaces the validator for mutable files with one that also
//! carries a fingerprint of the whole bundle, and answers `If-None-Match` itself.

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::Response,
};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tower_http::services::{ServeDir, ServeFile};

/// Builds the router that serves the web bundle in `root`.
///
/// Reads the bundle once, here, to fingerprint it (see [`bundle_fingerprint`]); that is a few hundred kilobytes of
/// hashing at start-up and nothing per request.
pub(crate) fn router(root: PathBuf) -> Router {
    let fingerprint: Arc<str> = bundle_fingerprint(&root).into();
    let index = ServeFile::new(root.join("index.html"))
        .precompressed_br()
        .precompressed_gzip();
    Router::new()
        .fallback_service(
            ServeDir::new(root)
                .precompressed_br()
                .precompressed_gzip()
                .append_index_html_on_directories(true)
                .fallback(index),
        )
        .layer(from_fn_with_state(fingerprint, headers))
}

/// Sets cache, framing and validator headers on every response from the file service.
///
/// For a mutable file the service's own `Last-Modified` and `If-Modified-Since` handling is switched off (the file
/// time is the same for every release, so it would always say "unchanged"), and its ETag is wrapped as
/// `"<bundle fingerprint>-<its ETag>"`. A request that already holds exactly that ETag gets a `304` without a body.
async fn headers(
    State(fingerprint): State<Arc<str>>,
    mut request: Request,
    next: Next,
) -> Response {
    let immutable = hashed_chunk(request.uri().path());
    // Taken out of the request so the file service never decides "not modified" on its (time, size) validators. A
    // chunk is fetched without validators in normal use (it is cached for a year), so answering it in full is fine.
    request.headers_mut().remove(header::IF_MODIFIED_SINCE);
    let if_none_match = request.headers_mut().remove(header::IF_NONE_MATCH);
    let mut response = next.run(request).await;
    // Vary applies to identity too: shared caches must not reuse it for a
    // browser that accepts a smaller representation, or vice versa.
    response
        .headers_mut()
        .append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    // Unknown SPA paths also return index.html. Never infer immutability just
    // from a requested filename when the response is the fallback document.
    let html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|value| value.as_bytes().starts_with(b"text/html"));
    let cacheable = immutable && !html && response.status().is_success();
    if !cacheable {
        revalidation(&mut response, &fingerprint, if_none_match.as_ref());
    }
    let cache = if cacheable {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    // No other site may frame the app: it hosts the passkey approval page
    // (#263, J134 P3-1). The Strict session cookie already keeps a framed
    // copy signed out; this is the policy, not just that side effect. Sent on
    // every response, so a document served under another type is covered
    // too. X-Frame-Options covers browsers without CSP frame-ancestors.
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// Replaces the file service's validators on a `no-cache` response and turns it into a `304` when the request's
/// `If-None-Match` already names the current release's copy.
///
/// Only a full `200` carries an ETag at all; a range or error response has none, so a browser cannot store a partial
/// body under a validator.
fn revalidation(response: &mut Response, fingerprint: &str, if_none_match: Option<&HeaderValue>) {
    response.headers_mut().remove(header::LAST_MODIFIED);
    let inner = response
        .headers_mut()
        .remove(header::ETAG)
        .filter(|_| response.status() == StatusCode::OK)
        .and_then(|tag| tag.to_str().ok().map(|tag| tag.trim_matches('"').to_owned()));
    let Some(inner) = inner else { return };
    let tag = format!("\"{fingerprint}-{inner}\"");
    if if_none_match.is_some_and(|wanted| names_etag(wanted, &tag)) {
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        *response.body_mut() = Body::empty();
        response.headers_mut().remove(header::CONTENT_LENGTH);
    }
    if let Ok(value) = HeaderValue::from_str(&tag) {
        response.headers_mut().insert(header::ETAG, value);
    }
}

/// True when an `If-None-Match` value is `*` or lists `tag` (a weak `W/` prefix is ignored, as weak comparison does).
fn names_etag(wanted: &HeaderValue, tag: &str) -> bool {
    wanted.to_str().is_ok_and(|wanted| {
        wanted.trim() == "*"
            || wanted
                .split(',')
                .any(|item| item.trim().trim_start_matches("W/") == tag)
    })
}

/// A short hex fingerprint of the bundle in `root`: every file's relative path, and the bytes of every file that
/// keeps its name across releases.
///
/// Content-hashed chunks and the precompressed `.br`/`.gz` copies are left out of the bytes (a chunk's name already is
/// its hash; a copy is derived from the file beside it), which keeps this to the small mutable part of the bundle.
/// When the folder cannot be read the fingerprint is unique to this process, so the browser refetches rather than
/// risk reusing another release's file.
fn bundle_fingerprint(root: &Path) -> String {
    let mut files = Vec::new();
    let hashed = collect_files(root, root, &mut files).and_then(|()| {
        files.sort();
        let mut digest = Sha256::new();
        for relative in &files {
            digest.update(relative.as_bytes());
            digest.update([0]);
            let name = relative.rsplit('/').next().unwrap_or(relative);
            let derived = name.ends_with(".br") || name.ends_with(".gz");
            if !hashed_chunk(&format!("/{relative}")) && !derived {
                let bytes = std::fs::read(root.join(relative))?;
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(&bytes);
            }
        }
        Ok(digest.finalize())
    });
    match hashed {
        Ok(digest) => digest[..8].iter().map(|byte| format!("{byte:02x}")).collect(),
        Err(_) => {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            format!("p{nanos:x}")
        }
    }
}

/// Appends the `/`-separated path, relative to `root`, of every file under `dir`.
fn collect_files(root: &Path, dir: &Path, files: &mut Vec<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(root, &path, files)?;
        } else if let Ok(relative) = path.strip_prefix(root) {
            files.push(
                relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    Ok(())
}

fn hashed_chunk(path: &str) -> bool {
    path.strip_prefix("/chunk-")
        .and_then(|name| name.strip_suffix(".js"))
        .is_some_and(|hash| {
            hash.len() == 8 && hash.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
}

#[cfg(test)]
#[path = "web_assets_tests.rs"]
mod tests;
