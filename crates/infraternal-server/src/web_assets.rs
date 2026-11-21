//! Serves build-time encodings without request CPU and caches only content-hashed files [5][41].
//!
//! Two kinds of file leave here. A file whose name carries a hash of its bytes never changes under that name, so it
//! is cached for a year: Bun's `chunk-<hash>.js`, the terminal engine `ghostty-vt-<hash>.wasm`, and the build's own fingerprinted names
//! `<stem>.<10 hex digits>.js|css|woff2` (the entry script, the page's style sheets and fonts; `apps/tracer/fingerprint.ts`
//! writes them, #573). Everything else (the page, the workers, the sheets and fonts that code loads by a fixed name)
//! keeps its name across releases, so it is `no-cache`: the browser asks again on every load and must be told reliably whether its copy is still the
//! current release's. That answer is the `ETag`, and the one the file service computes (file time and size) cannot give
//! it: reproducible bundles carry one fixed file time, so two releases whose `main.js` compress to the same number
//! of bytes have the same `ETag`, and a browser then reuses the *old* `main.js`, which imports chunk names that no
//! longer exist (#500, J538). [`headers`] therefore replaces the validator for mutable files with one that also
//! carries a fingerprint of the whole bundle, and answers `If-None-Match` itself.
//!
//! Two places have no app page behind them. A path with a file extension that the bundle lacks is a bare `404` (#518).
//! A path under `/docs/` that has no page is a `404` that carries the docs' own "not found" page (`docs/404.html`,
//! written by the docs build), because the app shell cannot render a docs address and shows a blank page (#527).

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{Next, from_fn, from_fn_with_state},
    response::Response,
};
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
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
    // The app page answers only for app routes (no file extension). A path that names a file the bundle does not hold
    // is a 404, so a tool asking for `/robots.txt` or a stale chunk is not handed HTML as if it were that file (#518).
    let index = Router::new()
        .fallback_service(
            ServeFile::new(root.join("index.html"))
                .precompressed_br()
                .precompressed_gzip(),
        )
        .layer(from_fn(missing_file_is_not_found));
    // Under `/docs` the app shell is never the answer: the docs are plain pages, so a miss there is the docs' own
    // "not found" page with a `404` status (#527). `ServeFile` handles `HEAD` and the encodings; the layer sets the status.
    let docs_missing = ServeFile::new(root.join("docs/404.html"))
        .precompressed_br()
        .precompressed_gzip();
    let index = Router::new()
        .route_service("/docs", docs_missing.clone())
        .route_service("/docs/{*rest}", docs_missing)
        .layer(from_fn(status_not_found))
        .fallback_service(index);
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

/// Turns the answer of a docs "not found" page into a `404`, and keeps a `Range` request from cutting it short. The
/// page is served as a file, so without this its status would be `200` and a cache or crawler would index it.
async fn status_not_found(mut request: Request, next: Next) -> Response {
    request.headers_mut().remove(header::RANGE);
    let mut response = next.run(request).await;
    if response.status().is_success() {
        *response.status_mut() = StatusCode::NOT_FOUND;
    }
    response
}

/// Answers `404` for a request whose last path segment has a file extension, and lets every other path through to the
/// app page. It runs only after the file service found nothing, so real files (including `favicon.ico`) never get here.
async fn missing_file_is_not_found(request: Request, next: Next) -> Response {
    let names_a_file = request
        .uri()
        .path()
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'));
    if names_a_file {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_FOUND;
        return response;
    }
    next.run(request).await
}

/// Sets cache, framing and validator headers on every response from the file service.
///
/// For a mutable file the service's own `Last-Modified` and `If-Modified-Since` handling is switched off (the file
/// time is the same for every release, so it would always say "unchanged"), and its `ETag` is wrapped as
/// `"<bundle fingerprint>-<its ETag>"`. A request that already holds exactly that `ETag` gets a `304` without a body.
async fn headers(
    State(fingerprint): State<Arc<str>>,
    mut request: Request,
    next: Next,
) -> Response {
    let immutable = immutable_name(request.uri().path());
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
/// Only a full `200` carries an `ETag` at all; a range or error response has none, so a browser cannot store a partial
/// body under a validator.
fn revalidation(response: &mut Response, fingerprint: &str, if_none_match: Option<&HeaderValue>) {
    response.headers_mut().remove(header::LAST_MODIFIED);
    let inner = response
        .headers_mut()
        .remove(header::ETAG)
        .filter(|_| response.status() == StatusCode::OK)
        .and_then(|tag| {
            tag.to_str()
                .ok()
                .map(|tag| tag.trim_matches('"').to_owned())
        });
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
            let derived = Path::new(relative).extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("br") || ext.eq_ignore_ascii_case("gz")
            });
            if !immutable_name(&format!("/{relative}")) && !derived {
                let bytes = std::fs::read(root.join(relative))?;
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(&bytes);
            }
        }
        Ok(digest.finalize())
    });
    hashed.map_or_else(
        |_| {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos());
            format!("p{nanos:x}")
        },
        |digest| {
            digest[..8].iter().fold(String::new(), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            })
        },
    )
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

/// True when `path` names a file whose name contains a hash of its contents, so the bytes behind it can never change.
///
/// Three shapes qualify: Bun's split chunks, `/chunk-<8 alphanumerics>.js`, the terminal engine,
/// `/ghostty-vt-<8 alphanumerics>.wasm` (the bundler's asset name, `apps/tracer/src/engine-wasm.ts`), and the fingerprinted files the tracer build
/// writes, `<stem>.<10 lowercase hex digits>.<js|css|woff2>` in any folder (`apps/tracer/fingerprint.ts`; keep the two
/// in step). A file that merely looks like one but is not in the bundle gets the single-page fallback, and [`headers`]
/// never trusts the name when the response is that HTML.
fn immutable_name(path: &str) -> bool {
    let bundled = |prefix: &str, suffix: &str| {
        path.strip_prefix(prefix)
            .and_then(|name| name.strip_suffix(suffix))
            .is_some_and(|hash| {
                hash.len() == 8 && hash.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
    };
    bundled("/chunk-", ".js") || bundled("/ghostty-vt-", ".wasm") || fingerprinted(path)
}

/// True for a file name ending `.<10 lowercase hex digits>.<js|css|woff2>` with a non-empty stem before the hash.
fn fingerprinted(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some(stem) = ["js", "css", "woff2"]
        .iter()
        .find_map(|extension| name.strip_suffix(&format!(".{extension}")))
    else {
        return false;
    };
    stem.len() > 11
        && stem.as_bytes()[stem.len() - 11] == b'.'
        && stem.as_bytes()[stem.len() - 10..]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
#[path = "web_assets_tests.rs"]
mod tests;
