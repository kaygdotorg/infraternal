//! Exercises actual static file services, encoding negotiation, byte lengths and SPA cache policy.

use super::*;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use tower::ServiceExt;

fn fixture() -> (PathBuf, Router) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("web-assets-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    for (name, bytes) in [
        ("chunk-1234abcd.js", b"identity payload".as_slice()),
        ("chunk-1234abcd.js.gz", b"gzip".as_slice()),
        ("chunk-1234abcd.js.br", b"br".as_slice()),
        ("index.html", b"<html>entry</html>".as_slice()),
        ("index.html.br", b"compressed html".as_slice()),
        ("font.woff2", b"font bytes".as_slice()),
        ("main.js", b"mutable entry".as_slice()),
    ] {
        std::fs::write(root.join(name), bytes).unwrap();
    }
    let app = router(root.clone());
    (root, app)
}

/// Verify negotiated encodings, case-insensitive Vary tokens and exact response lengths.
#[tokio::test]
async fn encodings_and_identity_have_correct_headers_and_sizes() {
    let (root, app) = fixture();
    for (accept, encoding, bytes) in [
        ("br, gzip", Some("br"), b"br".as_slice()),
        ("gzip", Some("gzip"), b"gzip".as_slice()),
        ("br;q=0.5, gzip;q=1", Some("gzip"), b"gzip".as_slice()),
        ("identity", None, b"identity payload".as_slice()),
        ("br;q=0, gzip;q=0", None, b"identity payload".as_slice()),
        ("", None, b"identity payload".as_slice()),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/chunk-1234abcd.js")
                    .header(header::ACCEPT_ENCODING, accept)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_ENCODING)
                .map(|v| v.to_str().unwrap()),
            encoding
        );
        assert!(
            response.headers()[header::VARY]
                .to_str()
                .unwrap()
                .eq_ignore_ascii_case("Accept-Encoding")
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(response.headers()[header::CONTENT_TYPE], "text/javascript");
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH].to_str().unwrap(),
            bytes.len().to_string()
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            bytes
        );
    }
    let head = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/chunk-1234abcd.js")
                .header(header::ACCEPT_ENCODING, "br")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.headers()[header::CONTENT_LENGTH], "2");
    assert_eq!(head.headers()[header::CONTENT_ENCODING], "br");
    assert!(
        head.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn spa_and_mutable_assets_revalidate_and_missing_brotli_uses_gzip() {
    let (root, app) = fixture();
    for (path, encoding) in [
        ("/", Some("br")),
        ("/index.html", Some("br")),
        ("/saved/session", Some("br")),
        ("/chunk-deadbeef.js", Some("br")),
        ("/font.woff2", None),
        ("/main.js", None),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(header::ACCEPT_ENCODING, "br, gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-cache",
            "{path}"
        );
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_ENCODING)
                .map(|v| v.to_str().unwrap()),
            encoding,
            "{path}"
        );
    }
    std::fs::remove_file(root.join("chunk-1234abcd.js.br")).unwrap();
    let fallback = app
        .oneshot(
            Request::builder()
                .uri("/chunk-1234abcd.js")
                .header(header::ACCEPT_ENCODING, "br, gzip")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fallback.headers()[header::CONTENT_ENCODING], "gzip");
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn no_other_site_may_frame_the_app() {
    // J134 P3-1: the approval page is the SPA's index, served for any path.
    let (root, app) = fixture();
    for path in [
        "/",
        "/index.html",
        "/approve/anything",
        "/chunk-1234abcd.js",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.headers()[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'none'",
            "{path}"
        );
        assert_eq!(
            response.headers()[header::X_FRAME_OPTIONS],
            "DENY",
            "{path}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A bundle holding only `main.js` (and its brotli copy), with every file given the one fixed file time that
/// reproducible builds use, so the file service's own (time, size) `ETag` cannot tell two releases apart.
fn release(main: &[u8], main_br: &[u8]) -> (PathBuf, Router) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("web-release-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    for (name, bytes) in [
        ("index.html", b"<html>entry</html>".as_slice()),
        ("main.js", main),
        ("main.js.br", main_br),
    ] {
        std::fs::write(root.join(name), bytes).unwrap();
        std::fs::File::options()
            .write(true)
            .open(root.join(name))
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
    }
    let app = router(root.clone());
    (root, app)
}

/// Sends one `GET` to `app` as a browser that accepts brotli, with `extra` request headers (the validators under test).
async fn get(app: &Router, uri: &str, extra: &[(header::HeaderName, &str)]) -> Response {
    let mut request = Request::builder()
        .uri(uri)
        .header(header::ACCEPT_ENCODING, "br");
    for (name, value) in extra {
        request = request.header(name, *value);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// #500, J538: a browser holding release A's `main.js` must not be told it is current when release B has a
/// different `main.js` of the same size under the same file time. That mix left iPhones on the old entry script,
/// which imported chunk names the new release no longer has ("Could not load setup").
#[tokio::test]
async fn a_different_release_with_equally_sized_files_is_never_not_modified() {
    let (root_a, release_a) = release(b"entry script A", b"brotli copy A");
    let (root_b, release_b) = release(b"entry script B", b"brotli copy B");
    let a = get(&release_a, "/main.js", &[]).await;
    let b = get(&release_b, "/main.js", &[]).await;
    let (tag_a, tag_b) = (a.headers()[header::ETAG].clone(), b.headers()[header::ETAG].clone());
    assert_ne!(tag_a, tag_b, "same size and time must not give the same ETag");
    let revalidated = get(&release_b, "/main.js", &[(header::IF_NONE_MATCH, tag_a.to_str().unwrap())]).await;
    assert_eq!(revalidated.status(), 200, "release B must send its own main.js");
    assert_eq!(
        revalidated.into_body().collect().await.unwrap().to_bytes().as_ref(),
        b"brotli copy B"
    );
    // Release A's own page keeps working with the cheap answer.
    let same = get(&release_a, "/main.js", &[(header::IF_NONE_MATCH, tag_a.to_str().unwrap())]).await;
    assert_eq!(same.status(), 304);
    assert_eq!(same.headers()[header::ETAG], tag_a);
    assert_eq!(same.headers()[header::CACHE_CONTROL], "no-cache");
    assert!(same.into_body().collect().await.unwrap().to_bytes().is_empty());
    // The file time is the same in every release, so If-Modified-Since never decides anything.
    let by_date = get(
        &release_b,
        "/main.js",
        &[(header::IF_MODIFIED_SINCE, "Fri, 01 Jan 2100 00:00:00 GMT")],
    )
    .await;
    assert_eq!(by_date.status(), 200);
    assert!(by_date.headers().get(header::LAST_MODIFIED).is_none());
    std::fs::remove_dir_all(root_a).unwrap();
    std::fs::remove_dir_all(root_b).unwrap();
}

/// The same holds for a release that changes only the page (`index.html`) or a file the browser fetched earlier.
#[tokio::test]
async fn the_etag_follows_the_whole_bundle() {
    let (root_a, release_a) = release(b"entry script", b"brotli copy");
    let first = get(&release_a, "/main.js", &[]).await.headers()[header::ETAG].clone();
    let (root_c, _) = release(b"entry script", b"brotli copy");
    std::fs::write(root_c.join("index.html"), b"<html>other</html>").unwrap();
    let changed = router(root_c.clone());
    let second = get(&changed, "/main.js", &[]).await.headers()[header::ETAG].clone();
    assert_ne!(first, second, "a changed bundle must change every mutable ETag");
    std::fs::remove_dir_all(root_a).unwrap();
    std::fs::remove_dir_all(root_c).unwrap();
}
