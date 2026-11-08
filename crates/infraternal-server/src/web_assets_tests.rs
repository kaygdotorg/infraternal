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
