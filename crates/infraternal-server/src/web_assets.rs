//! Serves build-time encodings without request CPU and caches only Bun's content-hashed chunks [5][41].

use axum::{
    Router,
    extract::Request,
    http::{HeaderValue, header},
    middleware::{Next, from_fn},
    response::Response,
};
use std::path::PathBuf;
use tower_http::services::{ServeDir, ServeFile};

pub(crate) fn router(root: PathBuf) -> Router {
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
        .layer(from_fn(headers))
}

async fn headers(request: Request, next: Next) -> Response {
    let immutable = hashed_chunk(request.uri().path());
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
    let cache = if immutable && !html && response.status().is_success() {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    response
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
