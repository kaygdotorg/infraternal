//! Independent #199 review: native route replies must correlate with an issued probe (D265, wire §9).

// Exercise the shipping implementation rather than a second liveness model.
#[path = "../src/liveness.rs"]
mod liveness;

use std::time::Duration;

#[tokio::test(start_paused = true)]
async fn unissued_native_probe_reply_cannot_extend_readiness() {
    let mut route = liveness::Liveness::new();
    let (nonce, stamp) = route.ping();
    tokio::time::advance(Duration::from_millis(1)).await;
    route.pong(nonce, stamp);
    tokio::time::advance(Duration::from_millis(24)).await;
    let (first, _) = route.ping();
    tokio::time::advance(Duration::from_millis(25)).await;
    let (second, _) = route.ping();
    let unissued = first + (second - first) / 2;
    assert!(first < unissued && unissued < second);
    tokio::time::advance(Duration::from_millis(10)).await;
    route.pong(unissued, unissued);
    // The actual probes remain unanswered. Their original 50ms budget has
    // elapsed, so an invented intermediate nonce must not keep the route live.
    // Paused time tests correlation and ordering, never host latency.
    tokio::time::advance(Duration::from_millis(40)).await;
    assert!(route.expired(), "an unissued reply retained readiness");
}
