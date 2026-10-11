//! Checks sequential CA ceremony admission through the real HTTP authority, #154 [168].
use super::*;

#[tokio::test]
#[ignore = "unresolved P2 CA-03: eight concurrent slots do not limit sequential requests; proposed 30/minute budget"]
async fn sequential_unlock_starts_require_a_temporal_budget() {
    let (f, app) = http_fixture().await;
    let started = Instant::now();
    let mut accepted = 0;
    for _ in 0..31 {
        let response = app
            .clone()
            .oneshot(ca_request(
                "/remote/ca/unlock/start",
                Some(ORIGIN),
                Some(&f.auth.session),
                "{}".into(),
            ))
            .await
            .unwrap();
        if response.status() == StatusCode::OK {
            accepted += 1;
        }
    }
    println!(
        "METRIC sequential_unlock_start_requests=31 accepted={accepted} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "fixture crossed proposed rate window"
    );
    assert!(
        accepted <= 30,
        "concurrency admission must also bound sequential ceremony work"
    );
    assert!(f.source.load().is_err());
}
