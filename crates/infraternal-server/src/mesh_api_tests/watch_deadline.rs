//! Validate expiry selection and measure visibility-change timer work at the Mesh inventory budget [164,170, #108].
use super::*;

#[tokio::test]
async fn watch_deadline_matches_complete_filtered_snapshots() {
    let f = Fixture::new().await;
    let viewers = seed_scale_inventory(&f).await;
    call(
        &f.service,
        OWNER,
        "mesh.role.define",
        json!({"name":"expiry-scope","actions":["mesh.manage_grants"],"scopes":["tag-007"]}),
        NOW,
    )
    .await
    .unwrap();
    call(
        &f.service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"expiry-scope"}),
        NOW,
    )
    .await
    .unwrap();
    for user in [OWNER, viewers[0].as_str(), MEMBER] {
        for tag in [None, Some("tag-007".to_owned())] {
            let filter = MeshFilter { tag, cursor: None };
            let (_, expected) = f
                .service
                .list_with_deadline(user, filter.clone(), NOW)
                .await
                .unwrap();
            assert_eq!(
                f.service.watch_deadline(user, &filter, NOW).await.unwrap(),
                expected
            );
            assert_eq!(
                f.service
                    .watch_deadline(user, &filter, NOW + 31)
                    .await
                    .unwrap(),
                None
            );
        }
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "weighted local scale measurement; run optimized without concurrent compilation"]
async fn watch_deadline_scale_benchmark() {
    let f = Fixture::new().await;
    let viewers = seed_scale_inventory(&f).await;
    let filter = MeshFilter {
        tag: Some("tag-007".to_owned()),
        cursor: None,
    };
    let mut direct = Vec::new();
    let mut snapshots = Vec::new();
    for _ in 0..10 {
        let begin = std::time::Instant::now();
        for viewer in &viewers {
            assert_eq!(
                f.service
                    .watch_deadline(viewer, &filter, NOW)
                    .await
                    .unwrap(),
                Some(NOW + 31)
            );
        }
        direct.push(begin.elapsed().as_micros());
        let begin = std::time::Instant::now();
        for viewer in &viewers {
            assert_eq!(
                f.service
                    .list_with_deadline(viewer, filter.clone(), NOW)
                    .await
                    .unwrap()
                    .1,
                Some(NOW + 31)
            );
        }
        snapshots.push(begin.elapsed().as_micros());
    }
    println!(
        "METRIC name=watch_deadline nodes=1000 tags=100 memberships=10000 grants=3000 viewers=50 sweeps=10 query_fanout_p50_us={} query_fanout_p95_us={} snapshot_fanout_p50_us={} snapshot_fanout_p95_us={} load={}",
        percentile_u128(&direct, 50),
        percentile_u128(&direct, 95),
        percentile_u128(&snapshots, 50),
        percentile_u128(&snapshots, 95),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    f.cleanup().await;
}
