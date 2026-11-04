//! Real SQLite regressions for Mesh input validation, authorization, inventory edits, and concurrency.
use crate::{
    auth::Auth,
    mesh_api::{MeshApiError, MeshFilter, MeshService, parse_action},
};
use futures_util::future::join_all;
use infraternal_plugin_mesh::policy as infraternal_mesh;
use infraternal_protocol::{Frame, encode_muxed_frame_into};
use serde_json::{Value, json};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;

const OWNER: &str = "mesh-owner";
const MEMBER: &str = "mesh-member";
const NOW: i64 = 1_800_000_000;
const SCALE_NODE_COUNT: i64 = 1_000;
const SCALE_TAG_COUNT: i64 = 100;
const SCALE_GRANT_COUNT: i64 = 3_000;
const SCALE_MEMBERSHIPS_PER_NODE: i64 = 10;
const SCALE_VIEWER_COUNT: usize = 50;

struct Fixture {
    pool: SqlitePool,
    service: MeshService,
    path: PathBuf,
}

impl Fixture {
    async fn new() -> Self {
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(|| PathBuf::from("target"), PathBuf::from);
        let directory = target.join("mesh-api-tests");
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{}.sqlite", Uuid::new_v4()));
        let options = SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await
            .unwrap();
        let _auth = Auth::new(pool.clone(), "localhost", "https://localhost")
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?, ?, 1, 'fixture', ?, 'Mesh owner')")
            .bind(OWNER)
            .bind(OWNER)
            .bind(OWNER)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?, ?, 0, 'fixture', ?, 'Mesh member')")
            .bind(MEMBER)
            .bind(MEMBER)
            .bind(MEMBER)
            .execute(&pool)
            .await
            .unwrap();
        Self {
            service: MeshService::new(pool.clone()),
            pool,
            path,
        }
    }

    async fn cleanup(self) {
        let Self {
            service,
            pool,
            path,
        } = self;
        drop(service);
        pool.close().await;
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(file));
        }
    }
}

async fn call(
    service: &MeshService,
    actor: &str,
    action: &str,
    input: Value,
    now: i64,
) -> Result<Value, MeshApiError> {
    let input = serde_json::to_vec(&input).unwrap();
    service.execute(actor, action, &input, now).await
}

async fn enroll(service: &MeshService, name: &str, key_byte: u8) -> u64 {
    call(
        service,
        OWNER,
        "mesh.node.enroll",
        json!({"name":name,"public_key":vec![key_byte;32]}),
        NOW,
    )
    .await
    .unwrap()["node_id"]
        .as_u64()
        .unwrap()
}

#[test]
fn parser_rejects_unknown_fields_user_endpoints_and_invalid_bounds() {
    for (action, input) in [
        (
            "mesh.node.enroll",
            br#"{"name":"db-1","public_key":[1,1],"private_key":"secret"}"#.as_slice(),
        ),
        ("mesh.node.observe", br#"{"node_id":0,"last_rtt_us":null}"#),
        (
            "mesh.grant.create",
            br#"{"name":"web","from":{"User":7},"to":{"Tag":"prod"},"both_ways":false}"#,
        ),
        (
            "mesh.grant.create",
            br#"{"name":"web","from":{"Tag":"prod"},"to":{"Tag":"db"},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":0}]}}"#,
        ),
        ("mesh.tag.create", br#"{"name":"bad_name"}"#),
        (
            "mesh.role.define",
            br#"{"name":"read-only","actions":["mesh.view"]}"#,
        ),
        ("mesh.unknown", b"{}"),
    ] {
        assert_eq!(parse_action(action, input), Err(MeshApiError::InvalidInput));
    }
}

#[tokio::test]
async fn inventory_lifecycle_preserves_policy_identity_and_audits_every_edit() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let first = enroll(service, "db-1", 1).await;
    let second = enroll(service, "web-1", 2).await;
    call(
        service,
        OWNER,
        "mesh.tag.create",
        json!({"name":"prod"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.tag.create",
        json!({"name":"staging"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"prod","node_id":first}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"staging","node_id":second}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.node.observe",
        json!({"node_id":first,"last_rtt_us":2150}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.node.rename",
        json!({"node_id":first,"name":"database-1"}),
        NOW,
    )
    .await
    .unwrap();

    let live = service
        .list(OWNER, MeshFilter::default(), NOW + 29)
        .await
        .unwrap();
    assert!(live.nodes[0].live);
    assert_eq!(live.nodes[0].last_rtt_us, Some(2150));
    assert_eq!(live.nodes[0].node.host, "database-1");
    let offline = service
        .list(OWNER, MeshFilter::default(), NOW + 31)
        .await
        .unwrap();
    assert!(!offline.nodes[0].live);

    let grant = call(
        service,
        OWNER,
        "mesh.grant.create",
        json!({
            "name":"prod-web",
            "from":{"Tag":"prod"},
            "to":{"Node":second},
            "both_ways":true
        }),
        NOW,
    )
    .await
    .unwrap();
    let grant_id = grant["grant_id"].as_u64().unwrap();
    call(
        service,
        OWNER,
        "mesh.tag.rename",
        json!({"name":"prod","new_name":"production"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.grant.rename",
        json!({"name":"prod-web","new_name":"production-web"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.grant.move",
        json!({"name":"production-web","side":"to","endpoint":{"Node":first}}),
        NOW,
    )
    .await
    .unwrap();
    let renamed = service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let saved = &renamed.grants[0];
    assert_eq!(saved.name, "production-web");
    assert_eq!(saved.arrow.id.0, grant_id);
    assert_eq!(
        saved.arrow.from,
        infraternal_mesh::rules::Endpoint::Tag("production".into())
    );
    assert_eq!(
        saved.arrow.to,
        infraternal_mesh::rules::Endpoint::Node(infraternal_mesh::model::NodeId(first))
    );
    assert!(saved.arrow.both_ways);
    assert_eq!(
        saved.arrow.ports,
        infraternal_mesh::rules::TrafficPolicy::All
    );

    assert_eq!(
        call(
            service,
            OWNER,
            "mesh.tag.delete",
            json!({"name":"production"}),
            NOW
        )
        .await,
        Err(MeshApiError::Conflict),
    );
    call(
        service,
        OWNER,
        "mesh.grant.delete",
        json!({"name":"production-web"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.tag.delete",
        json!({"name":"production"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.grant.create",
        json!({"name":"cleanup","from":{"Node":second},"to":{"Node":first},"both_ways":false}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.node.delete",
        json!({"node_id":second}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.tag.delete",
        json!({"name":"staging"}),
        NOW,
    )
    .await
    .unwrap();

    let dependent_grants: i64 = sqlx::query_scalar(
        "SELECT json_extract(detail_json, '$.dependent_grants') FROM mesh_audit WHERE action='mesh.node.delete'",
    )
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(dependent_grants, 1);
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_audit")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(revision, audits);
    assert_eq!(revision, 17);
    fixture.cleanup().await;
}

#[tokio::test]
async fn scoped_grant_role_filters_inventory_and_cannot_cross_tags() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let prod_node = enroll(service, "prod-db", 3).await;
    let dev_node = enroll(service, "dev-db", 4).await;
    for tag in ["prod", "dev"] {
        call(service, OWNER, "mesh.tag.create", json!({"name":tag}), NOW)
            .await
            .unwrap();
    }
    for (tag, node_id) in [("prod", prod_node), ("dev", dev_node)] {
        call(
            service,
            OWNER,
            "mesh.tag.member.add",
            json!({"tag":tag,"node_id":node_id}),
            NOW,
        )
        .await
        .unwrap();
    }
    call(
        service,
        OWNER,
        "mesh.role.define",
        json!({"name":"prod-grants","actions":["mesh.manage_grants"],"scopes":["prod"]}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"prod-grants"}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.define",
        json!({"name":"prod-nodes","actions":["mesh.manage_nodes"],"scopes":["prod"]}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"prod-nodes"}),
        NOW,
    )
    .await
    .unwrap();

    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.rename",
            json!({"node_id":prod_node,"name":"prod-db-scoped"}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.rename",
            json!({"node_id":dev_node,"name":"dev-db-scoped"}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    assert!(
        call(
            service,
            MEMBER,
            "mesh.node.observe",
            json!({"node_id":prod_node,"last_rtt_us":2150}),
            NOW,
        )
        .await
        .is_ok()
    );
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.observe",
            json!({"node_id":dev_node,"last_rtt_us":3250}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );

    let snapshot = service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.nodes.len(), 1);
    assert_eq!(snapshot.nodes[0].node.id.0, prod_node);
    assert_eq!(
        snapshot
            .tags
            .iter()
            .map(|tag| tag.name.as_str())
            .collect::<Vec<_>>(),
        ["prod"]
    );
    assert_eq!(
        service
            .list(
                MEMBER,
                MeshFilter {
                    tag: Some("dev".into()),
                    cursor: None,
                },
                NOW
            )
            .await,
        Err(MeshApiError::Denied),
    );
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.enroll",
            json!({"name":"new","public_key":vec![5_u8;32]}),
            NOW
        )
        .await,
        Err(MeshApiError::Denied),
    );
    call(
        service,
        MEMBER,
        "mesh.grant.create",
        json!({"name":"prod-to-prod","from":{"Tag":"prod"},"to":{"Node":prod_node},"both_ways":false}),
        NOW,
    )
    .await
    .unwrap();
    let before_denied: i64 =
        sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.grant.create",
            json!({"name":"cross-tag","from":{"Tag":"prod"},"to":{"Node":dev_node},"both_ways":false}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    let after_denied: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(before_denied, after_denied);
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_audit")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(before_denied, audits);

    let multi_tag_node = enroll(service, "multi-tag-db", 5).await;
    for tag in ["prod", "dev"] {
        call(
            service,
            OWNER,
            "mesh.tag.member.add",
            json!({"tag":tag,"node_id":multi_tag_node}),
            NOW,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.rename",
            json!({"node_id":multi_tag_node,"name":"multi-tag-renamed"}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.delete",
            json!({"node_id":multi_tag_node}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    let untagged_node = enroll(service, "untagged-db", 6).await;
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.rename",
            json!({"node_id":untagged_node,"name":"untagged-renamed"}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    fixture.cleanup().await;
}

#[tokio::test]
async fn concurrent_tag_edits_serialize_revisions_and_unique_names() {
    let fixture = Fixture::new().await;
    let service = fixture.service.clone();
    let (left, right) = tokio::join!(
        call(
            &service,
            OWNER,
            "mesh.tag.create",
            json!({"name":"alpha"}),
            NOW
        ),
        call(
            &service,
            OWNER,
            "mesh.tag.create",
            json!({"name":"beta"}),
            NOW
        ),
    );
    assert!(left.is_ok() && right.is_ok());
    let (first, second) = tokio::join!(
        call(
            &service,
            OWNER,
            "mesh.tag.create",
            json!({"name":"shared"}),
            NOW
        ),
        call(
            &service,
            OWNER,
            "mesh.tag.create",
            json!({"name":"shared"}),
            NOW
        ),
    );
    let successes = usize::from(first.is_ok()) + usize::from(second.is_ok());
    let conflicts = usize::from(first == Err(MeshApiError::Conflict))
        + usize::from(second == Err(MeshApiError::Conflict));
    assert_eq!(successes, 1);
    assert_eq!(conflicts, 1);
    let revision: i64 = sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_audit")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(revision, 3);
    assert_eq!(audits, revision);
    fixture.cleanup().await;
}

#[test]
fn shared_mesh_vectors_cover_each_production_action_and_wire_shape() {
    let manifest: Value = serde_json::from_str(include_str!(
        "../../../contracts/vectors/mesh/manifest.json"
    ))
    .unwrap();
    let expected_actions = [
        "mesh.list",
        "mesh.node.enroll",
        "mesh.node.observe",
        "mesh.node.rename",
        "mesh.node.delete",
        "mesh.tag.create",
        "mesh.tag.rename",
        "mesh.tag.delete",
        "mesh.tag.member.add",
        "mesh.tag.member.remove",
        "mesh.grant.create",
        "mesh.grant.move",
        "mesh.grant.delete",
        "mesh.grant.rename",
        "mesh.role.define",
        "mesh.role.assign",
        "mesh.default.get",
        "mesh.default.preview",
        "mesh.default.set",
    ];
    let actions = manifest["actions"].as_array().unwrap();
    assert_eq!(actions.len(), expected_actions.len());
    for (vector, expected_action) in actions.iter().zip(expected_actions) {
        let action = vector["action"].as_str().unwrap();
        assert_eq!(action, expected_action);
        let input = serde_json::to_vec(&vector["input"]).unwrap();
        parse_action(action, &input)
            .unwrap_or_else(|error| panic!("golden action {action} input must parse: {error:?}"));
    }

    let results = manifest["results"].as_array().unwrap();
    assert_eq!(results.len(), 4);
    for result in results {
        let value = &result["value"];
        assert!(value["revision"].as_u64().is_some());
        match result["action"].as_str().unwrap() {
            "mesh.list" => {
                assert!(value["nodes"].is_array());
                assert!(value["tags"].is_array());
                assert!(value["grants"].is_array());
                assert_eq!(
                    value["nodes"][0]["node"]["public_key"]
                        .as_array()
                        .unwrap()
                        .len(),
                    32
                );
                assert!(value["grants"][0]["arrow"]["id"].as_u64().is_some());
            }
            "mesh.node.enroll" => assert!(value["node_id"].as_u64().is_some()),
            "mesh.grant.create" => assert!(value["grant_id"].as_u64().is_some()),
            "mesh.tag.member.add" => assert_eq!(value.as_object().unwrap().len(), 1),
            action => panic!("unexpected golden result action {action}"),
        }
    }

    let subscriptions = manifest["subscriptions"].as_array().unwrap();
    assert_eq!(subscriptions.len(), 4);
    let expected_events = ["snapshot", "changed", "resync", "error"];
    for (vector, expected_event) in subscriptions.iter().zip(expected_events) {
        assert_eq!(vector["filter"]["topic"], "mesh");
        assert_eq!(vector["event"]["type"], expected_event);
        match expected_event {
            "snapshot" | "resync" => {
                assert!(vector["event"]["snapshot"]["revision"].as_u64().is_some());
            }
            "changed" => assert!(vector["event"]["revision"].as_u64().is_some()),
            "error" => assert!(vector["event"]["error"].as_str().is_some()),
            _ => unreachable!(),
        }
    }
}

/// Measure Mesh list, mutation and 50-viewer invalidation work at the D170 inventory point.
/// Run on infraternal-dev with `systemd-run --user --scope -p CPUWeight=10000`.
#[tokio::test]
#[ignore = "scale measurement; run on infraternal-dev under the weighted user scope"]
async fn mesh_api_scale_benchmark() {
    let fixture = Fixture::new().await;
    let pool = &fixture.pool;
    let rss_base_kib = proc_status_kib("VmRSS:");
    let viewers = seed_scale_inventory(&fixture).await;
    let filter = MeshFilter::default();
    let (list_samples, list_payload_bytes) =
        measure_scale_lists(&fixture.service, &viewers, &filter).await;
    let op_samples = measure_scale_operations(&fixture.service, &viewers).await;
    let (
        fanout_samples,
        fanout_cpu_samples_ns,
        outbound_event_bytes,
        subscriber_receiver_bytes,
        subscriber_rss_before_kib,
        subscriber_rss_after_kib,
    ) = measure_scale_fanout(&fixture.service, &viewers, &filter).await;
    let subscriber_receiver_bytes_50 = subscriber_receiver_bytes * SCALE_VIEWER_COUNT;

    let page_count: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(pool)
        .await
        .unwrap();
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(pool)
        .await
        .unwrap();
    let load: Vec<_> = std::fs::read_to_string("/proc/loadavg")
        .unwrap()
        .split_whitespace()
        .take(3)
        .map(str::to_owned)
        .collect();
    let host = std::process::Command::new("hostname")
        .output()
        .unwrap()
        .stdout;
    println!(
        "METRIC name=mesh_api_scale host={} cpus={} loadavg_1m={} loadavg_5m={} loadavg_15m={} nodes={SCALE_NODE_COUNT} tags={SCALE_TAG_COUNT} grants={SCALE_GRANT_COUNT} memberships={} viewers={SCALE_VIEWER_COUNT} list_samples={} list_p50_ms={:.3} list_p95_ms={:.3} list_p99_ms={:.3} list_payload_bytes={list_payload_bytes} op=mesh.node.observe op_samples={} op_p50_ms={:.3} op_p95_ms={:.3} op_p99_ms={:.3} fanout_samples={} fanout_viewers={SCALE_VIEWER_COUNT} fanout_p50_ms={:.3} fanout_p95_ms={:.3} fanout_p99_ms={:.3} fanout_cpu_p50_us={} fanout_cpu_p95_us={} fanout_cpu_p99_us={} fanout_cpu_per_viewer_p50_ns={} fanout_cpu_per_viewer_p95_ns={} fanout_cpu_per_viewer_p99_ns={} fanout_event_bytes_per_viewer={} fanout_event_bytes_per_change={} fanout_outbound_event_bytes_total={outbound_event_bytes} subscriber_receiver_bytes_each={subscriber_receiver_bytes} subscriber_receiver_bytes_50={subscriber_receiver_bytes_50} subscriber_rss_before_kib={subscriber_rss_before_kib} subscriber_rss_after_kib={subscriber_rss_after_kib} rss_base_kib={rss_base_kib} rss_final_kib={} rss_hwm_kib={} sqlite_page_count={page_count} sqlite_page_size={page_size}",
        String::from_utf8_lossy(&host).trim(),
        std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        load.first().map_or("unknown", String::as_str),
        load.get(1).map_or("unknown", String::as_str),
        load.get(2).map_or("unknown", String::as_str),
        SCALE_NODE_COUNT * SCALE_MEMBERSHIPS_PER_NODE,
        list_samples.len(),
        percentile_ms(&list_samples, 50),
        percentile_ms(&list_samples, 95),
        percentile_ms(&list_samples, 99),
        op_samples.len(),
        percentile_ms(&op_samples, 50),
        percentile_ms(&op_samples, 95),
        percentile_ms(&op_samples, 99),
        fanout_samples.len(),
        percentile_ms(&fanout_samples, 50),
        percentile_ms(&fanout_samples, 95),
        percentile_ms(&fanout_samples, 99),
        percentile_u128(&fanout_cpu_samples_ns, 50) / 1_000,
        percentile_u128(&fanout_cpu_samples_ns, 95) / 1_000,
        percentile_u128(&fanout_cpu_samples_ns, 99) / 1_000,
        percentile_u128(&fanout_cpu_samples_ns, 50) / u128::try_from(SCALE_VIEWER_COUNT).unwrap(),
        percentile_u128(&fanout_cpu_samples_ns, 95) / u128::try_from(SCALE_VIEWER_COUNT).unwrap(),
        percentile_u128(&fanout_cpu_samples_ns, 99) / u128::try_from(SCALE_VIEWER_COUNT).unwrap(),
        outbound_event_bytes / fanout_samples.len() / SCALE_VIEWER_COUNT,
        outbound_event_bytes / fanout_samples.len(),
        proc_status_kib("VmRSS:"),
        proc_status_kib("VmHWM:"),
    );
    measure_page_encoding_cpu(&fixture.service.list(OWNER, filter, NOW).await.unwrap());
    fixture.cleanup().await;
}

/// Compare the former direct encoding with bounded encoding on the same inventory.
/// Process CPU excludes shared-host scheduling delays; cloning is outside both intervals.
fn measure_page_encoding_cpu(snapshot: &crate::mesh_api::MeshSnapshot) {
    let mut direct = Vec::new();
    let mut paged = Vec::new();
    for _ in 0..100 {
        let candidate = snapshot.clone();
        let started = process_cpu_ns();
        let payload = serde_json::to_vec(snapshot).unwrap();
        direct.push(process_cpu_ns() - started);
        std::hint::black_box(payload);
        let started = process_cpu_ns();
        let page = crate::mesh_api::page_snapshot(candidate, None).unwrap();
        let payload = serde_json::to_vec(&page).unwrap();
        paged.push(process_cpu_ns() - started);
        std::hint::black_box(payload);
    }
    let direct_p50 = percentile_u128(&direct, 50);
    let paged_p50 = percentile_u128(&paged, 50);
    let extra = paged_p50.saturating_sub(direct_p50);
    println!(
        "METRIC name=mesh_page_encoding nodes={} tags={} grants={} samples=100 direct_cpu_p50_us={} direct_cpu_p95_us={} paged_cpu_p50_us={} paged_cpu_p95_us={} extra_cpu_p50_us={} extra_cpu_50_viewers_p50_us={}",
        snapshot.nodes.len(),
        snapshot.tags.len(),
        snapshot.grants.len(),
        direct_p50 / 1000,
        percentile_u128(&direct, 95) / 1000,
        paged_p50 / 1000,
        percentile_u128(&paged, 95) / 1000,
        extra / 1000,
        extra * 50 / 1000
    );
}

async fn seed_scale_inventory(fixture: &Fixture) -> Vec<String> {
    let mut tx = fixture.pool.begin().await.unwrap();
    for tag in 0..SCALE_TAG_COUNT {
        sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES (?,?)")
            .bind(format!("tag-{tag:03}"))
            .bind(NOW)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    for node in 1..=SCALE_NODE_COUNT {
        let mut public_key = [0_u8; 32];
        public_key[..8].copy_from_slice(&node.to_le_bytes());
        sqlx::query(
            "INSERT INTO mesh_nodes(id,name,public_key,last_seen,last_rtt_us) VALUES (?,?,?,?,?)",
        )
        .bind(node)
        .bind(format!("node-{node:04}"))
        .bind(public_key.as_slice())
        .bind(NOW)
        .bind(1_000_i64 + node)
        .execute(&mut *tx)
        .await
        .unwrap();
        for offset in 0..SCALE_MEMBERSHIPS_PER_NODE {
            let tag = (node * 7 + offset * 13) % SCALE_TAG_COUNT;
            sqlx::query("INSERT INTO mesh_tag_members(tag_name,node_id) VALUES (?,?)")
                .bind(format!("tag-{tag:03}"))
                .bind(node)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
    }
    for grant in 0..SCALE_GRANT_COUNT {
        let tag = grant % SCALE_TAG_COUNT;
        let node = grant % SCALE_NODE_COUNT + 1;
        sqlx::query(
            "INSERT INTO mesh_grants(name,from_kind,from_value,to_kind,to_value,both_ways,ports_json) VALUES (?,?,?,?,?,?,?)",
        )
        .bind(format!("grant-{grant:04}"))
        .bind("tag")
        .bind(format!("tag-{tag:03}"))
        .bind("node")
        .bind(node.to_string())
        .bind(grant % 2 == 0)
        .bind("\"All\"")
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    sqlx::query("INSERT INTO mesh_roles(name,created_at) VALUES ('mesh-scale-viewer',?)")
        .bind(NOW)
        .execute(&mut *tx)
        .await
        .unwrap();
    for action in ["mesh.manage_nodes", "mesh.manage_grants"] {
        sqlx::query("INSERT INTO mesh_role_actions(role_name,action,scope_tag) VALUES ('mesh-scale-viewer',?,NULL)")
            .bind(action)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let viewers: Vec<String> = (0..SCALE_VIEWER_COUNT)
        .map(|viewer| format!("mesh-bench-{viewer:03}"))
        .collect();
    for (index, viewer) in viewers.iter().enumerate() {
        sqlx::query(
            "INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?, ?, 0, 'benchmark-fixture', ?, ?)",
        )
        .bind(viewer)
        .bind(viewer)
        .bind(viewer)
        .bind(format!("Mesh benchmark viewer {index}"))
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO mesh_user_roles(user_id,role_name) VALUES (?,'mesh-scale-viewer')",
        )
        .bind(viewer)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    viewers
}

async fn measure_scale_lists(
    service: &MeshService,
    viewers: &[String],
    filter: &MeshFilter,
) -> (Vec<Duration>, usize) {
    const WARMUP: usize = 10;
    const SAMPLES: usize = 200;
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut payload_bytes = 0;
    for sample in 0..(WARMUP + SAMPLES) {
        let actor = &viewers[sample % SCALE_VIEWER_COUNT];
        let started = Instant::now();
        let snapshot = service.list(actor, filter.clone(), NOW).await.unwrap();
        let elapsed = started.elapsed();
        let payload = serde_json::to_vec(&snapshot).unwrap();
        if sample == WARMUP {
            payload_bytes = payload.len();
        }
        if sample >= WARMUP {
            samples.push(elapsed);
        }
    }
    (samples, payload_bytes)
}

async fn measure_scale_operations(service: &MeshService, viewers: &[String]) -> Vec<Duration> {
    const SAMPLES: usize = 200;
    let input = serde_json::to_vec(&json!({"node_id":1,"last_rtt_us":1234})).unwrap();
    let mut samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let actor = &viewers[sample % SCALE_VIEWER_COUNT];
        let now = NOW + i64::try_from(sample).unwrap();
        let started = Instant::now();
        service
            .execute(actor, "mesh.node.observe", &input, now)
            .await
            .unwrap();
        samples.push(started.elapsed());
    }
    samples
}

/// Measure the per-viewer server path through authorization and encoded Event bytes.
async fn measure_scale_fanout(
    service: &MeshService,
    viewers: &[String],
    filter: &MeshFilter,
) -> (Vec<Duration>, Vec<u128>, usize, usize, u64, u64) {
    const SAMPLES: usize = 100;
    let input = serde_json::to_vec(&json!({"node_id":1,"last_rtt_us":1234})).unwrap();
    let subscriber_rss_before_kib = proc_status_kib("VmRSS:");
    let mut receivers: Vec<_> = (0..SCALE_VIEWER_COUNT)
        .map(|_| service.subscribe())
        .collect();
    let subscriber_rss_after_kib = proc_status_kib("VmRSS:");
    let subscriber_receiver_bytes = std::mem::size_of_val(receivers.first().unwrap());
    let subscriber_receiver_allocation_bytes = receivers.capacity() * subscriber_receiver_bytes;
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut cpu_samples_ns = Vec::with_capacity(SAMPLES);
    let mut outbound_bytes = 0_usize;
    for sample in 0..SAMPLES {
        let actor = &viewers[sample % SCALE_VIEWER_COUNT];
        let now = NOW + 1_000 + i64::try_from(sample).unwrap();
        service
            .execute(actor, "mesh.node.observe", &input, now)
            .await
            .unwrap();
        let cpu_started = process_cpu_ns();
        let started = Instant::now();
        let updates = join_all(
            receivers
                .iter_mut()
                .map(tokio::sync::broadcast::Receiver::recv),
        )
        .await;
        let change = updates[0].as_ref().unwrap();
        let revision = change.revision;
        assert!(updates.iter().all(|update| {
            update
                .as_ref()
                .is_ok_and(|change| change.revision == revision)
        }));
        let checks = join_all(
            viewers
                .iter()
                .map(|viewer| service.can_view_change(viewer, filter, change)),
        )
        .await;
        assert!(checks.iter().all(|check| matches!(check, Ok(true))));
        let event = json!({"type":"changed","revision":revision});
        for sub_id in 0..SCALE_VIEWER_COUNT {
            let event_json = serde_json::to_vec(&event).unwrap();
            let mut encoded = Vec::with_capacity(event_json.len() + 12);
            encode_muxed_frame_into(
                0,
                &Frame::Event {
                    sub_id: u32::try_from(sub_id + 1).unwrap(),
                    event_json: &event_json,
                },
                &mut encoded,
            )
            .unwrap();
            outbound_bytes += encoded.len();
        }
        samples.push(started.elapsed());
        cpu_samples_ns.push(process_cpu_ns() - cpu_started);
    }
    assert_eq!(
        subscriber_receiver_allocation_bytes,
        subscriber_receiver_bytes * SCALE_VIEWER_COUNT
    );
    (
        samples,
        cpu_samples_ns,
        outbound_bytes,
        subscriber_receiver_bytes,
        subscriber_rss_before_kib,
        subscriber_rss_after_kib,
    )
}

fn percentile_ms(samples: &[Duration], percentile: usize) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index].as_secs_f64() * 1_000.0
}

fn percentile_u128(samples: &[u128], percentile: usize) -> u128 {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let index = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
    sorted[index]
}

fn process_cpu_ns() -> u128 {
    let cpu = nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID).unwrap();
    u128::try_from(cpu.tv_sec()).unwrap() * 1_000_000_000 + u128::try_from(cpu.tv_nsec()).unwrap()
}

fn proc_status_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}

mod membership;

mod identity;

mod invalidation;

mod pagination;

mod review_frame_budget;

mod review_filtered;

mod review_null_policy;

mod review_null_scope;

mod claude_review;

mod watch_deadline;

mod storage_diagnostics;
