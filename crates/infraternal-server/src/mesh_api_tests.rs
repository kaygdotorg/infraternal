//! Real SQLite regressions for Mesh input validation, authorization, inventory edits, and concurrency.
use crate::{
    auth::Auth,
    mesh_api::{MeshApiError, MeshFilter, MeshService, parse_action},
};
use serde_json::{Value, json};
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

const OWNER: &str = "mesh-owner";
const MEMBER: &str = "mesh-member";
const NOW: i64 = 1_800_000_000;

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
        ("mesh.unknown", b"{}"),
    ] {
        assert_eq!(parse_action(action, input), Err(MeshApiError::InvalidInput));
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the edit sequence beside its final revision and audit assertions.
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
#[allow(clippy::too_many_lines)] // Keep setup, scoped authorization, and failed-edit atomicity in one case.
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
                    tag: Some("dev".into())
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
