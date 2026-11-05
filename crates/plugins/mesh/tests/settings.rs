//! Exercise owner authorization, preview revision and fresh-passkey checks on the production SQLite schema [28,216].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used)]
use infraternal_plugin_mesh::dataplane::DefaultPolicy;
use infraternal_plugin_mesh::{
    api::{MeshApiError, MeshService},
    policy::model::PublicKey,
};
use serde_json::json;
#[tokio::test]
async fn default_switch_requires_owner_freshness_and_the_preview_revision() {
    let (pool, service, store, now) = fixture().await;
    let read = |v| serde_json::to_vec(&v).unwrap();
    let initial = DefaultPolicy::default();
    let desired = if initial == DefaultPolicy::Allow {
        DefaultPolicy::Deny
    } else {
        DefaultPolicy::Allow
    };
    assert_eq!(
        service
            .execute("member", "mesh.default.get", b"{}", now)
            .await,
        Err(MeshApiError::Denied)
    );
    let preview = service
        .execute(
            "owner",
            "mesh.default.preview",
            &read(json!({"default_policy":desired})),
            now,
        )
        .await
        .unwrap();
    // Node-to-server initiation remains implicit; server-to-node initiation follows Access.
    store
        .attach("other", PublicKey([3; 32]), None, false)
        .await
        .unwrap();
    assert_eq!(
        service
            .execute(
                "owner",
                "mesh.default.set",
                &read(json!({"default_policy":desired,"expected_revision":preview["revision"]})),
                now
            )
            .await,
        Err(MeshApiError::Conflict)
    );
    let preview = service
        .execute(
            "owner",
            "mesh.default.preview",
            &read(json!({"default_policy":desired})),
            now,
        )
        .await
        .unwrap();
    assert_eq!(
        preview["total_pairs"],
        if initial == DefaultPolicy::Allow {
            4
        } else {
            0
        }
    );
    let input = read(json!({"default_policy":desired,"expected_revision":preview["revision"]}));
    let fresh = service.with_fresh_authority("fixture-authority".into());
    assert_eq!(
        fresh
            .execute("owner", "mesh.default.set", &input, now)
            .await,
        Err(MeshApiError::FreshRequired)
    );
    assert_eq!(
        service
            .execute("owner", "mesh.default.get", b"{}", now)
            .await
            .unwrap()["default_policy"],
        json!(initial)
    );
    sqlx::query("UPDATE sessions SET fresh=?")
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
    let mut updates = service.subscribe();
    let applied = fresh
        .execute("owner", "mesh.default.set", &input, now)
        .await
        .unwrap();
    assert_applied(
        &pool,
        &service,
        &fresh,
        &mut updates,
        &applied,
        desired,
        &input,
        now,
    )
    .await;
}

async fn fixture() -> (
    sqlx::SqlitePool,
    MeshService,
    infraternal_plugin_mesh::store::Store,
    i64,
) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    for (id, owner) in [("owner", 1), ("member", 0)] {
        sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES(?,?,?,'fixture',?,?)").bind(id).bind(id).bind(owner).bind(id).bind(id).execute(&pool).await.unwrap();
    }
    let now = 1_800_000_000_i64;
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES('fixture-authority','owner','fixture',?,?,1)").bind(now+1000).bind(now-1000).execute(&pool).await.unwrap();
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    store
        .attach("server", PublicKey([1; 32]), None, true)
        .await
        .unwrap();
    store
        .attach("node", PublicKey([2; 32]), None, false)
        .await
        .unwrap();
    (pool, service, store, now)
}

// Check the committed policy, notification, audit and replay fence together.
async fn assert_applied(
    pool: &sqlx::SqlitePool,
    service: &MeshService,
    fresh: &MeshService,
    updates: &mut tokio::sync::broadcast::Receiver<infraternal_plugin_mesh::api::MeshChange>,
    applied: &serde_json::Value,
    desired: DefaultPolicy,
    input: &[u8],
    now: i64,
) {
    assert_eq!(applied["default_policy"], json!(desired));
    assert_eq!(
        updates.try_recv().unwrap().revision,
        applied["revision"].as_i64().unwrap()
    );
    assert_eq!(
        service
            .execute("owner", "mesh.default.get", b"{}", now)
            .await
            .unwrap()["default_policy"],
        json!(desired)
    );
    assert_eq!(
        fresh.execute("owner", "mesh.default.set", input, now).await,
        Err(MeshApiError::Conflict)
    );
    let audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM mesh_audit WHERE action='mesh.default.set'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(audit, 1);
}
