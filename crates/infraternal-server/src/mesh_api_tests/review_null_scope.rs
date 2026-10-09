//! Real SQLite evidence for null role scopes becoming global Mesh authority [D154, D187, #108].
use super::*;

#[tokio::test]
async fn review_null_role_scopes_preserve_denied_inventory_access() {
    let fixture = Fixture::new().await;
    enroll(&fixture.service, "private-host", 1).await;
    let before = fixture
        .service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await;
    assert_eq!(before, Err(MeshApiError::Denied));
    let inventory_before = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let defined = call(
        &fixture.service,
        OWNER,
        "mesh.role.define",
        json!({"name":"restricted","actions":["mesh.manage_nodes"],"scopes":null}),
        NOW,
    )
    .await;
    if defined.is_ok() {
        call(
            &fixture.service,
            OWNER,
            "mesh.role.assign",
            json!({"user_id":MEMBER,"role":"restricted"}),
            NOW,
        )
        .await
        .unwrap();
    }
    let after = fixture
        .service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await;
    let globally_enrolled = call(
        &fixture.service,
        MEMBER,
        "mesh.node.enroll",
        json!({"name":"member-host","public_key":vec![2_u8;32]}),
        NOW,
    )
    .await;
    println!(
        "null_scope_role={defined:?} member_visible_nodes={} global_enrollment={globally_enrolled:?}",
        after.as_ref().map_or(0, |view| view.nodes.len())
    );
    let inventory_after = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let roles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mesh_roles")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    let audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mesh_audit")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    fixture.cleanup().await;
    assert_eq!(
        inventory_after, inventory_before,
        "refusal preserves inventory and revision"
    );
    assert_eq!(roles, 0, "refusal stores no role authority");
    assert_eq!(audit, 1, "only the original enrollment is audited");
    assert_eq!(defined, Err(MeshApiError::InvalidInput));
    assert_eq!(after, Err(MeshApiError::Denied));
    assert_eq!(globally_enrolled, Err(MeshApiError::Denied));
}
