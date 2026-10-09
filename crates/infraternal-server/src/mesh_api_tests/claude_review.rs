//! Independent review regressions for scoped grant authority and observation ordering [D154, D164, #108].
use super::*;

/// A node endpoint's scopes are all of its current memberships. A grant role
/// scoped to one of them must not open access into a node another tag's
/// administrators also manage; node edits already require every membership.
#[tokio::test]
async fn claude_review_scoped_grant_cannot_target_node_in_unscoped_tag() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let shared = enroll(service, "shared-db", 7).await;
    for tag in ["prod", "dev"] {
        call(service, OWNER, "mesh.tag.create", json!({"name":tag}), NOW)
            .await
            .unwrap();
        call(
            service,
            OWNER,
            "mesh.tag.member.add",
            json!({"tag":tag,"node_id":shared}),
            NOW,
        )
        .await
        .unwrap();
    }
    for (role, action) in [
        ("prod-grants", "mesh.manage_grants"),
        ("prod-nodes", "mesh.manage_nodes"),
    ] {
        call(
            service,
            OWNER,
            "mesh.role.define",
            json!({"name":role,"actions":[action],"scopes":["prod"]}),
            NOW,
        )
        .await
        .unwrap();
        call(
            service,
            OWNER,
            "mesh.role.assign",
            json!({"user_id":MEMBER,"role":role}),
            NOW,
        )
        .await
        .unwrap();
    }
    // Baseline: the same prod-only scope cannot even rename this dev+prod node.
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.node.rename",
            json!({"node_id":shared,"name":"renamed"}),
            NOW,
        )
        .await,
        Err(MeshApiError::Denied),
    );
    let created = call(
        service,
        MEMBER,
        "mesh.grant.create",
        json!({"name":"prod-into-dev","from":{"Tag":"prod"},"to":{"Node":shared},"both_ways":true}),
        NOW,
    )
    .await;
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM mesh_grants")
        .fetch_one(&fixture.pool)
        .await
        .unwrap();
    println!("grant_create={created:?} grants_committed={grants}");
    // Existing grants require the same authority for rename/delete, and moves
    // must cover the old, new and retained node's complete memberships.
    call(
        service,
        OWNER,
        "mesh.grant.create",
        json!({"name":"existing","from":{"Tag":"prod"},"to":{"Node":shared},"both_ways":true}),
        NOW,
    )
    .await
    .unwrap();
    for (action, input) in [
        (
            "mesh.grant.rename",
            json!({"name":"existing","new_name":"renamed"}),
        ),
        ("mesh.grant.delete", json!({"name":"existing"})),
        (
            "mesh.grant.move",
            json!({"name":"existing","side":"to","endpoint":{"Tag":"prod"}}),
        ),
        (
            "mesh.grant.move",
            json!({"name":"existing","side":"from","endpoint":{"Tag":"dev"}}),
        ),
    ] {
        assert_eq!(
            call(service, MEMBER, action, input, NOW).await,
            Err(MeshApiError::Denied)
        );
    }
    fixture.cleanup().await;
    assert_eq!(
        created,
        Err(MeshApiError::Denied),
        "a prod-scoped grant role opened access into a node that is also in dev"
    );
    assert_eq!(grants, 0);
}
/// Observations admitted out of order must not move liveness backwards.
#[tokio::test]
async fn claude_review_late_committing_observation_does_not_rewind_last_seen() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let node = enroll(service, "edge-1", 9).await;
    // `now` is captured before the writer wait, so a request admitted at
    // NOW+5 can commit after one admitted at NOW+10.
    for at in [NOW + 10, NOW + 5] {
        call(
            service,
            OWNER,
            "mesh.node.observe",
            json!({"node_id":node,"last_rtt_us":100}),
            at,
        )
        .await
        .unwrap();
    }
    let snapshot = service
        .list(OWNER, MeshFilter::default(), NOW + 38)
        .await
        .unwrap();
    println!(
        "last_seen={:?} live_at_now_plus_38={}",
        snapshot.nodes[0].last_seen, snapshot.nodes[0].live
    );
    fixture.cleanup().await;
    assert_eq!(snapshot.nodes[0].last_seen, Some(NOW + 10));
    assert!(snapshot.nodes[0].live);
}
