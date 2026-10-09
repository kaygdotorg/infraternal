//! Independent filtered-subscription check for owners and global roles [D164, D187, #108].
use super::*;

#[tokio::test]
async fn review_global_viewers_do_not_refresh_unrelated_filtered_inventory() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let unrelated = enroll(service, "other-host", 4).await;
    for name in ["prod", "private"] {
        call(service, OWNER, "mesh.tag.create", json!({"name":name}), NOW)
            .await
            .unwrap();
    }
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"private","node_id":unrelated}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.define",
        json!({"name":"global-nodes","actions":["mesh.manage_nodes"]}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"global-nodes"}),
        NOW,
    )
    .await
    .unwrap();
    let filter = MeshFilter {
        tag: Some("prod".to_owned()),
        cursor: None,
    };
    let before = service.list(OWNER, filter.clone(), NOW).await.unwrap();
    let mut updates = service.subscribe();
    call(
        service,
        OWNER,
        "mesh.node.observe",
        json!({"node_id":unrelated,"last_rtt_us":42}),
        NOW,
    )
    .await
    .unwrap();
    let change = updates.recv().await.unwrap();
    let after = service.list(OWNER, filter.clone(), NOW).await.unwrap();
    assert_eq!(before.nodes, after.nodes);
    assert_eq!(before.tags, after.tags);
    assert_eq!(before.grants, after.grants);
    let mut notifications = Vec::new();
    for actor in [OWNER, MEMBER] {
        notifications.push(
            service
                .can_view_change(actor, &filter, &change)
                .await
                .unwrap(),
        );
    }
    println!(
        "requested_tag=prod changed_scopes={:?} owner_and_global_role_notified={notifications:?}",
        change.scopes
    );
    fixture.cleanup().await;
    assert_eq!(
        notifications,
        vec![false, false],
        "unrelated node observations refresh filtered inventories"
    );
}
