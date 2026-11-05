//! Reproduce suppressed notifications when membership changes a second tag viewer's snapshot.
use super::*;

#[tokio::test]
async fn review_membership_change_notifies_other_visible_tag() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let node = enroll(service, "shared-host", 1).await;
    for tag in ["prod", "private"] {
        call(service, OWNER, "mesh.tag.create", json!({"name":tag}), NOW)
            .await
            .unwrap();
        call(
            service,
            OWNER,
            "mesh.tag.member.add",
            json!({"tag":tag,"node_id":node}),
            NOW,
        )
        .await
        .unwrap();
    }
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
    let before = service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let mut updates = service.subscribe();
    call(
        service,
        OWNER,
        "mesh.tag.member.remove",
        json!({"tag":"private","node_id":node}),
        NOW,
    )
    .await
    .unwrap();
    let change = updates.recv().await.unwrap();
    let notified = service
        .can_view_change(MEMBER, &MeshFilter::default(), &change)
        .await
        .unwrap();
    let after = service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    assert_ne!(before.nodes, after.nodes);
    println!(
        "before_tags={:?}; after_tags={:?}; notification_scopes={:?}; delivery={notified}",
        before.nodes[0].node.tags, after.nodes[0].node.tags, change.scopes
    );
    fixture.cleanup().await;
    assert!(
        notified,
        "A viewer whose inventory changed must receive an invalidation"
    );
}

#[tokio::test]
async fn filtered_view_invalidations_follow_every_affected_host_tag() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let node = enroll(service, "shared-host", 3).await;
    let isolated = enroll(service, "isolated-host", 4).await;
    for tag in ["prod", "private", "other"] {
        call(service, OWNER, "mesh.tag.create", json!({"name":tag}), NOW)
            .await
            .unwrap();
    }
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"prod","node_id":node}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.define",
        json!({"name":"prod-editor","actions":["mesh.manage_nodes"],"scopes":["prod"]}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"prod-editor"}),
        NOW,
    )
    .await
    .unwrap();
    let filter = MeshFilter {
        tag: Some("prod".to_owned()),
        cursor: None,
    };
    let mut updates = service.subscribe();
    for (action, input) in [
        (
            "mesh.tag.member.add",
            json!({"tag":"private","node_id":node}),
        ),
        (
            "mesh.tag.rename",
            json!({"name":"private","new_name":"backend"}),
        ),
        (
            "mesh.tag.member.remove",
            json!({"tag":"backend","node_id":node}),
        ),
    ] {
        let before = service.list(MEMBER, filter.clone(), NOW).await.unwrap();
        call(service, OWNER, action, input, NOW).await.unwrap();
        let change = updates.recv().await.unwrap();
        let after = service.list(MEMBER, filter.clone(), NOW).await.unwrap();
        assert_ne!(before.nodes, after.nodes);
        assert!(
            service
                .can_view_change(MEMBER, &filter, &change)
                .await
                .unwrap()
        );
    }
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"other","node_id":isolated}),
        NOW,
    )
    .await
    .unwrap();
    let change = updates.recv().await.unwrap();
    assert!(
        !service
            .can_view_change(MEMBER, &filter, &change)
            .await
            .unwrap()
    );
    fixture.cleanup().await;
}
