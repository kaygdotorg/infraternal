//! Reproduce a scoped tag editor claiming a hidden host and granting it connectivity [D154 G3, D164, D187].
use super::*;

#[tokio::test]
async fn review_scoped_membership_cannot_claim_hidden_node() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let hidden = enroll(service, "hidden-host", 1).await;
    for tag in ["prod", "private"] {
        call(service, OWNER, "mesh.tag.create", json!({"name":tag}), NOW)
            .await
            .unwrap();
    }
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"private","node_id":hidden}),
        NOW,
    )
    .await
    .unwrap();
    call(service, OWNER, "mesh.role.define", json!({"name":"prod-editor","actions":["mesh.manage_tags","mesh.manage_grants"],"scopes":["prod"]}), NOW).await.unwrap();
    call(
        service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"prod-editor"}),
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        service
            .list(MEMBER, MeshFilter::default(), NOW)
            .await
            .unwrap()
            .nodes
            .len(),
        0
    );
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.grant.create",
            json!({"name":"before","from":{"Tag":"prod"},"to":{"Node":hidden},"both_ways":false}),
            NOW
        )
        .await,
        Err(MeshApiError::Denied)
    );
    let membership = call(
        service,
        MEMBER,
        "mesh.tag.member.add",
        json!({"tag":"prod","node_id":hidden}),
        NOW,
    )
    .await;
    let grant = call(
        service,
        MEMBER,
        "mesh.grant.create",
        json!({"name":"after","from":{"Tag":"prod"},"to":{"Node":hidden},"both_ways":false}),
        NOW,
    )
    .await;
    let exposed = service
        .list(MEMBER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    println!(
        "hidden node={hidden}; membership={membership:?}; grant={grant:?}; exposed_nodes={}; exposed_grants={}",
        exposed.nodes.len(),
        exposed.grants.len()
    );
    assert_eq!(membership, Err(MeshApiError::Denied));
    assert_eq!(grant, Err(MeshApiError::Denied));
    assert_eq!(exposed.nodes.len(), 0);
    assert_eq!(exposed.grants.len(), 0);
    fixture.cleanup().await;
    assert!(
        membership.is_err(),
        "D154 host scopes must prevent claiming a hidden node; adding the local tag also bypasses grant authorization"
    );
}

#[tokio::test]
async fn scoped_membership_checks_pre_edit_host_scope() {
    let fixture = Fixture::new().await;
    let service = &fixture.service;
    let node = enroll(service, "local-host", 2).await;
    let untagged = enroll(service, "untagged-host", 3).await;
    for tag in ["prod", "other", "private"] {
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
        json!({"name":"editor","actions":["mesh.manage_tags"],"scopes":["prod","other"]}),
        NOW,
    )
    .await
    .unwrap();
    call(
        service,
        OWNER,
        "mesh.role.assign",
        json!({"user_id":MEMBER,"role":"editor"}),
        NOW,
    )
    .await
    .unwrap();
    for action in ["mesh.tag.member.add", "mesh.tag.member.remove"] {
        call(
            service,
            MEMBER,
            action,
            json!({"tag":"other","node_id":node}),
            NOW,
        )
        .await
        .unwrap();
    }
    assert_eq!(
        call(
            service,
            MEMBER,
            "mesh.tag.member.add",
            json!({"tag":"prod","node_id":untagged}),
            NOW
        )
        .await,
        Err(MeshApiError::Denied)
    );
    call(
        service,
        OWNER,
        "mesh.tag.member.add",
        json!({"tag":"private","node_id":node}),
        NOW,
    )
    .await
    .unwrap();
    let before = service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let mut updates = service.subscribe();
    for action in ["mesh.tag.member.add", "mesh.tag.member.remove"] {
        assert_eq!(
            call(
                service,
                MEMBER,
                action,
                json!({"tag":"prod","node_id":node}),
                NOW
            )
            .await,
            Err(MeshApiError::Denied)
        );
    }
    assert_eq!(
        service
            .list(OWNER, MeshFilter::default(), NOW)
            .await
            .unwrap(),
        before
    );
    assert!(matches!(
        updates.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    fixture.cleanup().await;
}
