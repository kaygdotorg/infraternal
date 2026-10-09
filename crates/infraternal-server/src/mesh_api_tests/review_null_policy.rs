//! Independent transaction regression for null policy inputs becoming unrestricted grants [D164, #108].
use super::*;

#[tokio::test]
async fn review_null_port_policy_does_not_create_unrestricted_grant() {
    let fixture = Fixture::new().await;
    for name in ["prod", "db"] {
        call(
            &fixture.service,
            OWNER,
            "mesh.tag.create",
            json!({"name":name}),
            NOW,
        )
        .await
        .unwrap();
    }
    let result = call(
        &fixture.service,
        OWNER,
        "mesh.grant.create",
        json!({
            "name":"restricted", "from":{"Tag":"prod"}, "to":{"Tag":"db"},
            "both_ways":false, "ports":null,
        }),
        NOW,
    )
    .await;
    let after = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    println!(
        "explicit_null_result={result:?} committed_grants={:?}",
        after.grants
    );
    fixture.cleanup().await;
    assert_eq!(result, Err(MeshApiError::InvalidInput));
    assert_eq!(after.grants.len(), 0);
}
