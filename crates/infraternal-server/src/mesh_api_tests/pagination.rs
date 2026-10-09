//! Revision-bound continuation validation and permission checks for bounded Mesh inventories [D170].
use super::*;
use crate::mesh_api::MeshCursor;

#[tokio::test]
async fn continuation_restarts_on_change_and_rechecks_permissions() {
    let fixture = Fixture::new().await;
    enroll(&fixture.service, "first", 1).await;
    enroll(&fixture.service, "second", 2).await;
    let first = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let filter = MeshFilter {
        tag: None,
        cursor: Some(MeshCursor {
            revision: first.revision,
            offset: 1,
        }),
    };
    let tail = fixture
        .service
        .list(OWNER, filter.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(tail.nodes.len(), 1);
    assert_eq!(tail.nodes[0].node.host, "second");
    assert_eq!(
        fixture.service.list(MEMBER, filter.clone(), NOW).await,
        Err(MeshApiError::Denied)
    );
    enroll(&fixture.service, "third", 3).await;
    let restarted = fixture.service.list(OWNER, filter, NOW).await.unwrap();
    assert_eq!(restarted.revision, first.revision + 1);
    assert_eq!(restarted.nodes.len(), 3);
    for cursor in [
        MeshCursor {
            revision: restarted.revision + 1,
            offset: 1,
        },
        MeshCursor {
            revision: restarted.revision,
            offset: 0,
        },
        MeshCursor {
            revision: restarted.revision,
            offset: 3,
        },
    ] {
        assert_eq!(
            fixture
                .service
                .list(
                    OWNER,
                    MeshFilter {
                        tag: None,
                        cursor: Some(cursor)
                    },
                    NOW
                )
                .await,
            Err(MeshApiError::InvalidInput)
        );
    }
    fixture.cleanup().await;
}

#[tokio::test]
async fn an_unsendable_object_returns_a_sanitized_service_error() {
    let fixture = Fixture::new().await;
    sqlx::query("INSERT INTO mesh_tags(name,created_at) VALUES (?,?)")
        .bind("x".repeat(infraternal_protocol::MAX_FRAME_LEN))
        .bind(NOW)
        .execute(&fixture.pool)
        .await
        .unwrap();
    assert_eq!(
        fixture
            .service
            .list(OWNER, MeshFilter::default(), NOW)
            .await,
        Err(MeshApiError::Storage)
    );
    fixture.cleanup().await;
}
