//! Real passkey and SQLite regression for host removal purpose binding and offline revocation (#87).
use super::*;
#[tokio::test]
async fn fresh_removal_revokes_offline_host_and_cannot_replay() {
    let mut f = fixture().await;
    let host = Uuid::new_v4();
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'root@host.example',NULL)")
        .bind(host.as_bytes().as_slice())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let service = crate::remote_removal::Removal::new(
        f.auth.clone(),
        f.auth.pool.clone(),
        crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
        crate::remote_runtime::RemoteHosts::default(),
        PathBuf::new(),
    );
    let ordinary = f.auth.login_start(&f.user, NOW).await.unwrap();
    let ordinary_proof = f.software.login(&ordinary, ORIGIN, true);
    assert!(
        service
            .finish(
                &f.session,
                str_field(&ordinary, "ceremony"),
                ordinary_proof,
                NOW
            )
            .await
            .is_err()
    );
    let start = service.start(&f.session, host, true, NOW).await.unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    let id = str_field(&start, "ceremony");
    assert!(
        service
            .finish_host(&f.session, Uuid::new_v4(), id, proof.clone(), NOW)
            .await
            .is_err()
    );
    let result = service
        .finish(&f.session, id, proof.clone(), NOW)
        .await
        .unwrap();
    assert_eq!(result["host_cleanup"], "unreachable");
    assert!(service.finish(&f.session, id, proof, NOW).await.is_err());
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert!(revoked);
    let coordinates: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap")
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(coordinates, 0);
}

#[tokio::test]
async fn logout_or_role_loss_after_removal_start_preserves_host() {
    for logout in [true, false] {
        let mut f = fixture().await;
        let host = Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootful',0,1)").bind(host.as_bytes().as_slice()).bind(&f.user).execute(&f.auth.pool).await.unwrap();
        let service = crate::remote_removal::Removal::new(
            f.auth.clone(),
            f.auth.pool.clone(),
            crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
            crate::remote_runtime::RemoteHosts::default(),
            PathBuf::new(),
        );
        let start = service.start(&f.session, host, false, NOW).await.unwrap();
        let proof = f.software.login(&start, ORIGIN, true);
        if logout {
            f.auth.logout(&f.session).await.unwrap();
        } else {
            sqlx::query("UPDATE users SET owner=0")
                .execute(&f.auth.pool)
                .await
                .unwrap();
        }
        assert!(
            service
                .finish(&f.session, str_field(&start, "ceremony"), proof, NOW)
                .await
                .is_err()
        );
        let live: bool =
            sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
                .bind(host.as_bytes().as_slice())
                .fetch_one(&f.auth.pool)
                .await
                .unwrap();
        assert!(live);
    }
}
