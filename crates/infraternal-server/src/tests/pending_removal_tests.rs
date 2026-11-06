//! Retained cleanup coordinates must not authorize an old install or occupy a new one.
use super::*;

/// Retain the old bootstrap row while publishing an undelivered removal obligation.
async fn pending(f: &Fixture) {
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture','retained-pin')")
        .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,'owner',100,1,'unreachable')")
        .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO remote_login_cleanup(host_id,person_id,confirmed) VALUES(?,'owner',0)",
    )
    .bind(f.prior.as_bytes().as_slice())
    .execute(&f.pool)
    .await
    .unwrap();
}

/// Both the address and the pinned SSH key become available without deleting history.
#[tokio::test]
async fn pending_removal_does_not_reserve_address_or_key() {
    let f = fixture(true).await;
    pending(&f).await;
    for (address, lookup) in [
        ("user@fixture", None),
        ("user@new-address", Some("retained-pin")),
    ] {
        assert_eq!(
            f.backend
                .existing_host("owner", address, lookup)
                .await
                .unwrap(),
            None
        );
    }
}

/// The writer-side destination check accepts a new identity at a removed destination.
#[tokio::test]
async fn pending_removal_allows_fresh_bootstrap_invitation() {
    let f = fixture(true).await;
    pending(&f).await;
    for (address, lookup) in [
        ("user@fixture", None),
        ("user@new-address", Some("retained-pin")),
    ] {
        let host = Uuid::new_v4();
        f.backend
            .issuer
            .issue_bootstrap(
                &f.cookie,
                crate::remote_http::InvitationRequest {
                    host_id: host,
                    mode: Mode::Rootless,
                    execution_uid: 1002,
                    expected_key_digest: Some([8; 32]),
                },
                address,
                lookup,
            )
            .await
            .unwrap();
        assert_ne!(host, f.prior);
    }
    let retained: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_host_bootstrap WHERE host_id=?")
            .bind(f.prior.as_bytes().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(
        retained, 1,
        "new setup must preserve the old cleanup command's coordinates"
    );
}

/// A removed journal takes the fresh-enrollment path and never reuses its old authority.
#[tokio::test]
async fn pending_removal_cannot_resume_the_old_stuck_install() {
    let f = fixture(true).await;
    pending(&f).await;
    let digest = f
        .backend
        .issuer
        .store()
        .host_key_digest(f.prior)
        .await
        .unwrap()
        .unwrap();
    let (events, scripts) =
        run_stuck(&f, stuck_check(f.prior, &digest, "remote.example.test")).await;
    assert!(
        events.iter().any(|event| event.leftovers.is_some()),
        "{events:?}"
    );
    let position = |needle: &str| scripts.iter().position(|script| script.contains(needle));
    let aside = position("\nsupersede_stuck_install ")
        .expect("removed install is set aside before fresh enrollment");
    assert!(position("prepare-join-key").is_some_and(|key| key > aside));
    assert!(
        position("\nreplace_stuck_install ").is_none(),
        "{scripts:?}"
    );
    assert!(position("\nrestore_superseded_install ").unwrap() > aside);
    let issued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens WHERE host_id<>?")
            .bind(f.prior.as_bytes().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(issued, 1, "fresh enrollment uses a new host identity");
    let consumed: Option<i64> =
        sqlx::query_scalar("SELECT consumed_at FROM remote_join_tokens WHERE host_id=?")
            .bind(f.prior.as_bytes().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert!(
        consumed.is_some(),
        "the removed host's invitation is never reissued"
    );
}
