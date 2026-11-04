//! D333: the passkey tap that approves an API key approves its lifetime too. The review shows
//! it, and the redeemed key ends at that time however often it is renewed.
use super::*;

async fn approve(f: &Fixture, lifetime: Option<i64>) -> String {
    let approval = f
        .auth
        .device_start_for("cli", vec!["status:read".to_owned()], lifetime, NOW)
        .await
        .unwrap();
    bind_tap(&f.auth, &f.session, super::approve(&approval), NOW).await;
    f.auth
        .device_approve(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .unwrap();
    f.auth
        .device_redeem(str_field(&approval, "poll_token"), NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_key_request_defaults_to_24_hours_and_the_review_shows_it() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let approval = f
        .auth
        .device_start("cli", vec!["status:read".to_owned()], NOW)
        .await
        .unwrap();
    let review = f
        .auth
        .device_inspect(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .unwrap();
    assert_eq!(review["lifetime_seconds"], 86_400);
    assert!(
        approval.get("lifetime_seconds").is_none(),
        "the start response keeps the shape released CLIs accept"
    );

    bind_tap(&f.auth, &f.session, super::approve(&approval), NOW).await;
    f.auth
        .device_approve(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .unwrap();
    let key = f
        .auth
        .device_redeem(str_field(&approval, "poll_token"), NOW)
        .await
        .unwrap();
    let (renewed_at, expires_at, hard): (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT renewed_at,expires_at,hard_expires_at FROM api_keys WHERE token_hash=?",
    )
    .bind(hash(&key))
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(hard, Some(renewed_at + 86_400));
    assert_eq!(expires_at, renewed_at + 86_400);
}

#[tokio::test]
async fn a_requested_lifetime_stays_between_one_hour_and_the_owner_policy() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    for lifetime in [0, 3_599, 30 * 86_400 + 1] {
        assert!(
            matches!(
                f.auth
                    .device_start_for("cli", vec!["status:read".to_owned()], Some(lifetime), NOW)
                    .await,
                Err(Error::Invalid)
            ),
            "{lifetime}"
        );
    }
    for lifetime in [3_600, 7 * 86_400, 30 * 86_400] {
        assert!(
            f.auth
                .device_start_for("cli", vec!["status:read".to_owned()], Some(lifetime), NOW)
                .await
                .is_ok(),
            "{lifetime}"
        );
    }
}

#[tokio::test]
async fn renewal_never_carries_a_key_past_its_approved_lifetime() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let key = approve(&f, Some(7_200)).await;
    let key_hash = hash(&key);
    // Used after an hour: J90 renews, but only up to the approved end.
    f.auth.set_test_http_time(NOW + 3_700);
    assert!(f.auth.api_authorize(&key, "status:read").await.is_ok());
    let expires_at: i64 = sqlx::query_scalar("SELECT expires_at FROM api_keys WHERE token_hash=?")
        .bind(&key_hash)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(expires_at, NOW + 7_200);
    // Past the approved end the key is refused and tombstoned, though the owner policy is 30 days.
    f.auth.set_test_http_time(NOW + 7_200);
    assert!(f.auth.api_authorize(&key, "status:read").await.is_err());
    let dead: bool = sqlx::query_scalar("SELECT dead FROM api_keys WHERE token_hash=?")
        .bind(&key_hash)
        .fetch_one(&f.auth.pool)
        .await
        .unwrap();
    assert!(dead);
}

/// J154 P3-1: keys issued before D333 had no absolute end, so sliding renewal kept them alive
/// forever. At upgrade each gets one: never later than its current deadline, and never later
/// than 24 hours after the upgrade. (`api_keys` keeps no issue time, so the end cannot be
/// counted from issuance.) Keys from D333 on keep the end approved with them.
#[tokio::test]
async fn keys_issued_before_d333_get_an_absolute_end_at_upgrade() {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let mut before = sqlx::migrate!("./migrations");
    before
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 46);
    before.run(&pool).await.unwrap();
    let upgrade = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash) VALUES('owner','owner',1,'x')")
        .execute(&pool)
        .await
        .unwrap();
    for (key, expires_at, hard) in [
        ("long-sliding", upgrade + 30 * 86_400, None),
        ("near-its-end", upgrade + 3_600, None),
        (
            "approved-under-d333",
            upgrade + 30 * 86_400,
            Some(upgrade + 7 * 86_400),
        ),
    ] {
        sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead,hard_expires_at) VALUES(?,'owner','cli','[\"status:read\"]',?,?,0,?)")
            .bind(key)
            .bind(upgrade)
            .bind(expires_at)
            .bind(hard)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let ends: Vec<(String, Option<i64>)> =
        sqlx::query_as("SELECT token_hash,hard_expires_at FROM api_keys ORDER BY token_hash")
            .fetch_all(&pool)
            .await
            .unwrap();
    let [(_, d333), (_, long), (_, near)] = ends.as_slice() else {
        panic!("{ends:?}")
    };
    assert_eq!(*d333, Some(upgrade + 7 * 86_400), "an approved end is kept");
    assert_eq!(
        *near,
        Some(upgrade + 3_600),
        "never later than the current deadline"
    );
    let long = long.expect("a pre-D333 key gets an end");
    assert!(
        (upgrade + 86_400..=upgrade + 86_400 + 5).contains(&long),
        "24 hours after the upgrade: {long}"
    );
}
