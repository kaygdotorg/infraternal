//! Recovery rotation HTTP checks: only a signed-in device installs local ciphertext.
use super::*;

/// Digest of the `recovery.rotate` tap (D336); these tests set the session's tap directly.
fn rotation_tap() -> String {
    super::super::action_tap::digest(&TapAction::RotateRecovery)
}

#[tokio::test]
async fn recovery_rotation_requires_session_and_replaces_legacy_envelope() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    sqlx::query("UPDATE sessions SET fresh=unixepoch(),tap_action=?")
        .bind(rotation_tap())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let app = router(f.auth.clone());
    let cookie = format!("__Host-infraternal={}", f.session);
    let (status, _, state) = http_post_json_with_cookie(&app, "session", json!({}), &cookie).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(state["recovery_words_need_replacing"], true);
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let wrap = browser_wrap(
        &recovery_material(&words, "wrap"),
        &f.dek,
        &f.user,
        "recovery",
    );
    let payload = json!({"recovery_wrap":wrap,"recovery_verifier":recovery_verifier(&words)});
    assert_eq!(
        rotation_post(&app, payload.clone(), None, &f.user).await.0,
        axum::http::StatusCode::UNAUTHORIZED
    );
    let (status, _, _) = rotation_post(&app, payload, Some(&cookie), &f.user).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let row: (i64,i64,String) = sqlx::query_as("SELECT recovery_version,recovery_wrap_version,(SELECT blob FROM wraps WHERE kind='recovery') FROM users").fetch_one(&f.auth.pool).await.unwrap();
    assert_eq!((row.0, row.1), (2, 2));
    let stored: Wrap = serde_json::from_str(&row.2).unwrap();
    assert_eq!(
        unwrap_browser(
            &recovery_material(&words, "wrap"),
            &stored,
            &f.user,
            "recovery"
        )
        .unwrap(),
        f.dek
    );
    assert!(
        unwrap_browser(
            &recovery_material(&words, "auth"),
            &stored,
            &f.user,
            "recovery"
        )
        .is_err()
    );
    // HTTP session reads slide expiry using real time, so use that same clock
    // rather than the future deterministic enrollment time of this fixture.
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert!(f.auth.session(&f.session, now).await.is_ok());
    let start = f.auth.login_start(&f.user, now).await.unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    assert!(
        f.auth
            .login_finish(
                str_field(&start, "ceremony"),
                proof,
                "retained passkey",
                now
            )
            .await
            .is_ok()
    );
    let (_, _, state) = http_post_json_with_cookie(&app, "session", json!({}), &cookie).await;
    assert_eq!(state["recovery_words_need_replacing"], false);
}

#[tokio::test]
async fn recovery_phrase_routes_are_removed_and_words_fail_closed() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = router(f.auth.clone());
    for action in ["recovery-start", "recovery-resume", "recovery-upgrade"] {
        let (status, _, _) = http_post_json(
            &app,
            action,
            json!({"username":"owner","words":f.words,"verifier":recovery_verifier(&f.words)}),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    }
    let metadata: (i64, i64) =
        sqlx::query_as("SELECT recovery_version,recovery_wrap_version FROM users")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(metadata, (1, 1));
}

#[tokio::test]
async fn recovery_rotation_denies_pending_expired_and_stale_sessions() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = router(f.auth.clone());
    let cookie = format!("__Host-infraternal={}", f.session);
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let wrap = browser_wrap(
        &recovery_material(&words, "wrap"),
        &f.dek,
        &f.user,
        "recovery",
    );
    for statement in [
        "UPDATE sessions SET unlocked=0,fresh=unixepoch(),expires=unixepoch()+60,tap_action=?",
        "UPDATE sessions SET unlocked=1,fresh=unixepoch(),expires=unixepoch()-1,tap_action=?",
        // `ACTION_TAP_SECONDS` (120) after the tap it is stale.
        "UPDATE sessions SET unlocked=1,fresh=unixepoch()-120,expires=unixepoch()+60,tap_action=?",
        // A plain sign-in carries no action.
        "UPDATE sessions SET unlocked=1,fresh=unixepoch(),expires=unixepoch()+60,tap_action=NULL WHERE ?<>''",
    ] {
        sqlx::query(statement)
            .bind(rotation_tap())
            .execute(&f.auth.pool)
            .await
            .unwrap();
        assert_eq!(
            rotation_post(
                &app,
                json!({"recovery_wrap":wrap,"recovery_verifier":recovery_verifier(&words)}),
                Some(&cookie),
                &f.user
            )
            .await
            .0,
            axum::http::StatusCode::UNAUTHORIZED
        );
    }
    let metadata: (i64, i64) =
        sqlx::query_as("SELECT recovery_version,recovery_wrap_version FROM users")
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(metadata, (1, 1));
}

#[tokio::test]
async fn reviewer_concurrent_signed_in_rotations_commit_once() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let (old, ready) = f
        .auth
        .recovery_resume(&f.user, f.words.clone(), NOW)
        .await
        .unwrap();
    let begun = f.auth.recovery_ready(&old, ready).await.unwrap();
    sqlx::query("UPDATE sessions SET fresh=unixepoch(),tap_action=?")
        .bind(rotation_tap())
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let app = router(f.auth.clone());
    let cookie = format!("__Host-infraternal={}", f.session);
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let wrap = browser_wrap(
        &recovery_material(&words, "wrap"),
        &f.dek,
        &f.user,
        "recovery",
    );
    let payload = json!({"recovery_wrap":wrap,"recovery_verifier":recovery_verifier(&words)});
    let (a, b) = tokio::join!(
        rotation_post(&app, payload.clone(), Some(&cookie), &f.user),
        rotation_post(&app, payload, Some(&cookie), &f.user)
    );
    let ok = axum::http::StatusCode::OK;
    assert_ne!(a.0 == ok, b.0 == ok);
    assert!(f.auth.recovery_ready(&old, ready).await.is_err());
    assert!(replacement_for_rotation(&f, &begun, ready).await.is_err());
    let metadata: (i64, i64, i64) = sqlx::query_as(
        "SELECT recovery_version,recovery_wrap_version,(SELECT COUNT(*) FROM recovery) FROM users",
    )
    .fetch_one(&f.auth.pool)
    .await
    .unwrap();
    assert_eq!(metadata, (2, 2, 0));
    let events: Vec<String> = sqlx::query_scalar("SELECT event FROM recovery_audit ORDER BY id")
        .fetch_all(&f.auth.pool)
        .await
        .unwrap();
    assert_eq!(events, vec!["start", "cancel"]);
    assert!(f.auth.session(&f.session, NOW).await.is_ok());
    println!(
        "REVIEW signed-in rotation: one commit, v2 verifier/envelope, old capability and begun ceremony denied; passkey/session retained"
    );
}

async fn replacement_for_rotation(f: &Fixture, start: &Value, now: i64) -> Result<String> {
    let software = Software::new();
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    f.auth
        .registration_finish_with_verifier(
            str_field(start, "ceremony"),
            software.registration(start, ORIGIN, true),
            browser_wrap(&software.prf(start), &f.dek, &f.user, "passkey"),
            Some(browser_wrap(
                &recovery_material(&words, "wrap"),
                &f.dek,
                &f.user,
                "recovery",
            )),
            Some(recovery_verifier(&words)),
            now,
        )
        .await
}

async fn rotation_post(
    app: &axum::Router,
    value: Value,
    cookie: Option<&str>,
    user: &str,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Value) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-infraternal-user",
        axum::http::HeaderValue::from_str(user).unwrap(),
    );
    http_post_json_with_headers(app, "recovery-rotate", value, cookie, headers).await
}

#[tokio::test]
async fn recovery_rotation_cannot_follow_a_cookie_account_switch() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let other = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'other',0,'unused','other','Other')").bind(&other).execute(&f.auth.pool).await.unwrap();
    let token = random();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,tap_action) VALUES (?,?,'other device',unixepoch()+60,unixepoch(),?)").bind(hash(&token)).bind(&other).bind(rotation_tap()).execute(&f.auth.pool).await.unwrap();
    let app = router(f.auth.clone());
    let cookie = format!("__Host-infraternal={token}");
    let words = bip39::Mnemonic::generate(24).unwrap().to_string();
    let wrap = browser_wrap(
        &recovery_material(&words, "wrap"),
        &f.dek,
        &f.user,
        "recovery",
    );
    let (status, _, _) = rotation_post(
        &app,
        json!({"recovery_wrap":wrap,"recovery_verifier":recovery_verifier(&words)}),
        Some(&cookie),
        &f.user,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    let metadata: (i64, i64) =
        sqlx::query_as("SELECT recovery_version,recovery_wrap_version FROM users WHERE id=?")
            .bind(&other)
            .fetch_one(&f.auth.pool)
            .await
            .unwrap();
    assert_eq!(metadata, (1, 1));
}
