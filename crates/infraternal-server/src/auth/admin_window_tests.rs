//! D333: "In the browser, one tap starts 15 minutes of admin actions without taps." The window
//! counts from the tap that started the session; per-action changes still spend a tap.
use super::*;

#[tokio::test]
async fn one_tap_opens_a_fifteen_minute_admin_window() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    for elapsed in [0, 299, 300, 600, 899] {
        assert!(
            f.auth
                .fresh_session(&f.session, NOW + elapsed)
                .await
                .is_ok(),
            "admin actions {elapsed} s after the tap"
        );
    }
    assert!(matches!(
        f.auth.fresh_session(&f.session, NOW + 900).await,
        Err(Error::Denied)
    ));
}

#[tokio::test]
async fn key_revocation_is_an_admin_action_inside_the_window() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let token_hash = hash("fixture-window-revoke-key-never-print");
    sqlx::query("INSERT INTO api_keys(token_hash,user_id,device,scopes,renewed_at,expires_at,dead) VALUES(?,?,'fixture-cli','[\"status:read\"]',?,?,0)")
        .bind(&token_hash)
        .bind(&f.user)
        .bind(NOW)
        .bind(NOW + 86_400)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth
        .api_revoke(&f.session, &token_hash, NOW + 600)
        .await
        .expect("ten minutes after the tap, revoking a key needs no new tap");
}

/// D333 and D336: the admin window never covers a per-action change. Ten minutes into the
/// window, a key approval still needs its own passkey ceremony, bound to its code; an ordinary
/// sign-in ceremony made just now does not approve it.
#[tokio::test]
async fn per_action_changes_still_need_their_own_tap_inside_the_window() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let approval = f
        .auth
        .device_start(
            "cli",
            vec!["status:read".to_owned()],
            TEST_SOURCE,
            NOW + 600,
        )
        .await
        .unwrap();
    let code = str_field(&approval, "user_code").to_owned();
    f.auth
        .fresh_session(&f.session, NOW + 600)
        .await
        .expect("still inside the admin window");
    let login = f.auth.login_start(&f.user, NOW + 600).await.unwrap();
    let proof = f.software.login(&login, ORIGIN, true);
    assert!(matches!(
        f.auth
            .device_approve_finish(
                &f.session,
                &code,
                str_field(&login, "ceremony"),
                proof,
                NOW + 600
            )
            .await,
        Err(Error::Denied)
    ));
    approve_with_passkey(&mut f, &code, NOW + 600)
        .await
        .expect("the approval's own bound ceremony approves it");
}
