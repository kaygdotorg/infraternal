//! D333: a tap for each per-action change. One sign-in or re-authentication tap authorizes
//! one key approval (or passkey, recovery-key or security-settings change); the next one
//! needs a new tap.
use super::*;

async fn new_tap(f: &mut Fixture, now: i64) -> String {
    let start = f.auth.login_start(&f.user, now).await.unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    f.auth
        .login_finish(str_field(&start, "ceremony"), proof, "browser", now)
        .await
        .unwrap()
}

async fn request(f: &Fixture) -> Value {
    f.auth
        .device_start("cli", vec!["status:read".to_owned()], NOW)
        .await
        .unwrap()
}

#[tokio::test]
async fn one_tap_approves_one_key() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let (first, second) = (request(&f).await, request(&f).await);
    f.auth
        .device_approve(&f.session, str_field(&first, "user_code"), NOW)
        .await
        .unwrap();
    assert!(
        matches!(
            f.auth
                .device_approve(&f.session, str_field(&second, "user_code"), NOW)
                .await,
            Err(Error::Denied)
        ),
        "the sign-in tap was spent on the first key"
    );
    let tap = new_tap(&mut f, NOW + 1).await;
    f.auth
        .device_approve(&tap, str_field(&second, "user_code"), NOW + 1)
        .await
        .expect("a new tap approves the next key");
}

#[tokio::test]
async fn a_refused_change_leaves_the_tap_unspent() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    assert!(
        f.auth
            .device_approve(&f.session, "AAAAAAAAAAAAAAAA", NOW)
            .await
            .is_err(),
        "an unknown code is refused"
    );
    let approval = request(&f).await;
    f.auth
        .device_approve(&f.session, str_field(&approval, "user_code"), NOW)
        .await
        .expect("the refusal rolled back, so the tap is still unspent");
}

#[tokio::test]
async fn the_admin_window_does_not_cover_per_action_changes() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let first = request(&f).await;
    f.auth
        .device_approve(&f.session, str_field(&first, "user_code"), NOW)
        .await
        .unwrap();
    // Still well inside the browser's admin window, the security settings need their own tap.
    assert!(matches!(
        f.auth
            .update_security_settings(
                &f.session,
                serde_json::from_value(json!({"api_key_lifetime_days": 7})).unwrap(),
                NOW + 60,
            )
            .await,
        Err(Error::Denied)
    ));
}
