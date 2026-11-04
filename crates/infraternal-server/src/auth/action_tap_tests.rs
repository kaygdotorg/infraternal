//! D333 and D336: a per-action passkey tap is bound to the one action shown on screen.
//!
//! A sign-in or re-authentication ceremony may name one action (`login_start_for`). The tap then
//! authorizes exactly that action with exactly those parameters, once, within
//! `ACTION_TAP_SECONDS`. A plain sign-in authorizes none of them.
//!
//! Key approval (#263) runs its own ceremony, bound to the session and the code. The last test
//! here checks it the same way. CA role changes and CA setup also use their own purpose-bound
//! ceremonies, which `ca_administration_tests` checks.
use super::super::action_tap::{ACTION_TAP_SECONDS, TapAction};
use super::*;

/// Every per-action category D333 names whose tap is a session bound to one action (key
/// approval has its own ceremony; see the last test).
#[derive(Clone, Copy, Debug, PartialEq)]
enum Change {
    AddPasskey,
    RotateRecovery,
    SecuritySettings,
}
const CHANGES: [Change; 3] = [
    Change::AddPasskey,
    Change::RotateRecovery,
    Change::SecuritySettings,
];

/// One concrete action as the screen shows it: the category and its parameters.
struct Shown {
    change: Change,
    days: i64,
}

/// The action `change` with `days` as its lifetime parameter (used by security settings).
fn shown(change: Change, days: i64) -> Shown {
    Shown { change, days }
}

impl Shown {
    fn action(&self) -> TapAction {
        serde_json::from_value(match self.change {
            Change::AddPasskey => json!({"kind":"passkey.add"}),
            Change::RotateRecovery => json!({"kind":"recovery.rotate"}),
            Change::SecuritySettings => {
                json!({"kind":"security.settings","api_key_lifetime_days":self.days})
            }
        })
        .unwrap()
    }

    /// Run this change with the session `token` at `now`.
    async fn run(&self, f: &Fixture, token: &str, now: i64) -> Result<()> {
        match self.change {
            Change::AddPasskey => f.auth.add_start(token, now).await.map(drop),
            Change::RotateRecovery => {
                let words = bip39::Mnemonic::generate(24).unwrap().to_string();
                let wrap = browser_wrap(
                    &recovery_material(&words, "wrap"),
                    &f.dek,
                    &f.user,
                    "recovery",
                );
                f.auth
                    .recovery_rotate(token, &f.user, wrap, recovery_verifier(&words), now)
                    .await
            }
            Change::SecuritySettings => f
                .auth
                .update_security_settings(
                    token,
                    serde_json::from_value(json!({"api_key_lifetime_days": self.days})).unwrap(),
                    now,
                )
                .await
                .map(drop),
        }
    }
}

/// Sign in again with a tap bound to `bound`, or a plain sign-in for `None`.
async fn tap(f: &mut Fixture, bound: Option<&Shown>, now: i64) -> String {
    let action = bound.map(Shown::action);
    let start = f
        .auth
        .login_start_for(&f.user, action.as_ref(), now)
        .await
        .unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    f.auth
        .login_finish(str_field(&start, "ceremony"), proof, "browser", now)
        .await
        .unwrap()
}

fn denied(result: &Result<()>, why: &str) {
    assert!(matches!(result, Err(Error::Denied)), "{why}: {result:?}");
}

#[tokio::test]
async fn a_tap_for_one_action_cannot_authorize_another() {
    let _guard = SERIAL.lock().await;
    for a in CHANGES {
        for b in CHANGES.into_iter().filter(|b| *b != a) {
            let mut f = fixture().await;
            let tapped = shown(a, 7);
            let other = shown(b, 7);
            let token = tap(&mut f, Some(&tapped), NOW).await;
            denied(
                &other.run(&f, &token, NOW).await,
                &format!("a tap for {a:?} ran {b:?}"),
            );
            tapped
                .run(&f, &token, NOW)
                .await
                .unwrap_or_else(|error| panic!("the {a:?} tap still runs {a:?}: {error:?}"));
        }
    }
}

#[tokio::test]
async fn a_tap_is_bound_to_the_parameters_shown() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let (seven, thirty) = (
        shown(Change::SecuritySettings, 7),
        shown(Change::SecuritySettings, 30),
    );
    let token = tap(&mut f, Some(&seven), NOW).await;
    denied(
        &thirty.run(&f, &token, NOW).await,
        "a tap for a 7-day lifetime set 30 days",
    );
    seven.run(&f, &token, NOW).await.unwrap();
}

#[tokio::test]
async fn a_plain_sign_in_authorizes_no_per_action_change() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    for change in CHANGES {
        let action = shown(change, 7);
        let enrollment = f.session.clone();
        denied(
            &action.run(&f, &enrollment, NOW).await,
            &format!("the enrollment tap ran {change:?}"),
        );
        let plain = tap(&mut f, None, NOW).await;
        denied(
            &action.run(&f, &plain, NOW).await,
            &format!("a plain sign-in ran {change:?}"),
        );
    }
}

#[tokio::test]
async fn a_replayed_tap_is_refused() {
    let _guard = SERIAL.lock().await;
    for change in CHANGES {
        let mut f = fixture().await;
        let action = shown(change, 7);
        let token = tap(&mut f, Some(&action), NOW).await;
        action.run(&f, &token, NOW).await.unwrap();
        // The exact action the tap named, again.
        denied(
            &action.run(&f, &token, NOW + 1).await,
            &format!("a spent {change:?} tap ran twice"),
        );
    }
}

#[tokio::test]
async fn an_expired_tap_is_refused() {
    let _guard = SERIAL.lock().await;
    for change in CHANGES {
        let mut f = fixture().await;
        let late = shown(change, 7);
        let token = tap(&mut f, Some(&late), NOW).await;
        denied(
            &late.run(&f, &token, NOW + ACTION_TAP_SECONDS).await,
            &format!("a {change:?} tap ran {ACTION_TAP_SECONDS} s after it was made"),
        );
        let mut f = fixture().await;
        let on_time = shown(change, 7);
        let token = tap(&mut f, Some(&on_time), NOW).await;
        on_time
            .run(&f, &token, NOW + ACTION_TAP_SECONDS - 1)
            .await
            .unwrap_or_else(|error| panic!("a {change:?} tap inside its window: {error:?}"));
    }
}

#[tokio::test]
async fn a_bound_tap_still_starts_the_admin_window() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let action = shown(Change::SecuritySettings, 7);
    let token = tap(&mut f, Some(&action), NOW).await;
    action.run(&f, &token, NOW).await.unwrap();
    f.auth
        .fresh_session(&token, NOW + 60)
        .await
        .expect("the D333 browser admin window is unchanged");
}

/// A pending key request's user code, as the approval page shows it.
async fn key_request(f: &Fixture, now: i64) -> String {
    let request = f
        .auth
        .device_start("cli", vec!["status:read".to_owned()], TEST_SOURCE, now)
        .await
        .unwrap();
    str_field(&request, "user_code").to_owned()
}

/// Start the key-approval ceremony for `code` from `session` and make its passkey proof.
async fn approval_tap(f: &mut Fixture, session: &str, code: &str, now: i64) -> (String, Value) {
    let start = f
        .auth
        .device_approve_start(session, code, now)
        .await
        .unwrap();
    let proof = f.software.login(&start, ORIGIN, true);
    (str_field(&start, "ceremony").to_owned(), proof)
}

/// Key approval's tap is its own ceremony (#263), and D336 holds for it as for the taps above. It
/// is bound to the one code on the page and to the session that started it, it runs once, it
/// expires, and no other tap (a plain sign-in, or one bound to another action) stands in for it.
#[tokio::test]
async fn a_key_approval_tap_is_bound_to_its_code_and_session_once_and_expires() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let session = f.session.clone();
    let (x, y) = (key_request(&f, NOW).await, key_request(&f, NOW).await);

    // Bound to its code: the ceremony for X does not approve Y, and the attempt leaves it for X.
    let (ceremony, proof) = approval_tap(&mut f, &session, &x, NOW).await;
    denied(
        &f.auth
            .device_approve_finish(&session, &y, &ceremony, proof.clone(), NOW)
            .await,
        "a tap for key request X approved Y",
    );
    // Bound to its session: another signed-in session of the same person cannot finish it.
    let other = tapped_session(&f.auth, &f.user, json!({"kind":"passkey.add"}), NOW).await;
    denied(
        &f.auth
            .device_approve_finish(&other, &x, &ceremony, proof.clone(), NOW)
            .await,
        "another session finished this session's approval tap",
    );
    f.auth
        .device_approve_finish(&session, &x, &ceremony, proof.clone(), NOW)
        .await
        .expect("the tap approves the one key request it was made for");
    // Single use.
    denied(
        &f.auth
            .device_approve_finish(&session, &x, &ceremony, proof, NOW)
            .await,
        "an approval tap was replayed",
    );

    // Expiry: the ceremony is refused once its lifetime is over.
    let z = key_request(&f, NOW).await;
    let (ceremony, proof) = approval_tap(&mut f, &session, &z, NOW).await;
    denied(
        &f.auth
            .device_approve_finish(&session, &z, &ceremony, proof, NOW + super::super::CEREMONY)
            .await,
        "an expired approval tap approved a key",
    );

    // No other tap stands in: a session tapped for security settings, finishing with an
    // ordinary sign-in ceremony, approves nothing.
    let settings = tapped_session(
        &f.auth,
        &f.user,
        json!({"kind":"security.settings","api_key_lifetime_days":30}),
        NOW,
    )
    .await;
    let login = f.auth.login_start(&f.user, NOW).await.unwrap();
    let proof = f.software.login(&login, ORIGIN, true);
    denied(
        &f.auth
            .device_approve_finish(&settings, &y, str_field(&login, "ceremony"), proof, NOW)
            .await,
        "a tap for another action approved a key",
    );
}
