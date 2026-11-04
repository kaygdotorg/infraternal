//! D333 and D336: a per-action passkey tap is bound to the one action shown on screen.
//!
//! A sign-in or re-authentication ceremony may name one action (`login_start_for`). The tap then
//! authorizes exactly that action with exactly those parameters, once, within
//! `ACTION_TAP_SECONDS`. A plain sign-in authorizes none of them. CA role changes and CA setup
//! use their own purpose-bound ceremonies; `ca_administration_tests` checks those the same way.
use super::super::action_tap::{ACTION_TAP_SECONDS, TapAction};
use super::*;

/// Every per-action category D333 names that is served by the auth routes.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Change {
    ApproveKey,
    AddPasskey,
    RotateRecovery,
    SecuritySettings,
}
const CHANGES: [Change; 4] = [
    Change::ApproveKey,
    Change::AddPasskey,
    Change::RotateRecovery,
    Change::SecuritySettings,
];

/// One concrete action as the screen shows it: the category and its parameters.
struct Shown {
    change: Change,
    code: String,
    days: i64,
}

async fn shown(f: &Fixture, change: Change, days: i64) -> Shown {
    let request = f
        .auth
        .device_start("cli", vec!["status:read".to_owned()], NOW)
        .await
        .unwrap();
    Shown {
        change,
        code: str_field(&request, "user_code").to_owned(),
        days,
    }
}

impl Shown {
    fn action(&self) -> TapAction {
        serde_json::from_value(match self.change {
            Change::ApproveKey => json!({"kind":"device.approve","code":self.code}),
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
            Change::ApproveKey => f.auth.device_approve(token, &self.code, now).await,
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
            let tapped = shown(&f, a, 7).await;
            let other = shown(&f, b, 7).await;
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
    let (shown_key, other_key) = (
        shown(&f, Change::ApproveKey, 7).await,
        shown(&f, Change::ApproveKey, 7).await,
    );
    let token = tap(&mut f, Some(&shown_key), NOW).await;
    denied(
        &other_key.run(&f, &token, NOW).await,
        "a tap for one key request approved another",
    );
    shown_key.run(&f, &token, NOW).await.unwrap();

    let (seven, thirty) = (
        shown(&f, Change::SecuritySettings, 7).await,
        shown(&f, Change::SecuritySettings, 30).await,
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
        let action = shown(&f, change, 7).await;
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
        let action = shown(&f, change, 7).await;
        let token = tap(&mut f, Some(&action), NOW).await;
        action.run(&f, &token, NOW).await.unwrap();
        // The same action again: a key request with a fresh code needs its own tap, and the
        // other categories repeat the exact action the tap named.
        let again = if change == Change::ApproveKey {
            let next = shown(&f, change, 7).await;
            sqlx::query("UPDATE sessions SET tap_action=? WHERE token_hash=?")
                .bind(super::super::action_tap::digest(&next.action()))
                .bind(hash(&token))
                .execute(&f.auth.pool)
                .await
                .unwrap();
            next
        } else {
            action
        };
        denied(
            &again.run(&f, &token, NOW + 1).await,
            &format!("a spent {change:?} tap ran twice"),
        );
    }
}

#[tokio::test]
async fn an_expired_tap_is_refused() {
    let _guard = SERIAL.lock().await;
    for change in CHANGES {
        let mut f = fixture().await;
        let late = shown(&f, change, 7).await;
        let token = tap(&mut f, Some(&late), NOW).await;
        denied(
            &late.run(&f, &token, NOW + ACTION_TAP_SECONDS).await,
            &format!("a {change:?} tap ran {ACTION_TAP_SECONDS} s after it was made"),
        );
        let mut f = fixture().await;
        let on_time = shown(&f, change, 7).await;
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
    let action = shown(&f, Change::SecuritySettings, 7).await;
    let token = tap(&mut f, Some(&action), NOW).await;
    action.run(&f, &token, NOW).await.unwrap();
    f.auth
        .fresh_session(&token, NOW + 60)
        .await
        .expect("the D333 browser admin window is unchanged");
}
