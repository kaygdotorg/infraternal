//! D333: "In the browser, one tap starts 15 minutes of admin actions without taps." The window
//! counts from the tap that started the session; per-action changes still spend a tap.
use super::*;

/// One tap opens the window for fifteen minutes, and the first second after it asks for a tap again.
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
        Err(Error::FreshRequired)
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

/// Every browser route that needs the admin window, as `(router, path)`. A closed window must
/// answer 428 on all of them, so the page can offer the quick passkey renewal instead of a
/// dead-end 401 or 403 (#563, #498). A new fresh-session route is added here; the source scan
/// below fails until it is.
const FRESH_ROUTES: &[(&str, &str)] = &[
    ("auth", "api-revoke"),
    ("remote", "/remote/hosts/remove/start"),
    ("remote", "/remote/hosts/remove/finish"),
    ("remote", "/remote/hosts/forget"),
];

/// Table-driven proof that no fresh-session route says 401 or 403 for a closed window (#563).
#[tokio::test]
async fn every_fresh_session_route_answers_428_when_the_window_has_closed() {
    use axum::http::StatusCode;
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    // A tap long ago: the browser stays signed in, only the 15-minute window is closed.
    sqlx::query("UPDATE sessions SET fresh=1")
        .execute(&f.auth.pool)
        .await
        .unwrap();
    f.auth.set_test_http_time(NOW);
    let cookie = format!("__Host-infraternal={}", f.session);
    let host = Uuid::new_v4();
    let remote = crate::remote_removal_http::router(
        f.auth.clone(),
        crate::remote_removal::Removal::new(
            f.auth.clone(),
            f.auth.pool.clone(),
            crate::enrollment::EnrollmentStore::new(f.auth.pool.clone()),
            crate::remote_runtime::RemoteHosts::default(),
            PathBuf::new(),
        ),
    );
    let web = crate::auth::http::router(f.auth.clone());
    for (router, path) in FRESH_ROUTES {
        let status = if *router == "auth" {
            http_post_json_with_cookie(&web, path, json!({"id":"x"}), &cookie)
                .await
                .0
        } else {
            use tower::ServiceExt;
            // The window check runs before the body is looked at, so each body is minimal.
            let body = if path.ends_with("finish") {
                json!({"host_id":host,"review":"r"})
            } else {
                json!({"host_id":host})
            };
            remote
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(*path)
                        .header("origin", ORIGIN)
                        .header("content-type", "application/json")
                        .header("cookie", &cookie)
                        .body(axum::body::Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        };
        assert_eq!(
            status,
            StatusCode::PRECONDITION_REQUIRED,
            "{router} {path}: a closed admin window must answer 428"
        );
    }
}

/// A new call of the shared admin-window check must join `FRESH_ROUTES`: the files that call it
/// are listed, so adding one forces whoever adds it to read this test and extend the table.
#[test]
fn admin_window_callers_are_all_known() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    let mut stack = vec![src.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.extension().is_none_or(|e| e != "rs")
                || name.contains("test")
                || path.components().any(|c| c.as_os_str() == "socket_tests")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            if text.contains(".require_admin_window(") || text.contains(".fresh_session(") {
                found.push(
                    path.strip_prefix(&src)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    found.sort();
    assert_eq!(
        found,
        [
            "auth/devices.rs",
            "auth/sessions.rs",
            "remote_removal.rs",
            "remote_removal_http.rs",
            "websocket.rs"
        ],
        "a new caller of the admin-window check: add its route to FRESH_ROUTES and make it \
         answer Error::FreshRequired (HTTP 428)"
    );
}
