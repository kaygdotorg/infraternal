//! Ceremony pools cannot be filled to refuse someone else's sign-in or tap
//! (#263, J161 P3-1 and P3-2), and their global caps still hold.
use super::*;
use crate::runtime::ClientAddress;
use axum::http::StatusCode;
use std::net::IpAddr;

/// One address in the `index`th IPv4 /24, so each index is its own network.
fn v4_network(index: u32) -> IpAddr {
    IpAddr::V4((0x0a00_0000 + (index << 8) + 1).into())
}

/// One address in the `index`th IPv6 /48.
fn v6_network(index: u16) -> IpAddr {
    IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, index, 1, 0, 0, 0, 1))
}

/// A browser call from `source`, on the app's own origin.
async fn call(
    app: &axum::Router,
    source: IpAddr,
    action: &str,
    cookie: Option<&str>,
    body: &Value,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/auth/{action}"))
        .header("content-type", "application/json")
        .header("origin", ORIGIN)
        .extension(ClientAddress(source));
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, value)
}

/// Anonymous ceremonies waiting in the pool, per network.
async fn anonymous(auth: &Auth) -> HashMap<Option<IpAddr>, Vec<String>> {
    let pending = auth.pending.lock().await;
    let mut by_network: HashMap<Option<IpAddr>, Vec<String>> = HashMap::new();
    for (id, login) in &pending.logins {
        if matches!(login.state, LoginState::Discoverable(_)) {
            by_network
                .entry(login.network)
                .or_default()
                .push(id.clone());
        }
    }
    by_network
}

/// Sign in through the anonymous path from `source`, as a real browser does.
async fn sign_in(f: &mut Fixture, app: &axum::Router, source: IpAddr) -> StatusCode {
    let (status, headers, start) = call(app, source, "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::OK, "login-start from {source}");
    let binding = headers[axum::http::header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let mut proof = f.software.login(&start, ORIGIN, true);
    proof["response"]["userHandle"] =
        json!(B64.encode(Uuid::parse_str(&f.user).unwrap().as_bytes()));
    call(
        app,
        source,
        "login-finish",
        Some(&binding),
        &json!({"ceremony":start["ceremony"],"proof":proof,"device":"phone"}),
    )
    .await
    .0
}

/// Fill the anonymous pool from 32 /24s, 32 ceremonies each, one round per
/// second (well inside one ceremony lifetime). Returns each network's
/// ceremony IDs, oldest first. The pool is full at `NOW + 31`.
async fn fill_from_32_networks(f: &Fixture, app: &axum::Router) -> Vec<Vec<String>> {
    let mut started = vec![Vec::new(); 32];
    for round in 0..32 {
        f.auth.set_test_http_time(NOW + round);
        for (network, ids) in started.iter_mut().enumerate() {
            let source = v4_network(u32::try_from(network).unwrap());
            let (status, _, start) = call(app, source, "login-start", None, &json!({})).await;
            assert_eq!(status, StatusCode::OK, "network {network}, round {round}");
            ids.push(str_field(&start, "ceremony").to_owned());
        }
    }
    started
}

#[tokio::test]
async fn a_fresh_network_signs_in_while_32_networks_fill_the_anonymous_pool() {
    // J161 P3-1: 32 /24s (or /48s) at their share filled the pool, and every
    // sign-in without a session got 401.
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let app = super::http::router(f.auth.clone());
    let started = fill_from_32_networks(&f, &app).await;
    f.auth.set_test_http_time(NOW + 32);
    // One newcomer waits on its prompt; another signs in all the way.
    let (status, _, _) = call(&app, v4_network(500), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sign_in(&mut f, &app, v6_network(7)).await, StatusCode::OK);
    // Each newcomer evicted the oldest ceremony of a network holding the most.
    let left = anonymous(&f.auth).await;
    let mut evicted = 0;
    for (network, ids) in started.iter().enumerate() {
        let source = v4_network(u32::try_from(network).unwrap());
        let kept = &left[&Some(crate::runtime::browser_network(source))];
        if kept.len() == 31 {
            evicted += 1;
            assert!(
                !kept.contains(&ids[0]),
                "network {network} lost a newer ceremony"
            );
        } else {
            assert_eq!(kept.len(), 32, "network {network}");
        }
    }
    assert_eq!(evicted, 2, "two networks lost one ceremony each");
    assert_eq!(left.values().map(Vec::len).sum::<usize>(), 1023);
}

#[tokio::test]
async fn a_burst_in_one_second_still_evicts_the_oldest() {
    // Expiry has one-second resolution, so "oldest" must not depend on it:
    // the whole pool fills inside one second here.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let mut first = Vec::new();
    for round in 0..32 {
        for network in 0..32 {
            let (status, _, start) =
                call(&app, v4_network(network), "login-start", None, &json!({})).await;
            assert_eq!(status, StatusCode::OK);
            if round == 0 {
                first.push(str_field(&start, "ceremony").to_owned());
            }
        }
    }
    let (status, _, _) = call(&app, v4_network(700), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let pending = f.auth.pending.lock().await;
    let gone = first
        .iter()
        .filter(|id| !pending.logins.contains_key(*id))
        .count();
    assert_eq!(gone, 1, "the evicted ceremony was not a network's first");
}

#[tokio::test]
async fn a_full_pool_answers_its_heaviest_network_with_429() {
    // When the caller's network already holds as many as any other, nothing
    // is evictable for it: it is told to come back, not that its passkey failed.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    for network in 0..1024 {
        let (status, _, _) = call(&app, v4_network(network), "login-start", None, &json!({})).await;
        assert_eq!(status, StatusCode::OK, "network {network}");
    }
    let (status, headers, _) = call(&app, v4_network(3), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers[axum::http::header::RETRY_AFTER], "60");
    // A network with nothing waiting still gets a slot.
    let (status, _, _) = call(&app, v4_network(5000), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn each_network_keeps_its_share_of_32() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    for _ in 0..32 {
        let (status, _, _) = call(&app, v4_network(0), "login-start", None, &json!({})).await;
        assert_eq!(status, StatusCode::OK);
    }
    // Another address in the same /24 is the same network.
    let (status, headers, _) = call(
        &app,
        IpAddr::V4([10, 0, 0, 99].into()),
        "login-start",
        None,
        &json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers[axum::http::header::RETRY_AFTER], "60");
    let (status, _, _) = call(&app, v4_network(1), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_anonymous_pool_never_holds_more_than_1024() {
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let app = super::http::router(f.auth.clone());
    fill_from_32_networks(&f, &app).await;
    f.auth.set_test_http_time(NOW + 32);
    // A network at its share is throttled even when the pool is full.
    let (status, _, _) = call(&app, v4_network(0), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    // Newcomers replace entries; the pool never grows past 1024.
    for network in 100..164 {
        let (status, _, _) = call(&app, v4_network(network), "login-start", None, &json!({})).await;
        assert_eq!(status, StatusCode::OK, "network {network}");
    }
    let left = anonymous(&f.auth).await;
    assert_eq!(left.values().map(Vec::len).sum::<usize>(), 1024);
    assert!(left.values().all(|ids| ids.len() <= 32));
    // Expiry frees the pool.
    f.auth.set_test_http_time(NOW + 32 + CEREMONY);
    let (status, _, _) = call(&app, v4_network(0), "login-start", None, &json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        anonymous(&f.auth)
            .await
            .values()
            .map(Vec::len)
            .sum::<usize>(),
        1
    );
}

/// Another person with a live session, holding a copy of the fixture's
/// passkey so identified ceremonies can start for them.
async fn person(f: &Fixture, index: usize) -> (String, String) {
    let user = Uuid::new_v4().to_string();
    let name = format!("person{index}");
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,0,'unused',?,?)")
        .bind(&user)
        .bind(&name)
        .bind(&name)
        .bind(&name)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO passkeys(id,user_id,credential,prf_input) SELECT ?||id,?,credential,prf_input FROM passkeys WHERE user_id=?")
        .bind(format!("{index}-"))
        .bind(&user)
        .bind(&f.user)
        .execute(&f.auth.pool)
        .await
        .unwrap();
    let token = random();
    let mut tx = f.auth.pool.begin().await.unwrap();
    insert_session(&mut tx, &token, &user, "person's browser", NOW, None)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (user, token)
}

/// A pending CLI sign-in code (the kind any signed-in person may approve).
async fn sign_in_code(f: &Fixture) -> String {
    let started = f
        .auth
        .device_start("cli", vec!["hosts:read".into()], v4_network(900), NOW)
        .await
        .unwrap();
    str_field(&started, "user_code").to_owned()
}

/// Approval ceremonies and identified ceremonies each person holds.
async fn held(f: &Fixture, user: &str) -> (usize, usize) {
    let approvals = f
        .auth
        .approval_ceremonies
        .lock()
        .await
        .0
        .values()
        .filter(|ceremony| ceremony.user_id == user)
        .count();
    let pending = f.auth.pending.lock().await;
    let identified = pending
        .logins
        .values()
        .filter(|login| matches!(&login.state, LoginState::Identified(_, who) if who == user))
        .count()
        + pending
            .registrations
            .values()
            .filter(|r| r.user == user)
            .count();
    (approvals, identified)
}

#[tokio::test]
async fn one_person_cannot_fill_the_approval_or_identified_pools() {
    // J161 P3-2: one session repeating approval starts on its own sign-in
    // code refused every approval and fresh tap on the server.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let code = sign_in_code(&f).await;
    let (other, token) = person(&f, 1).await;
    for attempt in 0..1100 {
        f.auth
            .device_approve_start(&token, &code, NOW)
            .await
            .unwrap_or_else(|error| panic!("approval start {attempt}: {error:?}"));
        f.auth
            .login_start(&other, NOW)
            .await
            .unwrap_or_else(|error| panic!("fresh tap {attempt}: {error:?}"));
    }
    assert_eq!(held(&f, &other).await, (5, 5));
    // The owner's add-passkey registrations are bounded the same way.
    for attempt in 0..1100 {
        f.auth
            .add_start(&f.session, NOW)
            .await
            .unwrap_or_else(|error| panic!("add start {attempt}: {error:?}"));
    }
    assert_eq!(held(&f, &f.user).await, (0, 5));
    // Nobody else's slots were spent.
    assert!(
        f.auth
            .device_approve_start(&f.session, &code, NOW)
            .await
            .is_ok()
    );
    assert!(f.auth.login_start(&f.user, NOW).await.is_ok());
}

#[tokio::test]
async fn a_persons_newest_approval_ceremony_survives_their_cap() {
    let _guard = SERIAL.lock().await;
    let mut f = fixture().await;
    let app = super::http::router(f.auth.clone());
    f.auth.set_test_http_time(NOW);
    let code = sign_in_code(&f).await;
    let cookie = format!("__Host-infraternal={}", f.session);
    let mut starts = Vec::new();
    for _ in 0..6 {
        let (status, _, start) = call(
            &app,
            v4_network(1),
            "device-approve-start",
            Some(&cookie),
            &json!({"code": code}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        starts.push(start);
    }
    let finish = |start: &Value, proof: Value| json!({"code": code, "ceremony": start["ceremony"], "proof": proof});
    let oldest = finish(&starts[0], f.software.login(&starts[0], ORIGIN, true));
    let (status, _, _) = call(
        &app,
        v4_network(1),
        "device-approve-finish",
        Some(&cookie),
        &oldest,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "the evicted ceremony still approved"
    );
    let newest = finish(&starts[5], f.software.login(&starts[5], ORIGIN, true));
    let (status, _, _) = call(
        &app,
        v4_network(1),
        "device-approve-finish",
        Some(&cookie),
        &newest,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_approval_and_identified_pools_keep_their_server_caps() {
    // 205 people at five ceremonies each still fill each 1024 pool.
    let _guard = SERIAL.lock().await;
    let f = fixture().await;
    let code = sign_in_code(&f).await;
    let mut started = 0;
    for index in 0..205 {
        let (_, token) = person(&f, index).await;
        for _ in 0..5 {
            if started == 1024 {
                break;
            }
            f.auth
                .device_approve_start(&token, &code, NOW)
                .await
                .unwrap_or_else(|error| panic!("start {started}: {error:?}"));
            started += 1;
        }
    }
    let (newcomer, token) = person(&f, 999).await;
    assert!(matches!(
        f.auth.device_approve_start(&token, &code, NOW).await,
        Err(Error::Throttled)
    ));
    assert!(matches!(
        f.auth.login_start(&newcomer, NOW).await,
        Err(Error::Denied)
    ));
    // Expiry frees both pools.
    assert!(
        f.auth
            .device_approve_start(&token, &code, NOW + CEREMONY)
            .await
            .is_ok()
    );
}
