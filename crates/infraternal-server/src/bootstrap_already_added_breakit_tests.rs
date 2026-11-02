// SPDX-License-Identifier: AGPL-3.0-only
// Break-it review of the already-added host id (#189): the id reaches only the
// owner, never through a revoked host or a non-owner session, and names the
// host the person actually typed when two retained hosts match.
use super::*;

/// A session whose application SSH lookup is fixed, so the duplicate check can
/// match on `trust_lookup` as well as on the typed address.
struct Looked(Arc<AtomicUsize>, &'static str);
struct LookedSession(Sniff, &'static str);
impl SshTransport for Looked {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(LookedSession(
                Sniff {
                    opens: self.0.clone(),
                    refuse_key_payload_upload: false,
                },
                self.1,
            )) as Arc<dyn SshSession>)
        })
    }
}
impl SshSession for LookedSession {
    fn trust_lookup(&self) -> Option<String> {
        Some(self.1.to_owned())
    }
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        self.0.run(script, input)
    }
}

fn host_id_of(event: &Event) -> Option<serde_json::Value> {
    event
        .failure
        .as_ref()
        .and_then(|failure| serde_json::to_value(failure).unwrap().get("host_id").cloned())
}

async fn all_events(batch: &Batch) -> Vec<Event> {
    finished(batch).await;
    batch.events(0).1
}

#[tokio::test]
async fn a_revoked_host_never_names_its_id() {
    let f = fixture(true).await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
        .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    sqlx::query("UPDATE remote_hosts SET revoked_at=200 WHERE id=?")
        .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    for event in all_events(&start(&f, "owner")).await {
        assert!(host_id_of(&event).is_none(), "revoked host id leaked: {:?}", event.failure);
        assert!(!event.failure.as_ref().is_some_and(|f| f.already_added));
    }
}

#[tokio::test]
async fn a_non_owner_session_never_learns_the_owners_host_id() {
    let f = fixture(true).await;
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
        .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO users (id, name, owner, recovery_hash, username, display_name) VALUES ('member','member',0,'test','member','Member')")
        .execute(&f.pool).await.unwrap();
    let cookie = "M".repeat(43);
    let now = unix_now().unwrap();
    sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'member','fixture',?,?,1)")
        .bind(crate::auth::hash(&cookie)).bind(now + 3600).bind(now).execute(&f.pool).await.unwrap();
    let runner = Bootstrap::new(
        Arc::new(Sniff {
            opens: f.opens.clone(),
            refuse_key_payload_upload: false,
        }),
        f.backend.clone(),
        BinaryPaths { x86_64: "must-not-read-payload".into(), aarch64: "must-not-read-payload".into() },
    );
    let batch = runner
        .start_authenticated(
            "member".into(),
            Secret::new(cookie.as_bytes().to_vec()),
            vec![Target {
                id: "one".into(),
                address: TargetAddress::Manual("user@fixture".into()),
                credential: None,
                mode: InstallMode::Rootless,
                root_consent: false,
            }],
            None,
        )
        .unwrap();
    for event in all_events(&batch).await {
        assert!(host_id_of(&event).is_none(), "member learned a host id: {:?}", event.failure);
    }
}

/// Host B was added under another name whose effective lookup is the one this
/// address resolves to now; host A was added with exactly this address. The
/// typed address must decide which terminal opens, not SQLite's scan order.
#[tokio::test]
async fn the_typed_address_decides_which_host_is_named_when_two_match() {
    let f = fixture(true).await;
    let other = Uuid::from_u128(7);
    // B is inserted first so a rowid-order scan meets it before A.
    sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootless', 1002, 100)")
        .bind(other.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'alias-b','fixture-lookup')")
        .bind(other.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
        .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
    let batch = start_backend_with(&f, Arc::new(Looked(f.opens.clone(), "fixture-lookup")));
    let event = finished(&batch).await;
    assert!(event.failure.as_ref().unwrap().already_added, "{:?}", event.failure);
    assert_eq!(
        host_id_of(&event),
        Some(serde_json::Value::String(f.prior.to_string())),
        "the duplicate named the lookup-only match instead of the host with this exact address"
    );
}

fn start_backend_with(f: &Fixture, transport: Arc<dyn SshTransport>) -> Batch {
    Bootstrap::new(
        transport,
        f.backend.clone(),
        BinaryPaths { x86_64: "must-not-read-payload".into(), aarch64: "must-not-read-payload".into() },
    )
    .start_authenticated(
        "owner".into(),
        Secret::new(f.cookie.as_bytes().to_vec()),
        vec![Target {
            id: "one".into(),
            address: TargetAddress::Manual("user@fixture".into()),
            credential: None,
            mode: InstallMode::Rootless,
            root_consent: false,
        }],
        None,
    )
    .unwrap()
}
