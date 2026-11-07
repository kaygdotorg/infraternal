//! The removal outbox asks the host to uninstall itself on its cleanup-only reconnect (#409).
//!
//! A removed host's infraternal agent reconnects after its link is cut: at
//! once when it was online, or when it comes back after being offline. That
//! reconnect is admitted only to deliver the retained cleanup. These tests play
//! the agent's side of a real WebSocket link to the production admission path
//! and pin the order the outbox keeps: the login revocation and its receipt
//! (D352) first, then the uninstall request, then one transaction that records
//! the answer and retires the entry. An answer that never arrives retires
//! nothing, so the next reconnect asks again.
use super::tests::signing_certificate;
use super::*;
use futures_util::{SinkExt, StreamExt};
use infraternal_protocol::{Frame, encode_muxed_frame_into};
use openssl::{
    pkey::{PKey, Private},
    sign::Signer,
};
use tokio_tungstenite::tungstenite::Message as ClientMessage;

/// The host side of one agent WebSocket link.
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A host removed by its owner, `person`, with an uninstall still to deliver,
/// and a server whose agent route admits its cleanup-only reconnect.
struct Removed {
    /// The server's database, read to check the removal's ledger.
    pool: sqlx::SqlitePool,
    /// A clone of the server's own enrollment store: it shares the change
    /// signal a removal waits on.
    store: crate::enrollment::EnrollmentStore,
    /// The removed host.
    host: Uuid,
    /// The host's enrolled certificate, still valid and individually unrevoked.
    certificate: X509,
    /// The host's key, which signs the link's proof.
    key: PKey<Private>,
    /// Where the server's agent route listens.
    endpoint: std::net::SocketAddr,
    /// The server task, aborted when a test ends.
    server: tokio::task::JoinHandle<()>,
}

/// Enrol a host, then record its removal the way `publish` commits it for a
/// person's host: the cleanup row plus a removal row whose uninstall is
/// `pending`.
async fn removed() -> Removed {
    let (certificate, key) = signing_certificate();
    let fingerprint = certificate.digest(MessageDigest::sha256()).unwrap();
    // The shared fixture gives every test the same host id, but the cleanup
    // lane is process-wide and admits one cleanup per host at a time. So each
    // test enrolls a host of its own, with its own certificate, or parallel
    // tests refuse each other's reconnects.
    let (store, pool, _) = crate::enrollment::authority::tests::enrolled().await;
    let host = Uuid::new_v4();
    let now = crate::runtime::unix_seconds().unwrap();
    sqlx::query("INSERT INTO remote_hosts (id, owner_id, mode, execution_uid, created_at) VALUES (?, 'owner', 'rootless', 1002, ?)")
        .bind(host.as_bytes().as_slice())
        .bind(now - 1)
        .execute(&pool)
        .await
        .unwrap();
    let token = store
        .issue(
            "owner",
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &openssl::sha::sha256(&[3u8; 32]),
        )
        .await
        .unwrap();
    store
        .redeem(
            token.secret(),
            host,
            crate::enrollment::Mode::Rootless,
            now,
            &crate::enrollment::CertificateRecord {
                fingerprint: fingerprint.as_ref().try_into().unwrap(),
                issuer_fingerprint: [9; 32],
                public_key: [3; 32],
                not_before: now - 1,
                not_after: now - 1 + 604_800,
            },
        )
        .await
        .unwrap();
    let person = Uuid::new_v4();
    sqlx::query("INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,'cleanup','cleanup',0,'test')")
        .bind(person.to_string()).execute(&pool).await.unwrap();
    sqlx::query("UPDATE remote_hosts SET owner_id=? WHERE id=?")
        .bind(person.to_string())
        .bind(host.as_bytes().as_slice())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_login_cleanup(host_id,person_id) VALUES (?,?)")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO remote_host_removals(host_id,owner_id,requested_at,uninstall,host_cleanup) VALUES(?,?,unixepoch(),1,'pending')")
        .bind(host.as_bytes().as_slice())
        .bind(person.to_string())
        .execute(&pool)
        .await
        .unwrap();
    let waiter = store.clone();
    let api = Api {
        hosts: RemoteHosts::default(),
        store,
        admission: Arc::new(Semaphore::new(4)),
        sources: Arc::new(crate::remote_admission::SourceSlots::new(4)),
    };
    let router = Router::new()
        .route("/remote/agent", get(upgrade))
        .with_state(api);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Removed {
        pool,
        store: waiter,
        host,
        certificate,
        key,
        endpoint,
        server,
    }
}

impl Removed {
    /// Reconnect as the removed host's infraternal agent: proof, then Hello.
    async fn reconnect(&self) -> Socket {
        let (mut socket, _) =
            tokio_tungstenite::connect_async(format!("ws://{}/remote/agent", self.endpoint))
                .await
                .unwrap();
        let challenge = socket.next().await.unwrap().unwrap();
        let challenge: AgentLinkChallenge =
            serde_json::from_str(challenge.to_text().unwrap()).unwrap();
        let nonce = B64.decode(challenge.nonce).unwrap();
        let signature = Signer::new_without_digest(&self.key)
            .unwrap()
            .sign_oneshot_to_vec(&proof_bytes(self.host, &nonce))
            .unwrap();
        let proof = AgentLinkProof {
            message_type: "proof".to_owned(),
            host_id: self.host,
            certificate_der: B64.encode(self.certificate.to_der().unwrap()),
            signature: B64.encode(signature),
        };
        socket
            .send(ClientMessage::Text(
                serde_json::to_string(&proof).unwrap().into(),
            ))
            .await
            .unwrap();
        assert!(
            socket
                .next()
                .await
                .unwrap()
                .unwrap()
                .to_text()
                .unwrap()
                .contains("ready")
        );
        send(
            &mut socket,
            &Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "removal-outbox-test",
            },
        )
        .await;
        socket
    }

    /// The removal's ledger: (receipt confirmed, entry retired, uninstall state).
    async fn ledger(&self) -> (bool, bool, String) {
        sqlx::query_as("SELECT q.confirmed=1, h.revoked_at IS NOT NULL, r.host_cleanup FROM remote_hosts h JOIN remote_login_cleanup q ON q.host_id=h.id JOIN remote_host_removals r ON r.host_id=h.id WHERE h.id=?")
            .bind(self.host.as_bytes().as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// The kernel objects the removal recorded as left, as stored.
    async fn retained(&self) -> Option<String> {
        sqlx::query_scalar("SELECT retained FROM remote_host_removals WHERE host_id=?")
            .bind(self.host.as_bytes().as_slice())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Wait until the ledger matches `expected`, or fail after a bound.
    async fn settles(&self, expected: (bool, bool, &str)) {
        let reached = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (confirmed, retired, cleanup) = self.ledger().await;
                if (confirmed, retired, cleanup.as_str()) == expected {
                    return;
                }
                // sleep: the receipt commits on the server's task; poll the ledger briefly.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "ledger stayed {:?}, expected {expected:?}",
            self.ledger().await
        );
    }
}

/// Write one control-stream frame from the host's side.
async fn send(socket: &mut Socket, frame: &Frame<'_>) {
    let mut bytes = Vec::new();
    encode_muxed_frame_into(0, frame, &mut bytes).unwrap();
    socket
        .send(ClientMessage::Binary(bytes.into()))
        .await
        .unwrap();
}

/// The next control call the server sends, as (call id, action, input), or
/// `None` if the server closes the link or sends nothing within `wait`.
async fn try_next_call(socket: &mut Socket, wait: Duration) -> Option<(u32, String, Vec<u8>)> {
    tokio::time::timeout(wait, async {
        loop {
            let message = socket.next().await?.ok()?;
            if !message.is_binary() {
                continue;
            }
            let bytes = message.into_data();
            let decoded = infraternal_protocol::decode_muxed_frame(&bytes).unwrap();
            if let Frame::Call {
                call_id,
                action_id,
                input_json,
            } = decoded.frame
            {
                assert_eq!(decoded.stream_id, 0, "cleanup calls use the control stream");
                return Some((call_id, action_id.to_owned(), input_json.to_vec()));
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// The next control call the server sends, as (call id, action, input).
async fn next_call(socket: &mut Socket) -> (u32, String, Vec<u8>) {
    try_next_call(socket, Duration::from_secs(3))
        .await
        .expect("the server sent no control call")
}

/// Answer the login revocation with a durable receipt.
async fn receipt(socket: &mut Socket) {
    let (call_id, action, _) = next_call(socket).await;
    answer_receipt(socket, call_id, &action).await;
}

/// Reply to a `terminal.login.revoke` call with a durable receipt.
async fn answer_receipt(socket: &mut Socket, call_id: u32, action: &str) {
    assert_eq!(action, "terminal.login.revoke", "the receipt comes first");
    send(
        socket,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"revoked":true}"#,
        },
    )
    .await;
}

impl Removed {
    /// Reconnect the way a real infraternal agent does after losing its link:
    /// retry until the server takes the reconnect and asks for the receipt,
    /// then give it. Until the server's previous cleanup task has seen the
    /// old link go, it refuses a second one for the same host.
    async fn reconnect_until_receipt(&self) -> Socket {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let mut socket = self.reconnect().await;
            if let Some((call_id, action, _)) =
                try_next_call(&mut socket, Duration::from_secs(2)).await
            {
                answer_receipt(&mut socket, call_id, &action).await;
                return socket;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the server never took the host's reconnect"
            );
        }
    }
}

/// After the receipt, the outbox asks for exactly this host's uninstall, and
/// the host's acceptance and the receipt retire the entry together.
#[tokio::test]
async fn outbox_asks_for_the_uninstall_after_the_receipt_then_retires() {
    let removed = removed().await;
    let mut socket = removed.reconnect().await;
    receipt(&mut socket).await;
    let (call_id, action, input) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&input).unwrap(),
        serde_json::json!({"host": removed.host.simple().to_string(), "dry_run": false})
    );
    // Nothing is retired while the uninstall answer is outstanding.
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    // A removal waiting for the answer, as `publish` does for a connected host.
    let store = removed.store.clone();
    let host = removed.host;
    let waiting = tokio::spawn(async move {
        store
            .wait_removal_outcome(host, Duration::from_secs(5))
            .await
            .unwrap()
    });
    // The host reports one object the server knows and one string of its own.
    send(
        &mut socket,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"state":"accepted","cleanup":"pending","left":["infraternal0","run me"]}"#,
        },
    )
    .await;
    removed.settles((true, true, "requested")).await;
    // Only the server-known name is kept, and the waiter gets it (#235, #409).
    assert_eq!(
        removed.retained().await.as_deref(),
        Some(r#"["infraternal0"]"#)
    );
    assert_eq!(
        waiting.await.unwrap(),
        Some(("requested".to_owned(), vec!["infraternal0".to_owned()]))
    );
    removed.server.abort();
}

/// A removal whose host does not answer in time gets no outcome, and the
/// wait changes nothing: the removal stays pending for the outbox.
#[tokio::test]
async fn an_unanswered_removal_wait_ends_without_an_outcome() {
    let removed = removed().await;
    let answered = removed
        .store
        .wait_removal_outcome(removed.host, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(answered, None);
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    removed.server.abort();
}

/// A host that goes away before it answers the uninstall retires nothing; its
/// next reconnect gets the receipt request and the uninstall again.
#[tokio::test]
async fn lost_uninstall_answer_is_asked_again_on_the_next_reconnect() {
    let removed = removed().await;
    let mut socket = removed.reconnect().await;
    receipt(&mut socket).await;
    let (_, action, _) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    drop(socket);
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    let mut socket = removed.reconnect_until_receipt().await;
    // Still nothing retired: the uninstall is asked again before that.
    assert_eq!(removed.ledger().await, (false, false, "pending".to_owned()));
    let (call_id, action, _) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    send(
        &mut socket,
        &Frame::Result {
            call_id,
            ok: true,
            json: br#"{"state":"accepted","cleanup":"pending","left":[]}"#,
        },
    )
    .await;
    removed.settles((true, true, "requested")).await;
    removed.server.abort();
}

/// A host that answers no still gives its receipt: the entry retires, and the
/// removal records that the install stayed (`unreachable`).
#[tokio::test]
async fn refused_uninstall_retires_with_the_install_recorded_as_left() {
    let removed = removed().await;
    let mut socket = removed.reconnect().await;
    receipt(&mut socket).await;
    let (call_id, action, _) = next_call(&mut socket).await;
    assert_eq!(action, infraternal_plugin_remote::UNINSTALL.id);
    send(
        &mut socket,
        &Frame::Result {
            call_id,
            ok: false,
            json: b"{}",
        },
    )
    .await;
    removed.settles((true, true, "unreachable")).await;
    removed.server.abort();
}
