//! Joins SSH-installed machines through the live CA ledger and proves readiness over their admitted transport [138][168].
use super::{PendingRemoteRuntime, unix_now};
use crate::{
    embedded::{EmbeddedAgent, TerminalOutput, TerminalSize},
    enrollment::Mode,
    remote_http::{InvitationIssuer, InvitationRequest},
    remote_runtime::RemoteHosts,
};
use infraternal_plugin_ssh::{
    bootstrap::{Authority, Backend, Resolved},
    install::JoinMaterial,
    model::{Failure, InstallMode, Target},
    probe::Check,
    transport::{Operation, Secret},
};
use std::{collections::HashMap, sync::Mutex, time::Duration};
use uuid::Uuid;
use zeroize::Zeroize;

/// Fresh identities are owned by one batch until installation commits or rolls back.
/// No user-provided UUID can overwrite an already enrolled machine's authority.
pub(super) struct RemoteBackend {
    pub(super) base: PendingRemoteRuntime,
    pub(super) issuer: InvitationIssuer,
    pub(super) hosts: RemoteHosts,
    pub(super) attempts: Mutex<HashMap<Uuid, Attempt>>,
}
pub(super) struct Attempt {
    owner: String,
    batch: Uuid,
    uid: u32,
}
// Cancellation before JoinMaterial reaches the installer has no Resources.host
// to clean up. Release its unpublished ownership synchronously on every exit.
struct Unpublished<'a> {
    backend: &'a RemoteBackend,
    host: Uuid,
    published: bool,
}
impl Drop for Unpublished<'_> {
    fn drop(&mut self) {
        if !self.published
            && let Ok(mut attempts) = self.backend.attempts.lock()
        {
            attempts.remove(&self.host);
        }
    }
}
impl RemoteBackend {
    async fn authorize(&self, authority: &Authority) -> Result<(), Failure> {
        let auth = self.base.auth.as_ref().ok_or_else(unavailable)?;
        let cookie = cookie(authority)?;
        if auth
            .bootstrap_owner(cookie, unix_now()?)
            .await
            .is_ok_and(|owner| owner == authority.owner)
        {
            Ok(())
        } else {
            Err(Failure::unsupported(
                "The bootstrap session is no longer authorized.",
            ))
        }
    }
    fn uid(&self, authority: &Authority, host: Uuid) -> Result<u32, Failure> {
        self.attempts
            .lock()
            .map_err(|_| unavailable())?
            .get(&host)
            .filter(|attempt| attempt.owner == authority.owner && attempt.batch == authority.batch)
            .map(|attempt| attempt.uid)
            .ok_or_else(unavailable)
    }
    async fn actor(&self, authority: &Authority, host: Uuid) -> Result<EmbeddedAgent, Failure> {
        self.authorize(authority).await?;
        self.uid(authority, host)?;
        // The installation service has just started. This finite wait owns no
        // background timer and cannot turn token redemption into online proof.
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(actor) = self.hosts.actor(host).await {
                    return actor;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| {
            Failure::install(
                "The infraternal agent did not connect. Check the host's service and network.",
            )
        })
    }
    fn completed_record(&self, authority: &Authority, host: Uuid) -> Result<(), Failure> {
        self.uid(authority, host)?;
        self.attempts
            .lock()
            .map_err(|_| unavailable())?
            .remove(&host);
        Ok(())
    }
}
impl Backend for RemoteBackend {
    fn resolve<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        credential: Option<&'a str>,
    ) -> Operation<'a, Resolved> {
        Box::pin(async move {
            self.authorize(authority).await?;
            self.base.resolve(authority, target, credential).await
        })
    }
    fn invitation<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move {
            self.authorize(authority).await?;
            if !self.issuer.ready() {
                return Err(Failure::install(
                    "Set up or unlock host connections with an administrator passkey before adding a host.",
                ));
            }
            let host = Uuid::new_v4();
            let (mode, uid) = match target.mode {
                InstallMode::Rootless => (Mode::Rootless, check.uid),
                InstallMode::Root => (Mode::Rootful, 0),
            };
            {
                let mut attempts = self.attempts.lock().map_err(|_| unavailable())?;
                if attempts.len() >= 1600 {
                    return Err(Failure::install(
                        "Too many host installations are pending. Try again shortly.",
                    ));
                }
                attempts.insert(
                    host,
                    Attempt {
                        owner: authority.owner.clone(),
                        batch: authority.batch,
                        uid,
                    },
                );
            }
            let mut unpublished = Unpublished {
                backend: self,
                host,
                published: false,
            };
            let invitation = self
                .issuer
                .issue(
                    cookie(authority)?,
                    InvitationRequest {
                        host_id: host,
                        mode,
                        execution_uid: uid,
                    },
                )
                .await;
            let Ok(mut invitation) = invitation else {
                return Err(Failure::install(
                    "The host invitation was refused. Unlock your session and try again.",
                ));
            };
            let stdin = serde_json::to_vec(&invitation);
            invitation.token.zeroize();
            let stdin = stdin.map_err(|_| unavailable())?;
            unpublished.published = true;
            Ok(JoinMaterial {
                host,
                url: format!("{}/remote/join", self.issuer.origin()),
                stdin: Secret::new(stdin),
            })
        })
    }
    fn connected_facts<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            let actor = self.actor(authority, host).await?;
            let response = tokio::time::timeout(
                Duration::from_secs(10),
                actor.call(
                    "host.facts.read".into(),
                    br#"{"includeLive":false}"#.to_vec(),
                ),
            )
            .await
            .map_err(|_| unavailable())?
            .map_err(|_| unavailable())?;
            let facts: serde_json::Value =
                serde_json::from_slice(&response).map_err(|_| unavailable())?;
            if facts["executionUid"].as_u64() != Some(u64::from(self.uid(authority, host)?))
                || facts["mode"] != "remote"
            {
                return Err(Failure::install(
                    "The infraternal agent's execution identity does not match this installation.",
                ));
            }
            self.authorize(authority).await
        })
    }
    fn terminal_canary<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            let actor = self.actor(authority, host).await?;
            tokio::time::timeout(Duration::from_secs(10), canary(&actor))
                .await
                .map_err(|_| {
                    Failure::install("The host connected, but its terminal did not answer.")
                })??;
            self.authorize(authority).await
        })
    }
    fn failed<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            self.uid(authority, host)?;
            // Logout cannot prevent cleanup of this exact batch's new authority.
            self.issuer
                .store()
                .revoke(&authority.owner, host, unix_now()?)
                .await
                .map_err(|_| unavailable())?;
            self.completed_record(authority, host)
        })
    }
    fn completed<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move { self.completed_record(authority, host) })
    }
}
fn cookie(authority: &Authority) -> Result<&str, Failure> {
    std::str::from_utf8(authority.session().ok_or_else(unavailable)?.expose())
        .map_err(|_| unavailable())
}
fn unavailable() -> Failure {
    Failure::install(
        "Remote host readiness is unavailable. Check the host's service and try again.",
    )
}
async fn canary(actor: &EmbeddedAgent) -> Result<(), Failure> {
    use infraternal_protocol::{Frame, encode_muxed_frame_into};
    let session = actor
        .open(TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        })
        .await
        .map_err(|_| unavailable())?;
    let (handle, mut output) = actor
        .attach(session, 0, 0, 2)
        .await
        .map_err(|_| unavailable())?
        .split();
    let marker = format!("infraternal-ready-{}", Uuid::new_v4().simple());
    let middle = marker.len() / 2;
    // The two arguments keep the complete marker out of the shell's input echo.
    // Exit the private canary shell after output, so no readiness PTY stays idle.
    let command = format!(
        "printf '%s%s\\n' '{}' '{}'; exit\n",
        &marker[..middle],
        &marker[middle..]
    );
    let mut wire = Vec::new();
    for frame in [
        Frame::Credit { bytes: 65536 },
        Frame::Input {
            in_seq: 0,
            bytes: command.as_bytes(),
        },
    ] {
        // Input is leg A (odd); the attachment maps it onto its even leg-B stream.
        encode_muxed_frame_into(1, &frame, &mut wire).map_err(|_| unavailable())?;
        handle
            .send_frame(bytes::Bytes::copy_from_slice(&wire))
            .await
            .map_err(|_| unavailable())?;
    }
    let mut received = Vec::new();
    while let Some(event) = output.recv().await {
        match event {
            // A fast first command may be included in the initial faithful
            // repaint; snapshots carry confirmed PTY output just as deltas do.
            TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } => {
                if received.len() + bytes.len() > 65536 {
                    return Err(unavailable());
                }
                received.extend_from_slice(&bytes);
                if received
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes())
                {
                    return Ok(());
                }
            }
            TerminalOutput::Closed { .. } => break,
            _ => {}
        }
    }
    Err(unavailable())
}

#[cfg(test)]
mod tests {
    //! Check real SQLite authority and attempt retirement before any upload.
    use super::*;
    use crate::{
        auth::Auth,
        ca::{CaError, CaKeySource, CaMaterial},
        remote_http::{EnrollmentEndpoint, EnrollmentService},
    };
    use infraternal_plugin_ssh::{
        bootstrap::{Batch, Bootstrap},
        install::BinaryPaths,
        model::{Destination, Event, MeshEvidence, Step, TargetAddress},
        transport::{CommandOutput, Credentials, Input, SshSession, SshTransport},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    struct Signer(Option<CaMaterial>);
    impl CaKeySource for Signer {
        fn load(&self) -> Result<CaMaterial, CaError> {
            self.0.clone().ok_or(CaError)
        }
    }
    struct Sniff(Arc<AtomicUsize>);
    impl SshTransport for Sniff {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async move {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(Arc::new(Sniff(self.0.clone())) as Arc<dyn SshSession>)
            })
        }
    }
    impl SshSession for Sniff {
        fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
            Box::pin(async move {
                if script != infraternal_plugin_ssh::probe::CHECK_SCRIPT {
                    // Staging failure still requests rollback. Refuse cleanup
                    // safely so the backend must retire its public authority
                    // even when the host cannot be reached.
                    assert!(matches!(input, Input::Empty));
                    assert!(script.contains("validate_receipt"));
                    return Err(Failure::install("The read-only fixture refused cleanup."));
                }
                Ok(CommandOutput {
                    stdout:
                        b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n"
                            .to_vec(),
                })
            })
        }
    }
    struct Fixture {
        backend: Arc<RemoteBackend>,
        pool: sqlx::SqlitePool,
        prior: Uuid,
        cookie: String,
        opens: Arc<AtomicUsize>,
    }
    async fn fixture(unlocked: bool) -> Fixture {
        let (store, pool, prior) = crate::enrollment::authority::tests::enrolled().await;
        let auth = Auth::new(
            pool.clone(),
            "remote.example.test",
            "https://remote.example.test",
        )
        .await
        .unwrap();
        let cookie = "B".repeat(43);
        let now = unix_now().unwrap();
        sqlx::query("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,'owner','fixture',?,?,1)")
            .bind(crate::auth::hash(&cookie)).bind(now+3600).bind(now).execute(&pool).await.unwrap();
        let material = crate::ca::tests::test_material();
        let source: Arc<dyn CaKeySource> = Arc::new(Signer(unlocked.then_some(material.clone())));
        let issuer = InvitationIssuer::new(
            auth.clone(),
            pool.clone(),
            store,
            EnrollmentService {
                source: source.clone(),
                endpoint: EnrollmentEndpoint {
                    ca_der: material.issuer().to_der().unwrap(),
                    endpoint: "127.0.0.1:1".parse().unwrap(),
                    server_name: "remote.example.test".into(),
                },
            },
        );
        Fixture {
            backend: Arc::new(RemoteBackend {
                base: PendingRemoteRuntime {
                    auth: Some(auth),
                    key: Arc::new(crate::ssh_key::UnavailableSshKey),
                },
                issuer,
                hosts: RemoteHosts::from_source(Some(source)),
                attempts: Mutex::default(),
            }),
            pool,
            prior,
            cookie,
            opens: Arc::default(),
        }
    }
    fn start(f: &Fixture, owner: &str) -> Batch {
        let runner = Bootstrap::new(
            Arc::new(Sniff(f.opens.clone())),
            f.backend.clone(),
            BinaryPaths {
                x86_64: "must-not-read-payload".into(),
                aarch64: "must-not-read-payload".into(),
            },
        );
        runner
            .start_authenticated(
                owner.into(),
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
    async fn finished(batch: &Batch) -> Event {
        let mut changed = batch.subscribe();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(event) = batch
                    .events(0)
                    .1
                    .into_iter()
                    .find(|event| matches!(event.step, Step::Failed | Step::Done))
                {
                    return event;
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn cold_ca_refuses_before_invitation_or_upload() {
        let f = fixture(false).await;
        let batch = start(&f, "owner");
        let event = finished(&batch).await;
        assert_eq!(event.step, Step::Failed);
        assert!(event.message.contains("administrator passkey"));
        assert_eq!(f.opens.load(Ordering::Relaxed), 1);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_hosts")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn foreign_or_revoked_authority_never_opens_ssh() {
        let f = fixture(true).await;
        assert_eq!(finished(&start(&f, "stranger")).await.step, Step::Failed);
        sqlx::query("DELETE FROM sessions")
            .execute(&f.pool)
            .await
            .unwrap();
        assert_eq!(finished(&start(&f, "owner")).await.step, Step::Failed);
        assert_eq!(f.opens.load(Ordering::Relaxed), 0);
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn failed_upload_retires_only_the_new_host() {
        let f = fixture(true).await;
        assert_eq!(finished(&start(&f, "owner")).await.step, Step::Failed);
        let rows: Vec<(Vec<u8>, i64, Option<i64>)> =
            sqlx::query_as("SELECT id,execution_uid,revoked_at FROM remote_hosts")
                .fetch_all(&f.pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 2);
        for (id, uid, revoked) in rows {
            assert_eq!(uid, 1002);
            assert_eq!(revoked.is_none(), id == f.prior.as_bytes());
        }
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn unpublished_attempt_drop_releases_only_its_ownership() {
        let f = fixture(true).await;
        let host = Uuid::new_v4();
        let other = Uuid::new_v4();
        f.backend.attempts.lock().unwrap().insert(
            host,
            Attempt {
                owner: "owner".into(),
                batch: Uuid::new_v4(),
                uid: 1002,
            },
        );
        f.backend.attempts.lock().unwrap().insert(
            other,
            Attempt {
                owner: "other-owner".into(),
                batch: Uuid::new_v4(),
                uid: 1003,
            },
        );
        let guard = Unpublished {
            backend: &f.backend,
            host,
            published: false,
        };
        drop(guard);
        {
            let attempts = f.backend.attempts.lock().unwrap();
            assert!(!attempts.contains_key(&host));
            assert!(attempts.contains_key(&other));
        }
        let prior: bool =
            sqlx::query_scalar("SELECT revoked_at IS NULL FROM remote_hosts WHERE id=?")
                .bind(f.prior.as_bytes().as_slice())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(prior);
    }
}

#[cfg(test)]
#[path = "bootstrap_canary_tests.rs"]
mod canary_tests;
