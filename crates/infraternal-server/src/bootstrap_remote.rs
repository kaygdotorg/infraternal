//! Joins SSH-installed machines through the live CA ledger and proves readiness over their admitted transport [138][168].
use super::{PendingRemoteRuntime, unix_now};
use crate::{
    embedded::{EmbeddedAgent, TerminalOutput, TerminalSize},
    enrollment::Mode,
    remote_http::{InvitationIssuer, InvitationRequest},
    remote_runtime::RemoteHosts,
};
use infraternal_plugin_ssh::{
    bootstrap::{
        Authority, Backend, PreparedHostKey, Resolved, StuckInstall, StuckInstallCheck,
        StuckInstallRequest,
    },
    install::JoinMaterial,
    model::{Failure, InstallMode, InstallStep, Target},
    probe::Check,
    transport::{Operation, Secret},
};
use std::{collections::HashMap, sync::Mutex, time::Duration};
use uuid::Uuid;
use zeroize::Zeroize;

const CONNECTED_FACTS_TIMEOUT: Duration = Duration::from_secs(10);
const TERMINAL_CANARY_TIMEOUT: Duration = Duration::from_secs(10);

/// Preserve the original per-phase startup allowance and add eight authenticated
/// exchanges for TLS fallback, greeting and actor admission. This is a failure
/// bound, never a delay: route notifications release a healthy host immediately.
fn installed_actor_budget(round_trip: Duration) -> Duration {
    Duration::from_secs(30).saturating_add(round_trip.saturating_mul(8))
}

/// Cover the entire SSH command: installed-actor and active-route waits,
/// connected facts and terminal proof, plus admission and exit round trips.
/// Proof terms reuse the operation timeouts below; RTT terms use the measured
/// link. Bootstrap caps this derived duration at its 180-second setup deadline.
fn setup_commit_budget(round_trip: Duration) -> Duration {
    let installed_actor_admission = installed_actor_budget(round_trip);
    let active_route_admission = installed_actor_budget(round_trip);
    let connected_facts = CONNECTED_FACTS_TIMEOUT;
    let terminal_canary = TERMINAL_CANARY_TIMEOUT;
    let ssh_command_admission = round_trip;
    let ssh_exit_receipt = round_trip;

    installed_actor_admission
        .saturating_add(active_route_admission)
        .saturating_add(connected_facts)
        .saturating_add(terminal_canary)
        .saturating_add(ssh_command_admission)
        .saturating_add(ssh_exit_receipt)
}

/// Fresh identities are owned by one batch until installation commits or rolls back.
/// No user-provided UUID can overwrite an already enrolled machine's authority.
pub(super) struct RemoteBackend {
    pub(super) base: PendingRemoteRuntime,
    pub(super) issuer: InvitationIssuer,
    pub(super) hosts: RemoteHosts,
    pub(super) attempts: Mutex<HashMap<Uuid, Attempt>>,
    pub(super) sessions_changed: Mutex<Option<tokio::sync::watch::Sender<u64>>>,
}
pub(super) struct Attempt {
    owner: String,
    batch: Uuid,
    uid: u32,
    link_round_trip: Duration,
    destination: Option<(String, Option<String>)>,
    canary: Option<(EmbeddedAgent, [u8; 16], [u32; 2])>,
    retirement: Option<tokio::task::JoinHandle<Result<(), Failure>>>,
    /// A Replace of a host this server already enrolled (#305). It took on no
    /// restart-retirement obligation, since the host stays enrolled if the
    /// attempt fails, so its completion has none to discharge.
    replacement: bool,
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
        if super::authorize_authority(auth, authority).await {
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
    async fn publish_terminal_session(
        &self,
        authority: &Authority,
        host: Uuid,
        session_id: Uuid,
    ) -> Result<(), Failure> {
        let pool = &self.issuer.store().0;
        let changed = if let Some(key_hash) = authority.api_key_hash() {
            let auth = self.base.auth.as_ref().ok_or_else(unavailable)?;
            let mut tx = pool
                .begin_with("BEGIN IMMEDIATE")
                .await
                .map_err(|_| unavailable())?;
            let person = auth
                .api_authorize_key_hash_tx(&mut tx, key_hash, "hosts:write", None)
                .await
                .map_err(|_| unavailable())?
                .filter(|person| person == &authority.owner)
                .ok_or_else(unavailable)?;
            let changed = sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) SELECT ?,?,unixepoch(),unixepoch(),? FROM users u WHERE u.id=? AND u.owner=1 AND EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=? AND h.owner_id=u.id AND h.revoked_at IS NULL) ON CONFLICT(id) DO NOTHING")
                .bind(session_id.as_bytes().as_slice())
                .bind(&person)
                .bind(host.as_bytes().as_slice())
                .bind(&person)
                .bind(host.as_bytes().as_slice())
                .execute(&mut *tx)
                .await
                .map_err(|_| unavailable())?;
            tx.commit().await.map_err(|_| unavailable())?;
            changed
        } else {
            let cookie = cookie(authority)?;
            sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) SELECT ?,?,unixepoch(),unixepoch(),? FROM sessions WHERE token_hash=? AND user_id=? AND unlocked=1 AND expires>unixepoch() AND EXISTS(SELECT 1 FROM remote_hosts WHERE id=? AND owner_id=? AND revoked_at IS NULL) ON CONFLICT(id) DO NOTHING")
                .bind(session_id.as_bytes().as_slice())
                .bind(&authority.owner)
                .bind(host.as_bytes().as_slice())
                .bind(crate::auth::hash(cookie))
                .bind(&authority.owner)
                .bind(host.as_bytes().as_slice())
                .bind(&authority.owner)
                .execute(pool)
                .await
                .map_err(|_| unavailable())?
        };
        if changed.rows_affected() != 1 {
            let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM terminal_sessions WHERE id=? AND user_id=? AND remote_host_id=? AND closed_at IS NULL)")
                .bind(session_id.as_bytes().as_slice())
                .bind(&authority.owner)
                .bind(host.as_bytes().as_slice())
                .fetch_one(pool)
                .await
                .map_err(|_| unavailable())?;
            if !owned {
                return Err(unavailable());
            }
        }
        Ok(())
    }
    /// The owner's host already added at this address or SSH lookup, if any.
    ///
    /// Only a host whose setup finished, or whose infraternal agent is connected
    /// now, counts as added: "already added" offers its terminal, which must be able
    /// to open (#305, J241). A match whose setup never finished (its restart-
    /// retirement intent is still open) is otherwise one of two things:
    /// - an attempt in this server is still installing it: refused as "already
    ///   being added", with no host to open;
    /// - nothing is: an interrupted setup left it in this server's records. Startup
    ///   cannot retire it once its first shell was published (an open terminal
    ///   session keeps the obligation), so it survived every restart and turned each
    ///   later add of the same host into "already added" with a terminal that never
    ///   opened. Adding the host again asks for a working install there, so the
    ///   record is retired, as a cancelled attempt is, and the search continues.
    ///
    /// With `retire` false nothing is changed: an abandoned record is only reported
    /// as not added. The stuck-install check uses that, since it runs before the
    /// person has confirmed anything (J247 P3); the add retires it later.
    ///
    /// Hosts with a pending removal are not active destinations: their retained
    /// removal coordinates belong only to cleanup (#347). Nor are hosts whose
    /// denial is committed but whose login cleanup awaits their agent's receipt:
    /// they are no longer admitted.
    async fn existing_host(
        &self,
        owner: &str,
        address: &str,
        lookup: Option<&str>,
        retire: bool,
    ) -> Result<Option<Uuid>, Failure> {
        // Each pass retires at most one record; the bound only stops a storage
        // fault that keeps refusing the retirement from looping forever.
        for _ in 0..16 {
            let existing: Option<(Vec<u8>, bool)> = sqlx::query_as("SELECT h.id, EXISTS(SELECT 1 FROM remote_bootstrap_retirement_intents i WHERE i.host_id=h.id) FROM remote_host_bootstrap b JOIN remote_hosts h ON h.id=b.host_id WHERE h.owner_id=? AND h.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id) AND NOT EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0) AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?)) ORDER BY (b.address=?) DESC, h.id LIMIT 1")
                .bind(owner)
                .bind(address)
                .bind(lookup)
                .bind(lookup)
                .bind(address)
                .fetch_optional(&self.issuer.store().0)
                .await
                .map_err(|_| unavailable())?;
            let Some((host, unfinished)) = existing else {
                return Ok(None);
            };
            let host = Uuid::from_slice(&host).map_err(|_| unavailable())?;
            // Any connected infraternal agent keeps its host, even before it
            // has reported its session inventory (J247 P3).
            if !unfinished || self.hosts.actor(host).await.is_some() {
                return Ok(Some(host));
            }
            let running = self
                .attempts
                .lock()
                .map_err(|_| unavailable())?
                .contains_key(&host);
            if running {
                return Err(being_added());
            }
            if !retire {
                return Ok(None);
            }
            self.retire_abandoned_setup(owner, host).await?;
        }
        Err(unavailable())
    }

    /// Retire `host`, an unfinished setup record that no attempt here owns and whose
    /// infraternal agent is not connected (see [`existing_host`](Self::existing_host)).
    ///
    /// This is the cancelled-attempt path: fence the host's transport first, then
    /// revoke it and consume its intent in one writer transaction.
    async fn retire_abandoned_setup(&self, owner: &str, host: Uuid) -> Result<(), Failure> {
        let store = self.issuer.store();
        let now = unix_now()?;
        let _fence = store.1.cut(host).map_err(|_| unavailable())?;
        // Deny without waiting for the gone agent's receipt (#305 round 4): a
        // person's retirement otherwise waits for it, and the add hung to its
        // deadline. The outbox keeps the login cleanup; the cut stays until it is
        // confirmed, as for a removed offline host.
        match store.deny_abandoned_bootstrap(owner, host, now).await {
            Ok(()) => {}
            // Another path consumed the intent first (a cancelled attempt's own
            // retirement, or a completion): the caller's next lookup decides.
            Err(crate::enrollment::EnrollmentError::Denied) => {
                // Release this cut as a committed revocation does (J247 P3).
                store.1.tombstoned(host);
                return Ok(());
            }
            Err(_) => return Err(unavailable()),
        }
        tracing::info!(
            host_id = %host,
            outcome = "retired",
            "host provisioning found an earlier setup that never finished"
        );
        Ok(())
    }
    fn already_added(host_id: Uuid) -> Failure {
        Failure::install("This host is already added. Open its terminal from Console.")
            .with_existing_host_id(host_id)
    }
    /// Find persisted duplicates before the installer needs the matching payload.
    /// `retire` is passed to [`existing_host`](Self::existing_host): false only
    /// where nothing has been confirmed yet.
    async fn ensure_not_already_added(
        &self,
        authority: &Authority,
        target: &Target,
        lookup: Option<&str>,
        retire: bool,
    ) -> Result<(), Failure> {
        self.authorize(authority).await?;
        let infraternal_plugin_ssh::model::TargetAddress::Manual(address) = &target.address else {
            return Err(unavailable());
        };
        if !self.issuer.ready() {
            return Err(Failure::authority_locked());
        }
        if let Some(host_id) = self
            .existing_host(&authority.owner, address, lookup, retire)
            .await?
        {
            return Err(Self::already_added(host_id));
        }
        Ok(())
    }
    async fn actor(&self, authority: &Authority, host: Uuid) -> Result<EmbeddedAgent, Failure> {
        self.authorize(authority).await?;
        self.uid(authority, host)?;
        let budget = self
            .attempts
            .lock()
            .map_err(|_| unavailable())?
            .get(&host)
            .map_or_else(
                || installed_actor_budget(Duration::ZERO),
                |attempt| installed_actor_budget(attempt.link_round_trip),
            );
        // The service and actor each receive a link-scaled startup allowance.
        // Queue admission is progress, but never authenticated online proof.
        #[cfg(test)]
        let mesh_route_started = std::time::Instant::now();
        #[cfg(test)]
        let mesh_route_started_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let result = wait_installed_actor(&self.hosts, host, budget).await;
        #[cfg(test)]
        if std::env::var_os("ADDHOST_RETRY_PHASE_TIMING").is_some() {
            let elapsed_ms = mesh_route_started.elapsed().as_secs_f64() * 1000.0;
            let epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            println!(
                "TIMELINE source=server step=mesh_actor_route state=start epoch_ms={:.3}",
                mesh_route_started_epoch.as_secs_f64() * 1000.0
            );
            println!(
                "TIMELINE source=server step=mesh_actor_route state=end epoch_ms={:.3}",
                epoch.as_secs_f64() * 1000.0
            );
            println!(
                "METRIC breakit2 step=mesh_actor_route elapsed_ms={:.3} ok={}",
                elapsed_ms,
                result.is_ok()
            );
            if let Ok(limit_ms) = std::env::var("BREAKIT2_ROUTE_WAIT_MAX_MS") {
                let limit_ms = limit_ms
                    .parse::<f64>()
                    .expect("route-wait test budget must be numeric");
                assert!(
                    elapsed_ms <= limit_ms,
                    "mesh actor route wait took {elapsed_ms:.3} ms, over the {limit_ms:.3} ms budget"
                );
            }
        }
        result
    }
    /// Match immutable failed-bootstrap coordinates before automatic remote cleanup.
    async fn owns_failed_setup_record(
        &self,
        owner: &str,
        target: &Target,
        check: &Check,
        host: Uuid,
        lookup: Option<&str>,
    ) -> Result<bool, Failure> {
        target.validate()?;
        check.authorize_mode(target.mode)?;
        let infraternal_plugin_ssh::model::TargetAddress::Manual(address) = &target.address else {
            return Ok(false);
        };
        let (mode, uid) = match target.mode {
            InstallMode::Rootless => ("rootless", check.uid),
            InstallMode::Root => ("rootful", 0),
        };
        // A recorded authenticated SSH lookup must match the current lookup.
        // Only legacy rows without either lookup may use an exact destination.
        // Retired rows survive process restart, but cannot authorize cleanup for
        // another server's UUID, owner, execution account or privilege mode.
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts h JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NOT NULL AND h.mode=? AND h.execution_uid=? AND ((b.trust_lookup=? AND ? IS NOT NULL) OR (b.trust_lookup IS NULL AND ? IS NULL AND b.address=?)))")
            .bind(host.as_bytes().as_slice())
            .bind(owner)
            .bind(mode)
            .bind(i64::from(uid))
            .bind(lookup)
            .bind(lookup)
            .bind(lookup)
            .bind(address)
            .fetch_one(&self.issuer.store().0)
            .await
            .map_err(|_| unavailable())
    }

    /// The end of [`completed`](Backend::completed), after the login checks: mark the
    /// setup of this batch's attempt for `host` finished, then release the attempt.
    ///
    /// A Replace never recorded a retirement intent of its own (the host stays
    /// enrolled if it fails), so it may find none (#305); it still consumes one its
    /// host carries from a first setup that never finished (J247 P2).
    async fn finish_completion(&self, owner: &str, batch: Uuid, host: Uuid) -> Result<(), Failure> {
        let replacement = self
            .attempts
            .lock()
            .map_err(|_| unavailable())?
            .get(&host)
            .filter(|attempt| attempt.owner == owner && attempt.batch == batch)
            .map(|attempt| attempt.replacement)
            .ok_or_else(unavailable)?;
        self.finish_setup_record(owner, host, replacement).await?;
        self.attempts
            .lock()
            .map_err(|_| unavailable())?
            .remove(&host);
        Ok(())
    }
    /// Mark `host`'s setup finished by consuming its restart-retirement intent.
    ///
    /// A new install always has one. A Replace took on none of its own, but the
    /// host it replaced may still carry its first setup's open intent, when that
    /// setup never finished: consume it too, or the working host keeps reading as
    /// an abandoned setup that a later re-add retires while its agent is offline
    /// (#305, J247 P2). Only a Replace may find none.
    async fn finish_setup_record(
        &self,
        owner: &str,
        host: Uuid,
        replacement: bool,
    ) -> Result<(), Failure> {
        match self.issuer.store().complete_bootstrap(owner, host).await {
            Ok(()) => Ok(()),
            Err(crate::enrollment::EnrollmentError::Denied) if replacement => Ok(()),
            Err(_) => Err(unavailable()),
        }
    }
    /// D355: Start fresh just proved it emptied this account's install base on the
    /// host at `target`, or the add's check proved there is no install there at all
    /// (one base per account and mode), so any install the same
    /// person's stale entries had there is gone. Finish those entries now instead
    /// of leaving them pending for a receipt their gone agent never sends: deny
    /// the ones not yet denied, then complete their cleanup as that receipt would,
    /// which retires them and removes them from Console (#305).
    ///
    /// Only rows that are this person's, at this address (or SSH lookup), for this
    /// mode and execution account, unrevoked, and stale (an open setup intent or
    /// an unconfirmed cleanup) qualify; one a running attempt here owns, or whose
    /// infraternal agent is connected, is kept. Everything else stays as it is.
    async fn drop_cleaned_stale_entries(
        &self,
        owner: &str,
        target: &Target,
        check: &Check,
        lookup: Option<&str>,
    ) -> Result<(), Failure> {
        target.validate()?;
        check.authorize_mode(target.mode)?;
        let infraternal_plugin_ssh::model::TargetAddress::Manual(address) = &target.address else {
            return Ok(());
        };
        let (mode, uid) = match target.mode {
            InstallMode::Rootless => ("rootless", check.uid),
            InstallMode::Root => ("rootful", 0),
        };
        let store = self.issuer.store();
        let rows: Vec<(Vec<u8>, bool)> = sqlx::query_as("SELECT h.id, EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0) FROM remote_hosts h JOIN remote_host_bootstrap b ON b.host_id=h.id WHERE h.owner_id=? AND h.revoked_at IS NULL AND h.mode=? AND h.execution_uid=? AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?)) AND (EXISTS(SELECT 1 FROM remote_bootstrap_retirement_intents i WHERE i.host_id=h.id) OR EXISTS(SELECT 1 FROM remote_login_cleanup q WHERE q.host_id=h.id AND q.confirmed=0)) ORDER BY h.id LIMIT 64")
            .bind(owner)
            .bind(mode)
            .bind(i64::from(uid))
            .bind(address)
            .bind(lookup)
            .bind(lookup)
            .fetch_all(&store.0)
            .await
            .map_err(|_| unavailable())?;
        let person = Uuid::parse_str(owner).ok();
        for (host, pending) in rows {
            let host = Uuid::from_slice(&host).map_err(|_| unavailable())?;
            let running = self
                .attempts
                .lock()
                .map_err(|_| unavailable())?
                .contains_key(&host);
            if running || self.hosts.actor(host).await.is_some() {
                continue;
            }
            let now = unix_now()?;
            let _fence = store.1.cut(host).map_err(|_| unavailable())?;
            if !pending {
                match store.deny_abandoned_bootstrap(owner, host, now).await {
                    Ok(()) | Err(crate::enrollment::EnrollmentError::Denied) => {}
                    Err(_) => return Err(unavailable()),
                }
            }
            match person {
                // The cleanup Start fresh proved stands in for the gone agent's receipt.
                Some(person) => store
                    .confirm_login_cleanup(host, person)
                    .await
                    .map_err(|_| unavailable())?,
                // Legacy ledger owners are revoked directly by the denial.
                None => store.1.tombstoned(host),
            }
            tracing::info!(
                host_id = %host,
                outcome = "dropped",
                "host provisioning dropped an earlier entry whose install Start fresh removed"
            );
        }
        Ok(())
    }
    fn completed_record(&self, authority: &Authority, host: Uuid) -> Result<(), Failure> {
        self.uid(authority, host)?;
        self.attempts
            .lock()
            .map_err(|_| unavailable())?
            .remove(&host);
        Ok(())
    }
    fn reserve_attempt(
        &self,
        authority: &Authority,
        host: Uuid,
        uid: u32,
        address: &str,
        lookup: Option<&str>,
    ) -> Result<(), Failure> {
        let mut attempts = self.attempts.lock().map_err(|_| unavailable())?;
        // Preflight can overlap while a key is prepared; reserve at publication
        // so only one concurrent attempt can issue for this destination.
        if attempts.values().any(|attempt| {
            attempt.owner == authority.owner
                && attempt
                    .destination
                    .as_ref()
                    .is_some_and(|(pending, trust)| {
                        pending == address
                            || lookup.is_some_and(|value| trust.as_deref() == Some(value))
                    })
        }) {
            return Err(being_added());
        }
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
                link_round_trip: Duration::ZERO,
                destination: Some((address.to_owned(), lookup.map(str::to_owned))),
                canary: None,
                retirement: None,
                replacement: false,
            },
        );
        Ok(())
    }
    /// Hand off exact cleanup ownership before the first durable write can run.
    /// Compatibility callers retain the older post-result ownership boundary.
    async fn issue_attempt<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        lookup: Option<String>,
        binding: &'a PreparedHostKey,
        register: Option<&'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send)>,
    ) -> Result<JoinMaterial, Failure> {
        let host = binding.host;
        let expected_key_digest = binding.digest;
        self.authorize(authority).await?;
        let address = match &target.address {
            infraternal_plugin_ssh::model::TargetAddress::Manual(address) => address.as_str(),
            infraternal_plugin_ssh::model::TargetAddress::Discovered(_) => {
                return Err(unavailable());
            }
        };
        if !self.issuer.ready() {
            return Err(Failure::authority_locked());
        }
        let (mode, uid) = match target.mode {
            InstallMode::Rootless => (Mode::Rootless, check.uid),
            InstallMode::Root => (Mode::Rootful, 0),
        };
        self.reserve_attempt(authority, host, uid, address, lookup.as_deref())?;
        let mut unpublished = Unpublished {
            backend: self,
            host,
            published: false,
        };
        // Preflight avoids staging for an existing host. Repeat the durable
        // check after reserving the destination so another server process
        // cannot add the same host between preflight and invitation issuance.
        if let Some(existing_host) = self
            .existing_host(&authority.owner, address, lookup.as_deref(), true)
            .await?
        {
            return Err(Self::already_added(existing_host));
        }
        if let Some(register) = register {
            register(host)?;
            // AttemptResources now owns cleanup even if SQLx commits without
            // delivering its acknowledgement. Do not discard that journal.
            unpublished.published = true;
        }
        let request = InvitationRequest {
            host_id: host,
            mode,
            execution_uid: uid,
            expected_key_digest: Some(expected_key_digest),
        };
        let invitation = if let Some(key_hash) = authority.api_key_hash() {
            self.issuer
                .issue_bootstrap_api_key(key_hash, request, address, lookup.as_deref())
                .await
        } else {
            self.issuer
                .issue_bootstrap(cookie(authority)?, request, address, lookup.as_deref())
                .await
        };
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
    }
}
impl Backend for RemoteBackend {
    fn observe_link(&self, authority: &Authority, host: Uuid, round_trip: Duration) {
        if let Ok(mut attempts) = self.attempts.lock()
            && let Some(attempt) = attempts.get_mut(&host)
            && attempt.owner == authority.owner
            && attempt.batch == authority.batch
        {
            attempt.link_round_trip = round_trip;
        }
    }
    fn setup_commit_timeout(&self, authority: &Authority, host: Uuid) -> Option<Duration> {
        self.attempts
            .lock()
            .ok()?
            .get(&host)
            .filter(|attempt| attempt.owner == authority.owner && attempt.batch == authority.batch)
            .map(|attempt| setup_commit_budget(attempt.link_round_trip))
    }
    fn session_notifications(&self, notify: tokio::sync::watch::Sender<u64>) {
        if let Ok(mut current) = self.sessions_changed.lock() {
            *current = Some(notify);
        }
    }
    fn setup_cancelled(&self, host: Uuid) -> Operation<'_, ()> {
        Box::pin(async move {
            self.hosts.cancelled(host).await;
            Ok(())
        })
    }
    fn reissue_invitation<'a>(
        &'a self,
        authority: &'a Authority,
        host: Uuid,
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move {
            self.authorize(authority).await?;
            let uid = self.uid(authority, host)?;
            let expected_key_digest = self
                .issuer
                .store()
                .host_key_digest(host)
                .await
                .map_err(|_| unavailable())?
                .ok_or_else(|| {
                    Failure::install("The host's SSH-proved key is unavailable; retry add-host.")
                })?;
            let request = InvitationRequest {
                host_id: host,
                mode: if uid == 0 {
                    Mode::Rootful
                } else {
                    Mode::Rootless
                },
                execution_uid: uid,
                expected_key_digest: Some(expected_key_digest),
            };
            let mut invitation = if let Some(key_hash) = authority.api_key_hash() {
                self.issuer.reissue_api_key(key_hash, request).await
            } else {
                self.issuer.reissue(cookie(authority)?, request).await
            }
            .map_err(|_| unavailable())?;
            let stdin = serde_json::to_vec(&invitation);
            invitation.token.zeroize();
            Ok(JoinMaterial {
                host,
                url: format!("{}/remote/join", self.issuer.origin()),
                stdin: Secret::new(stdin.map_err(|_| unavailable())?),
            })
        })
    }
    fn authority_cancelled<'a>(&'a self, authority: &'a Authority) -> Operation<'a, ()> {
        Box::pin(async move {
            let auth = self.base.auth.as_ref().ok_or_else(unavailable)?;
            let mut events = auth.revocation_events(&authority.owner);
            loop {
                self.authorize(authority).await?;
                events.changed().await.map_err(|_| unavailable())?;
            }
        })
    }
    fn stop(&self) -> Operation<'_, ()> {
        Box::pin(async move {
            self.hosts
                .stop_provisioning()
                .await
                .map_err(|_| unavailable())
        })
    }
    fn early_terminal(&self) -> bool {
        true
    }
    fn publish_terminal<'a>(
        &'a self,
        authority: &'a Authority,
        host: Uuid,
        session_id: Uuid,
        channel: infraternal_plugin_ssh::duplex::Duplex,
        session: std::sync::Arc<dyn infraternal_plugin_ssh::transport::SshSession>,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            self.authorize(authority).await?;
            let uid = self.uid(authority, host)?;
            let guard = crate::remote_guard::AuthorityGuard::provisioning(
                self.issuer.store().clone(),
                &authority.owner,
                host,
                uid,
            )
            .await
            .map_err(|_| unavailable())?;
            self.hosts
                .admit_observed(
                    guard,
                    crate::remote_link::RemoteLink::ssh(channel, session)
                        .await
                        .map_err(|_| unavailable())?,
                    None,
                )
                .await
                .map_err(|_| unavailable())?;
            // Insert only under the same live owner capability; browser attach
            // subsequently rechecks both this record and host ownership.
            self.publish_terminal_session(authority, host, session_id)
                .await?;
            if let Ok(current) = self.sessions_changed.lock()
                && let Some(current) = &*current
            {
                current.send_modify(|version| *version = version.wrapping_add(1));
            }
            self.authorize(authority).await
        })
    }
    fn install_base_proven_empty<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        lookup: Option<String>,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            self.authorize(authority).await?;
            self.drop_cleaned_stale_entries(&authority.owner, target, check, lookup.as_deref())
                .await
        })
    }
    fn leftover_connected<'a>(
        &'a self,
        authority: &'a Authority,
        host: Uuid,
    ) -> Operation<'a, bool> {
        Box::pin(async move {
            self.authorize(authority).await?;
            Ok(self.hosts.actor(host).await.is_some())
        })
    }
    /// D359: the old install's id is no working host of this server, for any
    /// person: unknown here, removed, or revoked. A host this server still
    /// serves is never taken over from under it, even by root SSH.
    fn takeover_allowed<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, bool> {
        Box::pin(async move {
            self.authorize(authority).await?;
            let working: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_hosts h WHERE h.id=? AND h.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id))")
                .bind(host.as_bytes().as_slice())
                .fetch_one(&self.issuer.store().0)
                .await
                .map_err(|_| unavailable())?;
            Ok(!working)
        })
    }
    fn owns_failed_setup<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        host: Uuid,
        lookup: Option<String>,
    ) -> Operation<'a, bool> {
        Box::pin(async move {
            self.authorize(authority).await?;
            self.owns_failed_setup_record(&authority.owner, target, check, host, lookup.as_deref())
                .await
        })
    }

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
    fn enrollment_origin(&self) -> Option<String> {
        Some(self.issuer.origin().to_owned())
    }
    fn preflight_existing_host<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        lookup: Option<String>,
    ) -> Operation<'a, ()> {
        Box::pin(async move {
            self.ensure_not_already_added(authority, target, lookup.as_deref(), true)
                .await
        })
    }
    fn invitation<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
    ) -> Operation<'a, JoinMaterial> {
        self.invitation_with_trust(authority, target, check, None)
    }
    fn invitation_with_trust<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        lookup: Option<String>,
    ) -> Operation<'a, JoinMaterial> {
        let _ = (authority, target, check, lookup);
        Box::pin(async {
            Err(Failure::install(
                "Prepare the infraternal agent's key over SSH before issuing its invitation.",
            ))
        })
    }
    fn invitation_registered<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        lookup: Option<String>,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        let _ = (authority, target, check, lookup, register);
        Box::pin(async {
            Err(Failure::install(
                "Prepare the infraternal agent's key over SSH before issuing its invitation.",
            ))
        })
    }
    fn invitation_registered_with_key<'a>(
        &'a self,
        authority: &'a Authority,
        target: &'a Target,
        check: &'a Check,
        lookup: Option<String>,
        binding: PreparedHostKey,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        Box::pin(async move {
            self.issue_attempt(authority, target, check, lookup, &binding, Some(register))
                .await
        })
    }
    /// Reenroll removed identities as new hosts instead of reviving their interrupted install.
    fn check_stuck_install<'a>(
        &'a self,
        authority: &'a Authority,
        request: StuckInstallCheck<'a>,
    ) -> Operation<'a, StuckInstall> {
        Box::pin(async move {
            self.authorize(authority).await?;
            let infraternal_plugin_ssh::model::TargetAddress::Manual(address) =
                &request.target.address
            else {
                return Err(unavailable());
            };
            let lookup = request.lookup.as_deref();
            // (owner, revoked, matches this destination) for the journal's host id.
            let row: Option<(String, bool, bool)> = sqlx::query_as("SELECT h.owner_id, h.revoked_at IS NOT NULL, EXISTS(SELECT 1 FROM remote_host_bootstrap b WHERE b.host_id=h.id AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?))) FROM remote_hosts h WHERE h.id=? AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id)")
                .bind(address)
                .bind(lookup)
                .bind(lookup)
                .bind(request.host.as_bytes().as_slice())
                .fetch_optional(&self.issuer.store().0)
                .await
                .map_err(|_| unavailable())?;
            let Some((owner, revoked, matches)) = row else {
                // This identity is unknown here or belongs to a removed installation.
                // The machine may join as a new host after confirmation (D335),
                // but only if this server will accept it right now.
                // Before any confirmation: report only, retire nothing (J247 P3).
                self.ensure_not_already_added(authority, request.target, lookup, false)
                    .await?;
                return Ok(StuckInstall::Reenroll);
            };
            let stored = self
                .issuer
                .store()
                .host_key_digest(request.host)
                .await
                .map_err(|_| unavailable())?;
            decide_stuck_install(&StuckFacts {
                ours: owner == authority.owner && !revoked && matches,
                stored,
                reported: request.enrolled.map(|enrolled| enrolled.digest),
                // Connected means its agent is online now (Console's own signal).
                // `installed` only says the host was admitted, and stays true
                // after its agent stops; a dead install would then be "finished"
                // and left stopped (#305).
                connected: self.hosts.online(request.host).await,
                ca_ready: self.issuer.ready(),
            })
        })
    }
    /// Reissue only an active installation whose recorded identity still owns this destination.
    fn reissue_stuck_install<'a>(
        &'a self,
        authority: &'a Authority,
        request: StuckInstallRequest<'a>,
        register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
    ) -> Operation<'a, JoinMaterial> {
        let StuckInstallRequest {
            target,
            check,
            host,
            lookup,
            binding,
        } = request;
        Box::pin(async move {
            self.authorize(authority).await?;
            if binding.host != host {
                return Err(Failure::unsupported(
                    "The interrupted install belongs to another enrolled host.",
                ));
            }
            let address = match &target.address {
                infraternal_plugin_ssh::model::TargetAddress::Manual(address) => address.as_str(),
                infraternal_plugin_ssh::model::TargetAddress::Discovered(_) => {
                    return Err(unavailable());
                }
            };
            let lookup = lookup.as_deref();
            let registered: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM remote_host_bootstrap b JOIN remote_hosts h ON h.id=b.host_id WHERE h.id=? AND h.owner_id=? AND h.revoked_at IS NULL AND NOT EXISTS(SELECT 1 FROM remote_host_removals r WHERE r.host_id=h.id) AND (b.address=? OR (? IS NOT NULL AND b.trust_lookup=?)))")
                .bind(host.as_bytes().as_slice())
                .bind(&authority.owner)
                .bind(address)
                .bind(lookup)
                .bind(lookup)
                .fetch_one(&self.issuer.store().0)
                .await
                .map_err(|_| unavailable())?;
            if !registered {
                return Err(Failure::unsupported(
                    "The interrupted install no longer matches this enrolled host.",
                ));
            }
            let stored_digest = self
                .issuer
                .store()
                .host_key_digest(host)
                .await
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if stored_digest != binding.digest {
                return Err(Failure::install(
                    "The interrupted install's host identity does not match its enrolled key.",
                ));
            }
            if !self.issuer.ready() {
                return Err(Failure::authority_locked());
            }
            let uid = match target.mode {
                InstallMode::Rootless => check.uid,
                InstallMode::Root => 0,
            };
            self.reserve_attempt(authority, host, uid, address, lookup)?;
            if let Some(attempt) = self
                .attempts
                .lock()
                .map_err(|_| unavailable())?
                .get_mut(&host)
            {
                attempt.replacement = true;
            }
            let mut unpublished = Unpublished {
                backend: self,
                host,
                published: false,
            };
            register(host)?;
            // The existing host remains enrolled if the replacement attempt fails.
            unpublished.published = true;
            let join = self.reissue_invitation(authority, host).await?;
            if join.host != host {
                return Err(unavailable());
            }
            Ok(join)
        })
    }
    fn connected_facts<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            let actor = self.actor(authority, host).await?;
            let response = tokio::time::timeout(
                CONNECTED_FACTS_TIMEOUT,
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
            let actor = self
                .actor(authority, host)
                .await
                .map_err(|error| error.at(InstallStep::Readiness))?;
            let writers = canary_writers(&self.issuer.store().0).await?;
            canary_registered(&actor, writers, |session| {
                self.uid(authority, host)?;
                let mut attempts = self.attempts.lock().map_err(|_| unavailable())?;
                let attempt = attempts.get_mut(&host).ok_or_else(unavailable)?;
                attempt.canary = Some((actor.clone(), session, writers));
                Ok(())
            })
            .await?;
            // The primary exit proves retirement; cancellation after this point
            // must not try another writer against the already retired session.
            self.attempts
                .lock()
                .map_err(|_| unavailable())?
                .get_mut(&host)
                .ok_or_else(unavailable)?
                .canary = None;
            self.authorize(authority)
                .await
                .map_err(|error| error.at(InstallStep::Readiness))
        })
    }
    fn record_start_fresh(
        &self,
        target: &Target,
        host: Uuid,
        transaction: Uuid,
        outcome: &'static str,
    ) {
        self.base
            .record_start_fresh(target, host, transaction, outcome);
    }
    fn record_failure(
        &self,
        target: &Target,
        host: Option<Uuid>,
        phase: infraternal_plugin_ssh::model::Step,
        failure: &Failure,
    ) {
        self.base.record_failure(target, host, phase, failure);
    }
    fn cleanup_sessions<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            // Exact batch ownership remains valid after logout, solely for cleanup.
            self.uid(authority, host)?;
            let canary = self
                .attempts
                .lock()
                .map_err(|_| unavailable())?
                .get(&host)
                .and_then(|attempt| attempt.canary.clone());
            if let Some((actor, session, writers)) = canary {
                finish_canary(&actor, session, writers[1]).await?;
            }
            Ok(())
        })
    }
    fn retire_failed(&self, authority: &Authority, host: Uuid) -> Result<(), Failure> {
        self.uid(authority, host)?;
        let mut attempts = self.attempts.lock().map_err(|_| unavailable())?;
        let attempt = attempts.get_mut(&host).ok_or_else(unavailable)?;
        if attempt.retirement.is_none() {
            let store = self.issuer.store().clone();
            let owner = authority.owner.clone();
            let now = unix_now()?;
            // Fence synchronously: no SQLite or SSH await may preserve access
            // after cancellation. The durable intent covers process restart.
            let fence = store.1.cut(host).map_err(|_| unavailable())?;
            attempt.retirement = Some(tokio::spawn(async move {
                let _fence = fence;
                store
                    .retire_bootstrap(&owner, host, now)
                    .await
                    .map_err(|_| unavailable())
            }));
        }
        Ok(())
    }
    fn failed<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            // Compatibility wrappers may not forward the synchronous hook.
            self.retire_failed(authority, host)?;
            let retirement = self
                .attempts
                .lock()
                .map_err(|_| unavailable())?
                .get_mut(&host)
                .and_then(|attempt| attempt.retirement.take())
                .ok_or_else(unavailable)?;
            self.completed_record(authority, host)?;
            // Dropping this acknowledgement detaches, never aborts, the exact
            // writer. It keeps its queue position after the five-second caller
            // deadline; tombstone and intent consumption still commit together.
            retirement.await.map_err(|_| unavailable())?
        })
    }
    fn completed<'a>(&'a self, authority: &'a Authority, host: Uuid) -> Operation<'a, ()> {
        Box::pin(async move {
            // Only a confirmed new enrollment restores login access. Reconnect
            // and terminal opens never clear a persisted revocation marker.
            let actor = self.actor(authority, host).await?;
            if let Ok(person) = Uuid::parse_str(&authority.owner) {
                self.authorize(authority).await?;
                restore_login_access(&actor, person).await?;
                let account = if authority.api_key_hash().is_some() {
                    crate::preferred_accounts::resolve_for_key(
                        &self.issuer.store().0,
                        &authority.owner,
                        host,
                    )
                    .await
                    .map_err(|_| unavailable())?
                } else {
                    crate::preferred_accounts::resolve(
                        &self.issuer.store().0,
                        &authority.owner,
                        &crate::auth::hash(cookie(authority)?),
                        Some(host),
                    )
                    .await
                    .map_err(|_| unavailable())?
                };
                let grant = crate::login_access::grant(
                    &self.issuer.store().0,
                    &authority.owner,
                    Some(host),
                )
                .await
                .map_err(|_| unavailable())?;
                confirm_preferred_login(&actor, person, account, grant).await?;
                self.authorize(authority).await?;
            }
            self.finish_completion(&authority.owner, authority.batch, host)
                .await
        })
    }
}
/// Ledger admission alone does not identify the actor's currently greeted route.
async fn wait_installed_actor(
    hosts: &RemoteHosts,
    host: Uuid,
    budget: Duration,
) -> Result<EmbeddedAgent, Failure> {
    // Subscribe before inspecting the registry: admission between inspection
    // and suspension must remain visible, including the first host insertion.
    let mut admitted = hosts.5.subscribe();
    let actor = tokio::time::timeout(budget, async {
        loop {
            if hosts.installed(host).await
                && let Some(actor) = hosts.actor(host).await
            {
                break Ok::<_, Failure>(actor);
            }
            admitted.changed().await.map_err(|_| unavailable())?;
        }
    })
    .await
    .map_err(|_| route_unavailable())??;
    // An admitted replacement can still be queued behind the old SSH route.
    // Grant this concrete startup transition its own allowance, once only;
    // unrelated inventory events cannot extend a stalled host's deadline.
    tokio::time::timeout(budget, async {
        let mut changed = actor.changes();
        loop {
            if actor.installed_route().await.map_err(|_| unavailable())? {
                return Ok(actor);
            }
            tokio::select! {
                result = changed.changed() => result.map_err(|_| unavailable())?,
                result = admitted.changed() => result.map_err(|_| unavailable())?,
            }
        }
    })
    .await
    .map_err(|_| route_unavailable())?
}
/// What the server knows about a stuck upgrade's host id that it has a record for.
struct StuckFacts {
    /// Same owner, not revoked, and this destination.
    ours: bool,
    stored: Option<[u8; 32]>,
    reported: Option<[u8; 32]>,
    /// Connected now through the installed infraternal agent's authenticated link.
    connected: bool,
    ca_ready: bool,
}

/// Replace only what this server can re-enroll with the same key; finish an
/// upgrade whose host is already connected (#305 P1-1, P2-2).
fn decide_stuck_install(facts: &StuckFacts) -> Result<StuckInstall, Failure> {
    if !facts.ours {
        return Err(Failure::unsupported(
            "The interrupted install no longer matches this enrolled host.",
        ));
    }
    if facts.stored.is_none() || facts.stored != facts.reported {
        return Err(Failure::install(
            "The interrupted install's host identity does not match its enrolled key.",
        ));
    }
    if facts.connected {
        return Ok(StuckInstall::Finish);
    }
    if !facts.ca_ready {
        return Err(Failure::authority_locked());
    }
    Ok(StuckInstall::Replace)
}

/// Another attempt in this server is installing the same host now. Deliberately
/// carries no host id: its infraternal agent has not finished setup, so there is no
/// terminal to offer yet (#305, J241).
fn being_added() -> Failure {
    Failure::install("This host is already being added. Wait for its setup steps to finish.")
}

fn route_unavailable() -> Failure {
    Failure::install("The infraternal agent did not connect. Check the host's service and network.")
}

async fn confirm_preferred_login(
    actor: &EmbeddedAgent,
    person: Uuid,
    account: String,
    grant: crate::embedded::LoginGrant,
) -> Result<(), Failure> {
    // The PTY probe alone bypasses preferred account/PAM admission. Reuse the
    // exact preparation path used before real terminal opens, after restoration.
    tokio::time::timeout(Duration::from_secs(10), actor.prepare_login(person, Some(account), grant))
        .await.map_err(|_| unavailable())?.map_err(|_| Failure::install(
            "The host connected, but its preferred account login could not open. Check the host login path and try again."))
}

async fn restore_login_access(actor: &EmbeddedAgent, person: Uuid) -> Result<(), Failure> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Restored {
        restored: bool,
    }
    let unavailable = || {
        Failure::install(
            "The host's login access could not be restored. Check its service and add the host again.",
        )
    };
    let input =
        serde_json::to_vec(&serde_json::json!({"person": person})).map_err(|_| unavailable())?;
    let reply = tokio::time::timeout(
        Duration::from_secs(10),
        actor.call("terminal.login.restore".into(), input),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?;
    if reply.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
        || !serde_json::from_slice::<Restored>(&reply).is_ok_and(|reply| reply.restored)
    {
        return Err(unavailable());
    }
    Ok(())
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
/// Reserve private writers from the same SQLite allocator as durable browsers.
/// No private session is published. The write transaction prevents a browser
/// allocation from interleaving, and exhaustion preserves the ordinary cap.
async fn canary_writers(pool: &sqlx::SqlitePool) -> Result<[u32; 2], Failure> {
    let mut tx = pool.begin().await.map_err(|_| unavailable())?;
    sqlx::query("INSERT INTO sqlite_sequence(name,seq) SELECT 'terminal_writers',0 WHERE NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='terminal_writers')")
        .execute(&mut *tx).await.map_err(|_| unavailable())?;
    let end: Option<i64> = sqlx::query_scalar("UPDATE sqlite_sequence SET seq=seq+2 WHERE name='terminal_writers' AND seq<=2147483645 RETURNING seq")
        .fetch_optional(&mut *tx).await.map_err(|_| unavailable())?;
    let end = u32::try_from(end.ok_or_else(unavailable)?).map_err(|_| unavailable())?;
    tx.commit().await.map_err(|_| unavailable())?;
    Ok([(end - 1) * 2, end * 2])
}

#[cfg(test)]
async fn canary(actor: &EmbeddedAgent) -> Result<(), Failure> {
    canary_registered(actor, [2, 4], |_| Ok(())).await
}

/// Opt-in test evidence owns only fixed stage names and bounded public clocks.
/// Disabled diagnostics allocate no trace, sample no clocks and write no file.
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
struct CanaryStages {
    start: std::time::Instant,
    events: Mutex<Vec<serde_json::Value>>,
}
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
static CANARY_STAGES: Mutex<Option<std::sync::Arc<CanaryStages>>> = Mutex::new(None);
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
impl CanaryStages {
    fn record(&self, stage: &'static str) {
        let mut events = self.events.lock().unwrap();
        if events.len() < 32 {
            events.push(serde_json::json!({"stage":stage,
                "elapsed_us":self.start.elapsed().as_micros(),
                "wall_us":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros()}));
        }
    }
}
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
fn canary_stages(begin: bool) -> Option<std::sync::Arc<CanaryStages>> {
    if std::env::var("ACCEPTANCE_DIAGNOSTICS").ok().as_deref() != Some("canary-return") {
        return None;
    }
    let mut owner = CANARY_STAGES.lock().unwrap();
    if begin {
        let stages = std::sync::Arc::new(CanaryStages {
            start: std::time::Instant::now(),
            events: Mutex::new(Vec::new()),
        });
        stages.record("canary_registered_start");
        *owner = Some(stages);
    }
    owner.clone()
}
/// An early return records its exact failed wait boundary without changing the
/// production `await/map_err` chain. Success suppresses the failure-on-drop stamp.
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
struct CanaryWait {
    stages: std::sync::Arc<CanaryStages>,
    failure: Option<&'static str>,
}
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
impl CanaryWait {
    fn start(
        stages: &std::sync::Arc<CanaryStages>,
        start: &'static str,
        failure: &'static str,
    ) -> Self {
        stages.record(start);
        Self {
            stages: stages.clone(),
            failure: Some(failure),
        }
    }
    fn finish(mut self, success: &'static str) {
        self.stages.record(success);
        self.failure = None;
    }
}
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
impl Drop for CanaryWait {
    fn drop(&mut self) {
        if let Some(failure) = self.failure {
            self.stages.record(failure);
        }
    }
}
/// Keep frame classification and observation flags outside the production
/// canary flow. Helpers retain no payload and exist only in the opt-in fixture.
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
struct CanaryOutputStages {
    stages: Option<std::sync::Arc<CanaryStages>>,
    first_data: bool,
    marker_recorded: bool,
}
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
impl CanaryOutputStages {
    fn new() -> Self {
        Self {
            stages: canary_stages(false),
            first_data: false,
            marker_recorded: false,
        }
    }
    fn wait(&self, start: &'static str, error: &'static str) -> Option<CanaryWait> {
        self.stages
            .as_ref()
            .map(|stages| CanaryWait::start(stages, start, error))
    }
    fn finish(wait: Option<CanaryWait>, stage: &'static str) {
        if let Some(wait) = wait {
            wait.finish(stage);
        }
    }
    fn send_start(&self, frame: &infraternal_protocol::Frame<'_>) -> Option<CanaryWait> {
        let input = matches!(frame, infraternal_protocol::Frame::Input { .. });
        self.wait(
            if input {
                "send_input_start"
            } else {
                "send_credit_start"
            },
            if input {
                "send_input_return_error"
            } else {
                "send_credit_return_error"
            },
        )
    }
    fn send_complete(wait: Option<CanaryWait>, frame: &infraternal_protocol::Frame<'_>) {
        Self::finish(
            wait,
            if matches!(frame, infraternal_protocol::Frame::Input { .. }) {
                "send_input_complete"
            } else {
                "send_credit_complete"
            },
        );
    }
    fn data_seen(&mut self, nonempty: bool) {
        if !self.first_data
            && nonempty
            && let Some(stages) = &self.stages
        {
            stages.record("first_nonempty_data");
            self.first_data = true;
        }
    }
    fn marker_confirmed(&mut self, confirmed: bool) {
        if confirmed
            && !self.marker_recorded
            && let Some(stages) = &self.stages
        {
            stages.record("marker_confirmed");
            self.marker_recorded = true;
        }
    }
    fn observe_closed(&self, event: &TerminalOutput) {
        if matches!(event, TerminalOutput::Closed { .. })
            && let Some(stages) = &self.stages
        {
            stages.record("terminal_closed");
        }
    }
    fn exit_return(&self, success: bool) {
        if let Some(stages) = &self.stages {
            stages.record(if success {
                "exit_return_ok"
            } else {
                "exit_return_error"
            });
        }
    }
}

/// Called by the owned test adapter only after the production canary returns.
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
fn canary_stage_receipt() -> serde_json::Value {
    let stages = CANARY_STAGES.lock().unwrap().clone();
    serde_json::json!({"kind":"production_canary_stage_diagnostic","diagnostic_profile":"canary-return",
        "stage_limit":32,"contains_terminal_contents":false,"ordinary_latency_acceptance":false,
        "first_data_boundary":"actor-delivered Output or Snapshot",
        "send_completion_boundary":"attachment handle accepted leg-A frame; not network acknowledgement",
        "stages":stages.map(|stages|stages.events.lock().unwrap().clone()).unwrap_or_default()})
}

/// Early-return guards distinguish a failed wait from its successful completion.
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
#[test]
fn canary_stage_wait_retains_error_success_and_bound() {
    let stages = std::sync::Arc::new(CanaryStages {
        start: std::time::Instant::now(),
        events: Mutex::new(Vec::new()),
    });
    drop(CanaryWait::start(
        &stages,
        "failed_wait_start",
        "failed_wait_return",
    ));
    CanaryWait::start(&stages, "successful_wait_start", "unexpected_error")
        .finish("successful_wait_return");
    let names: Vec<_> = stages
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event["stage"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        names,
        [
            "failed_wait_start",
            "failed_wait_return",
            "successful_wait_start",
            "successful_wait_return"
        ]
    );
    for _ in 0..64 {
        stages.record("bounded_event");
    }
    let events = stages.events.lock().unwrap();
    assert_eq!(events.len(), 32);
    for event in events.iter() {
        assert_eq!(event.as_object().unwrap().len(), 3);
        assert!(event["elapsed_us"].is_number());
        assert!(event["wall_us"].is_number());
    }
}

/// Frame names and first-data flags must stay identical after hook extraction.
#[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
#[test]
fn canary_output_stages_classify_frames_and_record_flags_once() {
    let stages = std::sync::Arc::new(CanaryStages {
        start: std::time::Instant::now(),
        events: Mutex::new(Vec::new()),
    });
    let mut diagnostic = CanaryOutputStages {
        stages: Some(stages.clone()),
        first_data: false,
        marker_recorded: false,
    };
    for frame in [
        infraternal_protocol::Frame::Credit { bytes: 64 },
        infraternal_protocol::Frame::Input {
            in_seq: 0,
            bytes: b"x",
        },
    ] {
        CanaryOutputStages::send_complete(diagnostic.send_start(&frame), &frame);
    }
    diagnostic.data_seen(false);
    diagnostic.data_seen(true);
    diagnostic.data_seen(true);
    diagnostic.marker_confirmed(false);
    diagnostic.marker_confirmed(true);
    diagnostic.marker_confirmed(true);
    let names: Vec<_> = stages
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event["stage"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        names,
        [
            "send_credit_start",
            "send_credit_complete",
            "send_input_start",
            "send_input_complete",
            "first_nonempty_data",
            "marker_confirmed"
        ]
    );
}

async fn canary_registered(
    actor: &EmbeddedAgent,
    writers: [u32; 2],
    opened: impl FnOnce([u8; 16]) -> Result<(), Failure>,
) -> Result<(), Failure> {
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    let stages = canary_stages(true);
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    let canary_wait = stages.as_ref().map(|stages| {
        CanaryWait::start(
            stages,
            "canary_registered_enter",
            "canary_registered_return_error",
        )
    });
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    let open_wait = stages.as_ref().map(|stages| {
        CanaryWait::start(
            stages,
            "open_readiness_start",
            "open_readiness_return_error",
        )
    });
    let session = actor
        .open_readiness(TerminalSize {
            cols: 80,
            rows: 24,
            px_w: 0,
            px_h: 0,
        })
        .await
        .map_err(|_| unavailable().at(InstallStep::Readiness))?;
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    if let Some(wait) = open_wait {
        wait.finish("open_readiness_return_ok");
    }
    // Publish ownership before the next await: cancellation cannot lose this id.
    if let Err(error) = opened(session) {
        let _ = finish_canary(actor, session, writers[1]).await;
        return Err(error.at(InstallStep::Readiness));
    }
    let result = tokio::time::timeout(
        TERMINAL_CANARY_TIMEOUT,
        canary_output(actor, session, writers[0]),
    )
    .await
    .unwrap_or_else(|_| {
        Err(Failure::install(
            "The host connected, but its terminal did not answer. Check its service and try again.",
        ))
    });
    // Success includes the primary stream's exit proof. Reattaching then races
    // private-session retirement and can turn that proof into a handshake error.
    if result.is_err() {
        let _ = finish_canary(actor, session, writers[1]).await;
    }
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    if let Some(wait) = canary_wait {
        wait.finish(if result.is_ok() {
            "canary_registered_return_ok"
        } else {
            "canary_registered_return_error"
        });
    }
    result.map_err(|error| error.at(InstallStep::Readiness))
}

async fn canary_output(
    actor: &EmbeddedAgent,
    session: [u8; 16],
    writer: u32,
) -> Result<(), Failure> {
    use infraternal_protocol::{Frame, encode_muxed_frame_into};
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    let mut diagnostic = CanaryOutputStages::new();
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    let attach_wait = diagnostic.wait("attach_start", "attach_return_error");
    let (handle, mut output) = actor
        .attach(session, 0, 0, writer)
        .await
        .map_err(|_| unavailable())?
        .split();
    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
    CanaryOutputStages::finish(attach_wait, "attach_return_ok");
    let marker = "infraternal-ready";
    // The fixed non-login command waits for input so its output cannot precede
    // attachment. No user shell startup or echoed marker supplies readiness.
    let command = "\n";
    let mut wire = Vec::new();
    for frame in [
        Frame::Credit { bytes: 65536 },
        Frame::Input {
            in_seq: 0,
            bytes: command.as_bytes(),
        },
    ] {
        #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
        let send_wait = diagnostic.send_start(&frame);
        // Input is leg A (odd); the attachment maps it onto its even leg-B stream.
        encode_muxed_frame_into(1, &frame, &mut wire).map_err(|_| unavailable())?;
        handle
            .send_frame(bytes::Bytes::copy_from_slice(&wire))
            .await
            .map_err(|_| unavailable())?;
        #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
        CanaryOutputStages::send_complete(send_wait, &frame);
    }
    let mut received = Vec::new();
    let mut confirmed = false;
    while let Some(event) = output.recv().await {
        #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
        diagnostic.observe_closed(&event);
        match event {
            // A fast first command may be included in the initial faithful
            // repaint; snapshots carry confirmed PTY output just as deltas do.
            TerminalOutput::Output { bytes, .. } | TerminalOutput::Snapshot { bytes, .. } => {
                if received.len() + bytes.len() > 65536 {
                    return Err(unavailable());
                }
                #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
                diagnostic.data_seen(!bytes.is_empty());
                received.extend_from_slice(&bytes);
                confirmed = received
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes());
                #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
                diagnostic.marker_confirmed(confirmed);
            }
            TerminalOutput::Event { event_json } => {
                let notice: serde_json::Value =
                    serde_json::from_slice(&event_json).map_err(|_| unavailable())?;
                if notice["type"] == "terminal.exited" {
                    // The routed, authenticated exit must name this private session.
                    let exited = notice["session_id"]
                        .as_str()
                        .and_then(|id| Uuid::parse_str(id).ok())
                        .is_some_and(|id| id.as_bytes() == &session);
                    #[cfg(all(test, feature = "mesh-transport-proof", target_os = "linux"))]
                    diagnostic.exit_return(confirmed && exited && notice["status"] == 0);
                    return if confirmed && exited && notice["status"] == 0 {
                        Ok(())
                    } else {
                        Err(unavailable())
                    };
                }
            }
            TerminalOutput::Closed { .. } => break,
            TerminalOutput::Ack { .. }
            | TerminalOutput::Reconnecting
            | TerminalOutput::LinkDoubt
            | TerminalOutput::Recovered
            | TerminalOutput::RouteExpired => {}
        }
    }
    Err(unavailable())
}

/// A second writer can finish the fixed read even if the first attachment failed.
/// No shell command, signal or arbitrary user session is selected by this path.
async fn finish_canary(
    actor: &EmbeddedAgent,
    session: [u8; 16],
    writer: u32,
) -> Result<(), Failure> {
    use infraternal_protocol::{CLOSE_SESSION_GONE, Frame, encode_muxed_frame_into};
    tokio::time::timeout(Duration::from_secs(5), async {
        let (handle, mut output) = actor
            .attach(session, 0, 0, writer)
            .await
            .map_err(|_| unavailable())?
            .split();
        let mut wire = Vec::new();
        for frame in [
            Frame::Credit { bytes: 65536 },
            Frame::Input {
                in_seq: 0,
                bytes: b"\n",
            },
        ] {
            encode_muxed_frame_into(1, &frame, &mut wire).map_err(|_| unavailable())?;
            // A retired session can close input before its queued session-gone
            // notice is read. That notice, rather than a send race, proves cleanup.
            if handle
                .send_frame(bytes::Bytes::copy_from_slice(&wire))
                .await
                .is_err()
            {
                break;
            }
        }
        while let Some(event) = output.recv().await {
            match event {
                TerminalOutput::Event { event_json } => {
                    let notice: serde_json::Value =
                        serde_json::from_slice(&event_json).map_err(|_| unavailable())?;
                    if notice["type"] == "terminal.exited" {
                        return Ok(());
                    }
                }
                TerminalOutput::Closed {
                    code: CLOSE_SESSION_GONE,
                    ..
                } => return Ok(()),
                TerminalOutput::Closed { .. } => return Err(unavailable()),
                _ => {}
            }
        }
        Err(unavailable())
    })
    .await
    .map_err(|_| unavailable())?
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

    /// Exercises real SSH setup against an explicitly selected disposable host.
    #[path = "../bootstrap_breakit2_tests.rs"]
    mod breakit2_live;

    #[cfg(all(feature = "mesh-transport-proof", target_os = "linux"))]
    mod mesh_acceptance {
        //! Exercises real add-host mesh lifecycles in owned disposable containers [263], #201.
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap_mesh_acceptance_tests.rs"
        ));
    }

    mod review_cleanup {
        //! Checks cancellation cleanup against unavailable real SQLite storage.
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap_review_cleanup_tests.rs"
        ));
    }

    /// Pending removals release setup coordinates without reviving their identity.
    mod pending_removal_tests;

    /// D355: Start fresh's proven cleanup drops the person's stale entries.
    mod drop_cleaned_stale_tests;

    mod already_added_breakit {
        //! Break-it review of the already-added host id (#189).
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap_already_added_breakit_tests.rs"
        ));
    }

    /// A failed Replace or Re-enroll restores the stuck installation.
    #[path = "../bootstrap_stuck_restore_tests.rs"]
    mod stuck_restore;

    /// Take over of another server's finished install, and its put-back (D359).
    #[path = "../bootstrap_takeover_tests.rs"]
    mod takeover;

    mod retirement_contention {
        //! A separate SQLite writer can outlive the connection's busy timeout.
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/bootstrap_retirement_contention_tests.rs"
        ));
    }

    struct Signer(Option<CaMaterial>);
    impl CaKeySource for Signer {
        fn load(&self) -> Result<CaMaterial, CaError> {
            self.0.clone().ok_or(CaError)
        }
    }
    struct Sniff {
        opens: Arc<AtomicUsize>,
        refuse_key_payload_upload: bool,
    }
    /// Holds invitation delivery after publication so concurrent admission stays overlapped.
    struct InvitationGate {
        /// Reports at most one arrival per test batch through a bounded channel.
        arrivals: tokio::sync::mpsc::Sender<usize>,
        /// Keeps the invitation setup step pending until the test releases all batches.
        release: tokio::sync::watch::Receiver<bool>,
    }
    impl InvitationGate {
        /// Reports this batch's invitation, then waits for the test to release setup.
        async fn hold(&self, batch: usize) {
            self.arrivals
                .send(batch)
                .await
                .expect("invitation test stopped observing arrivals");
            let mut release = self.release.clone();
            tokio::time::timeout(TEST_HANG_BOUND, async {
                while !*release.borrow_and_update() {
                    release
                        .changed()
                        .await
                        .expect("invitation test dropped its release signal");
                }
            })
            .await
            .expect("invitation test did not release setup within its hang bound");
        }
    }
    /// Wraps the ordinary fixture transport to hold invitation setup for one batch.
    struct GatedSniff {
        sniff: Sniff,
        gate: Arc<InvitationGate>,
        batch: usize,
    }
    impl SshTransport for GatedSniff {
        fn open(
            &self,
            destination: Destination,
            credentials: Credentials,
            evidence: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async move {
                let session = self.sniff.open(destination, credentials, evidence).await?;
                Ok(Arc::new(GatedSession {
                    session,
                    gate: self.gate.clone(),
                    batch: self.batch,
                }) as Arc<dyn SshSession>)
            })
        }
    }
    /// Holds invitation stdin until the concurrency test releases its batch.
    struct GatedSession {
        session: Arc<dyn SshSession>,
        gate: Arc<InvitationGate>,
        batch: usize,
    }
    impl SshSession for GatedSession {
        fn trust_lookup(&self) -> Option<String> {
            self.session.trust_lookup()
        }

        fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
            let session = self.session.clone();
            let gate = self.gate.clone();
            let batch = self.batch;
            Box::pin(async move {
                if matches!(input, Input::Bytes(_)) {
                    gate.hold(batch).await;
                }
                session.run(script, input).await
            })
        }
    }
    impl SshTransport for Sniff {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async move {
                self.opens.fetch_add(1, Ordering::Relaxed);
                Ok(Arc::new(Sniff {
                    opens: self.opens.clone(),
                    refuse_key_payload_upload: self.refuse_key_payload_upload,
                }) as Arc<dyn SshSession>)
            })
        }
    }
    impl SshSession for Sniff {
        fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
            Box::pin(async move {
                if !script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) {
                    // #291 prepares the agent key before publishing its bound
                    // invitation. Reuse the cached payload and return a canonical
                    // digest in that preflight. The failure variant reports a
                    // usable codec so the real staged upload reaches its refusal.
                    if script.contains("printf 'reuse") {
                        assert!(matches!(input, Input::Empty));
                        return Ok(CommandOutput {
                            stdout: if self.refuse_key_payload_upload {
                                b"zstd\n".to_vec()
                            } else {
                                b"reuse\n".to_vec()
                            },
                        });
                    }
                    if self.refuse_key_payload_upload
                        && (script.contains("zstd -dc > \"$stage/payload\"")
                            || script.contains("gzip -dc > \"$stage/payload\"")
                            || script.contains("read_payload "))
                    {
                        assert!(matches!(
                            input,
                            Input::Bytes(_) | Input::File(_) | Input::Transfer(_)
                        ));
                        return Err(Failure::install(
                            "The fixture refused the key-preparation payload upload.",
                        )
                        .at(InstallStep::Upload));
                    }
                    if script.contains("ln \"$cache/payload\" \"$stage/payload\"") {
                        assert!(matches!(input, Input::Empty));
                        return Ok(CommandOutput { stdout: Vec::new() });
                    }
                    if script.contains("prepare-join-key") {
                        assert!(matches!(input, Input::Empty));
                        return Ok(CommandOutput {
                            stdout: b"KEY-DIGEST 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n".to_vec(),
                        });
                    }
                    if matches!(input, Input::Bytes(_)) {
                        // Invitations stay in stdin. Refusing setup exercises the
                        // post-publication cleanup path without reading or logging it.
                        return Err(Failure::install(
                            "The fixture refused the post-invitation setup.",
                        ));
                    }
                    // Staging failure still requests rollback. Refuse cleanup
                    // safely so the backend must retire its public authority
                    // even when the host cannot be reached.
                    assert!(matches!(input, Input::Empty));
                    assert!(script.contains("validate_receipt"));
                    return Err(Failure::install("The read-only fixture refused cleanup."));
                }
                Ok(CommandOutput {
                    stdout:
                        b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_CLEAR\n"
                            .to_vec(),
                })
            })
        }
    }
    struct RejoinSession {
        check: Vec<u8>,
        digest: [u8; 32],
        scripts: Arc<Mutex<Vec<String>>>,
    }
    impl SshTransport for RejoinSession {
        fn open(
            &self,
            _: Destination,
            _: Credentials,
            _: MeshEvidence,
        ) -> Operation<'_, Arc<dyn SshSession>> {
            Box::pin(async move {
                Ok(Arc::new(Self {
                    check: self.check.clone(),
                    digest: self.digest,
                    scripts: self.scripts.clone(),
                }) as Arc<dyn SshSession>)
            })
        }
    }
    impl SshSession for RejoinSession {
        fn run<'a>(&'a self, script: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
            let script = script.to_owned();
            Box::pin(async move {
                self.scripts.lock().unwrap().push(script.clone());
                let stdout = if script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) {
                    self.check.clone()
                } else if script.contains("prepare-join-key") {
                    let mut encoded = String::with_capacity(64);
                    for byte in self.digest {
                        for nibble in [byte >> 4, byte & 0x0f] {
                            encoded.push(char::from(b"0123456789abcdef"[usize::from(nibble)]));
                        }
                    }
                    format!("KEY-DIGEST {encoded}\n").into_bytes()
                } else if script.contains("agent --data \"$stage/state\" join ") {
                    // The enrollment command itself; setup routines may mention joining.
                    return Err(Failure::install("stop after the reissued invitation"));
                } else {
                    Vec::new()
                };
                Ok(CommandOutput { stdout })
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
        fixture_with_store(unlocked, store, pool, prior).await
    }
    async fn fixture_with_store(
        unlocked: bool,
        store: crate::enrollment::EnrollmentStore,
        pool: sqlx::SqlitePool,
        prior: Uuid,
    ) -> Fixture {
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
                sessions_changed: Mutex::default(),
            }),
            pool,
            prior,
            cookie,
            opens: Arc::default(),
        }
    }
    fn start(f: &Fixture, owner: &str) -> Batch {
        start_backend(f, owner, f.backend.clone())
    }
    /// Starts a fixture batch using the supplied backend and ordinary setup refusal.
    fn start_backend(f: &Fixture, owner: &str, backend: Arc<dyn Backend>) -> Batch {
        start_backend_with_payload_refusal(f, owner, backend, false, None)
    }
    /// Starts a fixture batch that refuses the staged SSH key payload upload.
    fn start_backend_refusing_key_payload_upload(f: &Fixture, owner: &str) -> Batch {
        start_backend_with_payload_refusal(f, owner, f.backend.clone(), true, None)
    }
    /// Starts one batch whose issued invitation waits until the test releases its gate.
    fn start_with_invitation_gate(
        f: &Fixture,
        owner: &str,
        batch: usize,
        gate: Arc<InvitationGate>,
    ) -> Batch {
        start_backend_with_payload_refusal(f, owner, f.backend.clone(), false, Some((gate, batch)))
    }
    /// Starts a fixture runner, optionally holding a published invitation for a concurrency test.
    fn start_backend_with_payload_refusal(
        f: &Fixture,
        owner: &str,
        backend: Arc<dyn Backend>,
        refuse_key_payload_upload: bool,
        invitation_gate: Option<(Arc<InvitationGate>, usize)>,
    ) -> Batch {
        let fixture_payload = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let sniff = Sniff {
            opens: f.opens.clone(),
            refuse_key_payload_upload,
        };
        let transport: Arc<dyn SshTransport> = if let Some((gate, batch)) = invitation_gate {
            Arc::new(GatedSniff { sniff, gate, batch })
        } else {
            Arc::new(sniff)
        };
        let runner = Bootstrap::new(
            transport,
            backend,
            BinaryPaths {
                x86_64: fixture_payload.clone(),
                aarch64: fixture_payload,
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
    // A generous failure bound keeps a lost event from hanging the suite without
    // treating ordinary scheduler load as a functional deadline.
    const TEST_HANG_BOUND: Duration = Duration::from_secs(60);

    async fn finished(batch: &Batch) -> Event {
        tokio::time::timeout(TEST_HANG_BOUND, async {
            let mut changed = batch.subscribe();
            loop {
                if let Some(event) = batch
                    .events(0)
                    .1
                    .into_iter()
                    .find(|event| matches!(event.step, Step::Failed | Step::Done))
                {
                    return event;
                }
                changed
                    .changed()
                    .await
                    .expect("bootstrap batch closed before publishing a terminal event");
            }
        })
        .await
        .expect("bootstrap batch did not publish a terminal event within the test hang bound")
    }
    async fn wait_invitation_committed(batch: &Batch, paused: &PausedInvitation) {
        tokio::time::timeout(TEST_HANG_BOUND, async {
            let mut changed = batch.subscribe();
            loop {
                tokio::select! {
                    () = paused.committed.notified() => return,
                    result = changed.changed() => {
                        result.expect("bootstrap batch closed before invitation publication");
                        if let Some(event) = batch.events(0).1.into_iter()
                            .find(|event| matches!(event.step, Step::Failed | Step::Done))
                        {
                            panic!("bootstrap ended before invitation publication: {}", event.message);
                        }
                    }
                }
            }
        })
        .await
        .expect("invitation was not committed within the test hang bound");
    }
    #[tokio::test]
    async fn automatic_cleanup_requires_the_exact_failed_server_host_binding() {
        let f = fixture(true).await;
        let target = Target {
            id: "one".into(),
            address: TargetAddress::Manual("user@fixture".into()),
            credential: None,
            mode: InstallMode::Rootless,
            root_consent: false,
        };
        let check =
            Check::parse(b"INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\n")
                .unwrap();
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture','observed-host')")
            .bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
        assert!(
            !f.backend
                .owns_failed_setup_record("owner", &target, &check, f.prior, Some("observed-host"))
                .await
                .unwrap()
        );
        sqlx::query("UPDATE remote_hosts SET revoked_at=created_at WHERE id=?")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(
            f.backend
                .owns_failed_setup_record("owner", &target, &check, f.prior, Some("observed-host"))
                .await
                .unwrap()
        );
        for (owner, host, lookup) in [
            ("stranger", f.prior, Some("observed-host")),
            ("owner", Uuid::new_v4(), Some("observed-host")),
            ("owner", f.prior, Some("different-host")),
            ("owner", f.prior, None),
        ] {
            assert!(
                !f.backend
                    .owns_failed_setup_record(owner, &target, &check, host, lookup)
                    .await
                    .unwrap()
            );
        }
        let mut alias = target.clone();
        alias.address = TargetAddress::Manual("user@alias".into());
        assert!(
            f.backend
                .owns_failed_setup_record("owner", &alias, &check, f.prior, Some("observed-host"))
                .await
                .unwrap()
        );
        let mut other_account = check.clone();
        other_account.uid = 1003;
        assert!(
            !f.backend
                .owns_failed_setup_record(
                    "owner",
                    &target,
                    &other_account,
                    f.prior,
                    Some("observed-host")
                )
                .await
                .unwrap()
        );
        sqlx::query("UPDATE remote_hosts SET mode='rootful',execution_uid=0 WHERE id=?")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(
            !f.backend
                .owns_failed_setup_record("owner", &target, &check, f.prior, Some("observed-host"))
                .await
                .unwrap()
        );
        sqlx::query("UPDATE remote_hosts SET mode='rootless',execution_uid=1002 WHERE id=?")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE remote_host_bootstrap SET trust_lookup=NULL WHERE host_id=?")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        assert!(
            f.backend
                .owns_failed_setup_record("owner", &target, &check, f.prior, None)
                .await
                .unwrap()
        );
        assert!(
            !f.backend
                .owns_failed_setup_record("owner", &alias, &check, f.prior, None)
                .await
                .unwrap()
        );
        assert!(
            !f.backend
                .owns_failed_setup_record("owner", &target, &check, f.prior, Some("observed-host"))
                .await
                .unwrap()
        );
        let mut unconfirmed = target.clone();
        unconfirmed.mode = InstallMode::Root;
        assert!(
            f.backend
                .owns_failed_setup_record("owner", &unconfirmed, &check, f.prior, None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cold_ca_refuses_before_invitation_or_upload() {
        let f = fixture(false).await;
        let batch = start(&f, "owner");
        let event = finished(&batch).await;
        assert_eq!(event.step, Step::Failed);
        assert!(event.message.contains("administrator passkey"));
        let failure = event.failure.as_ref().unwrap();
        assert!(
            serde_json::to_value(failure)
                .unwrap()
                .get("host_id")
                .is_none()
        );
        assert_eq!(f.opens.load(Ordering::Relaxed), 1);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_hosts")
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn readding_a_live_host_reports_already_added_before_issuing_a_certificate() {
        let f = fixture(true).await;
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)").bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
        let event = finished(&start(&f, "owner")).await;
        assert_eq!(event.step, Step::Failed);
        let failure = event.failure.as_ref().unwrap();
        assert!(failure.already_added);
        assert_eq!(
            serde_json::to_value(failure).unwrap()["host_id"],
            f.prior.to_string()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM remote_hosts")
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1
        );
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }

    /// Gives the fixture's enrolled host the shape production kept for `code` after an
    /// interrupted setup (#305, J241): its address, a setup that never finished (an open
    /// retirement intent) and the first shell published before setup failed, still open.
    /// That open session is what kept the row alive across every restart.
    async fn unfinished_setup_with_a_ghost_shell(f: &Fixture) {
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)").bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO terminal_sessions(id,user_id,created_at,last_seen,remote_host_id) VALUES(?,'owner',100,100,?)")
            .bind(Uuid::new_v4().as_bytes().as_slice()).bind(f.prior.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
        // Startup keeps it: retirement skips hosts with an open session.
        f.backend
            .issuer
            .store()
            .retire_unfinished_bootstraps()
            .await
            .unwrap();
    }

    /// Production 8d3207cc8 (#305, J241): Start fresh cleaned the host, then Check found
    /// this server's own half-finished row for the same address and said "already added",
    /// offering a terminal whose infraternal agent never finished setup. A setup that never
    /// finished, whose infraternal agent is not connected, is retired so setup continues.
    #[tokio::test]
    async fn readding_a_host_whose_setup_never_finished_retires_it_instead_of_already_added() {
        let f = fixture(true).await;
        unfinished_setup_with_a_ghost_shell(&f).await;
        let event = finished(&start(&f, "owner")).await;
        let failure = event.failure.as_ref();
        assert!(
            !failure.is_some_and(|failure| failure.already_added),
            "{failure:?}"
        );
        // Setup went past Check: it issued a new host's invitation (the fixture then refuses).
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM remote_hosts WHERE id<>?")
                .bind(f.prior.as_bytes().as_slice())
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1,
            "{event:?}"
        );
        let (revoked, intents): (bool, i64) = sqlx::query_as("SELECT (SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?), (SELECT count(*) FROM remote_bootstrap_retirement_intents WHERE host_id=?)")
            .bind(f.prior.as_bytes().as_slice()).bind(f.prior.as_bytes().as_slice()).fetch_one(&f.pool).await.unwrap();
        assert!(revoked, "the unfinished host must no longer count as added");
        assert_eq!(intents, 0);
    }

    /// J257 P3: P2 through its call site. A completed Replace (an attempt of this
    /// batch marked `replacement`) of a host whose first setup never finished
    /// consumes that intent and releases the attempt; another batch's attempt is
    /// never completed by this one.
    #[tokio::test]
    async fn completing_a_replace_through_its_call_site_marks_the_host_finished() {
        let f = fixture(true).await;
        unfinished_setup_with_a_ghost_shell(&f).await;
        let batch = Uuid::new_v4();
        f.backend.attempts.lock().unwrap().insert(
            f.prior,
            Attempt {
                owner: "owner".into(),
                batch,
                uid: 1002,
                link_round_trip: Duration::ZERO,
                destination: Some(("user@fixture".into(), None)),
                canary: None,
                retirement: None,
                replacement: true,
            },
        );
        assert!(
            f.backend
                .finish_completion("owner", Uuid::new_v4(), f.prior)
                .await
                .is_err(),
            "another batch must not complete this attempt"
        );
        f.backend
            .finish_completion("owner", batch, f.prior)
            .await
            .unwrap();
        let open: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM remote_bootstrap_retirement_intents WHERE host_id=?",
        )
        .bind(f.prior.as_bytes().as_slice())
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(open, 0, "the replaced host still reads as unfinished");
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }

    /// #305 round 4: production owners are person UUIDs, whose host retirement waits
    /// for a receipt from the host's infraternal agent. An abandoned setup's agent is
    /// gone, so retiring it during the add must deny it without that wait (as Remove
    /// does for an offline host), or every add of the address hangs to its deadline.
    #[tokio::test]
    async fn an_abandoned_setup_of_a_person_is_denied_without_waiting_for_its_gone_agent() {
        let f = fixture(true).await;
        let person = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users(id,name,username,owner,recovery_hash) VALUES (?,?,?,0,'test')",
        )
        .bind(&person)
        .bind(&person)
        .bind(&person)
        .execute(&f.pool)
        .await
        .unwrap();
        let ghost = Uuid::new_v4();
        sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,?,'rootless',1002,100)")
            .bind(ghost.as_bytes().as_slice()).bind(&person).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@ghost',NULL)")
            .bind(ghost.as_bytes().as_slice()).execute(&f.pool).await.unwrap();
        sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
            .bind(ghost.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        let found = tokio::time::timeout(
            Duration::from_secs(10),
            f.backend.existing_host(&person, "user@ghost", None, true),
        )
        .await
        .expect("retiring an abandoned setup must not wait for its gone agent")
        .unwrap();
        assert_eq!(found, None);
        // Denied durably: its certificate is no longer admitted, and the login
        // cleanup stays queued for an agent that may still reconnect.
        let pending: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM remote_login_cleanup WHERE host_id=? AND confirmed=0",
        )
        .bind(ghost.as_bytes().as_slice())
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(pending, 1);
        // And a second lookup does not find it again.
        assert_eq!(
            f.backend
                .existing_host(&person, "user@ghost", None, true)
                .await
                .unwrap(),
            None
        );
    }

    /// J247 P3: the stuck-install check runs before the person confirms anything, so
    /// its lookup reports an abandoned setup as not added and changes nothing.
    #[tokio::test]
    async fn the_check_before_confirmation_never_retires_an_abandoned_setup() {
        let f = fixture(true).await;
        unfinished_setup_with_a_ghost_shell(&f).await;
        assert_eq!(
            f.backend
                .existing_host("owner", "user@fixture", None, false)
                .await
                .unwrap(),
            None
        );
        let (revoked, intents): (bool, i64) = sqlx::query_as("SELECT (SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?), (SELECT count(*) FROM remote_bootstrap_retirement_intents WHERE host_id=?)")
            .bind(f.prior.as_bytes().as_slice()).bind(f.prior.as_bytes().as_slice()).fetch_one(&f.pool).await.unwrap();
        assert!(!revoked);
        assert_eq!(intents, 1);
    }

    /// #305, J247 P2: a Replace of a host whose first setup never finished must mark
    /// it finished, or a later re-add while its agent is offline would retire a
    /// working host. A Replace with nothing open stays fine; a new install with no
    /// intent is still refused.
    #[tokio::test]
    async fn a_completed_replace_marks_an_unfinished_host_finished() {
        let f = fixture(true).await;
        unfinished_setup_with_a_ghost_shell(&f).await;
        f.backend
            .finish_setup_record("owner", f.prior, true)
            .await
            .unwrap();
        let open: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM remote_bootstrap_retirement_intents WHERE host_id=?",
        )
        .bind(f.prior.as_bytes().as_slice())
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(open, 0, "the replaced host still reads as unfinished");
        // Now finished, so a re-add while it is offline names it, never retires it.
        let event = finished(&start(&f, "owner")).await;
        assert!(
            event
                .failure
                .as_ref()
                .is_some_and(|failure| failure.already_added),
            "{event:?}"
        );
        f.backend
            .finish_setup_record("owner", f.prior, true)
            .await
            .unwrap();
        assert!(
            f.backend
                .finish_setup_record("owner", f.prior, false)
                .await
                .is_err()
        );
    }

    /// The retirement above never reaches a setup still running in this server: a second
    /// tab adding the same address while the first one installs keeps the first attempt,
    /// and is told it is being added, never offered a terminal on a host still installing.
    #[tokio::test]
    async fn an_unfinished_setup_still_running_here_is_not_retired_by_another_add() {
        let f = fixture(true).await;
        unfinished_setup_with_a_ghost_shell(&f).await;
        f.backend.attempts.lock().unwrap().insert(
            f.prior,
            Attempt {
                owner: "owner".into(),
                batch: Uuid::new_v4(),
                uid: 1002,
                link_round_trip: Duration::ZERO,
                destination: Some(("user@fixture".into(), None)),
                canary: None,
                retirement: None,
                replacement: false,
            },
        );
        let event = finished(&start(&f, "owner")).await;
        assert_eq!(event.step, Step::Failed);
        let failure = event.failure.as_ref().unwrap();
        assert!(!failure.already_added, "{failure:?}");
        assert!(
            serde_json::to_value(failure)
                .unwrap()
                .get("host_id")
                .is_none()
        );
        assert!(event.message.contains("already being added"), "{event:?}");
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
                .bind(f.prior.as_bytes().as_slice())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(!revoked, "a running setup must keep its host");
    }

    #[tokio::test]
    async fn replacing_a_journaled_old_install_reissues_its_identity_without_a_duplicate_host() {
        let f = fixture(true).await;
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        let digest = f
            .backend
            .issuer
            .store()
            .host_key_digest(f.prior)
            .await
            .unwrap()
            .unwrap();
        let host = f.prior.simple();
        let transaction = Uuid::new_v4().simple();
        let check = format!(
            "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_UPGRADE {host} {transaction} 1:2 fixture 99999999 1 2026-11-02T04:05:06Z 0 {} remote.example.test idle\n",
            hex(&digest)
        )
        .into_bytes();
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let transport = Arc::new(RejoinSession {
            check,
            digest,
            scripts: scripts.clone(),
        });
        let binary = std::env::current_exe().unwrap();
        let runner = Bootstrap::new(
            transport,
            f.backend.clone(),
            BinaryPaths {
                x86_64: binary.clone(),
                aarch64: binary,
            },
        );
        let batch = runner
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
            .unwrap();
        let mut changed = batch.subscribe();
        let challenge = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let events = batch.events(0).1;
                if let Some(leftovers) = events.iter().find_map(|event| event.leftovers.as_ref()) {
                    break leftovers.challenge;
                }
                assert!(
                    events.iter().all(|event| event.step != Step::Failed),
                    "the old install must reach the explicit replacement action: {events:?}"
                );
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        runner
            .start_fresh(&batch, "owner", "one", challenge)
            .unwrap();
        let event = finished(&batch).await;
        assert_eq!(event.step, Step::Failed);
        assert!(!event.message.contains("interrupted install"), "{event:?}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM remote_hosts")
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1
        );
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM remote_hosts WHERE id=?")
                .bind(f.prior.as_bytes().as_slice())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert!(
            !revoked,
            "a failed replacement attempt must preserve the old host record"
        );
        let invitations: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM remote_join_tokens WHERE host_id=? AND consumed_at IS NULL",
        )
        .bind(f.prior.as_bytes().as_slice())
        .fetch_one(&f.pool)
        .await
        .unwrap();
        assert_eq!(
            invitations, 1,
            "the previous host must receive a fresh join invitation"
        );
        let scripts = scripts.lock().unwrap();
        assert!(
            scripts
                .iter()
                .any(|script| script.contains("https://remote.example.test/remote/join"))
        );
        assert!(scripts.iter().all(|script| !script.contains(":7443")));
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }
    fn hex(digest: &[u8; 32]) -> String {
        use std::fmt::Write as _;
        digest
            .iter()
            .fold(String::with_capacity(64), |mut text, byte| {
                let _ = write!(text, "{byte:02x}");
                text
            })
    }

    /// A stuck-upgrade check record for `host`, enrolled with `server` under `digest`.
    fn stuck_check(host: Uuid, digest: &[u8; 32], server: &str) -> Vec<u8> {
        format!(
            "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n1002\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_UPGRADE {} {} 1:2 fixture 99999999 1 2026-11-02T04:05:06Z 2 {} {server} idle\n",
            host.simple(),
            Uuid::new_v4().simple(),
            hex(digest)
        )
        .into_bytes()
    }

    /// Run add-host against a scripted stuck upgrade, confirming any offered action.
    async fn run_stuck(f: &Fixture, check: Vec<u8>) -> (Vec<Event>, Vec<String>) {
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let binary = std::env::current_exe().unwrap();
        let runner = Bootstrap::new(
            Arc::new(RejoinSession {
                check,
                digest: [7; 32],
                scripts: scripts.clone(),
            }),
            f.backend.clone(),
            BinaryPaths {
                x86_64: binary.clone(),
                aarch64: binary,
            },
        );
        let batch = runner
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
            .unwrap();
        let mut changed = batch.subscribe();
        // A hang bound, not a speed check: the whole add-host runs here, and
        // under the parallel suite on a loaded VM it has taken over 10 s.
        tokio::time::timeout(TEST_HANG_BOUND, async {
            let mut confirmed = false;
            loop {
                let events = batch.events(0).1;
                if events.iter().any(|event| event.step == Step::Failed) {
                    break;
                }
                if !confirmed
                    && let Some(leftovers) =
                        events.iter().find_map(|event| event.leftovers.as_ref())
                {
                    confirmed = true;
                    runner
                        .start_fresh(&batch, "owner", "one", leftovers.challenge)
                        .unwrap();
                }
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let events = batch.events(0).1;
        let scripts = scripts.lock().unwrap().clone();
        (events, scripts)
    }

    fn mutating(scripts: &[String]) -> Vec<&'static str> {
        [
            "\nreplace_stuck_install ",
            "\nsupersede_stuck_install ",
            "\nfinish_stuck_upgrade ",
            "prepare-join-key",
        ]
        .into_iter()
        .filter(|action| scripts.iter().any(|script| script.contains(action)))
        .collect()
    }

    #[test]
    fn stuck_install_verdict_follows_record_key_link_and_ca() {
        let facts = |ours, stored: Option<[u8; 32]>, reported, connected, ca_ready| StuckFacts {
            ours,
            stored,
            reported,
            connected,
            ca_ready,
        };
        let key = Some([1; 32]);
        assert_eq!(
            decide_stuck_install(&facts(true, key, key, false, true)).unwrap(),
            StuckInstall::Replace
        );
        // P2-2: connected with this identity finishes the journal, CA or not.
        assert_eq!(
            decide_stuck_install(&facts(true, key, key, true, false)).unwrap(),
            StuckInstall::Finish
        );
        for (refused, text) in [
            (facts(false, key, key, false, true), "no longer matches"),
            (
                facts(true, key, Some([2; 32]), true, true),
                "does not match its enrolled key",
            ),
            (
                facts(true, key, None, false, true),
                "does not match its enrolled key",
            ),
            (
                facts(true, None, None, false, true),
                "does not match its enrolled key",
            ),
            (facts(true, key, key, false, false), "administrator passkey"),
        ] {
            let error = decide_stuck_install(&refused).unwrap_err();
            assert!(error.message.contains(text), "{}", error.message);
        }
    }

    #[tokio::test]
    async fn a_machine_another_server_enrolled_joins_as_a_new_host_after_confirmation() {
        let f = fixture(true).await;
        let stuck = Uuid::new_v4();
        let (events, scripts) = run_stuck(&f, stuck_check(stuck, &[9; 32], "old.example")).await;
        let lock = events
            .iter()
            .find(|event| event.leftovers.is_some())
            .and_then(|event| event.failure.as_ref())
            .map(|failure| serde_json::to_value(failure).unwrap()["setup_lock"].clone())
            .expect("the person is asked before anything changes");
        assert_eq!(lock["enrolled_with"], "old.example");
        assert_eq!(lock["sessions"], 2);
        // Set aside first, then a new key, then the new host's invitation.
        let position = |needle: &str| scripts.iter().position(|script| script.contains(needle));
        let aside = position("\nsupersede_stuck_install ").expect("the old install is set aside");
        let failed = events.iter().rev().find(|event| event.step == Step::Failed);
        assert!(
            position("prepare-join-key").is_some_and(|key| key > aside),
            "{failed:?}"
        );
        assert!(position("\nreplace_stuck_install ").is_none());
        // The fixture refuses the join: the set-aside install is put back.
        // stuck_restore runs that restore program for real and checks the result.
        assert!(position("\nrestore_superseded_install ").unwrap() > aside);
        let stuck_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE id=?")
            .bind(stuck.as_bytes().as_slice())
            .fetch_one(&f.pool)
            .await
            .unwrap();
        assert_eq!(stuck_rows, 0, "the old host id is never adopted");
        let issued: i64 =
            sqlx::query_scalar("SELECT count(*) FROM remote_join_tokens WHERE host_id<>?")
                .bind(f.prior.as_bytes().as_slice())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(issued, 1, "one invitation for a new host id");
    }

    #[tokio::test]
    async fn a_locked_ca_refuses_reenrollment_before_anything_changes() {
        let f = fixture(false).await;
        let (events, scripts) =
            run_stuck(&f, stuck_check(Uuid::new_v4(), &[9; 32], "old.example")).await;
        let failed = events
            .iter()
            .find(|event| event.step == Step::Failed)
            .unwrap();
        assert!(
            failed.message.contains("administrator passkey"),
            "{}",
            failed.message
        );
        assert!(events.iter().all(|event| event.leftovers.is_none()));
        assert_eq!(mutating(&scripts), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn a_foreign_key_for_this_servers_host_is_refused_before_anything_changes() {
        let f = fixture(true).await;
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        let (events, scripts) =
            run_stuck(&f, stuck_check(f.prior, &[9; 32], "remote.example.test")).await;
        let failed = events
            .iter()
            .find(|event| event.step == Step::Failed)
            .unwrap();
        assert!(
            failed.message.contains("does not match its enrolled key"),
            "{}",
            failed.message
        );
        assert!(events.iter().all(|event| event.leftovers.is_none()));
        assert_eq!(mutating(&scripts), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn foreign_or_revoked_authority_never_opens_ssh() {
        let f = fixture(true).await;
        sqlx::query("INSERT INTO remote_host_bootstrap(host_id,address,trust_lookup) VALUES(?,'user@fixture',NULL)")
            .bind(f.prior.as_bytes().as_slice())
            .execute(&f.pool)
            .await
            .unwrap();
        let foreign = finished(&start(&f, "stranger")).await;
        assert_eq!(foreign.step, Step::Failed);
        assert!(
            serde_json::to_value(foreign.failure.as_ref().unwrap())
                .unwrap()
                .get("host_id")
                .is_none()
        );
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
    async fn failed_key_payload_upload_does_not_publish_a_host_record() {
        let f = fixture(true).await;
        let event = finished(&start_backend_refusing_key_payload_upload(&f, "owner")).await;
        assert_eq!(event.step, Step::Failed);
        assert!(matches!(
            event.failure.as_ref().unwrap().failed_step.as_ref(),
            Some(InstallStep::Upload)
        ));
        let rows: Vec<(Vec<u8>, i64, Option<i64>)> =
            sqlx::query_as("SELECT id,execution_uid,revoked_at FROM remote_hosts")
                .fetch_all(&f.pool)
                .await
                .unwrap();
        assert_eq!(
            rows.len(),
            1,
            "key preparation failed before invitation issuance"
        );
        assert_eq!(rows[0].0, f.prior.as_bytes());
        assert_eq!(rows[0].1, 1002);
        assert!(rows[0].2.is_none());
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
                link_round_trip: Duration::ZERO,
                destination: None,
                canary: None,
                retirement: None,
                replacement: false,
            },
        );
        f.backend.attempts.lock().unwrap().insert(
            other,
            Attempt {
                owner: "other-owner".into(),
                batch: Uuid::new_v4(),
                uid: 1003,
                link_round_trip: Duration::ZERO,
                destination: None,
                canary: None,
                retirement: None,
                replacement: false,
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

    /// Holds the committed invitation before its caller receives the result.
    /// No production hook is needed: the real backend and SQLite commit run
    /// unchanged, while this adapter models a delayed commit acknowledgement.
    struct PausedInvitation {
        inner: Arc<RemoteBackend>,
        committed: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    impl PausedInvitation {
        async fn pause(&self, join: JoinMaterial) -> Result<JoinMaterial, Failure> {
            self.committed.notify_one();
            self.release.notified().await;
            Ok(join)
        }
    }
    impl Backend for PausedInvitation {
        fn enrollment_origin(&self) -> Option<String> {
            self.inner.enrollment_origin()
        }
        fn preflight_existing_host<'a>(
            &'a self,
            a: &'a Authority,
            t: &'a Target,
            lookup: Option<String>,
        ) -> Operation<'a, ()> {
            self.inner.preflight_existing_host(a, t, lookup)
        }
        fn resolve<'a>(
            &'a self,
            a: &'a Authority,
            t: &'a Target,
            c: Option<&'a str>,
        ) -> Operation<'a, Resolved> {
            self.inner.resolve(a, t, c)
        }
        fn invitation<'a>(
            &'a self,
            a: &'a Authority,
            t: &'a Target,
            c: &'a Check,
        ) -> Operation<'a, JoinMaterial> {
            self.invitation_with_trust(a, t, c, None)
        }
        fn invitation_with_trust<'a>(
            &'a self,
            a: &'a Authority,
            t: &'a Target,
            c: &'a Check,
            lookup: Option<String>,
        ) -> Operation<'a, JoinMaterial> {
            Box::pin(async move {
                self.pause(self.inner.invitation_with_trust(a, t, c, lookup).await?)
                    .await
            })
        }
        fn invitation_registered<'a>(
            &'a self,
            a: &'a Authority,
            t: &'a Target,
            c: &'a Check,
            lookup: Option<String>,
            register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
        ) -> Operation<'a, JoinMaterial> {
            Box::pin(async move {
                self.pause(
                    self.inner
                        .invitation_registered(a, t, c, lookup, register)
                        .await?,
                )
                .await
            })
        }
        fn invitation_registered_with_key<'a>(
            &'a self,
            a: &'a Authority,
            t: &'a Target,
            c: &'a Check,
            lookup: Option<String>,
            binding: PreparedHostKey,
            register: &'a mut (dyn FnMut(Uuid) -> Result<(), Failure> + Send),
        ) -> Operation<'a, JoinMaterial> {
            Box::pin(async move {
                self.pause(
                    self.inner
                        .invitation_registered_with_key(a, t, c, lookup, binding, register)
                        .await?,
                )
                .await
            })
        }
        fn connected_facts<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
            self.inner.connected_facts(a, h)
        }
        fn terminal_canary<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
            self.inner.terminal_canary(a, h)
        }
        fn cleanup_sessions<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
            self.inner.cleanup_sessions(a, h)
        }
        fn failed<'a>(&'a self, a: &'a Authority, h: Uuid) -> Operation<'a, ()> {
            self.inner.failed(a, h)
        }
    }

    #[tokio::test]
    async fn cancelled_invitation_after_commit_retires_its_host_record() {
        let f = fixture(true).await;
        let paused = Arc::new(PausedInvitation {
            inner: f.backend.clone(),
            committed: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        });
        let batch = start_backend(&f, "owner", paused.clone());
        wait_invitation_committed(&batch, &paused).await;
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL"
            )
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            2
        );
        let mut changed = batch.subscribe();
        drop(batch);
        tokio::time::timeout(TEST_HANG_BOUND, async {
            while changed.changed().await.is_ok() {}
        })
        .await
        .expect("cancelled bootstrap batch did not close its event stream");
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL"
            )
            .fetch_one(&f.pool)
            .await
            .unwrap(),
            1
        );
        assert!(f.backend.attempts.lock().unwrap().is_empty());
    }

    /// Measures real admission with the declared maximum attempt journal held.
    /// SSH sniffing is read-only synthetic; auth and owner state use real SQLite.
    #[tokio::test]
    #[ignore = "#169 local bounded-journal scale evidence under CPUWeight scope"]
    async fn destination_reservation_admission_at_1600_pending_hosts() {
        fn rss() -> usize {
            std::fs::read_to_string("/proc/self/status")
                .unwrap()
                .lines()
                .find_map(|line| {
                    line.strip_prefix("VmRSS:")
                        .map(|value| value.split_whitespace().next().unwrap().parse().unwrap())
                })
                .unwrap()
        }
        let f = fixture(true).await;
        let before = rss();
        let (capacity, string_bytes) = {
            let mut attempts = f.backend.attempts.lock().unwrap();
            for index in 0..1600 {
                attempts.insert(
                    Uuid::new_v4(),
                    Attempt {
                        owner: "owner".into(),
                        batch: Uuid::new_v4(),
                        uid: 1002,
                        link_round_trip: Duration::ZERO,
                        destination: Some((format!("user@host-{index}.example.invalid"), None)),
                        canary: None,
                        retirement: None,
                        replacement: false,
                    },
                );
            }
            let bytes: usize = attempts
                .values()
                .map(|attempt| {
                    attempt.owner.capacity() + attempt.destination.as_ref().unwrap().0.capacity()
                })
                .sum();
            (attempts.capacity(), bytes)
        };
        let held = rss();
        let mut samples = Vec::new();
        for _ in 0..100 {
            let started = std::time::Instant::now();
            let batches: Vec<_> = (0..8).map(|_| start(&f, "owner")).collect();
            let events = futures_util::future::join_all(batches.iter().map(finished)).await;
            assert!(events.iter().all(
                |event| event.message.contains("Too many host installations")
                    && event.host_id.is_none()
            ));
            samples.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        samples.sort_by(f64::total_cmp);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM remote_hosts")
                .fetch_one(&f.pool)
                .await
                .unwrap(),
            1
        );
        println!(
            "METRIC destination_admission pending=1600 active_per_sample=8 samples=100 requests=800 refused=800 map_capacity={capacity} attempt_size={} string_capacity_bytes={string_bytes} rss_before_kib={before} rss_held_kib={held} p50_ms={:.3} p99_ms={:.3}",
            std::mem::size_of::<Attempt>(),
            samples[50],
            samples[99]
        );
        println!(
            "ENVIRONMENT machine={} cores={} load={}",
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            std::thread::available_parallelism().unwrap().get(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim()
        );
    }

    #[tokio::test]
    async fn breakit2_unpublished_invitation_retires_durable_authority() {
        let f = fixture(true).await;
        // A deterministic SQLite failure after issue() commits tests the exact
        // unpublished boundary without exposing the memory-only invitation.
        sqlx::query("CREATE TRIGGER breakit2_refuse_address BEFORE INSERT ON remote_host_bootstrap BEGIN SELECT RAISE(ABORT,'fixture address persistence refusal'); END")
            .execute(&f.pool).await.unwrap();
        assert_eq!(finished(&start(&f, "owner")).await.step, Step::Failed);
        assert!(f.backend.attempts.lock().unwrap().is_empty());
        let live: i64 =
            sqlx::query_scalar("SELECT count(*) FROM remote_hosts WHERE revoked_at IS NULL")
                .fetch_one(&f.pool)
                .await
                .unwrap();
        assert_eq!(
            live, 1,
            "unpublished cleanup removed memory ownership but leaked durable host authority"
        );
    }

    /// Holds one invitation open while all same-destination competitors reach admission.
    #[tokio::test]
    async fn breakit2_concurrent_same_destination_issues_only_one_invitation() {
        let f = fixture(true).await;
        // At most one invitation can be reported by each of these eight batches.
        let (arrivals, mut arrived) = tokio::sync::mpsc::channel(8);
        let (release, release_signal) = tokio::sync::watch::channel(false);
        let gate = Arc::new(InvitationGate {
            arrivals,
            release: release_signal,
        });
        let batches: Vec<_> = (0..8)
            .map(|batch| start_with_invitation_gate(&f, "owner", batch, gate.clone()))
            .collect();
        let first_invitation = tokio::time::timeout(TEST_HANG_BOUND, arrived.recv())
            .await
            .expect("no invitation was published within the test hang bound")
            .expect("all invitation reporters closed before publishing");
        assert!(first_invitation < batches.len());
        let second_invitation = tokio::time::timeout(TEST_HANG_BOUND, async {
            tokio::select! {
                _ = futures_util::future::join_all(batches.iter().enumerate().filter_map(|(batch, started)| {
                    (batch != first_invitation).then_some(finished(started))
                })) => false,
                extra = arrived.recv() => extra.is_some(),
            }
        })
        .await
        .expect("same-destination competitors did not reach a terminal event");
        // Release even after observing a duplicate so every fixture task can clean up.
        release.send_replace(true);
        let events = futures_util::future::join_all(batches.iter().map(finished)).await;
        assert!(
            !second_invitation,
            "a second invitation was published while the first attempt remained reserved"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.host_id.is_some())
                .count(),
            1,
            "concurrent batches reserved the same destination and issued distinct host identities"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.message.contains("already being added"))
                .count(),
            7
        );
    }
}

#[cfg(test)]
#[path = "bootstrap_canary_tests.rs"]
mod canary_tests;

#[cfg(test)]
#[path = "bootstrap_admission_tests.rs"]
mod admission_tests;
