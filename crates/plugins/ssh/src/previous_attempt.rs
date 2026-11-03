//! Rechecks earlier host provisioning ownership and liveness before explicit recovery [17][139], #169.

use std::borrow::Cow;

use crate::{
    install::Installation,
    model::{Failure, FailureKind, InstallMode, Leftovers, Target},
    probe::{CHECK_SCRIPT, Check},
    transport::{Input, SshSession},
};

// Shell proof notes live outside transmitted literals to keep setup and the binary small [243].
// This program emits only fixed records and public ids, never process arguments or file contents.
// no_redirect has already permitted only the home alias and symlinks above
// it. Resolve that alias so /proc descriptor links under the real home are
// still recognized as live setup state.
// A running b-0.1.0 infraternal agent binds sessions/plugins.sock as 0775 (#305).
// Its parent sessions directory must be 0700 and owned by this user, so the
// socket's own mode grants no access; an upgrade check requires only that it
// is a real socket owned by the user.
// UUID session sockets retain their existing liveness checks. The fixed control
// socket is probed directly; a global basename never proves it belongs here.
// Inspect executable and open-descriptor links in one native traversal,
// never argv or environments. Per-link shell subprocesses grow with every
// other workload's open files. Bound the process table and refuse paths
// that cannot be represented literally by find's link-pattern predicate.
// Processes can exit or belong to another uid during traversal. Other
// failures (missing utility, oversized argv) cannot prove absence.
// Every directory from / to the setup root must be real, except the home
// directory itself or a directory above it (e.g. /home -> /var/home): a
// symlink below home could send recovery to leftovers somewhere else (#169).
// Final retirement can stop after the owner or base is gone. The private
// outside receipt still identifies the exact host/transaction for the
// server's durable authorization; a replacement directory never matches.
// Only an empty root is reachable after retiring the owner marker.
// An interrupted fresh lock is recoverable through its original journal.
// An upgrade owns previous enrolled data and is never a start-fresh target.
// Receipt and any surviving lock must describe the same fresh attempt.
// Fresh acquisition receipts own only these staging artifacts. Since D291 a
// fresh attempt that stops at Connect also holds its private state copy and
// payload cache, and one that stops during activation holds the same empty
// progress markers its rollback already understands (#305).
// More advanced/unknown layouts need their original rollback; do not
// recursively delete foreign files just because a lock is marked ours.
// Only the acquisition journal proves an otherwise empty lock.
// A receipt may coexist with interrupted acquisition retirement. Validate
// that sibling binding before removing even otherwise-owned sockets.
// Any unjournaled root entry refuses the entire recovery before mutation,
// including sockets elsewhere that would otherwise be safe to retire.
// Validate every socket before deleting any. Only these session rendezvous
// names and empty directories belong to this legacy fresh-install receipt.
pub(crate) const INSPECT: &str = include_str!("previous_attempt.sh");

/// Nonsecret coordinates bind confirmation to exactly the directory observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviousAttempt {
    pub(crate) host: uuid::Uuid,
    pub(crate) transaction: uuid::Uuid,
    identity: String,
    sockets: u16,
    lease_owner: Option<LeaseOwner>,
    /// An upgrade journal's enrolled identity, if the host could read it.
    enrolled: Option<Enrolled>,
    /// An install an earlier Replace or Re-enroll set aside and did not put back.
    set_aside: Option<SetAside>,
}

/// A stuck install an earlier attempt set aside, as Check found it (#305 P2-1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SetAside {
    /// A Replace moved only the journal; a Re-enroll moved the whole install.
    replaced: bool,
    machine: String,
    /// Whether its service was enabled and running when it was set aside.
    enabled: bool,
    active: bool,
}

/// The stuck install's enrolled key digest and the server that issued it (#305, D335).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub digest: [u8; 32],
    pub server: String,
}

/// The old lease coordinates remain bound into the replacement confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LeaseOwner {
    machine: String,
    pid: u32,
    birth: u64,
    since: String,
}

/// Fold the ownership check into the existing SSH sniff, without another round trip.
#[must_use]
pub fn check_script(mode: InstallMode) -> String {
    // The read-only check carries only the guard it executes (D255).
    let inspect = Installation::script_for(
        mode,
        uuid::Uuid::nil(),
        uuid::Uuid::nil(),
        &format!(
            "{}\n{}\n{INSPECT}\nsetup_check=yes\ninspect_previous",
            crate::install::SETUP_GUARD,
            crate::install::RUNTIME_CLEANUP
        ),
    );
    format!("{CHECK_SCRIPT}\n{inspect}")
}

/// Decode exact fixed records; arbitrary host output never enters public diagnostics.
/// # Errors
/// Refuses unknown output, invalid identifiers and unsupported ownership formats.
pub fn parse_check(bytes: &[u8]) -> Result<(Check, Option<PreviousAttempt>), Failure> {
    // The check lines plus an upgrade record with two host names stay below 1 KiB.
    if bytes.len() > 1024 {
        return Err(refused());
    }
    let end = bytes
        .iter()
        .enumerate()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(8)
        .map(|(index, _)| index + 1)
        .ok_or_else(refused)?;
    let check = Check::parse(&bytes[..end])?;
    let previous = parse(&bytes[end..])?;
    Ok((check, previous))
}

fn parse(bytes: &[u8]) -> Result<Option<PreviousAttempt>, Failure> {
    if bytes == b"INFRATERNAL_SETUP_CLEAR\n" {
        return Ok(None);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| refused())?;
    let fields: Vec<_> = text
        .strip_suffix('\n')
        .ok_or_else(refused)?
        .split(' ')
        .collect();
    if let [
        "INFRATERNAL_SETUP_LOCKED",
        machine,
        pid,
        birth,
        since,
        attempt,
    ] = fields.as_slice()
    {
        let (machine, pid, since) = parse_active_lock(machine, pid, birth, since)?;
        let attempt = if *attempt == "unknown" {
            None
        } else {
            Some(canonical_id(attempt)?)
        };
        return Err(Failure::new(
            FailureKind::SetupRunning,
            "Setup is already running on this host.",
        )
        .with_setup_lock(machine, pid, since, true)
        .with_setup_attempt(attempt));
    }
    if let ["INFRATERNAL_SETUP_REFUSED", cause] = fields.as_slice() {
        return Err(Failure::install(refusal_message(cause)));
    }
    if let [
        "INFRATERNAL_SETUP_SET_ASIDE",
        kind,
        host,
        transaction,
        machine,
        enabled,
        active,
    ] = fields.as_slice()
    {
        let flag = |value: &str| match value {
            "yes" => Ok(true),
            "no" => Ok(false),
            _ => Err(refused()),
        };
        let replaced = match *kind {
            "replaced" => true,
            "superseded" => false,
            _ => return Err(refused()),
        };
        return Ok(Some(PreviousAttempt {
            host: canonical_id(host)?,
            transaction: canonical_id(transaction)?,
            identity: String::new(),
            sockets: 0,
            lease_owner: None,
            enrolled: None,
            set_aside: Some(SetAside {
                replaced,
                machine: parse_machine(machine)?,
                enabled: flag(enabled)?,
                active: flag(active)?,
            }),
        }));
    }
    let (host, transaction, identity, sockets, lease_owner, enrolled) = match fields.as_slice() {
        [
            "INFRATERNAL_SETUP_STALE",
            host,
            transaction,
            identity,
            sockets,
        ] => (*host, *transaction, *identity, *sockets, None, None),
        [
            "INFRATERNAL_SETUP_UPGRADE",
            host,
            transaction,
            identity,
            machine,
            pid,
            birth,
            since,
            sockets,
            digest,
            server,
        ] => (
            *host,
            *transaction,
            *identity,
            *sockets,
            Some(parse_lease_owner(machine, pid, birth, since)?),
            parse_enrolled(digest, server)?,
        ),
        _ => return Err(refused()),
    };
    let host = canonical_id(host)?;
    let transaction = canonical_id(transaction)?;
    let (device, inode) = identity.split_once(':').ok_or_else(refused)?;
    for number in [device, inode] {
        if number.parse::<u64>().is_err()
            || number.is_empty()
            || !number.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(refused());
        }
    }
    if sockets.is_empty() || !sockets.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused());
    }
    let sockets = sockets.parse::<u16>().map_err(|_| refused())?;
    if sockets > 1024 {
        return Err(refused());
    }
    Ok(Some(PreviousAttempt {
        host,
        transaction,
        identity: (*identity).into(),
        sockets,
        lease_owner,
        enrolled,
        set_aside: None,
    }))
}

fn parse_enrolled(digest: &str, server: &str) -> Result<Option<Enrolled>, Failure> {
    if digest == "-" && server == "-" {
        return Ok(None);
    }
    let bytes = digest.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(refused());
    }
    let mut parsed = [0_u8; 32];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        let nibble = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        parsed[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(Some(Enrolled {
        digest: parsed,
        server: parse_machine(server)?,
    }))
}

fn parse_machine(value: &str) -> Result<String, Failure> {
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('-')
        || value.starts_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(refused());
    }
    Ok(value.to_owned())
}

fn parse_since(value: &str) -> Result<String, Failure> {
    if value == "unknown" {
        return Ok(value.to_owned());
    }
    let bytes = value.as_bytes();
    let separators = [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'Z'),
    ];
    if bytes.len() != 20
        || separators
            .iter()
            .any(|(index, separator)| bytes.get(*index) != Some(separator))
        || bytes.iter().enumerate().any(|(index, byte)| {
            !separators.iter().any(|(at, _)| *at == index) && !byte.is_ascii_digit()
        })
    {
        return Err(refused());
    }
    Ok(value.to_owned())
}

fn parse_pid(value: &str) -> Result<u32, Failure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused());
    }
    let pid = value.parse::<u32>().map_err(|_| refused())?;
    if pid == 0 {
        return Err(refused());
    }
    Ok(pid)
}

fn parse_birth(value: &str) -> Result<u64, Failure> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(refused());
    }
    value.parse::<u64>().map_err(|_| refused())
}

fn parse_active_lock(
    machine: &str,
    pid: &str,
    birth: &str,
    since: &str,
) -> Result<(String, Option<u32>, String), Failure> {
    let machine = parse_machine(machine)?;
    let pid = if pid == "unknown" {
        if birth != "unknown" {
            return Err(refused());
        }
        None
    } else {
        let pid = parse_pid(pid)?;
        parse_birth(birth)?;
        Some(pid)
    };
    Ok((machine, pid, parse_since(since)?))
}

fn parse_lease_owner(
    machine: &str,
    pid: &str,
    birth: &str,
    since: &str,
) -> Result<LeaseOwner, Failure> {
    Ok(LeaseOwner {
        machine: parse_machine(machine)?,
        pid: parse_pid(pid)?,
        birth: parse_birth(birth)?,
        since: parse_since(since)?,
    })
}

fn canonical_id(value: &str) -> Result<uuid::Uuid, Failure> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| refused())?;
    if id.simple().to_string() != value {
        return Err(refused());
    }
    Ok(id)
}

impl PreviousAttempt {
    /// A stale upgrade journal belongs to an already enrolled host and needs replacement.
    #[must_use]
    pub(crate) fn replacement_host(&self) -> Option<uuid::Uuid> {
        self.lease_owner.as_ref().map(|_| self.host)
    }

    /// Preserve lease coordinates when presenting the explicit stuck-upgrade action.
    #[must_use]
    pub(crate) fn stuck_failure(&self, reenroll: bool) -> Failure {
        let failure = Failure::new(
            FailureKind::StalePreviousAttempt,
            "An earlier install stopped while replacing this infraternal agent.",
        );
        if let Some(owner) = &self.lease_owner {
            failure
                .with_setup_lock(
                    owner.machine.clone(),
                    Some(owner.pid),
                    owner.since.clone(),
                    false,
                )
                .with_setup_attempt(Some(self.transaction))
                .with_stuck_install(
                    self.sockets,
                    reenroll.then(|| {
                        self.enrolled
                            .as_ref()
                            .map_or_else(String::new, |enrolled| enrolled.server.clone())
                    }),
                )
        } else {
            failure
        }
    }

    #[must_use]
    pub fn findings(&self, mode: InstallMode, challenge: uuid::Uuid) -> Leftovers {
        let upgrade = self.lease_owner.is_some();
        Leftovers {
            challenge,
            mode,
            findings: vec![
                Cow::Borrowed(if upgrade {
                    "An interrupted upgrade journal"
                } else {
                    "Earlier setup ownership marker"
                }),
                Cow::Borrowed(if upgrade {
                    "The enrolled host identity is kept"
                } else {
                    "Fresh setup ownership journal"
                }),
                // An upgrade journal counts only sessions a live shim serves,
                // and replacing it ends them; say how many (#305, D13).
                match (upgrade, self.sockets) {
                    (false, 0) => Cow::Borrowed("No live setup found"),
                    (false, _) => Cow::Borrowed("Local sockets with no listener"),
                    (true, 0) => Cow::Borrowed("No open terminal sessions"),
                    (true, 1) => Cow::Borrowed("1 open terminal session will end"),
                    (true, open) => Cow::Owned(format!("{open} open terminal sessions will end")),
                },
            ],
        }
    }

    /// Whether Check found an install an earlier attempt set aside, and if so
    /// whether that was a Replace (true) or a Re-enroll (false).
    #[must_use]
    pub(crate) fn set_aside(&self) -> Option<bool> {
        self.set_aside.as_ref().map(|aside| aside.replaced)
    }

    /// The offer to put a set-aside install back as it was found (#305 P2-1).
    #[must_use]
    pub(crate) fn set_aside_failure(&self) -> Failure {
        let failure = Failure::new(
            FailureKind::StalePreviousAttempt,
            "An earlier add-host set this infraternal agent aside and did not put it back.",
        );
        match &self.set_aside {
            Some(aside) => failure
                .with_setup_lock(aside.machine.clone(), None, "unknown".into(), false)
                .with_setup_attempt(Some(self.transaction))
                .with_set_aside(),
            None => failure,
        }
    }

    /// What putting a set-aside install back does.
    #[must_use]
    pub fn set_aside_findings(&self, mode: InstallMode, challenge: uuid::Uuid) -> Leftovers {
        let (enabled, active) = self
            .set_aside
            .as_ref()
            .map_or((false, false), |aside| (aside.enabled, aside.active));
        Leftovers {
            challenge,
            mode,
            findings: vec![
                Cow::Borrowed("An infraternal agent an earlier add-host set aside"),
                Cow::Borrowed("Nothing was deleted; it goes back where it was"),
                Cow::Borrowed(match (enabled, active) {
                    (true, true) => "Its service is enabled and started again, as it was found",
                    (true, false) => "Its service is enabled again but not started, as it was found",
                    (false, true) => "Its service is started again but not enabled, as it was found",
                    (false, false) => "Its service stays stopped and disabled, as it was found",
                }),
            ],
        }
    }

    /// The enrolled identity the host reported for an upgrade journal.
    #[must_use]
    pub(crate) fn enrolled(&self) -> Option<&Enrolled> {
        self.enrolled.as_ref()
    }

    /// Confirmation for joining a machine another server enrolled as a new host (D335).
    #[must_use]
    pub fn reenroll_findings(&self, mode: InstallMode, challenge: uuid::Uuid) -> Leftovers {
        let mut leftovers = self.findings(mode, challenge);
        leftovers.findings[0] = self
            .enrolled
            .as_ref()
            .map_or(Cow::Borrowed("Enrolled with another server"), |enrolled| {
                Cow::Owned(format!("Enrolled with another server: {}", enrolled.server))
            });
        leftovers.findings[1] = Cow::Borrowed(
            "It joins this server as a new host; the old install is set aside, not deleted",
        );
        leftovers
    }

    /// The exact upgrade record every mutating step recompares on the host.
    fn upgrade_record(&self) -> String {
        let owner = self.lease_owner.as_ref();
        let (pid, birth) = owner.map_or((0, 0), |owner| (owner.pid, owner.birth));
        let mut enrolled = String::from("- -");
        if let Some(identity) = &self.enrolled {
            enrolled.clear();
            for byte in identity.digest {
                let _ = std::fmt::Write::write_fmt(&mut enrolled, format_args!("{byte:02x}"));
            }
            enrolled.push(' ');
            enrolled.push_str(&identity.server);
        }
        format!(
            "INFRATERNAL_SETUP_UPGRADE {} {} {} {} {pid} {birth} {} {} {enrolled}",
            self.host.simple(),
            self.transaction.simple(),
            self.identity,
            owner.map_or("", |owner| owner.machine.as_str()),
            owner.map_or("", |owner| owner.since.as_str()),
            self.sockets,
        )
    }

    /// Run one upgrade-journal routine for this exact observed record (#305, D335).
    async fn upgrade_action(
        &self,
        session: &dyn SshSession,
        target: &Target,
        action: &str,
    ) -> Result<(), Failure> {
        target.validate()?;
        let body = format!(
            "{}\n{}\n{INSPECT}\n{action} {}\n",
            crate::install::SETUP_LOCK,
            crate::install::RUNTIME_CLEANUP,
            crate::transport::shell_quote(&self.upgrade_record())
        );
        session
            .run(
                &Installation::script_for(target.mode, self.host, self.transaction, &body),
                Input::Empty,
            )
            .await
            .map_err(classify)?;
        Ok(())
    }

    /// Set aside a stuck install another server enrolled, after the same ordered retirement.
    /// # Errors
    /// Refuses a changed record or live holders; any failure after the stop restores the service.
    pub async fn supersede(
        &self,
        session: &dyn SshSession,
        target: &Target,
    ) -> Result<(), Failure> {
        self.upgrade_action(session, target, "supersede_stuck_install")
            .await
    }

    /// Put a set-aside install back after the new enrollment failed and rolled back.
    /// `replaced` names a Replace (journal only) rather than a Re-enroll (whole install).
    /// Returns false when this transaction was never set aside, so nothing changed.
    /// # Errors
    /// Refuses while any new installation or unit is still in place.
    pub async fn restore_set_aside(
        &self,
        session: &dyn SshSession,
        target: &Target,
        replaced: bool,
    ) -> Result<bool, Failure> {
        target.validate()?;
        let body = format!(
            "{}\n{}\n{INSPECT}\n{} {}\n",
            crate::install::SETUP_LOCK,
            crate::install::RUNTIME_CLEANUP,
            if replaced {
                "restore_replaced_install"
            } else {
                "restore_superseded_install"
            },
            self.transaction.simple()
        );
        let output = session
            .run(
                &Installation::script_for(target.mode, self.host, self.transaction, &body),
                Input::Empty,
            )
            .await
            .map_err(classify)?;
        match output.stdout.as_slice() {
            b"restored\n" => Ok(true),
            b"untouched\n" => Ok(false),
            _ => Err(refused()),
        }
    }

    /// Finish an upgrade whose host is connected with this identity: only its commit was lost.
    /// # Errors
    /// Refuses a changed record.
    pub async fn finish_upgrade(
        &self,
        session: &dyn SshSession,
        target: &Target,
    ) -> Result<(), Failure> {
        self.upgrade_action(session, target, "finish_stuck_upgrade")
            .await
    }

    /// Recover only the exact observed attempt, using its existing rollback implementation.
    /// # Errors
    /// Refuses changed ownership, live setup, foreign contents and unknown journal formats.
    pub async fn start_fresh(
        &self,
        session: &dyn SshSession,
        target: &Target,
    ) -> Result<(), Failure> {
        target.validate()?;
        // Confirmation mutates: it needs the lease routines as well as the guard.
        let setup_lock = crate::install::SETUP_LOCK;
        if self.lease_owner.is_some() {
            return self
                .upgrade_action(session, target, "replace_stuck_install")
                .await;
        }
        let expected = format!(
            "INFRATERNAL_SETUP_STALE {} {} {} {}",
            self.host.simple(),
            self.transaction.simple(),
            self.identity,
            self.sockets
        );
        // Revalidate listeners after ownership reads, immediately before removal.
        // The exact observed record already contains the root identity; reuse its
        // penultimate field rather than allocating another formatted shell argument.
        let body = format!(
            "{setup_lock}\n{}\n{INSPECT}\nsetup_guard\nobserved=$(inspect_previous)\n[ \"$observed\" = {} ] || exit 75\nidentity=${{observed% *}}\nidentity=${{identity##* }}\nnot_live\nretire_control_socket\nfor entry in \"$base/sessions\"/*.sock \"$base/sessions/sessions\"/*.sock; do\n    [ \"$entry\" != \"$base/sessions/plugins.sock\" ] || continue\n    [ ! -S \"$entry\" ] || rm -- \"$entry\"\ndone\n{}\n{}",
            crate::install::RUNTIME_CLEANUP,
            crate::transport::shell_quote(&expected),
            crate::install::FRESH_CLEANUP,
            crate::install::ROLLBACK_TRANSACTION
        );
        session
            .run(
                &Installation::script_for(target.mode, self.host, self.transaction, &body),
                Input::Empty,
            )
            .await
            .map_err(classify)?;
        Ok(())
    }
}

/// Installer-owned statuses are fixed vocabulary; remote output remains withheld.
#[must_use]
// Keep failure-only mapping out of x86_64 async callers for the measured size
// budget; other targets retain their measured code generation [243], #230.
#[cfg_attr(target_arch = "x86_64", cold)]
#[cfg_attr(target_arch = "x86_64", inline(never))]
pub fn classify(mut error: Failure) -> Failure {
    if error.kind != FailureKind::Install {
        return error;
    }
    // Reuse the original failure rather than constructing a temporary failure
    // (and its diagnostic vector) solely to copy two static fields [243].
    error.message = match error.exit_status {
        Some(73) => {
            error.kind = FailureKind::SetupRunning;
            "Setup is already running on this host. Wait for it to finish, then try again."
        }
        Some(75) => REFUSED_MESSAGE,
        Some(71 | 72) => {
            "Host provisioning cannot safely remove these leftovers because their ownership is not proven."
        }
        Some(76) => crate::model::SOCKET_PROBE_UNAVAILABLE,
        Some(77) => crate::model::SOCKET_PROBE_UNCERTAIN,
        _ => return error,
    };
    error.log_tail.clear();
    error
}
const REFUSED_MESSAGE: &str = "The earlier setup journal has an unsupported or changed format. Host provisioning left it untouched.";

/// Map the check's fixed cause token to trusted text; the host never supplies prose (#305).
/// An unknown token keeps the generic refusal rather than echoing remote bytes.
fn refusal_message(cause: &str) -> &'static str {
    match cause {
        "entry" => {
            "The earlier setup lock holds a file this version does not recognize. Host provisioning left it untouched."
        }
        "kind" => {
            "The earlier setup journal records a setup kind this version does not recognize. Host provisioning left it untouched."
        }
        "transaction" => {
            "The earlier setup lock and its journal name different setup attempts. Host provisioning left them untouched."
        }
        "lease" => {
            "The earlier setup lease record is malformed. Host provisioning left it untouched."
        }
        "marker" => {
            "The earlier setup journal's progress markers contradict each other. Host provisioning left it untouched."
        }
        "cache" => {
            "The earlier setup's payload cache has an unrecognized owner record. Host provisioning left it untouched."
        }
        "owner" => {
            "The setup directory's owner record is malformed or names another host. Host provisioning left it untouched."
        }
        "receipt" => {
            "The earlier setup's rollback receipt has an older or changed format. Host provisioning left it untouched."
        }
        "identity" => {
            "The setup directory was replaced after the earlier setup recorded it. Host provisioning left it untouched."
        }
        "unit" => {
            "The earlier infraternal agent's service unit is enabled for an unrecognized target. Host provisioning left it untouched."
        }
        "size" => {
            "The earlier setup left more files, sockets or processes than host provisioning inspects. Host provisioning left it untouched."
        }
        "aside" => {
            "Several earlier installs are set aside beside the setup directory, so it is unclear which to put back. Host provisioning left them untouched."
        }
        "id" => {
            "The earlier setup journal has a malformed host, transaction or session id. Host provisioning left it untouched."
        }
        "tool" => {
            "This host lacks /proc or find, or its setup path contains shell pattern characters, so the earlier setup cannot be inspected safely."
        }
        _ => REFUSED_MESSAGE,
    }
}

fn refused() -> Failure {
    Failure::install(REFUSED_MESSAGE)
}

#[cfg(test)]
mod tests {
    //! Pins the public confirmation text derived from the fixed check records (#305).
    use super::*;

    fn upgrade(sockets: u16) -> PreviousAttempt {
        let record = format!(
            "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z {sockets} - -\n",
            "1".repeat(32),
            "2".repeat(32)
        );
        parse(record.as_bytes()).unwrap().unwrap()
    }

    #[test]
    fn replacement_confirmation_names_the_sessions_it_ends() {
        let finding = |sockets| {
            upgrade(sockets)
                .findings(InstallMode::Rootless, uuid::Uuid::nil())
                .findings[2]
                .clone()
        };
        assert_eq!(finding(0), "No open terminal sessions");
        assert_eq!(finding(1), "1 open terminal session will end");
        assert_eq!(finding(3), "3 open terminal sessions will end");
    }

    #[test]
    fn upgrade_record_round_trips_with_its_enrolled_identity() {
        let digest = "ab".repeat(32);
        let record = format!(
            "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z 2 {digest} old.example\n",
            "1".repeat(32),
            "2".repeat(32)
        );
        let previous = parse(record.as_bytes()).unwrap().unwrap();
        assert_eq!(
            previous.enrolled(),
            Some(&Enrolled {
                digest: [0xab; 32],
                server: "old.example".into()
            })
        );
        assert_eq!(format!("{}\n", previous.upgrade_record()), record);
        assert!(upgrade(0).upgrade_record().ends_with(" 0 - -"));
        for bad in [
            format!("{} old.example", "AB".repeat(32)),
            "- old.example".into(),
            format!("{digest} -bad"),
        ] {
            let record = format!(
                "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z 2 {bad}\n",
                "1".repeat(32),
                "2".repeat(32)
            );
            assert!(parse(record.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_set_aside_install_is_offered_back_by_its_record() {
        let record = format!(
            "INFRATERNAL_SETUP_SET_ASIDE superseded {} {} host yes no\n",
            "1".repeat(32),
            "2".repeat(32)
        );
        let previous = parse(record.as_bytes()).unwrap().unwrap();
        assert_eq!(previous.set_aside(), Some(false));
        assert_eq!(previous.replacement_host(), None, "never a Replace offer");
        let failure = serde_json::to_value(previous.set_aside_failure()).unwrap();
        assert_eq!(failure["setup_lock"]["set_aside"], true);
        assert!(
            failure["message"]
                .as_str()
                .unwrap()
                .contains("set this machine's infraternal agent aside"),
            "{failure}"
        );
        let findings = previous.set_aside_findings(InstallMode::Rootless, uuid::Uuid::nil());
        assert_eq!(
            findings.findings[2],
            "Its service is enabled again but not started, as it was found"
        );
        for bad in ["moved", "superseded-x"] {
            let record = format!(
                "INFRATERNAL_SETUP_SET_ASIDE {bad} {} {} host yes no\n",
                "1".repeat(32),
                "2".repeat(32)
            );
            assert!(parse(record.as_bytes()).is_err(), "{bad}");
        }
        let record = format!(
            "INFRATERNAL_SETUP_SET_ASIDE replaced {} {} host maybe no\n",
            "1".repeat(32),
            "2".repeat(32)
        );
        assert!(parse(record.as_bytes()).is_err());
    }

    #[test]
    fn reenroll_confirmation_names_the_other_server_and_the_sessions() {
        let record = format!(
            "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z 2 {} old.example\n",
            "1".repeat(32),
            "2".repeat(32),
            "ab".repeat(32)
        );
        let previous = parse(record.as_bytes()).unwrap().unwrap();
        let message = serde_json::to_value(previous.stuck_failure(true)).unwrap()["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains("enrolled with another server, old.example."),
            "{message}"
        );
        assert!(message.contains("set aside, not deleted"), "{message}");
        assert!(
            message.ends_with("2 open terminal sessions will end."),
            "{message}"
        );
        let lock = &serde_json::to_value(previous.stuck_failure(true)).unwrap()["setup_lock"];
        assert_eq!(lock["sessions"], 2);
        assert_eq!(lock["enrolled_with"], "old.example");
        assert!(serde_json::to_value(previous.stuck_failure(false)).unwrap()["setup_lock"]["enrolled_with"].is_null());
    }
}
