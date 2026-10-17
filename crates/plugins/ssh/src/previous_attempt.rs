//! Rechecks earlier host provisioning ownership and liveness before explicit recovery [17][139], #169.

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
// Fresh acquisition receipts own only these staging artifacts.
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
            "{}\n{}\n{INSPECT}\ninspect_previous",
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
    if bytes.len() > 512 {
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
    let [
        "INFRATERNAL_SETUP_STALE",
        host,
        transaction,
        identity,
        sockets,
    ] = fields.as_slice()
    else {
        return Err(refused());
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
    let sockets = sockets.parse::<u16>().map_err(|_| refused())?;
    if sockets > 1024 {
        return Err(refused());
    }
    Ok(Some(PreviousAttempt {
        host,
        transaction,
        identity: (*identity).into(),
        sockets,
    }))
}

fn canonical_id(value: &str) -> Result<uuid::Uuid, Failure> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| refused())?;
    if id.simple().to_string() != value {
        return Err(refused());
    }
    Ok(id)
}

impl PreviousAttempt {
    #[must_use]
    pub fn findings(&self, mode: InstallMode, challenge: uuid::Uuid) -> Leftovers {
        Leftovers {
            challenge,
            mode,
            findings: vec![
                "Earlier setup ownership marker",
                "Fresh setup ownership journal",
                if self.sockets == 0 {
                    "No live setup found"
                } else {
                    "Local sockets with no listener"
                },
            ],
        }
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
        let expected = format!(
            "INFRATERNAL_SETUP_STALE {} {} {} {}",
            self.host.simple(),
            self.transaction.simple(),
            self.identity,
            self.sockets
        );
        // Confirmation mutates: it needs the lease routines as well as the guard.
        let setup_lock = crate::install::SETUP_LOCK;
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

fn refused() -> Failure {
    Failure::install(REFUSED_MESSAGE)
}
