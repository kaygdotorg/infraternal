//! Rechecks earlier host provisioning ownership and liveness before explicit recovery [17][139], #169.

use crate::{
    install::Installation,
    model::{Failure, FailureKind, InstallMode, Leftovers, Target},
    probe::{CHECK_SCRIPT, Check},
    transport::{Input, SshSession},
};

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
    let inspect = Installation::script_for(
        mode,
        uuid::Uuid::nil(),
        uuid::Uuid::nil(),
        &format!(
            "{}\n{}\n{INSPECT}\ninspect_previous",
            include_str!("setup_lock.sh"),
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
        let body = format!(
            "{}\n{}\n{INSPECT}\nsetup_guard\nobserved=$(inspect_previous)\n[ \"$observed\" = {} ] || exit 75\n# Revalidate listeners after ownership reads, immediately before removal.\nnot_live\nretire_control_socket\nfor entry in \"$base/sessions\"/*.sock \"$base/sessions/sessions\"/*.sock; do\n    [ ! -S \"$entry\" ] || rm -- \"$entry\"\ndone\n{}\n{}",
            include_str!("setup_lock.sh"),
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
pub fn classify(mut error: Failure) -> Failure {
    if error.kind != FailureKind::Install {
        return error;
    }
    let classified = match error.exit_status {
        Some(73) => Failure::new(
            FailureKind::SetupRunning,
            "Setup is already running on this host. Wait for it to finish, then try again.",
        ),
        Some(75) => refused(),
        Some(71 | 72) => Failure::install(
            "Host provisioning cannot safely remove these leftovers because their ownership is not proven.",
        ),
        _ => return error,
    };
    error.kind = classified.kind;
    error.message = classified.message;
    error.log_tail.clear();
    error
}
fn refused() -> Failure {
    Failure::install(
        "The earlier setup journal has an unsupported or changed format. Host provisioning left it untouched.",
    )
}
