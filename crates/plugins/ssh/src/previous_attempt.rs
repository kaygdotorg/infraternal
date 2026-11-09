//! Rechecks earlier host provisioning ownership and liveness before explicit recovery [17][139], #169.

use std::{borrow::Cow, fmt::Write as _};

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

/// Maximum public check output, including at most 1024 bounded terminal confirmation records (D368).
pub(crate) const MAX_CHECK_OUTPUT: usize = 512 * 1024;

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
    /// The stuck upgrade's agent is running and started after the journal's
    /// lease: it may be serving and connected to its server now (#305 P2-2).
    live: bool,
    /// This attempt's cancel token, shared by its set-aside and its restore.
    /// A restore that finds nothing moved leaves it on the host, and the
    /// set-aside refuses to start once it is there (#305, J202 P2).
    cancel: Option<uuid::Uuid>,
}

/// A stuck install an earlier attempt set aside, as Check found it (#305 P2-1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct SetAside {
    /// Which action set it aside, so the matching restore puts it back.
    kind: AsideKind,
    machine: String,
    /// Whether its service was enabled and running when it was set aside.
    enabled: bool,
    active: bool,
}

/// What an earlier attempt set aside, which decides how it is put back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AsideKind {
    /// A Replace moved only the stuck journal (`restore_replaced_install`).
    Replaced,
    /// A Re-enroll moved the whole stuck install (`restore_superseded_install`, D335).
    Superseded,
    /// A Take over moved a whole finished install (`restore_taken_over_install`, D359).
    TakenOver,
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
    parse_check_with_absence(bytes).map(|(check, previous, _)| (check, previous))
}

/// What the read-only check found in place of an earlier unfinished setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Remains {
    /// `INFRATERNAL_SETUP_CLEAR`, or a journal record: proves nothing more.
    Unproven,
    /// `INFRATERNAL_SETUP_ABSENT` (D355): the base, unit and launcher each do
    /// not exist, so the account has no infraternal install at all.
    Absent,
    /// `INFRATERNAL_SETUP_INSTALLED …` (#394): a finished install with no
    /// journal. Its `.bootstrap-owner` names a host id this attempt does not
    /// carry, so staging would refuse it (exit 71). The caller answers before
    /// staging: already added here, a Take over (D359), or
    /// [`installed_elsewhere`].
    Installed(FinishedInstall),
}

/// A finished install the check found, as its fixed record names it (#394, D359):
/// `INFRATERNAL_SETUP_INSTALLED <host> <dev:ino> <live|idle> <ready|busy|unproven>`.
/// The whole record is sent back to the host with a Take over, which refuses
/// unless the install is still exactly this one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinishedInstall {
    /// The host id in its `.bootstrap-owner`: the old install's id, which the
    /// Take over confirmation names.
    pub host: uuid::Uuid,
    /// The install root's `device:inode`.
    identity: String,
    /// Its agent's unit is active.
    pub live: bool,
    /// Whether the host may take it over.
    pub takeover: Takeover,
    /// Authenticated terminal records reviewed before any scope is stopped (D368).
    pub terminals: Vec<TakeoverTerminal>,
}

/// A terminal shown on the Take over confirmation, with a private fingerprint binding its scope.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TakeoverTerminal {
    /// The scope's canonical session id, never a service name supplied by the host.
    #[serde(skip)]
    id: uuid::Uuid,
    /// The account running the foreground program.
    pub account: String,
    /// The foreground executable's short name, never its arguments.
    pub program: String,
    /// When the authenticated shim opened this terminal, in Unix seconds.
    pub since: u64,
    /// Binds socket, shim, scope and process identities across the confirmation.
    #[serde(skip)]
    fingerprint: String,
}

impl TakeoverTerminal {
    /// Decode one bounded comma-separated terminal record; names cannot contain shell syntax.
    fn parse(record: &str) -> Result<Self, Failure> {
        let fields: Vec<_> = record.split(',').collect();
        let [id, account, program, since, fingerprint] = fields.as_slice() else {
            return Err(refused());
        };
        let account = decode_terminal_name(account)?;
        let program = decode_terminal_name(program)?;
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refused());
        }
        if since.is_empty()
            || since.starts_with('0')
            || !since.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(refused());
        }
        let since = since.parse::<u64>().map_err(|_| refused())?;
        if since == 0 || since > 253_402_300_799 {
            return Err(refused());
        }
        Ok(Self {
            id: canonical_id(id)?,
            account,
            program,
            since,
            fingerprint: (*fingerprint).into(),
        })
    }

    /// Reproduce the exact host record, including its scope fingerprint.
    fn record(&self) -> String {
        format!(
            "{},{},{},{},{}",
            self.id.simple(),
            encode_terminal_name(&self.account),
            encode_terminal_name(&self.program),
            self.since,
            self.fingerprint
        )
    }
}

/// Decode a printable public name while keeping the host's fixed records free of shell syntax.
fn decode_terminal_name(record: &str) -> Result<String, Failure> {
    if record.is_empty()
        || record.len() > 128
        || !record.len().is_multiple_of(2)
        || !record
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refused());
    }
    let bytes = record
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).map_err(|_| refused())?, 16)
                .map_err(|_| refused())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let name = String::from_utf8(bytes).map_err(|_| refused())?;
    if name.chars().any(char::is_control) {
        return Err(refused());
    }
    Ok(name)
}

/// Reproduce the safe transport encoding of one public terminal name.
fn encode_terminal_name(name: &str) -> String {
    let mut record = String::with_capacity(name.len() * 2);
    for byte in name.as_bytes() {
        let _ = write!(record, "{byte:02x}");
    }
    record
}

/// Whether a finished install may be taken over, as the host proved it (D359).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Takeover {
    /// Root's own install, every part proven infraternal's, and used by
    /// its infraternal agent and authenticated own session scopes: Take over may be offered.
    Ready,
    /// Another holder uses it, or a terminal cannot be safely attributed to its own scope.
    Busy,
    /// Not provably infraternal's, or not root's: never offered.
    Unproven,
}

/// [`parse_check`], plus what the check proved about the account's install
/// ([`Remains`]).
/// # Errors
/// As [`parse_check`].
pub fn parse_check_with_absence(
    bytes: &[u8],
) -> Result<(Check, Option<PreviousAttempt>, Remains), Failure> {
    // Ordinary checks stay below 1 KiB; D368 adds bounded terminal records.
    if bytes.len() > MAX_CHECK_OUTPUT {
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
    let rest = &bytes[end..];
    if rest == b"INFRATERNAL_SETUP_ABSENT\n" {
        return Ok((check, None, Remains::Absent));
    }
    if let Some(record) = rest
        .strip_prefix(b"INFRATERNAL_SETUP_INSTALLED ")
        .and_then(|record| record.strip_suffix(b"\n"))
    {
        let installed = parse_installed(std::str::from_utf8(record).map_err(|_| refused())?)?;
        return Ok((check, None, Remains::Installed(installed)));
    }
    let previous = parse(rest)?;
    Ok((check, previous, Remains::Unproven))
}

/// `<host> <dev:ino> <live|idle> <ready|busy|unproven>`, exactly (D359).
fn parse_installed(record: &str) -> Result<FinishedInstall, Failure> {
    let fields: Vec<&str> = record.split(' ').collect();
    let [host, identity, live, takeover, terminal_records @ ..] = fields.as_slice() else {
        return Err(refused());
    };
    if terminal_records.len() > 1024 {
        return Err(refused());
    }
    let terminals = terminal_records
        .iter()
        .map(|record| TakeoverTerminal::parse(record))
        .collect::<Result<Vec<_>, _>>()?;
    if terminals.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || (!terminals.is_empty() && *takeover != "ready")
    {
        return Err(refused());
    }
    Ok(FinishedInstall {
        terminals,
        host: canonical_id(host)?,
        identity: parse_identity(identity)?,
        live: parse_liveness(live)?,
        takeover: match *takeover {
            "ready" => Takeover::Ready,
            "busy" => Takeover::Busy,
            "unproven" => Takeover::Unproven,
            _ => return Err(refused()),
        },
    })
}

/// A root identity, `device:inode`, both plain decimal numbers.
fn parse_identity(identity: &str) -> Result<String, Failure> {
    let (device, inode) = identity.split_once(':').ok_or_else(refused)?;
    for number in [device, inode] {
        if number.is_empty()
            || !number.bytes().all(|b| b.is_ascii_digit())
            || number.parse::<u64>().is_err()
        {
            return Err(refused());
        }
    }
    Ok(identity.to_owned())
}

/// The answer for [`Remains::Installed`] when Take over is not offered: the
/// machine runs a finished infraternal install for another host id (another
/// server's, another person's on this server, or one whose host was removed
/// here). Setup stops before changing anything, because removing it is a Take
/// over (D359), not leftover cleanup (#394). Reported at the connect step,
/// whose check found it; the location goes in Details.
#[must_use]
pub fn installed_elsewhere(mode: InstallMode) -> Failure {
    let mut failure = Failure::new(FailureKind::UnrecognizedInstall, INSTALLED_ELSEWHERE);
    failure.failed_step = Some(crate::model::InstallStep::Connect);
    failure.log_tail.push(crate::model::setup_location(mode));
    failure
}

/// Public text for [`installed_elsewhere`]; also pinned by the tracer copy test.
/// True in every case it covers: an install of another server, of another
/// person on this server, or of an earlier setup this server retired (J314).
pub const INSTALLED_ELSEWHERE: &str = "This machine already has an infraternal agent from an earlier setup, so nothing was changed. If an infraternal server still lists it, remove it there to uninstall it, then add it here again.";

/// The Take over offer's own words: what was found and what Take over does (D359).
pub const TAKEOVER_OFFER: &str = "This machine already has an infraternal agent from an earlier setup that isn't one of this server's hosts. Take it over to set it up here.";

/// The refusal for a finished install that something still uses (D359).
/// It holds before the stop (nothing touched) and after it (the agent was put
/// back as it was found), so it never claims that nothing changed (J342 P3-4).
pub const TAKEOVER_BUSY: &str = "This machine has an infraternal agent from an earlier setup, and a program is still using it outside the terminal sessions it can safely identify. The old install is kept, but any terminals you confirmed closed stay closed. Stop that program, then try again.";

impl FinishedInstall {
    /// The exact record the host compares before it changes anything.
    fn record(&self) -> String {
        let mut record = format!(
            "INFRATERNAL_SETUP_INSTALLED {} {} {} {}",
            self.host.simple(),
            self.identity,
            if self.live { "live" } else { "idle" },
            match self.takeover {
                Takeover::Ready => "ready",
                Takeover::Busy => "busy",
                Takeover::Unproven => "unproven",
            }
        );
        for terminal in &self.terminals {
            record.push(' ');
            record.push_str(&terminal.record());
        }
        record
    }

    /// The refusal when Take over is not offered: in use ([`TAKEOVER_BUSY`]),
    /// or set up elsewhere ([`installed_elsewhere`]).
    #[must_use]
    pub fn refusal(&self, mode: InstallMode) -> Failure {
        let mut failure = installed_elsewhere(mode);
        if self.takeover == Takeover::Busy {
            failure.message = TAKEOVER_BUSY;
        }
        failure
    }

    /// The paused step that offers Take over and names the old install (D359).
    #[must_use]
    pub(crate) fn takeover_failure(&self, mode: InstallMode) -> Failure {
        let mut failure =
            installed_elsewhere(mode).with_takeover(self.host, self.live, self.terminals.clone());
        failure.message = TAKEOVER_OFFER;
        failure
    }

    /// What confirming Take over does, for the confirmation's Details.
    #[must_use]
    pub(crate) fn takeover_findings(&self, mode: InstallMode, challenge: uuid::Uuid) -> Leftovers {
        let mut leftovers = Leftovers {
            challenge,
            mode,
            findings: vec![
                Cow::Borrowed(
                    "An infraternal agent from an earlier setup that isn't one of this server's hosts",
                ),
                Cow::Borrowed(if self.live {
                    "Its infraternal agent is running; Take over stops it"
                } else {
                    "Its infraternal agent is stopped"
                }),
                Cow::Borrowed(
                    "It is set aside, put back if setup fails, and deleted once this machine has joined",
                ),
            ],
        };
        for terminal in &self.terminals {
            leftovers.findings.push(Cow::Owned(format!(
                "An open terminal: {}, {}; Take over closes it",
                terminal.account, terminal.program
            )));
        }
        leftovers
    }

    /// This install as the attempt that takes it over with `token` sees it:
    /// what the server puts back if the new install fails (D359).
    #[must_use]
    pub(crate) fn taken_over(&self, token: uuid::Uuid) -> PreviousAttempt {
        PreviousAttempt {
            host: self.host,
            transaction: token,
            identity: self.identity.clone(),
            sockets: 0,
            lease_owner: None,
            enrolled: None,
            set_aside: Some(SetAside {
                kind: AsideKind::TakenOver,
                machine: String::new(),
                enabled: false,
                active: false,
            }),
            live: self.live,
            cancel: None,
        }
    }

    /// Set this exact install aside on the host so a fresh one can take its
    /// place (`take_over_finished_install`, D359). `token` names the set-aside;
    /// [`PreviousAttempt::restore_set_aside`] with the same token puts it back.
    /// # Errors
    /// Refuses a changed or busy install, a rootless base and a token whose
    /// restore already ran; any failure after the stop has put it back.
    pub(crate) async fn take_over(
        &self,
        session: &dyn SshSession,
        target: &Target,
        token: uuid::Uuid,
    ) -> Result<(), Failure> {
        target.validate()?;
        let record = format!("{}\n", self.record());
        // A long terminal list travels over stdin, never the operating system's single-argument limit.
        let body = format!(
            "{}\n{}\n{INSPECT}\nIFS= read -r takeover_record\ntake_over_finished_install \"$takeover_record\" {}\n",
            crate::install::SETUP_LOCK,
            crate::install::RUNTIME_CLEANUP,
            token.simple()
        );
        session
            .run(
                &Installation::script_for(target.mode, self.host, token, &body),
                Input::Bytes(record.as_bytes()),
            )
            .await
            .map_err(classify)
            .map_err(|mut error| {
                match error.exit_status {
                    Some(73) => {
                        error.kind = FailureKind::UnrecognizedInstall;
                        error.message = TAKEOVER_BUSY;
                    }
                    Some(75) => {
                        error.kind = FailureKind::UnrecognizedInstall;
                        error.message = "This install or its open terminals changed since you reviewed them. Try again to review it before taking over. Terminals you confirmed closed stay closed.";
                    }
                    _ => {}
                }
                error
            })?;
        Ok(())
    }
}

/// Decode the check's record after its fixed check lines: clear, a refusal, a
/// running setup, a set-aside install, or an earlier attempt to recover.
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
    if let ["INFRATERNAL_SETUP_SET_ASIDE", record @ ..] = fields.as_slice() {
        return parse_set_aside(record).map(Some);
    }
    let (host, transaction, identity, sockets, lease_owner, enrolled, live) =
        match fields.as_slice() {
            [
                "INFRATERNAL_SETUP_STALE",
                host,
                transaction,
                identity,
                sockets,
            ] => (*host, *transaction, *identity, *sockets, None, None, false),
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
                live,
            ] => (
                *host,
                *transaction,
                *identity,
                *sockets,
                Some(parse_lease_owner(machine, pid, birth, since)?),
                parse_enrolled(digest, server)?,
                parse_liveness(live)?,
            ),
            _ => return Err(refused()),
        };
    let host = canonical_id(host)?;
    let transaction = canonical_id(transaction)?;
    let identity = parse_identity(identity)?;
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
        identity,
        sockets,
        lease_owner,
        enrolled,
        set_aside: None,
        live,
        cancel: None,
    }))
}

/// `<superseded|replaced|taken_over> <host> <tx> <machine> <enabled> <active>`:
/// an install an earlier Replace, Re-enroll or Take over set aside and did not
/// put back (#305 P2-1, D359). A Take over's `<tx>` is its token.
fn parse_set_aside(record: &[&str]) -> Result<PreviousAttempt, Failure> {
    let [kind, host, transaction, machine, enabled, active] = record else {
        return Err(refused());
    };
    let flag = |value: &str| match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(refused()),
    };
    let kind = match *kind {
        "replaced" => AsideKind::Replaced,
        "superseded" => AsideKind::Superseded,
        "taken_over" => AsideKind::TakenOver,
        _ => return Err(refused()),
    };
    Ok(PreviousAttempt {
        host: canonical_id(host)?,
        transaction: canonical_id(transaction)?,
        identity: String::new(),
        sockets: 0,
        lease_owner: None,
        enrolled: None,
        live: false,
        cancel: None,
        set_aside: Some(SetAside {
            kind,
            machine: parse_machine(machine)?,
            enabled: flag(enabled)?,
            active: flag(active)?,
        }),
    })
}

/// The upgrade record's last field: `live` or `idle` (#305 P2-2).
fn parse_liveness(value: &str) -> Result<bool, Failure> {
    match value {
        "live" => Ok(true),
        "idle" => Ok(false),
        _ => Err(refused()),
    }
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
        // Only an upgrade journal (it has a lease owner) was replacing an agent;
        // a fresh setup that stopped had nothing to replace (#305, J272).
        let failure = Failure::new(
            FailureKind::StalePreviousAttempt,
            if self.lease_owner.is_some() {
                "An earlier install stopped while replacing this infraternal agent."
            } else {
                "An earlier setup of this host stopped before it finished."
            },
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
                    reenroll && self.live,
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
                // An upgrade journal counts only sessions a live shim serves.
                // A Replace keeps them: the new agent adopts them (D337, D13).
                match (upgrade, self.sockets) {
                    (false, 0) => Cow::Borrowed("No live setup found"),
                    (false, _) => Cow::Borrowed("Local sockets with no listener"),
                    (true, 0) => Cow::Borrowed("No open terminal sessions"),
                    (true, 1) => Cow::Borrowed("1 open terminal session will carry over"),
                    (true, open) => {
                        Cow::Owned(format!("{open} open terminal sessions will carry over"))
                    }
                },
            ],
        }
    }

    /// Whether Check found an install an earlier attempt set aside, and which
    /// action set it aside.
    #[must_use]
    pub(crate) fn set_aside(&self) -> Option<AsideKind> {
        self.set_aside.as_ref().map(|aside| aside.kind)
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
                    (true, false) => {
                        "Its service is enabled again but not started, as it was found"
                    }
                    (false, true) => {
                        "Its service is started again but not enabled, as it was found"
                    }
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

    /// Another server's install whose agent runs with open terminals may be in use
    /// there. The host cannot see whether that agent is connected, so it is not
    /// taken over until ownership of that server can be proven (D337).
    #[must_use]
    pub(crate) fn in_use_elsewhere(&self) -> bool {
        self.live && self.sockets > 0
    }

    /// The refusal for an install [`Self::in_use_elsewhere`] keeps from being taken over.
    #[must_use]
    pub(crate) fn in_use_failure(&self) -> Failure {
        let mut failure = self.stuck_failure(true).in_use_elsewhere();
        // The step's own text: the public message names the server and terminals.
        failure.message = "This machine is in use by another server.";
        failure
    }

    /// Confirmation for joining a machine another server enrolled as a new host (D335).
    #[must_use]
    pub fn reenroll_findings(&self, mode: InstallMode, challenge: uuid::Uuid) -> Leftovers {
        let mut leftovers = self.findings(mode, challenge);
        // An unreadable identity proves no other server: say only what is known.
        leftovers.findings[0] = self.enrolled.as_ref().map_or(
            Cow::Borrowed("An install this server did not enroll; its identity cannot be read"),
            |enrolled| Cow::Owned(format!("Enrolled with another server: {}", enrolled.server)),
        );
        // Sessions authorised by another server are never handed to this
        // one: a Re-enroll ends them (D337).
        leftovers.findings[2] = match self.sockets {
            0 => Cow::Borrowed("No open terminal sessions"),
            1 => Cow::Borrowed("1 open terminal session will end"),
            open => Cow::Owned(format!("{open} open terminal sessions will end")),
        };
        leftovers.findings[1] = if self.live {
            Cow::Borrowed(
                "Its infraternal agent is running and may be connected to that server now; joining here disconnects it",
            )
        } else {
            Cow::Borrowed(
                "It joins this server as a new host; the old install and its key are deleted once it has joined",
            )
        };
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
            "INFRATERNAL_SETUP_UPGRADE {} {} {} {} {pid} {birth} {} {} {enrolled} {}",
            self.host.simple(),
            self.transaction.simple(),
            self.identity,
            owner.map_or("", |owner| owner.machine.as_str()),
            owner.map_or("", |owner| owner.since.as_str()),
            self.sockets,
            if self.live { "live" } else { "idle" },
        )
    }

    /// The same attempt, bound to `cancel`: its set-aside and its restore pass
    /// this token, so the two never both act (#305, J202 P2).
    #[must_use]
    pub(crate) fn with_cancel(mut self, cancel: uuid::Uuid) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// This attempt's cancel token as the host scripts take it, or `-`.
    fn cancel_argument(&self) -> String {
        self.cancel
            .map_or_else(|| "-".to_owned(), |cancel| cancel.simple().to_string())
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
            "{}\n{}\n{INSPECT}\n{action} {} {}\n",
            crate::install::SETUP_LOCK,
            crate::install::RUNTIME_CLEANUP,
            crate::transport::shell_quote(&self.upgrade_record()),
            self.cancel_argument()
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
    /// `kind` names the action that set it aside, and so the restore that undoes it.
    /// Returns false when this transaction was never set aside, so nothing changed.
    /// # Errors
    /// Refuses while any new installation or unit is still in place.
    pub(crate) async fn restore_set_aside(
        &self,
        session: &dyn SshSession,
        target: &Target,
        kind: AsideKind,
    ) -> Result<bool, Failure> {
        target.validate()?;
        // A Take over's token is its transaction and its cancel at once.
        let action = match kind {
            AsideKind::Replaced => "restore_replaced_install",
            AsideKind::Superseded => "restore_superseded_install",
            AsideKind::TakenOver => "restore_taken_over_install",
        };
        let cancel = if kind == AsideKind::TakenOver {
            String::new()
        } else {
            self.cancel_argument()
        };
        let body = format!(
            "{}\n{}\n{INSPECT}\n{action} {} {cancel}\n",
            crate::install::SETUP_LOCK,
            crate::install::RUNTIME_CLEANUP,
            self.transaction.simple(),
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
            "{setup_lock}\n{}\n{INSPECT}\nsetup_guard\nobserved=$(inspect_previous)\n[ \"$observed\" = {} ] || exit 75\nidentity=${{observed% *}}\nidentity=${{identity##* }}\nnot_live\nstop_activated_agent\nretire_control_socket\nfor entry in \"$base/sessions\"/*.sock \"$base/sessions/sessions\"/*.sock; do\n    [ \"$entry\" != \"$base/sessions/plugins.sock\" ] || continue\n    [ ! -S \"$entry\" ] || rm -- \"$entry\"\ndone\n{}\n{}",
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
            "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z {sockets} - - idle\n",
            "1".repeat(32),
            "2".repeat(32)
        );
        parse(record.as_bytes()).unwrap().unwrap()
    }

    #[test]
    fn replacement_confirmation_says_open_sessions_carry_over() {
        let finding = |sockets| {
            upgrade(sockets)
                .findings(InstallMode::Rootless, uuid::Uuid::nil())
                .findings[2]
                .clone()
        };
        assert_eq!(finding(0), "No open terminal sessions");
        assert_eq!(finding(1), "1 open terminal session will carry over");
        assert_eq!(finding(3), "3 open terminal sessions will carry over");
        let message = serde_json::to_value(upgrade(2).stuck_failure(false)).unwrap()["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.ends_with("2 open terminal sessions will carry over."),
            "{message}"
        );
    }

    #[test]
    fn upgrade_record_round_trips_with_its_enrolled_identity() {
        let digest = "ab".repeat(32);
        let record = format!(
            "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z 2 {digest} old.example idle\n",
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
        assert!(upgrade(0).upgrade_record().ends_with(" 0 - - idle"));
        for bad in [
            format!("{} old.example", "AB".repeat(32)),
            "- old.example".into(),
            format!("{digest} -bad"),
        ] {
            let record = format!(
                "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z 2 {bad} idle\n",
                "1".repeat(32),
                "2".repeat(32)
            );
            assert!(parse(record.as_bytes()).is_err(), "{bad}");
        }
    }

    /// D359: the record a Take over sends back is exactly the one Check reported,
    /// the offer names the old install, and only "ready" reads as offerable.
    #[test]
    fn a_finished_install_record_round_trips_into_its_take_over() {
        let line = format!("{} 64:1234 live ready", "a".repeat(32));
        let installed = parse_installed(&line).unwrap();
        assert_eq!(
            installed.record(),
            format!("INFRATERNAL_SETUP_INSTALLED {line}")
        );
        assert_eq!(installed.takeover, Takeover::Ready);
        let offer = serde_json::to_value(installed.takeover_failure(InstallMode::Root)).unwrap();
        assert_eq!(offer["kind"], "unrecognized_install");
        assert_eq!(offer["takeover"]["install"], "a".repeat(32));
        assert_eq!(offer["takeover"]["live"], true);
        assert_eq!(offer["message"], TAKEOVER_OFFER);
        assert!(!TAKEOVER_OFFER.contains('/'), "paths go in Details only");
        let plain = serde_json::to_value(installed.refusal(InstallMode::Root)).unwrap();
        assert!(plain.get("takeover").is_none(), "a refusal offers nothing");
        let busy = parse_installed(&format!("{} 64:1234 idle busy", "a".repeat(32))).unwrap();
        assert_eq!(busy.refusal(InstallMode::Root).message, TAKEOVER_BUSY);
        let taken = installed.taken_over(uuid::Uuid::from_u128(7));
        assert_eq!(taken.set_aside(), Some(AsideKind::TakenOver));
        assert_eq!(
            taken.transaction,
            uuid::Uuid::from_u128(7),
            "the token names the set-aside"
        );
    }

    /// D368: a terminal-bearing offer carries exactly the reviewed metadata back to the host.
    #[test]
    fn terminal_takeover_record_names_what_confirmation_will_close() {
        let terminal = format!(
            "{},726f6f74,62617368,1792195200,7074732f33,2,session-8.scope,{}",
            "3".repeat(32),
            "a".repeat(64)
        );
        let line = format!("{} 64:1234 live ready {terminal}", "1".repeat(32));
        let installed = parse_installed(&line).unwrap();
        assert_eq!(
            installed.record(),
            format!("INFRATERNAL_SETUP_INSTALLED {line}")
        );
        let offer = serde_json::to_value(installed.takeover_failure(InstallMode::Root)).unwrap();
        let shown = &offer["takeover"]["terminals"][0];
        assert_eq!(shown["account"], "root");
        assert_eq!(shown["program"], "bash");
        assert_eq!(shown["since"], 1_792_195_200_u64);
        assert_eq!(shown["tty"], "pts/3");
        assert_eq!(shown["others"], 2);
        assert!(
            shown.get("unit").is_none(),
            "the close unit stays between server and host"
        );
        let findings = installed.takeover_findings(InstallMode::Root, uuid::Uuid::nil());
        assert!(findings.findings.iter().any(|line| line
            == "An open terminal: root, bash on pts/3 and 2 other programs; Take over closes it"));
        for invalid in [
            terminal.replace("726f6f74", "bad name"),
            terminal.replace("62617368", "$(id)"),
            terminal.replace("7074732f33", "7474793031"),
            terminal.replace(",2,", ",02,"),
            terminal.replace(",2,", ",-1,"),
            terminal.replace(",2,", ",1025,"),
            terminal.replace("session-8.scope", "sshd.service"),
            terminal.replace("session-8.scope", "session-8 x.scope"),
            terminal.replace(
                "session-8.scope",
                &format!("infraternal-session-{}.scope", "4".repeat(32)),
            ),
            terminal.replace(",session-8.scope", ""),
            format!("{terminal} {terminal}"),
        ] {
            assert!(
                parse_installed(&format!("{} 64:1234 live ready {invalid}", "1".repeat(32)))
                    .is_err(),
                "{invalid}"
            );
        }
    }

    /// #433: the old layout's own scope still parses, with no terminal name when the kernel had none.
    #[test]
    fn an_old_layout_terminal_record_closes_its_own_scope() {
        let id = "3".repeat(32);
        let terminal = format!(
            "{id},726f6f74,62617368,1792195200,2d,0,infraternal-session-{id}.scope,{}",
            "b".repeat(64)
        );
        let line = format!("{} 64:1234 idle ready {terminal}", "1".repeat(32));
        let installed = parse_installed(&line).unwrap();
        assert_eq!(
            installed.record(),
            format!("INFRATERNAL_SETUP_INSTALLED {line}")
        );
        assert_eq!(installed.terminals[0].tty, None);
        assert_eq!(
            installed.terminals[0].finding(),
            "An open terminal: root, bash; Take over closes it"
        );
    }

    /// A set-aside install's record offers Put it back, and names which restore
    /// puts it back (Re-enroll or Take over, D359); unknown kinds refuse.
    #[test]
    fn a_set_aside_install_is_offered_back_by_its_record() {
        let record = format!(
            "INFRATERNAL_SETUP_SET_ASIDE superseded {} {} host yes no\n",
            "1".repeat(32),
            "2".repeat(32)
        );
        let previous = parse(record.as_bytes()).unwrap().unwrap();
        assert_eq!(previous.set_aside(), Some(AsideKind::Superseded));
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
        // D359: a Take over's set-aside is put back by its own restore, named by its token.
        let record = format!(
            "INFRATERNAL_SETUP_SET_ASIDE taken_over {} {} host yes yes\n",
            "1".repeat(32),
            "7".repeat(32)
        );
        let taken = parse(record.as_bytes()).unwrap().unwrap();
        assert_eq!(taken.set_aside(), Some(AsideKind::TakenOver));
        assert_eq!(taken.transaction.simple().to_string(), "7".repeat(32));
        for bad in ["moved", "superseded-x", "taken-over"] {
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
            "INFRATERNAL_SETUP_UPGRADE {} {} 1:2 host 99 1 2026-11-02T07:48:26Z 2 {} old.example idle\n",
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
        assert!(message.contains("deleted once it has joined"), "{message}");
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
