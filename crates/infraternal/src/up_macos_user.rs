//! Installs and removes macOS user mode, the default way a Mac joins (#146, D203 C2 as
//! amended 2026-11-20, D395).
//!
//! In user mode the infraternal agent runs as the person at the Mac, from a `LaunchAgent` in
//! their login session, with every file under their `~/Library` (D395):
//!
//! - `~/Library/Application Support/infraternal/agent`: the enrollment (0700);
//! - `~/Library/Application Support/infraternal/state`: mesh state and key (0700);
//! - `~/Library/Application Support/infraternal/bin/infraternal`: the binary;
//! - `~/Library/Logs/infraternal/agent.log`: the agent's output;
//! - `~/Library/LaunchAgents/kayg.infraternal.agent.plist`: the `LaunchAgent`.
//!
//! The mesh needs root for three things only, so `up` installs the on-demand mesh helper
//! ([`infraternal_plugin_mesh::macos_helper`]) with **one** `sudo` prompt, before the approval
//! code is shown, so a refused password never wastes the owner's passkey approval. Then it
//! enrolls as the person (a rootless invitation bound to their uid), publishes the binary and
//! the `LaunchAgent`, and waits until launchd runs it. Any failure before that rolls back this
//! run's own paths and asks the helper to remove itself (no second prompt).
//!
//! Removal (`infraternal --bootstrap-uninstall <host>`, run as the same person) stops the
//! `LaunchAgent`, which closes the utun and with it the mesh routes, asks the helper to remove
//! its resolver files and its own registration, and deletes the files above. It refuses
//! unless the install's receipt names `<host>`.
//!
//! Builds before the move to `kayg.infraternal` (#580) installed under `org.infraternal.*`
//! names. `up` on such a Mac moves it over ([`migrate_agent`]) and removal takes both sets;
//! the install folders, the enrollment and the mesh key keep their paths, so the node keeps its
//! identity.

use super::{
    Failure, JoinMode, SUDO_CANDIDATES, approval_display_is_terminal, fail, join_approval_link,
    local_hostname, machine_key_short, machine_start_body, map_remote_failure, needs_terminal,
    print_approval, server_url, start_approval, take_join_key, trusted_tool, wait_for_approval,
};
use crate::cli::output::{CommandResult, CommandState, Exit, emit};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use infraternal_plugin_mesh::{
    macos_helper,
    macos_local_network::{self, LocalNetwork},
    macos_service::MACHINE_BASE,
    macos_user_mode::{self, AGENT_LABEL, Request, legacy},
};
use serde_json::json;
use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, ErrorKind, Read},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// The root-mode `LaunchDaemon`, under its current and its pre-#580 name; user mode refuses to
/// install beside either.
const ROOT_MODE_PLISTS: [&str; 2] = [macos_user_mode::DAEMON_PLIST, legacy::DAEMON_PLIST];
/// How long `up` waits for launchd to report the agent running.
const START_WAIT: Duration = Duration::from_secs(15);
/// The fixed launchctl, never found through `PATH`.
const LAUNCHCTL: &str = "/bin/launchctl";

/// Where one person's user-mode install lives (D395).
pub(super) struct Paths {
    /// `~/Library/Application Support/infraternal`.
    base: PathBuf,
    /// The enrollment directory.
    data: PathBuf,
    /// The mesh state directory.
    state: PathBuf,
    /// The installed binary.
    binary: PathBuf,
    /// `~/Library/Logs/infraternal`.
    logs: PathBuf,
    /// The `LaunchAgent` property list.
    launch_agent: PathBuf,
    /// The `LaunchAgent` property list of a build before #580, which `up` removes.
    legacy_launch_agent: PathBuf,
}

impl Paths {
    /// The paths for the account `uid`, from its password-database home, never `$HOME`
    /// alone, so a changed environment cannot point the install elsewhere.
    fn for_uid(uid: u32) -> io::Result<Self> {
        let home = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?
            .ok_or(ErrorKind::NotFound)?
            .dir;
        let library = home.join("Library");
        let base = macos_user_mode::user_install_base(&home);
        Ok(Self {
            data: base.join("agent"),
            state: base.join("state"),
            binary: macos_user_mode::user_install_binary(&home),
            logs: library.join("Logs/infraternal"),
            launch_agent: library.join(format!("LaunchAgents/{AGENT_LABEL}.plist")),
            legacy_launch_agent: library
                .join(format!("LaunchAgents/{}.plist", legacy::AGENT_LABEL)),
            base,
        })
    }

    /// The receipt naming this install's host.
    fn receipt(&self) -> PathBuf {
        self.base.join(macos_user_mode::USER_RECEIPT)
    }

    /// The `PATH` line `up` prints, since a per-user Mac install adds no link (D395).
    fn path_line(&self) -> String {
        format!(
            "export PATH=\"{}:$PATH\"",
            self.binary
                .parent()
                .unwrap_or(&self.base)
                .display()
                .to_string()
                .replace('"', "\\\"")
        )
    }
}

/// Whether a path exists, without following a final link.
fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Refuse a Mac where user mode cannot install cleanly, before any prompt or approval.
fn preflight(paths: &Paths, uid: u32) -> io::Result<()> {
    for path in [MACHINE_BASE, ROOT_MODE_PLISTS[0], ROOT_MODE_PLISTS[1]] {
        if exists(Path::new(path))? {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "{path} exists: this Mac runs infraternal in root mode. Remove that installation first, or run infraternal up --system."
                ),
            ));
        }
    }
    for path in [&paths.base, &paths.launch_agent, &paths.legacy_launch_agent] {
        if exists(path)? {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                format!(
                    "{} already exists. Remove the existing installation before running infraternal up again.",
                    path.display()
                ),
            ));
        }
    }
    if let Some(registered) = macos_helper::registered_uid()?
        && registered != uid
    {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "The mesh helper on this Mac belongs to another account. Only one account per Mac can run user mode.",
        ));
    }
    if let Ok(data) = crate::remote::default_data()
        && exists(&data.join("identity.json"))?
    {
        return Err(io::Error::new(
            ErrorKind::AlreadyExists,
            "An infraternal agent identity already exists for this user. Manage that installation instead of running infraternal up.",
        ));
    }
    Ok(())
}

/// Install the mesh helper for `uid` with the one `sudo` prompt of user mode.
fn install_helper(sudo: &Path, executable: &Path, uid: u32) -> Result<(), Failure> {
    eprintln!(
        "infraternal needs your administrator password once, to let its mesh helper create the network interface, one route and a DNS entry."
    );
    let status = Command::new(sudo)
        .arg("--")
        .arg(executable)
        .arg(macos_helper::INSTALL_ENTRY)
        .arg(uid.to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|_| Failure::SudoUnavailable)?;
    if status.success() {
        Ok(())
    } else {
        Err(Failure::SudoDenied)
    }
}

/// Request a fresh user-mode approval, enroll as this person, and start the `LaunchAgent`.
pub(crate) fn run(server_input: &str, json_output: bool) -> ExitCode {
    let server = match server_url(server_input) {
        Ok(server) => server,
        Err(failure) => return fail(json_output, failure),
    };
    let origin = server.origin().ascii_serialization();
    if !approval_display_is_terminal(json_output) {
        return needs_terminal(&origin, json_output);
    }
    let uid = nix::unistd::Uid::current().as_raw();
    if uid == 0 || nix::unistd::Uid::effective().is_root() {
        eprintln!(
            "infraternal up: run this as the person who uses this Mac, without sudo. For a Mac without a logged-in user, use infraternal up --system."
        );
        return fail(json_output, Failure::InstallConflict);
    }
    let Ok(executable) = env::current_exe() else {
        return fail(json_output, Failure::Permission);
    };
    let sudo = match trusted_tool(&SUDO_CANDIDATES, Failure::SudoUnavailable) {
        Ok(sudo) => sudo,
        Err(failure) => return fail(json_output, failure),
    };
    let Ok(paths) = Paths::for_uid(uid) else {
        return fail(json_output, Failure::LocalState);
    };
    if let Some(outcome) = refresh_existing(&paths, uid, &sudo, &executable, json_output) {
        return outcome;
    }
    if let Err(error) = preflight(&paths, uid) {
        eprintln!("{error}");
        return fail(json_output, Failure::InstallConflict);
    }
    if let Err(failure) = install_helper(&sudo, &executable, uid) {
        return fail(json_output, failure);
    }
    // From here every failure also removes the helper this run installed.
    let mut install = Install::new(paths, uid);
    let hostname = local_hostname();
    let result = enroll_and_start(
        &mut install,
        &server,
        &origin,
        &hostname,
        &executable,
        json_output,
    );
    match result {
        Ok((fingerprint, short_key)) => {
            install.committed = true;
            let paths = &install.paths;
            let local_network = wait_for_local_network(&paths.state);
            let path_line = paths.path_line();
            emit(
                CommandResult::new(
                    "up",
                    CommandState::Ready,
                    "This Mac joined the server in user mode and its infraternal agent is running.",
                    json!({
                        "server": origin,
                        "hostname": hostname,
                        "mode": "user",
                        "key_fingerprint": fingerprint,
                        "machine_key": short_key,
                        "service": AGENT_LABEL,
                        "status": "active",
                        "path": paths.binary.display().to_string(),
                        "local_network": local_network.map(LocalNetwork::word),
                    }),
                )
                .with_body(format!(
                    "Mac joined as {hostname} (user mode).\nService: active ({AGENT_LABEL})\nCommand: {}\nAdd it to your PATH:\n  {path_line}",
                    paths.binary.display()
                )),
                json_output,
                Exit::Ok,
            )
        }
        Err(failure) => fail(json_output, failure),
    }
}

/// How long `up` waits for the person to answer the Local Network alert.
const LOCAL_NETWORK_WAIT: Duration = Duration::from_secs(90);

/// Tell the person about the Local Network alert and wait for their answer (#576).
///
/// The user-mode agent is a launchd agent, so macOS asks the person before it may reach hosts
/// on this Mac's own networks; the agent raises that alert as soon as it starts and writes what
/// it learns to its state folder ([`macos_local_network::STATE_FILE`]). `up` waits briefly for
/// the first answer, and when access is not allowed yet, says what to click and waits up to
/// [`LOCAL_NETWORK_WAIT`] for it. It never fails the join: peers across the internet work
/// either way, and the agent keeps checking, so a later Allow works without a restart. Returns
/// the last state seen, if any.
fn wait_for_local_network(state: &Path) -> Option<LocalNetwork> {
    let file = state.join(macos_local_network::STATE_FILE);
    let read = || {
        fs::read_to_string(&file)
            .ok()
            .and_then(|text| LocalNetwork::from_word(&text))
    };
    let poll = |until: Instant, done: &dyn Fn(LocalNetwork) -> bool| {
        let mut last = read();
        while !last.is_some_and(done) && Instant::now() < until {
            // sleep: the agent publishes its answer only through this file.
            std::thread::sleep(Duration::from_millis(250));
            last = read();
        }
        last
    };
    let first = poll(Instant::now() + Duration::from_secs(5), &|_| true);
    if matches!(
        first,
        Some(LocalNetwork::Allowed | LocalNetwork::NoLocalNetwork)
    ) {
        return first;
    }
    eprintln!(
        "macOS asks whether infraternal may find devices on your local network. Click Allow, so this Mac reaches mesh peers on the same network directly. Waiting up to {} seconds…",
        LOCAL_NETWORK_WAIT.as_secs()
    );
    let last = poll(Instant::now() + LOCAL_NETWORK_WAIT, &|state| {
        state == LocalNetwork::Allowed
    });
    if last == Some(LocalNetwork::Allowed) {
        eprintln!("Local Network access allowed.");
    } else {
        eprintln!(
            "Local Network access is not allowed yet. Peers on other networks work; to reach peers on this network, turn on infraternal under System Settings > Privacy & Security > Local Network. No restart is needed."
        );
    }
    last
}

/// Bring an existing user-mode install of this account up to this build, or `None` when there
/// is nothing to refresh (owner, 2026-11-21, review J1027 L3).
///
/// The helper is a root-owned copy of the binary from install time, and it refuses an agent
/// that speaks another protocol version. Without this, an agent update that changed the
/// protocol broke the mesh and `up` refused to repair it ("already exists"), leaving only
/// uninstall and re-join. So when this account already has a user-mode install (its receipt
/// and a helper registered for its uid) and the helper or the installed agent binary differs
/// from the running binary, `up` reinstalls the helper from this binary with one `sudo` prompt,
/// replaces the agent binary, and restarts the agent; the enrollment is kept. Comparing the
/// bytes, not a version number, also carries a fixed helper to Macs whose protocol did not
/// change. When both already match, `None` lets [`preflight`] report the existing install.
fn refresh_existing(
    paths: &Paths,
    uid: u32,
    sudo: &Path,
    executable: &Path,
    json_output: bool,
) -> Option<ExitCode> {
    if !exists(&paths.receipt()).ok()? || macos_helper::registered_uid().ok()? != Some(uid) {
        return None;
    }
    let old_names = legacy::Found {
        agent_plist: exists(&paths.legacy_launch_agent).unwrap_or(true),
        ..macos_helper::legacy_helper_found()
    };
    let old_helper = old_names.helper.plist || old_names.helper.binary || old_names.helper.socket;
    // A `LaunchAgent` the new names lack is unfinished work too (an earlier move that stopped
    // halfway), so a second `up` finishes it.
    let agent_listed = exists(&paths.launch_agent).unwrap_or(false);
    let helper_current =
        !old_helper && same_bytes(Path::new(macos_user_mode::HELPER_BINARY), executable);
    let agent_current =
        !old_names.agent_plist && agent_listed && same_bytes(&paths.binary, executable);
    if helper_current && agent_current {
        return None;
    }
    let moving = old_helper || old_names.agent_plist || !agent_listed;
    if moving {
        eprintln!(
            "infraternal: this Mac runs infraternal under its old names; moving it to kayg.infraternal. Its enrollment and mesh key are kept."
        );
    } else {
        eprintln!(
            "infraternal: this Mac already runs infraternal in user mode with another build; updating its mesh helper and infraternal agent to this one."
        );
    }
    // The helper first: its install also removes an old helper (one `sudo` prompt), and a
    // refused password leaves everything as it was.
    if !helper_current && let Err(failure) = install_helper(sudo, executable, uid) {
        return Some(fail(json_output, failure));
    }
    let refreshed = (|| {
        if !agent_current {
            replace_binary(executable, &paths.binary)?;
        }
        if moving {
            migrate_agent(paths, uid)
        } else {
            restart_agent(uid)
        }
    })();
    let local_network = (moving && refreshed.is_ok())
        .then(|| wait_for_local_network(&paths.state))
        .flatten();
    Some(match refreshed {
        Ok(()) => emit(
            CommandResult::new(
                "up",
                CommandState::Ready,
                "This Mac's user-mode install now runs this build; its enrollment is unchanged.",
                json!({
                    "mode": "user",
                    "refreshed": true,
                    "helper_refreshed": !helper_current,
                    "agent_refreshed": !agent_current,
                    "service": AGENT_LABEL,
                    "status": "active",
                    "path": paths.binary.display().to_string(),
                    "migrated_names": moving,
                    "local_network": local_network.map(LocalNetwork::word),
                }),
            )
            .with_body(format!(
                "User mode updated to this build.\nService: active ({AGENT_LABEL})\nCommand: {}",
                paths.binary.display()
            )),
            json_output,
            Exit::Ok,
        ),
        Err(error) => {
            eprintln!("{error}");
            fail(json_output, Failure::Partial)
        }
    })
}

/// Whether two files hold the same bytes; any read failure counts as different.
fn same_bytes(left: &Path, right: &Path) -> bool {
    let (Ok(mut left), Ok(mut right)) = (fs::File::open(left), fs::File::open(right)) else {
        return false;
    };
    match (left.metadata(), right.metadata()) {
        (Ok(a), Ok(b)) if a.len() == b.len() => {}
        _ => return false,
    }
    let mut a = vec![0_u8; 1 << 16];
    let mut b = vec![0_u8; 1 << 16];
    loop {
        let Ok(read) = left.read(&mut a) else {
            return false;
        };
        if read == 0 {
            return true;
        }
        if right.read_exact(&mut b[..read]).is_err() || a[..read] != b[..read] {
            return false;
        }
    }
}

/// Replace the installed agent binary with `source`, atomically.
///
/// The new image is staged beside the old one with the same checks as a first install
/// (hashed twice, dyld check), then renamed over it, so the running agent keeps its old image
/// until it restarts and a failure leaves the old binary in place.
fn replace_binary(source: &Path, binary: &Path) -> io::Result<()> {
    let mut input = fs::File::open(source)?;
    let staging =
        binary.with_file_name(format!(".infraternal-up-{}.pending", uuid::Uuid::new_v4()));
    let output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&staging)?;
    let staged = super::macos::stage_binary(&mut input, output, &staging)
        .and_then(|()| fs::rename(&staging, binary));
    if staged.is_err() {
        let _ = fs::remove_file(&staging);
    }
    staged
}

/// Restart the user-mode agent so it runs the current binary, and wait until it runs.
fn restart_agent(uid: u32) -> io::Result<()> {
    launchctl_checked(&[
        "kickstart".into(),
        "-k".into(),
        format!("gui/{uid}/{AGENT_LABEL}").into(),
    ])?;
    let deadline = Instant::now() + START_WAIT;
    while !agent_running(uid)? {
        if Instant::now() >= deadline {
            return Err(io::Error::other(
                "launchd did not report the infraternal agent as running after the update",
            ));
        }
        // sleep: launchd exposes job state only through polling.
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(())
}

/// Move the user-mode `LaunchAgent` from the old names to the new ones (#580).
///
/// The old agent is unloaded first, because two agents on one enrollment would fight over the
/// utun and the mesh ports. Then the new property list is written (it names the same binary,
/// enrollment and state, so the node keeps its identity and mesh key), the Local Network
/// answer from the old identity is forgotten so `up` reads the new one, and the new agent is
/// loaded and waited for. The old property list is deleted only once the new agent runs; if it
/// does not, the old agent is loaded again, so a failed move leaves a working Mac. Safe to
/// run again after an interruption, and when only some of the steps are needed.
fn migrate_agent(paths: &Paths, uid: u32) -> io::Result<()> {
    let steps = old_agent_steps(paths)?;
    let old_agent = !steps.is_empty();
    // Unload first; the property list is deleted only once the new agent runs.
    for step in steps
        .iter()
        .filter(|step| **step == legacy::Step::UnloadAgent)
    {
        apply_old_agent_step(paths, uid, *step)?;
    }
    let result = (|| {
        if !exists(&paths.launch_agent)? {
            let log = paths.logs.join("agent.log");
            let plist = macos_user_mode::agent_plist(
                &paths.binary.to_string_lossy(),
                &paths.data.to_string_lossy(),
                &paths.state.to_string_lossy(),
                &log.to_string_lossy(),
            );
            write_new(&paths.launch_agent, plist.as_bytes(), 0o644)?;
        }
        // A new identity gets its own Local Network question; the old answer is not it.
        let _ = fs::remove_file(paths.state.join(macos_local_network::STATE_FILE));
        stop_agent(uid)?;
        launchctl_checked(&[
            "bootstrap".into(),
            format!("gui/{uid}").into(),
            paths.launch_agent.clone().into(),
        ])?;
        let deadline = Instant::now() + START_WAIT;
        while !agent_running(uid)? {
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "launchd did not report the infraternal agent as running after the move",
                ));
            }
            // sleep: launchd exposes job state only through polling.
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    })();
    match result {
        Ok(()) => steps
            .iter()
            .filter(|step| **step == legacy::Step::RemoveAgentPlist)
            .try_for_each(|step| apply_old_agent_step(paths, uid, *step)),
        Err(error) => {
            // Put the old agent back so the Mac keeps its mesh; the new plist stays, and a
            // second `up` finishes the move.
            let _ = stop_agent(uid);
            if old_agent {
                let _ = launchctl_checked(&[
                    "bootstrap".into(),
                    format!("gui/{uid}").into(),
                    paths.legacy_launch_agent.clone().into(),
                ]);
            }
            Err(error)
        }
    }
}

/// The approval, enrollment and activation, all under the install's rollback.
fn enroll_and_start(
    install: &mut Install,
    server: &url::Url,
    origin: &str,
    hostname: &str,
    executable: &Path,
    json_output: bool,
) -> Result<(String, String), Failure> {
    let host_id = uuid::Uuid::new_v4();
    let data = crate::remote::default_data().map_err(|_| Failure::LocalState)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Failure::Runtime)?;
    let key_digest = runtime
        .block_on(crate::remote::prepare_machine_join_key(origin, &data))
        .map_err(|error| map_remote_failure(&error))?;
    let _key_copy = super::PendingKeyCopy(&data);
    let key_pkcs8 = take_join_key(&data)?;
    if crate::remote::key_digest_from_pkcs8(&key_pkcs8).ok() != Some(key_digest) {
        return Err(Failure::LocalState);
    }
    let fingerprint = format!("SHA256:{}", STANDARD_NO_PAD.encode(key_digest));
    let short_key = machine_key_short(&fingerprint).ok_or(Failure::Failed)?;
    let join = JoinMode::User(install.uid);
    let body = machine_start_body(host_id, hostname, &fingerprint, join)?;
    let approval = runtime.block_on(start_approval(server, &body))?;
    let link = join_approval_link(server, &approval.user_code);
    print_approval(json_output, &short_key, &approval.user_code, &link)?;
    let mut invitation = runtime.block_on(wait_for_approval(
        server, &approval, host_id, origin, join, None,
    ))?;
    let invitation_bytes =
        Zeroizing::new(serde_json::to_vec(&invitation.0).map_err(|_| Failure::Failed)?);
    invitation.wipe();
    install.directories().map_err(|error| {
        eprintln!("{error}");
        Failure::LocalState
    })?;
    let join_url = format!("{origin}/remote/join");
    let data_directory = install.paths.data.clone();
    super::termination::run(|_interrupted| async move {
        crate::remote::join_with_key(&join_url, &data_directory, &invitation_bytes, &key_pkcs8)
            .await
            .map_err(|error| map_remote_failure(&error))
    })
    .map_err(|error| {
        eprintln!("{error}");
        Failure::Failed
    })??;
    install.activate(executable, host_id).map_err(|error| {
        eprintln!("{error}");
        Failure::Partial
    })?;
    Ok((fingerprint, short_key))
}

/// One user-mode install in progress; dropped before commit, it undoes this run.
struct Install {
    /// Where the install goes.
    paths: Paths,
    /// The person's uid.
    uid: u32,
    /// Paths this run created, oldest first, removed newest first on rollback.
    created: Vec<PathBuf>,
    /// Set once launchd was asked to load the `LaunchAgent`.
    agent_loaded: bool,
    /// Set once launchd reports the agent running; rollback is then skipped.
    committed: bool,
}

impl Install {
    /// Start tracking an install whose helper is already registered.
    fn new(paths: Paths, uid: u32) -> Self {
        Self {
            paths,
            uid,
            created: Vec::new(),
            agent_loaded: false,
            committed: false,
        }
    }

    /// Create one private directory, recording it if this run made it.
    fn directory(&mut self, path: &Path, mode: u32) -> io::Result<()> {
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {
                self.created.push(path.to_owned());
                fs::set_permissions(path, fs::Permissions::from_mode(mode))
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)?;
                if metadata.is_dir() && metadata.uid() == self.uid && metadata.mode() & 0o022 == 0 {
                    Ok(())
                } else {
                    Err(io::Error::new(
                        ErrorKind::PermissionDenied,
                        format!("{} is not a private folder of this account", path.display()),
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Create the install's folders. The base, enrollment and state are private (0700).
    fn directories(&mut self) -> io::Result<()> {
        let library = self
            .paths
            .logs
            .parent()
            .and_then(Path::parent)
            .ok_or(ErrorKind::InvalidInput)?
            .to_owned();
        let launch_agents = self
            .paths
            .launch_agent
            .parent()
            .ok_or(ErrorKind::InvalidInput)?
            .to_owned();
        let support = self
            .paths
            .base
            .parent()
            .ok_or(ErrorKind::InvalidInput)?
            .to_owned();
        let logs_parent = self
            .paths
            .logs
            .parent()
            .ok_or(ErrorKind::InvalidInput)?
            .to_owned();
        let bin = self
            .paths
            .binary
            .parent()
            .ok_or(ErrorKind::InvalidInput)?
            .to_owned();
        for (path, mode) in [
            (library, 0o700),
            (support, 0o700),
            (logs_parent, 0o700),
            (launch_agents, 0o755),
        ] {
            self.directory(&path, mode)?;
        }
        let base = self.paths.base.clone();
        let data = self.paths.data.clone();
        let state = self.paths.state.clone();
        let logs = self.paths.logs.clone();
        for (path, mode) in [
            (base, 0o700),
            (data, 0o700),
            (state, 0o700),
            (bin, 0o700),
            (logs, 0o700),
        ] {
            self.directory(&path, mode)?;
        }
        Ok(())
    }

    /// Publish the binary, receipt and `LaunchAgent`, start it, and wait until launchd runs it.
    fn activate(&mut self, source: &Path, host: uuid::Uuid) -> io::Result<()> {
        let binary = self.paths.binary.clone();
        let mut input = fs::File::open(source)?;
        if !input.metadata()?.is_file() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "The running image is not a regular file. Run infraternal up from the downloaded binary.",
            ));
        }
        let staging =
            binary.with_file_name(format!(".infraternal-up-{}.pending", uuid::Uuid::new_v4()));
        let output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&staging)?;
        let published = super::macos::publish_binary(&mut input, output, &staging, &binary);
        let _ = fs::remove_file(&staging);
        published?;
        self.created.push(binary.clone());
        let receipt = self.paths.receipt();
        write_new(&receipt, format!("{}\n", host.simple()).as_bytes(), 0o600)?;
        self.created.push(receipt);
        let log = self.paths.logs.join("agent.log");
        let plist = macos_user_mode::agent_plist(
            &binary.to_string_lossy(),
            &self.paths.data.to_string_lossy(),
            &self.paths.state.to_string_lossy(),
            &log.to_string_lossy(),
        );
        let launch_agent = self.paths.launch_agent.clone();
        write_new(&launch_agent, plist.as_bytes(), 0o644)?;
        self.created.push(launch_agent.clone());
        self.agent_loaded = true;
        launchctl_checked(&[
            "bootstrap".into(),
            format!("gui/{}", self.uid).into(),
            launch_agent.into(),
        ])?;
        let deadline = Instant::now() + START_WAIT;
        while !agent_running(self.uid)? {
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "launchd did not report the infraternal agent as running",
                ));
            }
            // sleep: launchd exposes job state only through polling.
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }
}

impl Drop for Install {
    /// An install dropped before commit (error, panic) stops the agent, removes this run's
    /// paths newest first, and asks the helper to remove itself.
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if self.agent_loaded {
            let _ = stop_agent(self.uid);
        }
        for path in self.created.drain(..).rev() {
            let result = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&path),
                Ok(_) => fs::remove_file(&path),
                Err(_) => continue,
            };
            if let Err(error) = result {
                eprintln!(
                    "infraternal: could not remove {} during rollback ({:?}); remove it before retrying.",
                    path.display(),
                    error.kind()
                );
            }
        }
        if let Err(error) = macos_helper::request(&Request::Remove, None) {
            eprintln!(
                "infraternal: the mesh helper could not remove itself ({error}); run sudo {} {} to remove it.",
                macos_helper::installed_binary(),
                macos_helper::REMOVE_ENTRY
            );
        }
    }
}

/// Create a new file with its final mode; an existing path is refused.
fn write_new(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// Run `/bin/launchctl` with a clean environment.
fn launchctl(arguments: &[OsString]) -> io::Result<std::process::Output> {
    Command::new(LAUNCHCTL)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .output()
}

/// Run `/bin/launchctl` and require success.
fn launchctl_checked(arguments: &[OsString]) -> io::Result<()> {
    let output = launchctl(arguments)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "launchctl {} failed: {}",
            arguments
                .first()
                .map(|argument| argument.to_string_lossy())
                .unwrap_or_default(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Whether launchd reports the user-mode agent running in `uid`'s session.
fn agent_running(uid: u32) -> io::Result<bool> {
    let output = launchctl(&["print".into(), format!("gui/{uid}/{AGENT_LABEL}").into()])?;
    Ok(output.status.success()
        && String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line.trim() == "state = running"))
}

/// Unload the user-mode agent; a job that is not loaded is already stopped.
fn stop_agent(uid: u32) -> io::Result<()> {
    stop_agent_label(uid, AGENT_LABEL)
}

/// Unload the agent job named `label` (the current or the pre-#580 one) from `uid`'s session.
fn stop_agent_label(uid: u32, label: &str) -> io::Result<()> {
    let output = launchctl(&["bootout".into(), format!("gui/{uid}/{label}").into()])?;
    let reason = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if output.status.success()
        || reason.contains("no such process")
        || reason.contains("could not find")
    {
        Ok(())
    } else {
        Err(io::Error::other(
            "launchctl could not stop the infraternal agent",
        ))
    }
}

/// The person's own old-name steps of [`legacy::plan`] for this account: what exists now.
fn old_agent_steps(paths: &Paths) -> io::Result<Vec<legacy::Step>> {
    Ok(legacy::plan(legacy::Found {
        agent_plist: exists(&paths.legacy_launch_agent)?,
        ..legacy::Found::default()
    }))
}

/// Carry out one person-level step of [`legacy::plan`]: unload the old `LaunchAgent`, or delete
/// its property list. Root steps belong to the helper's install and are skipped here.
fn apply_old_agent_step(paths: &Paths, uid: u32, step: legacy::Step) -> io::Result<()> {
    match step {
        legacy::Step::UnloadAgent => stop_agent_label(uid, legacy::AGENT_LABEL),
        legacy::Step::RemoveAgentPlist => match fs::remove_file(&paths.legacy_launch_agent) {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
        _ => Ok(()),
    }
}

/// Remove this person's user-mode install when run as `--bootstrap-uninstall <host>`, or as
/// the server-requested [`macos_user_mode::USER_REMOVE_HANDOFF`] child.
///
/// The handoff child is what the agent starts, in its own process group, when the server asks
/// it to uninstall (J1087): it first waits for the one armed byte the agent writes after its
/// reply went out, so a dropped reply removes nothing, then removes the install exactly like
/// the person's own command (which also stops the agent that started it).
///
/// Returns `None` for any other command, for root (root mode has its own removal), and when
/// this account has no user-mode receipt, so the existing removal paths keep their meaning.
#[must_use]
pub(crate) fn uninstall_if_requested() -> Option<ExitCode> {
    let arguments: Vec<OsString> = env::args_os().skip(1).collect();
    let handoff = arguments
        .first()
        .is_some_and(|first| first == macos_user_mode::USER_REMOVE_HANDOFF);
    if arguments.len() != 2 || !(handoff || arguments[0] == "--bootstrap-uninstall") {
        return None;
    }
    let uid = nix::unistd::Uid::current().as_raw();
    if uid == 0 || nix::unistd::Uid::effective().is_root() {
        return None;
    }
    let paths = Paths::for_uid(uid).ok()?;
    if !exists(&paths.receipt()).unwrap_or(false) {
        return None;
    }
    let host = arguments[1].to_str()?;
    if handoff {
        let mut armed = [0_u8];
        if io::stdin().read_exact(&mut armed).is_err() || armed != [1] {
            return Some(ExitCode::FAILURE);
        }
    }
    Some(match uninstall(&paths, uid, host) {
        Ok(()) => {
            println!(
                "infraternal: user mode removed; the mesh route, DNS entry and helper are gone."
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("infraternal: user mode could not be removed completely: {error}");
            ExitCode::FAILURE
        }
    })
}

/// Stop the agent, remove the helper's resolver files and registration, then this person's files.
fn uninstall(paths: &Paths, uid: u32, host: &str) -> io::Result<()> {
    let mut receipt = String::new();
    fs::File::open(paths.receipt())?
        .take(64)
        .read_to_string(&mut receipt)?;
    if !macos_user_mode::receipt_names_host(&receipt, host) {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "this install belongs to another host",
        ));
    }
    stop_agent(uid)?;
    // The old-name agent, if this Mac still has it: unload only; its file goes below.
    let old_steps = old_agent_steps(paths)?;
    for step in old_steps
        .iter()
        .filter(|step| **step == legacy::Step::UnloadAgent)
    {
        apply_old_agent_step(paths, uid, *step)?;
    }
    // An unreadable registration is reported after the person's own files are gone, with the
    // administrator command that removes the helper; it is never read as "no helper" (J1087).
    let helper = match macos_helper::registration_for_current_user() {
        Ok(true) => macos_helper::request(&Request::Remove, None).map(|_| ()),
        Ok(false) => Ok(()),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "the mesh helper registration could not be read ({error}); run sudo {} {} to remove the helper",
                macos_helper::installed_binary(),
                macos_helper::REMOVE_ENTRY
            ),
        )),
    };
    for plist in [&paths.launch_agent, &paths.legacy_launch_agent] {
        match fs::remove_file(plist) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    for directory in [&paths.base, &paths.logs] {
        match fs::remove_dir_all(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    helper
}
