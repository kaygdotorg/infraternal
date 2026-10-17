//! Reads what this node runs from its service unit files and data directories (#237).
//!
//! `infraternal status` must answer from facts on disk, not from a unit's
//! description text or from a service manager that may not be reachable. The
//! probe therefore works in three steps:
//!
//! 1. Find infraternal unit files in the system and user unit directories and
//!    classify each by its effective `ExecStart` (drop-ins included, an empty
//!    `ExecStart=` resets earlier ones). The classification uses the
//!    subcommand (`server` or `agent`), so any unit name and any description
//!    works. `--state` comes from the same line, so a node with a
//!    non-default runtime directory is read where it really keeps its state.
//! 2. Ask the owning manager for the `ActiveState` of only those units (at most
//!    a few `systemctl show` calls). A manager that does not answer makes that
//!    unit "Unknown"; it never makes the whole node unknown, because the
//!    other manager's units are still readable.
//! 3. Read mesh facts from the public snapshot the mesh writes next to the
//!    runtime state, and the kernel's interface list under `/sys`.
//!
//! No network is touched and no file is written. Every path is injected through
//! [`Roots`] so tests build whole nodes in a temporary directory.
//!
//! This is its own crate so that it is built size-optimized like the other
//! management code (D243); it runs once per `status` call, never on a data path.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Mesh interface created by the mesh component.
const MESH_INTERFACE: &str = "infraternal0";

/// Which service manager owns a unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    /// The system manager (rootful nodes).
    System,
    /// The invoking user's manager (rootless nodes).
    User,
}

impl Scope {
    const fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
        }
    }
}

/// What a unit runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `infraternal server`.
    Server,
    /// `infraternal agent`, the host daemon.
    Agent,
}

/// Activity of one unit as its manager reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    /// Running.
    Active,
    /// Installed and not running.
    Inactive,
    /// Exited with an error.
    Failed,
    /// The manager gave no answer.
    Unknown,
}

/// One infraternal unit found on disk.
#[derive(Clone, Debug)]
pub struct Unit {
    /// Owning manager.
    pub scope: Scope,
    /// File name, e.g. `infraternal-server.service`.
    pub name: String,
    /// Server or agent.
    pub kind: Kind,
    /// `--state` argument, when given.
    pub state: Option<PathBuf>,
}

/// Every location the probe reads; tests substitute a temporary tree.
#[derive(Clone, Debug)]
pub struct Roots {
    /// System unit directories, in manager precedence order.
    pub system_units: Vec<PathBuf>,
    /// The user's unit directory, when a home is known.
    pub user_units: Option<PathBuf>,
    /// Runtime state of the default node (`/run/infraternal` or the user's runtime dir).
    pub run_dir: Option<PathBuf>,
    /// Default data directories checked when no unit names one.
    pub data_dirs: Vec<PathBuf>,
    /// Kernel interface list.
    pub net_class: PathBuf,
}

impl Roots {
    /// The real locations of this process.
    #[must_use]
    #[inline(never)]
    pub fn detect() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let rooted = nix::unistd::Uid::effective().is_root();
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|home| home.join(".config")));
        let run_dir = if rooted {
            Some(PathBuf::from("/run/infraternal"))
        } else {
            std::env::var_os("XDG_RUNTIME_DIR").map(|dir| PathBuf::from(dir).join("infraternal"))
        };
        Self {
            // Installers write units to /etc; packaged units elsewhere are not ours.
            system_units: vec![PathBuf::from("/etc/systemd/system")],
            user_units: config.map(|config| config.join("systemd/user")),
            run_dir,
            // A server's database lives here when no unit names it.
            data_dirs: vec![PathBuf::from("/var/lib/infraternal")],
            net_class: PathBuf::from("/sys/class/net"),
        }
    }
}

/// What the node is, from its units and data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Nothing installed.
    None,
    /// Runs the server.
    Server,
    /// Runs the host daemon only.
    Host,
    /// Both.
    Both,
}

impl Role {
    /// What the role runs, for sentences.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Host => "agent",
            Self::Both => "server and agent",
            Self::None => "node",
        }
    }

    /// Stable identifier for `--json`.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Server => "server",
            Self::Host => "host",
            Self::Both => "both",
        }
    }
}

/// One row of the components table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    /// Registered component id.
    pub name: String,
    /// Short state word.
    pub state: String,
    /// Extra fact for the same row (peer count, version, unit).
    pub detail: String,
}

/// The whole answer.
#[derive(Debug)]
pub struct NodeStatus {
    /// Role of this node.
    pub role: Role,
    /// Units found with their activity.
    pub units: Vec<(Unit, Activity)>,
    /// Components, in the order asked for.
    pub components: Vec<Component>,
}

/// Probe the node. Never inlined: the caller is speed-optimized and would copy this body. `ids` are the registered component ids, in display order.
#[inline(never)]
pub fn probe(
    roots: &Roots,
    ids: &[String],
    activity: &dyn Fn(Scope, &str) -> Activity,
) -> NodeStatus {
    let units: Vec<_> = discover(roots)
        .into_iter()
        .map(|unit| {
            let state = activity(unit.scope, &unit.name);
            (unit, state)
        })
        .collect();
    let has = |kind| units.iter().any(|(unit, _)| unit.kind == kind);
    let server_data = has(Kind::Server)
        || roots
            .data_dirs
            .iter()
            .any(|dir| dir.join("infraternal.sqlite").is_file());
    let role = match (server_data, has(Kind::Agent)) {
        (true, true) => Role::Both,
        (true, false) => Role::Server,
        (false, true) => Role::Host,
        (false, false) => Role::None,
    };
    let components = ids
        .iter()
        .map(|id| component(id, role, &units, roots))
        .collect();
    NodeStatus {
        role,
        units,
        components,
    }
}

/// Units in discovery order: system directories first, then the user's. A
/// name seen in an earlier directory of the same scope wins, as in the manager.
fn discover(roots: &Roots) -> Vec<Unit> {
    let mut found: Vec<Unit> = Vec::new();
    let user = roots.user_units.as_ref().map(|dir| (Scope::User, dir));
    for (scope, dir) in roots
        .system_units
        .iter()
        .map(|dir| (Scope::System, dir))
        .chain(user)
    {
        let Ok(mut entries) = fs::read_dir(dir) else {
            continue;
        };
        while let Some(Ok(entry)) = entries.next() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("infraternal") || !name.ends_with(".service") {
                continue;
            }
            if found.iter().any(|u| u.scope == scope && u.name == name) {
                continue;
            }
            if let Some(unit) = read_unit(scope, dir, &name) {
                found.push(unit);
            }
        }
    }
    found
}

/// Classify a unit by its effective `ExecStart`.
fn read_unit(scope: Scope, dir: &Path, name: &str) -> Option<Unit> {
    let mut exec: Option<String> = None;
    let mut apply = |text: &str| {
        for line in text.lines() {
            if let Some(value) = line.trim().strip_prefix("ExecStart=") {
                exec = (!value.trim().is_empty()).then(|| value.trim().to_owned());
            }
        }
    };
    apply(&fs::read_to_string(dir.join(name)).ok()?);
    // Drop-ins apply in file-name order; the directory is small, so insert in place.
    let mut dropins: Vec<PathBuf> = Vec::new();
    if let Ok(mut entries) = fs::read_dir(dir.join(format!("{name}.d"))) {
        while let Some(Ok(entry)) = entries.next() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "conf") {
                let at = dropins
                    .iter()
                    .position(|p| *p > path)
                    .unwrap_or(dropins.len());
                dropins.insert(at, path);
            }
        }
    }
    for path in dropins {
        if let Ok(text) = fs::read_to_string(path) {
            apply(&text);
        }
    }
    let exec = exec?;
    // The first word is the program; the next non-option word is the subcommand.
    let kind = match exec
        .split_whitespace()
        .skip(1)
        .map(|word| word.trim_matches('"'))
        .find(|word| !word.starts_with('-'))
    {
        Some("server") => Kind::Server,
        Some("agent") => Kind::Agent,
        _ => return None,
    };
    Some(Unit {
        scope,
        name: name.to_owned(),
        kind,
        state: option(&exec, "--state"),
    })
}

/// Value of `--flag value` or `--flag=value`. Unit files may quote words; paths
/// containing spaces are not supported by the installer, so quotes are trimmed.
fn option(line: &str, flag: &str) -> Option<PathBuf> {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == flag {
            return words.next().map(|v| PathBuf::from(v.trim_matches('"')));
        }
        if let Some(v) = word.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
            return Some(PathBuf::from(v.trim_matches('"')));
        }
    }
    None
}

fn word(activity: Activity) -> &'static str {
    match activity {
        Activity::Active => "Running",
        Activity::Inactive => "Stopped",
        Activity::Failed => "Failed",
        Activity::Unknown => "Unknown",
    }
}

fn row(name: &str, state: &str, detail: impl Into<String>) -> Component {
    Component {
        name: name.to_owned(),
        state: state.to_owned(),
        detail: detail.into(),
    }
}

fn component(id: &str, role: Role, units: &[(Unit, Activity)], roots: &Roots) -> Component {
    let of = |kind| units.iter().find(|(unit, _)| unit.kind == kind);
    let unit_detail = |unit: &Unit| format!("{} service", unit.scope.label());
    match id {
        "server" => match of(Kind::Server) {
            Some((unit, state)) => row(id, word(*state), unit_detail(unit)),
            None if matches!(role, Role::Server | Role::Both) => {
                row(id, "Stopped", "data found, no service unit")
            }
            None => row(id, "Not installed", ""),
        },
        "agent" | "host" => {
            // The server embeds an agent as its own subprocess, so it is
            // up exactly while the server is.
            let (state, detail) = match (of(Kind::Agent), of(Kind::Server)) {
                (Some((unit, state)), _) => (word(*state), unit_detail(unit)),
                (None, Some((_, state))) => (word(*state), "embedded in the server".to_owned()),
                (None, None) => ("Not installed", String::new()),
            };
            row(id, state, detail)
        }
        "mesh" => mesh(units, roots),
        "release" => {
            if role == Role::None {
                row(id, "Not installed", "")
            } else {
                row(
                    id,
                    "Ready",
                    format!("version {}", env!("CARGO_PKG_VERSION")),
                )
            }
        }
        "ssh" => {
            if matches!(role, Role::Server | Role::Both) {
                row(id, "Ready", "adds hosts over SSH")
            } else {
                row(id, "Server only", "")
            }
        }
        // relay and backup declare their commands only; no runtime exists yet.
        _ => row(id, "Not available yet", ""),
    }
}

/// Peer count from the mesh's public snapshot, read by a bounded scan instead of
/// a JSON parse: parsing would pull a second deserializer into the static binary
/// (D243) for one number. The file is written by our own serializer; a layout
/// this scan cannot follow reads as "unknown", never as a wrong number.
fn peer_count(bytes: &[u8]) -> Option<usize> {
    let key = b"\"peers\"";
    let at = bytes.windows(key.len()).position(|w| w == key)? + key.len();
    let mut rest = bytes[at..]
        .iter()
        .skip_while(|b| b.is_ascii_whitespace() || **b == b':');
    if rest.next() != Some(&b'{') {
        return None;
    }
    let (mut depth, mut count, mut quoted, mut escaped, mut any) = (1_u32, 0, false, false, false);
    for &byte in rest {
        if quoted {
            quoted = escaped || byte != b'"';
            escaped = !escaped && byte == b'\\';
            continue;
        }
        match byte {
            b'"' => (quoted, any) = (true, true),
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(usize::from(any) + count);
                }
            }
            b',' if depth == 1 => count += 1,
            _ => {}
        }
    }
    None
}

/// Mesh state: the kernel interface says whether it is up, the snapshot says how many peers.
fn mesh(units: &[(Unit, Activity)], roots: &Roots) -> Component {
    let link = roots.net_class.join(MESH_INTERFACE).exists();
    let mut dirs: Vec<PathBuf> = units
        .iter()
        .filter_map(|(unit, _)| unit.state.clone())
        .collect();
    dirs.extend(roots.run_dir.clone());
    let mut unreadable = false;
    let mut found = false;
    let mut peers = None;
    for dir in dirs {
        match fs::read(dir.join("mesh-public.json")) {
            Ok(bytes) => {
                found = true;
                peers = peer_count(&bytes);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => unreadable = true,
            Err(_) => {}
        }
    }
    match (link, peers) {
        (true, Some(count)) => row("mesh", "Running", format!("peers: {count}")),
        (true, None) if unreadable => row("mesh", "Running", "peers need root to read"),
        (true, None) => row("mesh", "Running", "peers unknown"),
        (false, _) if found => row("mesh", "Stopped", "interface is down"),
        (false, _) => row("mesh", "Not set up", ""),
    }
}

/// Ask the owning manager for one unit's `ActiveState`; a missing manager is
/// "Unknown" for that unit only. Runs without a shell and with no secrets.
#[must_use]
pub fn manager_activity(scope: Scope, unit: &str) -> Activity {
    let mut command = Command::new("systemctl");
    if scope == Scope::User {
        command.arg("--user");
    }
    let Ok(output) = command
        .args([
            "show",
            "--property=ActiveState",
            "--value",
            "--no-pager",
            unit,
        ])
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return Activity::Unknown;
    };
    if !output.status.success() {
        return Activity::Unknown;
    }
    match String::from_utf8_lossy(&output.stdout).trim() {
        "active" | "reloading" | "activating" => Activity::Active,
        "failed" => Activity::Failed,
        "inactive" | "deactivating" => Activity::Inactive,
        _ => Activity::Unknown,
    }
}

impl NodeStatus {
    /// Units that are installed here and not running: what a script should be told about.
    #[must_use]
    pub fn down(&self) -> Vec<&Unit> {
        self.units
            .iter()
            .filter(|(_, state)| *state != Activity::Active)
            .map(|(unit, _)| unit)
            .collect()
    }

    /// Overall activity, one plain sentence, and the follow-ups that are true now.
    /// A machine with nothing installed is not joined: it reports `Inactive` with how to join.
    #[must_use]
    #[inline(never)]
    pub fn headline(&self) -> (Activity, String, Vec<String>) {
        if self.role == Role::None {
            return (
                Activity::Inactive,
                "This machine is not set up yet.".to_owned(),
                vec![
                    "infraternal agent join <server-url>".to_owned(),
                    "infraternal server init".to_owned(),
                ],
            );
        }
        let overall = self.overall();
        let down = self.down();
        let who = match self.role {
            Role::Server => "The server",
            Role::Host | Role::None => "The infraternal agent",
            Role::Both => "The server and the infraternal agent",
        };
        let plural = self.role == Role::Both;
        let message = if down.is_empty() {
            format!(
                "{who} {} running on this machine.",
                if plural { "are" } else { "is" }
            )
        } else if overall == Activity::Active {
            "Part of this machine's setup is not running.".to_owned()
        } else {
            let state = match (overall, plural) {
                (Activity::Failed, false) => "has failed",
                (Activity::Failed, true) => "have failed",
                (Activity::Unknown, false) => "is not answering",
                (Activity::Unknown, true) => "are not answering",
                (_, false) => "is not running",
                (_, true) => "are not running",
            };
            format!("{who} {state} on this machine.")
        };
        let next = down
            .iter()
            .take(3)
            .map(|unit| match unit.scope {
                Scope::System => format!("systemctl status {}", unit.name),
                Scope::User => format!("systemctl --user status {}", unit.name),
            })
            .collect();
        (overall, message, next)
    }

    /// Overall activity: any running unit means the node is up.
    #[must_use]
    pub fn overall(&self) -> Activity {
        if self
            .units
            .iter()
            .any(|(_, state)| *state == Activity::Active)
        {
            Activity::Active
        } else if self
            .units
            .iter()
            .any(|(_, state)| *state == Activity::Failed)
        {
            Activity::Failed
        } else if self
            .units
            .iter()
            .any(|(_, state)| *state == Activity::Unknown)
        {
            Activity::Unknown
        } else {
            Activity::Inactive
        }
    }
}

#[cfg(test)]
mod tests;
