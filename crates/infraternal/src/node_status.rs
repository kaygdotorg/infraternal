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
//!    works. `--data` and `--state` come from the same line, so a node with
//!    non-default paths is read where it really keeps its state.
//! 2. Ask the owning manager for the `ActiveState` of only those units (at most
//!    a few `systemctl show` calls). A manager that does not answer makes that
//!    unit "Unknown"; it never makes the whole node unknown, because the
//!    other manager's units are still readable.
//! 3. Read mesh facts from the public snapshot the mesh writes next to the
//!    runtime state, and the kernel's interface list under `/sys`.
//!
//! No network is touched and no file is written. Every path is injected through
//! [`Roots`] so tests build whole nodes in a temporary directory.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde_json::{Value, json};

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
    /// `--data` argument, when given.
    pub data: Option<PathBuf>,
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
    pub fn detect() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let rooted = nix::unistd::Uid::effective().is_root();
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|home| home.join(".config")));
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|home| home.join(".local/share")));
        let run_dir = if rooted {
            Some(PathBuf::from("/run/infraternal"))
        } else {
            std::env::var_os("XDG_RUNTIME_DIR").map(|dir| PathBuf::from(dir).join("infraternal"))
        };
        let mut data_dirs = vec![PathBuf::from("/var/lib/infraternal")];
        data_dirs.extend(data.map(|data| data.join("infraternal")));
        Self {
            system_units: [
                "/etc/systemd/system",
                "/run/systemd/system",
                "/usr/lib/systemd/system",
            ]
            .map(PathBuf::from)
            .to_vec(),
            user_units: config.map(|config| config.join("systemd/user")),
            run_dir,
            data_dirs,
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

/// Probe the node. `ids` are the registered component ids, in display order.
pub fn probe(
    roots: &Roots,
    ids: &[String],
    activity: &dyn Fn(Scope, &str) -> Activity,
) -> NodeStatus {
    let mut units = discover(roots);
    units.sort_by(|left, right| {
        (left.scope as u8, &left.name).cmp(&(right.scope as u8, &right.name))
    });
    let units: Vec<_> = units
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

fn discover(roots: &Roots) -> Vec<Unit> {
    let mut found: Vec<Unit> = Vec::new();
    let dirs = roots
        .system_units
        .iter()
        .map(|dir| (Scope::System, dir))
        .chain(roots.user_units.iter().map(|dir| (Scope::User, dir)));
    for (scope, dir) in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("infraternal") || !name.ends_with(".service") {
                continue;
            }
            // The first directory that has the name wins, as in the manager.
            if found
                .iter()
                .any(|unit| unit.scope == scope && unit.name == name)
            {
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
    let mut dropins: Vec<_> = fs::read_dir(dir.join(format!("{name}.d")))
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "conf"))
        .collect();
    dropins.sort();
    for path in dropins {
        if let Ok(text) = fs::read_to_string(path) {
            apply(&text);
        }
    }
    let words = split_words(&exec?);
    // `-`/`@`/`+` prefixes are execution modifiers of the program word.
    let subcommand = words
        .iter()
        .skip(1)
        .find(|word| !word.starts_with('-'))
        .map(String::as_str);
    let kind = match subcommand {
        Some("server") => Kind::Server,
        Some("agent") => Kind::Agent,
        _ => return None,
    };
    Some(Unit {
        scope,
        name: name.to_owned(),
        kind,
        data: option(&words, "--data"),
        state: option(&words, "--state"),
    })
}

/// Split on whitespace, honouring the simple double and single quotes used by unit files.
fn split_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    for ch in line.chars() {
        match (quote, ch) {
            (Some(open), ch) if ch == open => quote = None,
            (Some(_), ch) => current.push(ch),
            (None, '"' | '\'') => {
                quote = Some(ch);
                started = true;
            }
            (None, ch) if ch.is_whitespace() => {
                if started || !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, ch) => current.push(ch),
        }
    }
    if started || !current.is_empty() {
        words.push(current);
    }
    words
}

fn option(words: &[String], flag: &str) -> Option<PathBuf> {
    let prefix = format!("{flag}=");
    words.iter().enumerate().find_map(|(index, word)| {
        if word == flag {
            words.get(index + 1).map(PathBuf::from)
        } else {
            word.strip_prefix(&prefix).map(PathBuf::from)
        }
    })
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
    let unit_detail = |unit: &Unit| format!("{} ({})", unit.name, unit.scope.label());
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

/// Mesh state: the kernel interface says whether it is up, the snapshot says how many peers.
fn mesh(units: &[(Unit, Activity)], roots: &Roots) -> Component {
    let link = roots.net_class.join(MESH_INTERFACE).exists();
    let mut dirs: Vec<PathBuf> = units
        .iter()
        .filter_map(|(unit, _)| unit.state.clone())
        .collect();
    dirs.extend(roots.run_dir.clone());
    dirs.extend(units.iter().filter_map(|(unit, _)| unit.data.clone()));
    dirs.extend(roots.data_dirs.clone());
    let mut unreadable = false;
    let mut snapshot: Option<Value> = None;
    for dir in dirs {
        match fs::read(dir.join("mesh-public.json")) {
            Ok(bytes) => {
                if let Ok(value) = serde_json::from_slice(&bytes) {
                    snapshot = Some(value);
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => unreadable = true,
            Err(_) => {}
        }
    }
    let peers = snapshot
        .as_ref()
        .and_then(|value| value.pointer("/config/peers"))
        .and_then(Value::as_object)
        .map(serde_json::Map::len);
    let enabled = snapshot
        .as_ref()
        .and_then(|value| value.get("enabled"))
        .and_then(Value::as_bool);
    let plural = |count: usize| format!("{count} peer{}", if count == 1 { "" } else { "s" });
    match (link, peers, enabled) {
        (true, Some(count), _) => row("mesh", "Running", plural(count)),
        (true, None, _) if unreadable => row("mesh", "Running", "peers need root to read"),
        (true, None, _) => row("mesh", "Running", "peers unknown"),
        (false, _, Some(true)) => row("mesh", "Stopped", "enabled, interface is down"),
        (false, _, Some(false)) => row("mesh", "Stopped", "disabled"),
        (false, ..) => row("mesh", "Not set up", ""),
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
    /// Components as the stable `--json` rows.
    #[must_use]
    pub fn component_rows(&self) -> Vec<Value> {
        self.components
            .iter()
            .map(|c| json!({"name": c.name, "state": c.state, "detail": c.detail}))
            .collect()
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
