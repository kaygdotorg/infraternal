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
//! 2. Ask the owning manager for the runtime properties of only those units (at most
//!    two observations per unit, four concurrent `systemctl show` calls). A manager that does not answer makes that
//!    unit "Unknown"; it never makes the whole node unknown, because the
//!    other manager's units are still readable.
//! 3. Read mesh facts from the public snapshot the mesh writes next to the
//!    runtime state, and the kernel's interface list under `/sys`.
//!
//! Headline/exit contract for configured roles (D299/D303). A retained server
//! database establishes the server role even when its unit is masked/missing.
//! A host role needs an installed infraternal-agent unit; an absent unconfigured
//! role is not a failed component. An inactive masked host unit alone does not
//! establish a host role; a running masked unit still does. Masked below means
//! masked and inactive. Disabled below means disabled and inactive;
//! disabling autostart or masking alone never overrides an observed running process.
//!
//! Standalone server or infraternal agent:
//!
//! | State | Headline predicate | Exit |
//! | --- | --- | --- |
//! | active | is running | 0 |
//! | crash-looping | is restarting repeatedly | 5 |
//! | failed | has failed | 5 |
//! | masked / missing / disabled | is not running | 5 |
//! | unknown | status of part of this machine's setup is unknown | 0 |
//!
//! Both configured roles; rows=server, columns=infraternal agent:
//!
//! | | active | looping | failed | masked | missing | disabled | unknown |
//! | --- | --- | --- | --- | --- | --- | --- | --- |
//! | active | R/0 | P/5 | P/5 | S/0 | P/5 | P/5 | U/0 |
//! | looping | P/5 | L/5 | Q/5 | S/5 | Q/5 | Q/5 | X/5 |
//! | failed | P/5 | Q/5 | F/5 | S/5 | P/5 | P/5 | X/5 |
//! | masked | P/5 | Q/5 | P/5 | S/5 | D/5 | D/5 | X/5 |
//! | missing | P/5 | Q/5 | P/5 | S/5 | D/5 | D/5 | X/5 |
//! | disabled | P/5 | Q/5 | P/5 | S/5 | D/5 | D/5 | X/5 |
//! | unknown | U/0 | X/5 | X/5 | S/0 | X/5 | X/5 | U/0 |
//!
//! S: only the server role is configured; use its standalone headline/exit.
//! R/L/F/D: both running/restarting repeatedly/failed/not running on this
//! machine. P: "Part of this machine's setup is not running." Q: "Part of
//! this machine's setup is restarting repeatedly." U: "The status of part of
//! this machine's setup is unknown." X: "Part of this machine's setup is not
//! running; another status is unknown." Any known down role prevents a Running
//! envelope; an unanswered manager alone retains the established Unknown/0.
//!
//! No network is touched and no file is written. Every path is injected through
//! [`Roots`] so tests build whole nodes in a temporary directory.
//!
//! This is its own crate so that it is built size-optimized with the other
//! management code (D243). The status probe and installed-data lookup run only
//! for their respective CLI commands, never on a data path.

#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Mesh interface created by the mesh component.
const MESH_INTERFACE: &str = "infraternal0";

/// Allow process startup and two local responses under CPU contention (#312).
/// A 25 ms response exceeded 40 ms in 51/100 loaded-host samples (86 ms max).
/// Half a second leaves scheduling margin for both observations; child-exit
/// readiness still returns immediately. Admission uses the same bound, so a
/// stalled manager cannot multiply the wait by the number of installed units.
const MANAGER_QUERY_BUDGET: std::time::Duration = std::time::Duration::from_millis(500);

/// The budget in force. Debug builds let integration tests widen it, because
/// a 470 MB debug binary page-faulting on a contended build disk can spend
/// seconds inside the window (#334); release builds always use the constant.
fn manager_query_budget() -> std::time::Duration {
    #[cfg(debug_assertions)]
    if let Some(milliseconds) = std::env::var("INFRATERNAL_TEST_MANAGER_QUERY_BUDGET_MS")
        .ok()
        .and_then(|value| value.parse().ok())
    {
        return std::time::Duration::from_millis(milliseconds);
    }
    MANAGER_QUERY_BUDGET
}

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
    /// Repeated restarts, with the last observed main-process exit.
    Restarting {
        /// systemd wait code: 1 exited, 2 signalled, 3 core dumped; 0 unavailable.
        code: u32,
        /// Exit status or signal number.
        status: i32,
    },
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
    /// A canonical installer unit masked on disk is unavailable by configuration.
    masked: bool,
    /// Plain local query failure, without manager output or sensitive arguments.
    pub query_error: Option<&'static str>,
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
        // Debug builds expose a fixture root to CLI integration tests; release
        // builds always read the installer-owned system unit directory.
        let system_units = {
            #[cfg(debug_assertions)]
            if let Some(directory) = std::env::var_os("INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR") {
                vec![PathBuf::from(directory)]
            } else {
                vec![PathBuf::from("/etc/systemd/system")]
            }
            #[cfg(not(debug_assertions))]
            {
                vec![PathBuf::from("/etc/systemd/system")]
            }
        };
        Self {
            // Installers write units to /etc; packaged units elsewhere are not ours.
            system_units,
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
    assemble(roots, ids, units)
}

/// Assemble component facts after every unit has kept its own observation.
fn assemble(roots: &Roots, ids: &[String], mut units: Vec<(Unit, Activity)>) -> NodeStatus {
    // A bare host-service mask carries no installed ExecStart or retained data.
    // Only an observed live service establishes that role despite the mask.
    units.retain(|(unit, state)| {
        !unit.masked
            || unit.kind == Kind::Server
            || matches!(state, Activity::Active | Activity::Restarting { .. })
    });
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

/// Query with at most four 128 KiB workers and four manager children. Each
/// scope reserves two workers, so a stalled system manager cannot exhaust the
/// user's capacity. Admission ends after 500 ms; each admitted unit has its own
/// 500 ms deadline (including any second observation). Unqueried/refused work
/// stays Unknown with a reason; neither spawn nor join is a panic path.
#[must_use]
pub fn probe_local(roots: &Roots, ids: &[String]) -> NodeStatus {
    let mut units: Vec<_> = discover(roots)
        .into_iter()
        .map(|mut unit| {
            unit.query_error = Some("service query worker unavailable");
            let state = Activity::Unknown;
            (unit, state)
        })
        .collect();
    let admission = std::time::Instant::now() + manager_query_budget();
    // Discovery orders system units before user units. Keep observations in
    // that order, so component rows and diagnostics use the same first unit.
    let system = units.partition_point(|(unit, _)| unit.scope == Scope::System);
    std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(4);
        let (system, user) = units.split_at_mut(system);
        for group in [system, user] {
            let chunk_size = group.len().div_ceil(2).max(1);
            for chunk in group.chunks_mut(chunk_size) {
                let worker = std::thread::Builder::new()
                    .stack_size(128 * 1024)
                    .spawn_scoped(scope, move || {
                        for (unit, state) in chunk {
                            if std::time::Instant::now() >= admission {
                                unit.query_error = Some("service query capacity exhausted");
                                continue;
                            }
                            match manager_activity_result(unit.scope, &unit.name) {
                                Ok(activity) => {
                                    *state = activity;
                                    unit.query_error = None;
                                }
                                Err(reason) => unit.query_error = Some(reason),
                            }
                        }
                    });
                if let Ok(worker) = worker {
                    workers.push(worker);
                }
            }
        }
        // Explicitly join even a panicked worker, preventing scope's automatic
        // join from unwinding the status command. Its unfinished rows stay unknown.
        for worker in workers {
            let _ = worker.join();
        }
    });
    assemble(roots, ids, units)
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
            if let Some(unit) = read_unit(scope, dir, &name, false) {
                found.push(unit);
            }
        }
    }
    found
}

/// Return the data directory configured by an installed system server unit.
///
/// Unlike status discovery, this lookup considers custom unit names because
/// `server init --name` lets the installer choose one. It reads only system
/// service files and their drop-ins, where the installer records the absolute
/// `--data` path. User units do not override a system install.
#[must_use]
pub fn server_data_directory(roots: &Roots) -> Option<PathBuf> {
    let mut seen = HashSet::new();
    for directory in &roots.system_units {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".service"))
            .collect();
        names.sort_unstable();
        for name in names {
            if !seen.insert(name.clone()) {
                continue;
            }
            let Some(unit) = read_unit(Scope::System, directory, &name, true) else {
                continue;
            };
            if let (Kind::Server, Some(data)) =
                (unit.kind, unit.data.filter(|path| path.is_absolute()))
            {
                return Some(data);
            }
        }
    }
    None
}

/// Classify a unit by its effective `ExecStart`.
fn read_unit(scope: Scope, dir: &Path, name: &str, require_infraternal: bool) -> Option<Unit> {
    // A mask erases ExecStart, but canonical installer names still identify
    // their configured role. Never guess the role of a masked custom name.
    if fs::canonicalize(dir.join(name)).is_ok_and(|path| path == Path::new("/dev/null")) {
        let kind = match name {
            "infraternal-server.service" => Kind::Server,
            "infraternal-agent.service" => Kind::Agent,
            _ => return None,
        };
        return Some(Unit {
            scope,
            name: name.to_owned(),
            kind,
            data: None,
            state: None,
            masked: true,
            query_error: None,
        });
    }
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
    let words = exec.as_deref().and_then(exec_words)?;
    let program = Path::new(words.first()?);
    if require_infraternal && !is_infraternal_program(program) {
        return None;
    }
    // Exact subcommand words preserve support for global flags before the
    // command; quoted data paths remain one word and cannot match by substring.
    let kind = words.iter().skip(1).find_map(|word| match word.as_str() {
        "server" => Some(Kind::Server),
        "agent" => Some(Kind::Agent),
        _ => None,
    })?;
    Some(Unit {
        scope,
        name: name.to_owned(),
        kind,
        data: option(&words, "--data"),
        state: option(&words, "--state"),
        masked: false,
        query_error: None,
    })
}

/// The installer records the resolved executable, which may have a versioned name.
/// Accept that identity as well as the ordinary command name; an arbitrary
/// program with a `server` argument must not select this CLI's data directory.
fn is_infraternal_program(program: &Path) -> bool {
    program
        .file_name()
        .is_some_and(|name| name == "infraternal")
        || (program.is_absolute()
            && std::env::current_exe().is_ok_and(|current| {
                program == current
                    || fs::canonicalize(program).is_ok_and(|resolved| resolved == current)
            }))
}

/// Split the installer-generated systemd command into its arguments.
///
/// systemd quotes paths with spaces and backslash-escapes embedded quotes and
/// backslashes. Unclosed quotes or a trailing escape are rejected so callers
/// fall back to the ordinary data directory instead of guessing.
fn exec_words(line: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut started = false;
    for character in line.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            started = true;
        } else if character == '\\' {
            escaped = true;
            started = true;
        } else if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                word.push(character);
            }
        } else if matches!(character, '"' | '\'') {
            quote = Some(character);
            started = true;
        } else if character.is_whitespace() {
            if started {
                words.push(std::mem::take(&mut word));
                started = false;
            }
        } else {
            word.push(character);
            started = true;
        }
    }
    if escaped || quote.is_some() {
        return None;
    }
    if started {
        words.push(word);
    }
    Some(words)
}

/// Value of `--flag value` or `--flag=value` in parsed unit arguments.
fn option(words: &[String], flag: &str) -> Option<PathBuf> {
    for (index, word) in words.iter().enumerate() {
        if word == flag {
            return words.get(index + 1).map(PathBuf::from);
        }
        if let Some(v) = word.strip_prefix(flag).and_then(|r| r.strip_prefix('=')) {
            return Some(PathBuf::from(v));
        }
    }
    None
}

fn word(activity: Activity) -> &'static str {
    match activity {
        Activity::Active => "Running",
        Activity::Restarting { .. } => "Restarting repeatedly",
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
    let unit_detail = |unit: &Unit, activity: Activity| {
        let scope = unit.scope.label();
        if unit.masked {
            format!("{scope} service; service is masked")
        } else if let Activity::Restarting { code, status } = activity {
            match code {
                1 => format!("{scope} service; last exit status {status}"),
                2 | 3 => format!("{scope} service; last signal {status}"),
                _ => format!("{scope} service; last exit unavailable"),
            }
        } else if let Some(reason) = unit.query_error {
            format!("{scope} service; {reason}")
        } else {
            format!("{scope} service")
        }
    };
    match id {
        "server" => match of(Kind::Server) {
            Some((unit, state)) => row(id, word(*state), unit_detail(unit, *state)),
            None if matches!(role, Role::Server | Role::Both) => {
                row(id, "Stopped", "data found, no service unit")
            }
            None => row(id, "Not installed", ""),
        },
        "agent" | "host" => {
            // The server embeds an agent as its own subprocess, so it is
            // up exactly while the server is.
            let (state, detail) = match (of(Kind::Agent), of(Kind::Server)) {
                (Some((unit, state)), _) => (word(*state), unit_detail(unit, *state)),
                (None, Some((unit, state))) => (
                    word(*state),
                    if matches!(state, Activity::Restarting { .. }) {
                        unit_detail(unit, *state) + "; embedded in the server"
                    } else {
                        "embedded in the server".to_owned()
                    },
                ),
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

/// A single manager observation. Borrowed properties keep the CLI-only parser small.
#[derive(Default)]
struct Observation<'a> {
    active: &'a str,
    sub: &'a str,
    restarts: u64,
    started: u64,
    pid: u32,
    code: u32,
    status: i32,
}

impl<'a> Observation<'a> {
    fn read(text: &'a str) -> Self {
        let mut value = Self::default();
        for line in text.lines() {
            let Some((key, field)) = line.split_once('=') else {
                continue;
            };
            match key {
                "ActiveState" => value.active = field,
                "SubState" => value.sub = field,
                "NRestarts" => value.restarts = field.parse().unwrap_or(0),
                "ExecMainStartTimestampMonotonic" => {
                    value.started = field.parse().unwrap_or(0);
                }
                "MainPID" => value.pid = field.parse().unwrap_or(0),
                "ExecMainCode" => value.code = field.parse().unwrap_or(0),
                "ExecMainStatus" => value.status = field.parse().unwrap_or(0),
                _ => {}
            }
        }
        value
    }

    fn recent(&self, now: u64) -> bool {
        self.started != 0
            && now
                .checked_sub(self.started)
                .is_some_and(|age| age <= 10_000_000)
    }

    fn activity(&self, previous: Option<&Self>, now: u64) -> Activity {
        // A failed/stopped unit stays failed/stopped, even if it restarted before.
        // Historical restart counts alone never condemn a recovered service.
        if matches!(self.active, "active" | "activating" | "reloading") {
            let changed = previous.is_some_and(|old| {
                self.restarts > old.restarts
                    || (old.pid != 0 && self.pid != 0 && self.pid != old.pid)
            });
            if self.sub == "auto-restart"
                || self.sub == "auto-restart-queued"
                || changed
                || (self.restarts >= 2 && self.recent(now))
            {
                return Activity::Restarting {
                    code: self.code,
                    status: self.status,
                };
            }
            // Without a comparable start time, historical restart counts cannot
            // prove either a stable process or a recent loop. Preserve unknown.
            if self.restarts >= 2 && (self.started == 0 || now < self.started) {
                return Activity::Unknown;
            }
        }
        match self.active {
            "active" | "reloading" => Activity::Active,
            "failed" => Activity::Failed,
            "inactive" | "deactivating" => Activity::Inactive,
            // Starting is not evidence that a process is running yet.
            _ => Activity::Unknown,
        }
    }
}

/// Ask only the owning local manager. The deadline includes a second observation
/// for a newly started process, without a sampling sleep or network request.
#[must_use]
pub fn manager_activity(scope: Scope, unit: &str) -> Activity {
    manager_activity_result(scope, unit).unwrap_or(Activity::Unknown)
}

fn manager_activity_result(scope: Scope, unit: &str) -> Result<Activity, &'static str> {
    manager_activity_before(
        scope,
        unit,
        std::time::Instant::now() + manager_query_budget(),
    )
}

fn manager_activity_before(
    scope: Scope,
    unit: &str,
    deadline: std::time::Instant,
) -> Result<Activity, &'static str> {
    let first = manager_properties(scope, unit, deadline)?;
    let first = Observation::read(&first);
    // systemd reports this property in microseconds of CLOCK_MONOTONIC.
    // Wall time and boot time include different clock adjustments/suspends.
    let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .ok()
        .and_then(|time| {
            use nix::sys::time::TimeValLike;
            u64::try_from(time.num_microseconds()).ok()
        })
        .unwrap_or(0);
    let activity = first.activity(None, now);
    if activity == Activity::Active && first.recent(now) {
        // Only a fresh start needs another immediate look. Old healthy services
        // cost one local query; the restart window expires without saved state.
        let second = manager_properties(scope, unit, deadline)?;
        return known_activity(Observation::read(&second).activity(Some(&first), now));
    }
    known_activity(activity)
}

fn known_activity(activity: Activity) -> Result<Activity, &'static str> {
    if activity == Activity::Unknown {
        Err("service manager did not provide a readable runtime state")
    } else {
        Ok(activity)
    }
}

fn manager_properties(
    scope: Scope,
    unit: &str,
    deadline: std::time::Instant,
) -> Result<String, &'static str> {
    if std::time::Instant::now() >= deadline {
        return Err("service manager query timed out");
    }
    #[cfg(test)]
    let mut command = Command::new(
        tests::MANAGER_PROGRAM
            .with(|program| program.borrow().clone())
            .unwrap_or_else(|| "systemctl".into()),
    );
    #[cfg(not(test))]
    let mut command = Command::new("systemctl");
    if scope == Scope::User {
        command.arg("--user");
    }
    let mut child = command.args([
        "show",
        "--property=ActiveState,SubState,NRestarts,MainPID,ExecMainStartTimestampMonotonic,ExecMainCode,ExecMainStatus",
        "--no-pager", unit,
    ]).env("LC_ALL", "C").env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null()).stderr(Stdio::null()).stdout(Stdio::piped()).spawn().map_err(|_| "could not start the service manager query")?;
    let status = wait_manager_child(&mut child, deadline);
    if let Ok(status) = status {
        let output = child
            .wait_with_output()
            .map_err(|_| "could not read the service manager response")?;
        if status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err("service manager query was refused")
        }
    } else {
        // Reap only the process this probe started. An unresponsive
        // manager is unknown, never grounds to claim a running service.
        let _ = child.kill();
        let _ = child.wait();
        Err("service manager query timed out")
    }
}

/// Wait for this owned child's exit, keeping both observations on one deadline.
/// The unreaped child pins its PID, so opening its lifetime descriptor cannot
/// subscribe to a reused PID. Readiness wakes immediately without a sampling tick.
fn wait_manager_child(
    child: &mut std::process::Child,
    deadline: std::time::Instant,
) -> Result<std::process::ExitStatus, ()> {
    #[cfg(target_os = "linux")]
    if let Ok(descriptor) = infraternal_shim::process_exit_descriptor(child.id()) {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;

        let mut fds = [PollFd::new(descriptor.as_fd(), PollFlags::POLLIN)];
        loop {
            let left = deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or(())?;
            // poll uses milliseconds; round up so sub-millisecond budget
            // never becomes a busy loop or an early timeout.
            let millis = left.as_nanos().div_ceil(1_000_000);
            let timeout = PollTimeout::try_from(millis).map_err(|_| ())?;
            match poll(&mut fds, timeout) {
                Ok(0) => return Err(()),
                Ok(_)
                    if fds[0]
                        .revents()
                        .is_some_and(|flags| flags.contains(PollFlags::POLLIN)) =>
                {
                    return child.wait().map_err(|_| ());
                }
                Err(nix::errno::Errno::EINTR) => {}
                _ => return Err(()),
            }
        }
    }
    // Non-Linux hosts, older kernels and denied/unavailable exit descriptors
    // retain the existing bounded fallback. Readiness registration failure
    // alone must not hide a manager response that was previously readable.
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            _ => return Err(()),
        }
    }
}

impl NodeStatus {
    /// Installed observations plus configured roles whose service disappeared.
    fn activities(&self) -> impl Iterator<Item = Activity> + '_ {
        self.units.iter().map(|(_, state)| *state).chain(
            (matches!(self.role, Role::Server | Role::Both)
                && !self.units.iter().any(|(unit, _)| unit.kind == Kind::Server))
            .then_some(Activity::Inactive),
        )
    }

    /// Count every configured role known down, including a missing server unit.
    #[must_use]
    pub fn confirmed_down_count(&self) -> usize {
        self.activities()
            .filter(|state| {
                matches!(
                    state,
                    Activity::Inactive | Activity::Failed | Activity::Restarting { .. }
                )
            })
            .count()
    }

    /// Units that are installed here and not running: what a script should be told about.
    #[must_use]
    pub fn down(&self) -> Vec<&Unit> {
        self.units
            .iter()
            .filter(|(_, state)| *state != Activity::Active)
            .map(|(unit, _)| unit)
            .collect()
    }

    /// Units that are confirmed unavailable (stopped, failed or restarting). A unit whose manager gave no
    /// answer is unknown, not down: `status` exits 5 only for what is known to be down (D303).
    #[must_use]
    pub fn confirmed_down(&self) -> Vec<&Unit> {
        self.units
            .iter()
            .filter(|(_, state)| {
                matches!(
                    state,
                    Activity::Inactive | Activity::Failed | Activity::Restarting { .. }
                )
            })
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
        let down = self.confirmed_down_count();
        let active = self.activities().any(|state| state == Activity::Active);
        let has_unknown = self
            .units
            .iter()
            .any(|(_, state)| *state == Activity::Unknown);
        let who = match self.role {
            Role::Server => "The server",
            Role::Host | Role::None => "The infraternal agent",
            Role::Both => "The server and the infraternal agent",
        };
        let plural = self.role == Role::Both;
        let message = if down == 0 && (overall == Activity::Active || has_unknown) {
            if has_unknown {
                "The status of part of this machine's setup is unknown.".to_owned()
            } else {
                format!(
                    "{who} {} running on this machine.",
                    if plural { "are" } else { "is" }
                )
            }
        } else if active {
            "Part of this machine's setup is not running.".to_owned()
        } else if has_unknown {
            "Part of this machine's setup is not running; another status is unknown.".to_owned()
        } else if plural
            && matches!(overall, Activity::Restarting { .. })
            && self
                .activities()
                .any(|state| !matches!(state, Activity::Restarting { .. }))
        {
            // A grouped headline must not turn another stopped/failed role
            // into a second restart loop; component rows keep their own facts.
            "Part of this machine's setup is restarting repeatedly.".to_owned()
        } else if plural
            && !matches!(overall, Activity::Restarting { .. })
            && self.activities().any(|state| state != overall)
        {
            "Part of this machine's setup is not running.".to_owned()
        } else {
            let state = match (overall, plural) {
                (Activity::Restarting { .. }, false) => "is restarting repeatedly",
                (Activity::Restarting { .. }, true) => "are restarting repeatedly",
                (Activity::Failed, false) => "has failed",
                (Activity::Failed, true) => "have failed",
                (Activity::Unknown, false) => "is not answering",
                (Activity::Unknown, true) => "are not answering",
                (_, false) => "is not running",
                (_, true) => "are not running",
            };
            format!("{who} {state} on this machine.")
        };
        let mut next: Vec<_> = self
            .down()
            .iter()
            .take(3)
            .map(|unit| {
                let restarting = self.units.iter().any(|(u, a)| {
                    u.scope == unit.scope
                        && u.name == unit.name
                        && matches!(a, Activity::Restarting { .. })
                });
                match (restarting, unit.scope) {
                    (true, Scope::System) => {
                        format!("journalctl -u {} -n 30 --no-pager", unit.name)
                    }
                    (true, Scope::User) => {
                        format!("journalctl --user -u {} -n 30 --no-pager", unit.name)
                    }
                    (false, Scope::System) => format!("systemctl status {}", unit.name),
                    (false, Scope::User) => format!("systemctl --user status {}", unit.name),
                }
            })
            .collect();
        if let Some(repair) = self.server_recovery_step() {
            next.insert(0, repair);
        }
        // Repair actions share the CLI's three-step budget with diagnostics,
        // including actions prepended above (D299).
        next.truncate(3);
        (overall, message, next)
    }

    /// Recover retained server configuration only when runtime evidence needs it.
    fn server_recovery_step(&self) -> Option<String> {
        if let Some((unit, _)) = self.units.iter().find(|(unit, state)| {
            unit.kind == Kind::Server
                && unit.masked
                && matches!(state, Activity::Inactive | Activity::Failed)
        }) {
            // A mask is recoverable without recreating the service. Preserve
            // the owning scope; never advise a running service to be repaired.
            let manager = match unit.scope {
                Scope::System => "systemctl",
                Scope::User => "systemctl --user",
            };
            Some(format!("{manager} unmask {}", unit.name))
        } else if matches!(self.role, Role::Server | Role::Both)
            && !self.units.iter().any(|(unit, _)| unit.kind == Kind::Server)
        {
            Some(
                "Restore the server service for the existing data, then run infraternal status."
                    .to_owned(),
            )
        } else {
            None
        }
    }

    /// Overall activity follows configured roles: a healthy companion cannot
    /// hide a known down role. Unknown alone is not proof of a stopped service.
    #[must_use]
    pub fn overall(&self) -> Activity {
        if let Some(state) = self
            .activities()
            .find(|state| matches!(state, Activity::Restarting { .. }))
        {
            state
        } else if self.activities().any(|state| state == Activity::Failed) {
            Activity::Failed
        } else if self.activities().any(|state| state == Activity::Inactive) {
            Activity::Inactive
        } else if self.activities().any(|state| state == Activity::Active) {
            Activity::Active
        } else if self.activities().any(|state| state == Activity::Unknown) {
            Activity::Unknown
        } else {
            Activity::Inactive
        }
    }
}

#[cfg(test)]
mod tests;
