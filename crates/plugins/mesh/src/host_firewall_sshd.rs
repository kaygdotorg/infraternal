//! Keeps sshd reachable through every default-drop host table (J671, #483).
//!
//! # The invariant
//!
//! Before a default-drop `inet infraternal_host` table is saved or applied,
//! by any path (a console `server init`, `server init` over SSH, a later
//! policy change such as the mesh listener, or the boot loader), its admin
//! rules must admit every TCP port sshd listens on **now** and every port it
//! would listen on **after a restart**, each in an address family sshd
//! really accepts on that port. When any source of that knowledge cannot be
//! read, nothing is saved or applied and the refusal names what failed and
//! the ports seen so far. Nothing is ever guessed (22 is not assumed).
//!
//! Three review rounds (J608, J658, J670) each found one more way the
//! port was predicted wrongly: the console path guessed 22, the
//! configuration hid a live `-p 2222`, the SSH path checked only the
//! session's port, an IPv4 rule counted for an IPv6-only sshd, and a stopped
//! service's `-p` was invisible. This module is the one place that answers
//! "which ports must stay open for sshd", and [`check_sshd_admission`] is
//! the one check every caller runs, so a new path cannot skip it.
//!
//! # Address families (decided 2026-11-14 under D392, #483)
//!
//! A rule limited to a source network counts for a port when sshd accepts
//! that network's address family on that port; it does not have to cover
//! every family sshd accepts there. So an IPv4-only admin rule admits a
//! dual-stack sshd on 22, while it can never admit an IPv6-only sshd (that
//! rule passes no packet sshd would answer). Requiring every family was
//! rejected: production's admin rule is IPv4-only, and under that stricter
//! reading the boot loader would refuse prod's own table and fail open at the
//! next boot, while IPv4 administrators would have kept their way in
//! throughout. An interface-only or unrestricted rule covers both families.
//!
//! # Sources ([`sshd_ports`])
//!
//! Every source is asked and the answers are combined; none wins over
//! another, and each source's ports must be admitted on their own.
//! 1. `ssh.socket` / `sshd.socket` when active or enabled (socket
//!    activation: the service manager owns the listener).
//! 2. `ssh.service` / `sshd.service` when loaded: its `ExecStart` with
//!    `Environment=` and `EnvironmentFile=` expanded (`$SSHD_OPTS`,
//!    `$OPTIONS`, drop-ins already merged by the manager), asked through
//!    `sshd -G <the service's -p/-o/-f/-4/-6 arguments>`. This is what the
//!    next `systemctl restart ssh` would listen on.
//! 3. sshd's own configuration, `sshd -G` (or `-T`), for an sshd started
//!    outside the service manager.
//! 4. Listening sockets held right now by `sshd` processes owned by root or
//!    by the ssh service's account.
//!
//! Sources 1 and 2 exist only when systemd is the running service manager
//! (`/run/systemd/system` is a directory, as `sd_booted()` checks); on a host
//! without it there are no units to read, which is not a failure.

#[cfg(target_os = "linux")]
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use super::{AllowRule, IpPrefix, PolicyError, Protocol};
#[cfg(target_os = "linux")]
use super::{discover_systemctl, safe_nft_path};

/// One TCP port sshd accepts connections on, and the address families it accepts them in.
///
/// A rule limited to IPv4 sources can only reach a port sshd accepts over
/// IPv4, and the same for IPv6 (J670). At least one family is always set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SshdPort {
    /// The TCP port; never zero.
    pub port: u16,
    /// Whether IPv4 clients can connect on this port.
    pub ipv4: bool,
    /// Whether IPv6 clients can connect on this port.
    pub ipv6: bool,
}

impl SshdPort {
    /// A port accepted over both IPv4 and IPv6.
    #[must_use]
    pub const fn dual_stack(port: u16) -> Self {
        Self {
            port,
            ipv4: true,
            ipv6: true,
        }
    }

    /// A port accepted over IPv4 only.
    #[must_use]
    pub const fn ipv4(port: u16) -> Self {
        Self {
            port,
            ipv4: true,
            ipv6: false,
        }
    }

    /// A port accepted over IPv6 only.
    #[must_use]
    pub const fn ipv6(port: u16) -> Self {
        Self {
            port,
            ipv4: false,
            ipv6: true,
        }
    }

    /// The port a listener on `address` accepts, or `None` for a loopback-only one.
    ///
    /// `dual` says whether an unspecified IPv6 address (`[::]`) also accepts
    /// IPv4: true for a socket unit without `BindIPv6Only=ipv6-only`, false
    /// for sshd's own sockets, which always set `IPV6_V6ONLY`. A loopback
    /// listener needs no rule: the network cannot reach it.
    fn listening_on(address: SocketAddr, dual: bool) -> Option<Self> {
        let ip = address.ip();
        if address.port() == 0 || ip.is_loopback() {
            return None;
        }
        Some(match ip {
            IpAddr::V4(_) => Self::ipv4(address.port()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(mapped) if mapped.is_loopback() => return None,
                Some(_) => Self::ipv4(address.port()),
                None if dual && v6.is_unspecified() => Self::dual_stack(address.port()),
                None => Self::ipv6(address.port()),
            },
        })
    }

    /// Merge one source's answers: one entry per port with every family seen, sorted.
    fn merge(ports: Vec<Self>) -> Vec<Self> {
        let mut merged: Vec<Self> = Vec::new();
        for port in ports {
            if port.port == 0 || !(port.ipv4 || port.ipv6) {
                continue;
            }
            match merged.iter_mut().find(|known| known.port == port.port) {
                Some(known) => {
                    known.ipv4 |= port.ipv4;
                    known.ipv6 |= port.ipv6;
                }
                None => merged.push(port),
            }
        }
        merged.sort_unstable();
        merged
    }

    /// Whether `rule` is an administrator's way in to this port.
    ///
    /// The rule must be TCP on this port and must not be limited to the
    /// loopback interface, to a single source address (/32 or /128), to a
    /// loopback source network, or to an address family sshd does not
    /// accept on this port: those admit only local logins, one machine, or
    /// no packet at all, which proves nothing about the administrators' path
    /// (J608, J658, J670). A real interface or a real source network of a
    /// family sshd uses is a deliberate admin path and counts.
    fn admitted_by(self, rule: &AllowRule) -> bool {
        rule.protocol == Protocol::Tcp
            && rule.port == self.port
            && rule.interface.as_deref() != Some("lo")
            && rule.source.as_ref().is_none_or(|source| {
                let ipv4 = source.address().is_ipv4();
                (if ipv4 { self.ipv4 } else { self.ipv6 })
                    && source.prefix() < if ipv4 { 32 } else { 128 }
                    && !loopback_only(source)
            })
    }
}

/// Prints `22`, or `2201 (IPv6 only)` when sshd accepts the port in one family.
impl fmt::Display for SshdPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ipv4, self.ipv6) {
            (true, false) => write!(formatter, "{} (IPv4 only)", self.port),
            (false, true) => write!(formatter, "{} (IPv6 only)", self.port),
            _ => write!(formatter, "{}", self.port),
        }
    }
}

/// One place sshd's ports were learned from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshdPortSource {
    /// A short name for the source, for messages ("sshd's configuration", ...).
    pub source: String,
    /// The ports this source names, one per port, sorted; never empty.
    pub ports: Vec<SshdPort>,
}

/// sshd's ports as learned from every source, or why they could not all be.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SshdPorts {
    /// Every source was read and these named ports; never empty. The table
    /// must admit each source's ports ([`SshdPorts::required`]).
    Known(Vec<SshdPortSource>),
    /// At least one source could not be read, or none named a port.
    Unknown {
        /// What failed and why, for the refusal.
        failed: String,
        /// The sources that did answer, so the refusal can name their ports.
        seen: Vec<SshdPortSource>,
    },
}

impl SshdPorts {
    /// Combine each source's answer; any failed source makes the result unknown.
    ///
    /// A source that answers with no port (sshd is not running, no socket
    /// unit) is fine. A source that fails is not skipped: what it would have
    /// said is exactly what could lock sshd out.
    #[must_use]
    pub fn combine(answers: Vec<(String, Result<Vec<SshdPort>, String>)>) -> Self {
        let mut seen = Vec::new();
        let mut failed = Vec::new();
        let mut silent = Vec::new();
        for (source, answer) in answers {
            match answer.map(SshdPort::merge) {
                Ok(ports) if ports.is_empty() => silent.push(source),
                Ok(ports) => seen.push(SshdPortSource { source, ports }),
                Err(reason) => failed.push(format!("{source}: {reason}")),
            }
        }
        if !failed.is_empty() {
            return Self::Unknown {
                failed: failed.join("; "),
                seen,
            };
        }
        if seen.is_empty() {
            return Self::Unknown {
                failed: format!("no source named a port ({})", silent.join(", ")),
                seen,
            };
        }
        Self::Known(seen)
    }

    /// Every port a source named, sorted and without exact duplicates; empty when unknown.
    ///
    /// The same port from two sources with different families stays twice:
    /// each source's sshd must be reachable on its own.
    #[must_use]
    pub fn required(&self) -> Vec<SshdPort> {
        let Self::Known(sources) = self else {
            return Vec::new();
        };
        let mut ports = sources
            .iter()
            .flat_map(|source| source.ports.iter().copied())
            .collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Each source and its ports: `22 (from sshd's configuration); 2222 (from running sshd processes)`.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Known(sources) => describe_sources(sources),
            Self::Unknown { failed, .. } => failed.clone(),
        }
    }
}

/// Name each source with its ports, or `none` when the list is empty.
fn describe_sources(sources: &[SshdPortSource]) -> String {
    if sources.is_empty() {
        return "none".to_owned();
    }
    sources
        .iter()
        .map(|source| format!("{} (from {})", join_ports(&source.ports), source.source))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Join ports for a message: `22, 2201 (IPv6 only)`.
fn join_ports(ports: &[SshdPort]) -> String {
    ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `rules` admit every port in `ports`; an empty list never passes.
///
/// Guessing 22 when nothing was learned let a console install lock out an
/// sshd on 2222 (J608), so no ports means no proof.
#[must_use]
pub fn admits_sshd(rules: &[AllowRule], ports: &[SshdPort]) -> bool {
    !ports.is_empty() && uncovered_sshd_ports(rules, ports).is_empty()
}

/// The ports in `ports` that no rule in `rules` admits, in order.
///
/// See [`SshdPort`]'s `admitted_by` for which rules count.
#[must_use]
pub fn uncovered_sshd_ports(rules: &[AllowRule], ports: &[SshdPort]) -> Vec<SshdPort> {
    ports
        .iter()
        .copied()
        .filter(|port| !rules.iter().any(|rule| port.admitted_by(rule)))
        .collect()
}

/// The invariant's one check: refuse unless `rules` admit every port in `sshd`.
///
/// Every path that saves or applies a default-drop table calls this with
/// what [`sshd_ports`] learned (or a test's fixed answer). An unknown
/// answer refuses: a source that could not be read may hold the port that
/// would be dropped.
///
/// # Errors
/// [`PolicyError::SshdNotAdmitted`] names the ports no rule admits and
/// every source's ports; [`PolicyError::SshdPortsUnknown`] names the
/// sources that failed and the ports the others named.
pub fn check_sshd_admission(rules: &[AllowRule], sshd: &SshdPorts) -> Result<(), PolicyError> {
    match sshd {
        SshdPorts::Known(_) => {
            let required = sshd.required();
            let missing = uncovered_sshd_ports(rules, &required);
            if missing.is_empty() && !required.is_empty() {
                return Ok(());
            }
            Err(PolicyError::SshdNotAdmitted {
                missing: join_ports(&missing),
                uses: sshd.describe(),
            })
        }
        SshdPorts::Unknown { failed, seen } => Err(PolicyError::SshdPortsUnknown {
            failed: failed.clone(),
            seen: describe_sources(seen),
        }),
    }
}

/// Whether every address in `source` is a loopback address.
///
/// `source` holds its network address (host bits cleared), so `::1/127` is
/// stored as `::/127`: it covers `::` and `::1` and nothing routable. A
/// wider network that merely contains loopback (`64.0.0.0/2`) is not
/// loopback-only.
fn loopback_only(source: &IpPrefix) -> bool {
    match source.address() {
        IpAddr::V4(address) => source.prefix() >= 8 && address.octets()[0] == 127,
        IpAddr::V6(address) => {
            (source.prefix() >= 127 && address.segments()[..7] == [0; 7])
                || (source.prefix() >= 104
                    && address
                        .to_ipv4_mapped()
                        .is_some_and(|mapped| mapped.octets()[0] == 127))
        }
    }
}

/// The fixed places sshd is looked for, never through `PATH` (the same rule as nft, D386).
#[cfg(target_os = "linux")]
const SSHD_CANDIDATES: &[&str] = &[
    "/usr/sbin/sshd",
    "/usr/bin/sshd",
    "/sbin/sshd",
    "/usr/local/sbin/sshd",
    "/run/current-system/sw/bin/sshd",
    "/nix/var/nix/profiles/default/bin/sshd",
    "/nix/var/nix/profiles/system/sw/bin/sshd",
    "/root/.nix-profile/bin/sshd",
];

/// The ssh service units asked for `ExecStart` and the service account.
#[cfg(target_os = "linux")]
const SSH_SERVICES: &[&str] = &["ssh.service", "sshd.service"];

/// Learn every TCP port sshd accepts on now or will after a restart, from every source.
///
/// See the module documentation for the sources. systemctl and sshd are
/// run only from fixed, root-owned paths with a clean environment. Run as
/// root: the live listeners of root's sshd and some distributions'
/// configuration are root-only, and an unreadable source makes the answer
/// [`SshdPorts::Unknown`].
#[cfg(target_os = "linux")]
#[must_use]
pub fn sshd_ports() -> SshdPorts {
    let mut answers = Vec::new();
    let mut owners = vec![0];
    let mut service_binaries = Vec::new();
    if systemd_is_running() {
        match discover_systemctl(None) {
            Ok(systemctl) => {
                answers.push((
                    "sshd's systemd socket unit".to_owned(),
                    capture(
                        &systemctl,
                        &[
                            "show",
                            "--property=Listen,ActiveState,UnitFileState,BindIPv6Only",
                            "ssh.socket",
                            "sshd.socket",
                        ],
                    )
                    .map(|text| socket_unit_ports(&text, ipv6_binds_dual_stack())),
                ));
                let mut arguments = vec![
                    "show",
                    "--property=Id,LoadState,UID,ExecStart,Environment,EnvironmentFiles",
                ];
                arguments.extend(SSH_SERVICES);
                match capture(&systemctl, &arguments) {
                    Ok(text) => {
                        for unit in service_units(&text) {
                            owners.extend(unit.uid);
                            if unit.loaded {
                                service_binaries.extend(unit.binaries());
                                answers.push((
                                    format!("{}'s ExecStart", unit.id),
                                    service_ports(&unit),
                                ));
                            }
                        }
                    }
                    Err(reason) => answers.push(("sshd's systemd service".to_owned(), Err(reason))),
                }
            }
            Err(error) => answers.push(("systemctl".to_owned(), Err(error.to_string()))),
        }
    }
    answers.push((
        "sshd's configuration".to_owned(),
        installed_sshd(&service_binaries).and_then(|sshd| sshd_effective_ports(&sshd, &[])),
    ));
    answers.push((
        "running sshd processes".to_owned(),
        sshd_listening_ports(&owners),
    ));
    SshdPorts::combine(answers)
}

/// Elsewhere there is no default-drop server table, so nothing is known and nothing passes.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn sshd_ports() -> SshdPorts {
    SshdPorts::Unknown {
        failed: "sshd's ports are read only on Linux".to_owned(),
        seen: Vec::new(),
    }
}

/// Whether systemd is the running service manager, the check `sd_booted()` makes.
#[cfg(target_os = "linux")]
fn systemd_is_running() -> bool {
    fs::symlink_metadata("/run/systemd/system").is_ok_and(|metadata| metadata.is_dir())
}

/// Whether a socket unit's `[::]` listener also takes IPv4 under `BindIPv6Only=default`.
///
/// `default` follows the `net.ipv6.bindv6only` sysctl; it is 0 (dual stack)
/// almost everywhere. An unreadable sysctl answers "IPv6 only", which can
/// only make the check stricter.
#[cfg(target_os = "linux")]
fn ipv6_binds_dual_stack() -> bool {
    fs::read_to_string("/proc/sys/net/ipv6/bindv6only").is_ok_and(|value| value.trim() == "0")
}

/// sshd at a fixed, root-owned path, else the root-owned binary a loaded service starts.
#[cfg(target_os = "linux")]
fn installed_sshd(service_binaries: &[PathBuf]) -> Result<PathBuf, String> {
    let mut tried = Vec::new();
    for candidate in SSHD_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .chain(service_binaries.iter().cloned())
    {
        match safe_nft_path(&candidate) {
            Ok(Some(path)) => return Ok(path),
            Ok(None) => {}
            Err(_) => tried.push(format!("{} is not root-controlled", candidate.display())),
        }
    }
    tried.push("no sshd at the fixed paths".to_owned());
    Err(tried.join("; "))
}

/// Ask `sshd` for the ports it would listen on with `arguments`: `sshd -G`, else `sshd -T`.
#[cfg(target_os = "linux")]
fn sshd_effective_ports(sshd: &Path, arguments: &[String]) -> Result<Vec<SshdPort>, String> {
    let mut tried = Vec::new();
    for flag in ["-G", "-T"] {
        let mut all = vec![flag];
        all.extend(arguments.iter().map(String::as_str));
        match capture(sshd, &all) {
            Ok(text) => {
                let ports = sshd_config_ports(&text);
                if ports.is_empty() && !text.lines().any(|line| is_key(line, "listenaddress")) {
                    tried.push(format!("sshd {flag} printed no port"));
                    continue;
                }
                return Ok(ports);
            }
            Err(reason) => tried.push(format!("sshd {flag}: {reason}")),
        }
    }
    Err(tried.join("; "))
}

/// Whether `line` is `key value` for this (case-insensitive) key.
#[cfg(target_os = "linux")]
fn is_key(line: &str, key: &str) -> bool {
    line.split_ascii_whitespace()
        .next()
        .is_some_and(|first| first.eq_ignore_ascii_case(key))
}

/// Run a fixed, already trusted program with a clean environment and return its stdout.
///
/// The error is the first line of its stderr (or the spawn error), short
/// enough to quote in a refusal.
#[cfg(target_os = "linux")]
fn capture(program: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .env_clear()
        .env("LANG", "C")
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| error.to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(stderr
        .lines()
        .next()
        .map_or_else(|| format!("exit {}", output.status), str::to_owned))
}

/// The ports in `sshd -G`/`-T` output, with their families.
///
/// sshd prints one `listenaddress <addr>:<port>` per socket it will open,
/// with `Port` already applied, so those are exact: `[::]:22` is IPv6 only
/// (sshd sets `IPV6_V6ONLY`), `0.0.0.0:22` IPv4. Loopback addresses are
/// skipped. Only when a release prints no `listenaddress` line at all are
/// the `port` lines used, in the families `addressfamily` names.
#[must_use]
pub fn sshd_config_ports(text: &str) -> Vec<SshdPort> {
    let mut listen = Vec::new();
    let mut saw_listen = false;
    let mut ports = Vec::new();
    let mut family = (true, true);
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(key), Some(value)) = (fields.next(), fields.next()) else {
            continue;
        };
        if key.eq_ignore_ascii_case("listenaddress") {
            saw_listen = true;
            listen.extend(
                value
                    .parse::<SocketAddr>()
                    .ok()
                    .and_then(|address| SshdPort::listening_on(address, false)),
            );
        } else if key.eq_ignore_ascii_case("port") {
            ports.extend(value.parse::<u16>().ok());
        } else if key.eq_ignore_ascii_case("addressfamily") {
            family = match value {
                "inet" => (true, false),
                "inet6" => (false, true),
                _ => (true, true),
            };
        }
    }
    if saw_listen {
        return SshdPort::merge(listen);
    }
    SshdPort::merge(
        ports
            .into_iter()
            .map(|port| SshdPort {
                port,
                ipv4: family.0,
                ipv6: family.1,
            })
            .collect(),
    )
}

/// The TCP ports of active or enabled socket units in `systemctl show` output.
///
/// The output has one block per unit, separated by a blank line, holding
/// `Listen=<address> (Stream)` lines plus `ActiveState=`, `UnitFileState=`
/// and `BindIPv6Only=`. A unit that is neither active nor enabled (a stock
/// `ssh.socket` next to a plain `ssh.service`) does not listen and is
/// ignored. A `[::]` or bare-port listener takes IPv4 too unless the unit
/// says `ipv6-only`, or says `default` and `default_dual` is false.
#[must_use]
pub fn socket_unit_ports(text: &str, default_dual: bool) -> Vec<SshdPort> {
    let mut ports = Vec::new();
    for block in text.split("\n\n") {
        let mut listens = Vec::new();
        let mut live = false;
        let mut dual = default_dual;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Listen=") {
                if let Some(address) = value.strip_suffix(" (Stream)") {
                    listens.push(address.to_owned());
                }
            } else if let Some(state) = line.strip_prefix("ActiveState=") {
                live |= state == "active";
            } else if let Some(state) = line.strip_prefix("UnitFileState=") {
                live |= state.starts_with("enabled");
            } else if let Some(mode) = line.strip_prefix("BindIPv6Only=") {
                dual = match mode {
                    "ipv6-only" => false,
                    "both" => true,
                    _ => default_dual,
                };
            }
        }
        if !live {
            continue;
        }
        for address in listens {
            let address = address.parse::<SocketAddr>().ok().or_else(|| {
                address
                    .parse::<u16>()
                    .ok()
                    .map(|port| SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
            });
            ports.extend(address.and_then(|address| SshdPort::listening_on(address, dual)));
        }
    }
    SshdPort::merge(ports)
}

/// One ssh service unit as `systemctl show` describes it.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct ServiceUnit {
    /// The unit's real name (an alias such as `sshd.service` reports its target's).
    id: String,
    /// Whether the unit file was found and is not masked.
    loaded: bool,
    /// The running service's numeric uid, when it runs as another account.
    uid: Option<u32>,
    /// The raw `ExecStart=` value(s).
    exec_start: Vec<String>,
    /// The raw `Environment=` value(s).
    environment: Vec<String>,
    /// The raw `EnvironmentFiles=` values, one file each.
    environment_files: Vec<String>,
}

#[cfg(target_os = "linux")]
impl ServiceUnit {
    /// The executable each `ExecStart` runs (its `path=`).
    fn binaries(&self) -> Vec<PathBuf> {
        self.exec_start
            .iter()
            .flat_map(|value| exec_commands(value))
            .map(|(path, _)| PathBuf::from(path))
            .collect()
    }
}

/// Split `systemctl show` output for the ssh services into units, one per real unit.
///
/// `sshd.service` is an alias of `ssh.service` on some distributions; both
/// report the same `Id=`, so the second is dropped.
#[cfg(target_os = "linux")]
fn service_units(text: &str) -> Vec<ServiceUnit> {
    let mut units: Vec<ServiceUnit> = Vec::new();
    for block in text.split("\n\n") {
        let mut unit = ServiceUnit::default();
        for line in block.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "Id" => value.clone_into(&mut unit.id),
                "LoadState" => unit.loaded = value == "loaded",
                "UID" => unit.uid = value.trim().parse().ok(),
                "ExecStart" if !value.is_empty() => unit.exec_start.push(value.to_owned()),
                "Environment" if !value.is_empty() => unit.environment.push(value.to_owned()),
                "EnvironmentFiles" if !value.is_empty() => {
                    unit.environment_files.push(value.to_owned());
                }
                _ => {}
            }
        }
        if unit.id.is_empty() || units.iter().any(|known| known.id == unit.id) {
            continue;
        }
        units.push(unit);
    }
    units
}

/// The `(path, argv)` of each command in a `systemctl show` `ExecStart=` value.
///
/// The value looks like `{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D
/// $SSHD_OPTS ; ignore_errors=no ; ... }`, once per command. The manager
/// prints `argv[]` joined by spaces without quoting, so it is split on
/// whitespace; an argument containing a quote or a backslash cannot be
/// split faithfully and makes the caller refuse (see [`service_ports`]).
#[cfg(target_os = "linux")]
fn exec_commands(value: &str) -> Vec<(String, String)> {
    value
        .split('{')
        .skip(1)
        .filter_map(|command| {
            let command = command.split('}').next()?;
            let mut path = None;
            let mut argv = None;
            for field in command.split(" ; ") {
                let field = field.trim();
                if let Some(value) = field.strip_prefix("path=") {
                    path = Some(value.to_owned());
                } else if let Some(value) = field.strip_prefix("argv[]=") {
                    argv = Some(value.to_owned());
                }
            }
            Some((path?, argv?))
        })
        .collect()
}

/// What a loaded ssh service would listen on when (re)started.
///
/// Its environment is built the way the manager builds it (`Environment=`,
/// then each `EnvironmentFile=` in order, later ones winning), its
/// `ExecStart` arguments are expanded with it, the ones that change sshd's
/// listeners (`-p`, `-o`, `-f`, `-4`, `-6`) are kept, and the service's own
/// root-owned sshd binary is asked with `-G`. Anything that cannot be read
/// or parsed faithfully is an error, never a guess.
#[cfg(target_os = "linux")]
fn service_ports(unit: &ServiceUnit) -> Result<Vec<SshdPort>, String> {
    let mut environment = HashMap::new();
    for value in &unit.environment {
        for assignment in split_quoted(value)? {
            if let Some((key, value)) = assignment.split_once('=') {
                environment.insert(key.to_owned(), value.to_owned());
            }
        }
    }
    for entry in &unit.environment_files {
        let (path, optional) = match entry.rsplit_once(" (ignore_errors=") {
            Some((path, flag)) => (path, flag.starts_with("yes")),
            None => (entry.as_str(), false),
        };
        match fs::read_to_string(path) {
            Ok(text) => environment.extend(parse_environment_file(&text)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound && optional => {}
            Err(error) => return Err(format!("EnvironmentFile {path}: {error}")),
        }
    }
    let mut ports = Vec::new();
    for value in &unit.exec_start {
        for (path, argv) in exec_commands(value) {
            if argv.contains(['"', '\'', '\\']) {
                return Err(format!(
                    "ExecStart `{argv}` has quoted arguments that cannot be read back exactly"
                ));
            }
            let words = argv
                .split_ascii_whitespace()
                .skip(1)
                .flat_map(|word| expand_word(word, &environment))
                .collect::<Vec<_>>();
            let Ok(Some(sshd)) = safe_nft_path(Path::new(&path)) else {
                return Err(format!("{path} is not a root-controlled executable"));
            };
            ports.extend(sshd_effective_ports(&sshd, &listener_arguments(&words)?)?);
        }
    }
    Ok(ports)
}

/// Expand one `ExecStart` word as the manager does.
///
/// A word that is exactly `$NAME` becomes the variable's value split on
/// whitespace (zero or more words); `${NAME}` anywhere in a word is
/// replaced by the value as is. An unset variable is empty.
#[cfg(target_os = "linux")]
fn expand_word(word: &str, environment: &HashMap<String, String>) -> Vec<String> {
    if let Some(name) = word.strip_prefix('$')
        && !name.starts_with('{')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return environment
            .get(name)
            .map(|value| value.split_ascii_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
    }
    let mut expanded = String::new();
    let mut rest = word;
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}') else {
            break;
        };
        let name = &rest[start + 2..start + end];
        expanded.push_str(environment.get(name).map_or("", String::as_str));
        rest = &rest[start + end + 1..];
    }
    expanded.push_str(rest);
    vec![expanded]
}

/// Keep only the sshd options that decide its listeners: `-p`, `-o`, `-f`, `-4`, `-6`.
///
/// Options are read the way sshd's `getopt` reads them, so clustered flags
/// (`-De`) and attached values (`-p2222`, `-oPort=2222`) are understood.
/// Everything else (`-D`, `-e`, `-E <log>`, host keys) is dropped: it does
/// not change the ports, and `-E` would make `sshd -G` open a log file.
///
/// # Errors
/// An option that needs a value but has none, or a stray non-option word.
#[cfg(target_os = "linux")]
fn listener_arguments(words: &[String]) -> Result<Vec<String>, String> {
    /// sshd's options that take a value (from its `getopt` string).
    const WITH_VALUE: &str = "CEbcfghkopu";
    let mut kept = Vec::new();
    let mut words = words.iter();
    while let Some(word) = words.next() {
        let Some(flags) = word.strip_prefix('-').filter(|flags| !flags.is_empty()) else {
            return Err(format!("unexpected sshd argument `{word}`"));
        };
        for (index, flag) in flags.char_indices() {
            if WITH_VALUE.contains(flag) {
                let attached = &flags[index + flag.len_utf8()..];
                let value = if attached.is_empty() {
                    words
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("sshd option -{flag} has no value"))?
                } else {
                    attached.to_owned()
                };
                if matches!(flag, 'p' | 'o' | 'f') {
                    kept.push(format!("-{flag}"));
                    kept.push(value);
                }
                break;
            }
            if matches!(flag, '4' | '6') {
                kept.push(format!("-{flag}"));
            }
        }
    }
    Ok(kept)
}

/// Split a `systemctl show` `Environment=` value into its `KEY=value` words.
///
/// The manager double-quotes a word that holds spaces and escapes with a
/// backslash inside quotes (`"SSHD_OPTS=-p 2222" B=x`).
///
/// # Errors
/// An unterminated quote.
#[cfg(target_os = "linux")]
fn split_quoted(value: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' | '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some(end) if end == c => break,
                        Some('\\') if c == '"' => word.extend(chars.next()),
                        Some(other) => word.push(other),
                        None => return Err(format!("unterminated quote in `{value}`")),
                    }
                }
            }
            '\\' => {
                in_word = true;
                word.extend(chars.next());
            }
            c if c.is_ascii_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                word.push(c);
            }
        }
    }
    if in_word {
        words.push(word);
    }
    Ok(words)
}

/// The `KEY=value` pairs of an environment file, in the manager's syntax.
///
/// Blank lines and lines starting with `#` or `;` are comments. A value may
/// be single- or double-quoted (backslash escapes inside double quotes); an
/// unquoted value is trimmed. A trailing backslash continues the line.
///
/// # Errors
/// An unterminated quote.
#[cfg(target_os = "linux")]
fn parse_environment_file(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();
    let mut pending = String::new();
    for line in text.lines() {
        if let Some(continued) = line.strip_suffix('\\') {
            pending.push_str(continued);
            continue;
        }
        pending.push_str(line);
        let line = std::mem::take(&mut pending);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim_start();
        let value = if value.starts_with(['"', '\'']) {
            split_quoted(value)?.concat()
        } else {
            value.trim_end().to_owned()
        };
        pairs.push((key.trim().to_owned(), value));
    }
    Ok(pairs)
}

/// The ports `sshd` processes owned by one of `owners` are listening on right now.
///
/// Reads `/proc/net/tcp{,6}` for listening sockets (IPv4 from `tcp`, IPv6
/// from `tcp6`, where sshd's sockets are always IPv6-only; an IPv4-mapped
/// address counts as IPv4) and maps their inodes to `sshd` processes through
/// `/proc/<pid>/fd`, which only root can read for root's processes. A
/// process counts only when its real and effective uids (from
/// `/proc/<pid>/status`) are both in `owners`: any user can start a program
/// named `sshd` (J658). The owner of `/proc/<pid>` is not used, because a
/// process that marks itself non-dumpable shows as root there. Loopback
/// listeners are skipped. A socket-activated sshd's listener belongs to the
/// service manager, so the socket unit is asked for it instead.
///
/// # Errors
/// A `/proc` table, or the descriptors of an owned `sshd`, that cannot be
/// read: that sshd's port would be unknown. A process that exits meanwhile
/// is skipped.
#[cfg(target_os = "linux")]
pub fn sshd_listening_ports(owners: &[u32]) -> Result<Vec<SshdPort>, String> {
    let mut sockets = HashMap::new();
    proc_net_listeners("/proc/net/tcp", &mut sockets)?;
    proc_net_listeners("/proc/net/tcp6", &mut sockets)?;
    let mut ports = Vec::new();
    let processes = fs::read_dir("/proc").map_err(|error| format!("/proc: {error}"))?;
    for process in processes.filter_map(Result::ok) {
        let path = process.path();
        if fs::read_to_string(path.join("comm")).map_or(true, |name| name.trim_end() != "sshd") {
            continue;
        }
        let owned = fs::read_to_string(path.join("status")).is_ok_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Uid:"))
                .is_some_and(|uids| {
                    let mut uids = uids.split_ascii_whitespace().map(str::parse::<u32>);
                    matches!(
                        (uids.next(), uids.next()),
                        (Some(Ok(real)), Some(Ok(effective)))
                            if owners.contains(&real) && owners.contains(&effective)
                    )
                })
        });
        if !owned {
            continue;
        }
        let descriptors = match fs::read_dir(path.join("fd")) {
            Ok(descriptors) => descriptors,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "{}: {error} (run as root)",
                    path.join("fd").display()
                ));
            }
        };
        for descriptor in descriptors.filter_map(Result::ok) {
            let Ok(target) = fs::read_link(descriptor.path()) else {
                continue;
            };
            let inode = target
                .to_str()
                .and_then(|text| text.strip_prefix("socket:["))
                .and_then(|text| text.strip_suffix(']'))
                .and_then(|text| text.parse::<u64>().ok());
            if let Some(port) = inode.and_then(|inode| sockets.get(&inode)) {
                ports.push(*port);
            }
        }
    }
    Ok(SshdPort::merge(ports))
}

/// Map the listening sockets in one `/proc/net/tcp{,6}` table from inode to port.
#[cfg(target_os = "linux")]
fn proc_net_listeners(table: &str, into: &mut HashMap<u64, SshdPort>) -> Result<(), String> {
    let text = match fs::read_to_string(table) {
        Ok(text) => text,
        // A kernel without IPv6 has no tcp6 table, and so no IPv6 listener.
        Err(error) if error.kind() == io::ErrorKind::NotFound && table.ends_with('6') => {
            return Ok(());
        }
        Err(error) => return Err(format!("{table}: {error}")),
    };
    for line in text.lines().skip(1) {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
        let (Some(local), Some(&"0A"), Some(inode)) = (fields.get(1), fields.get(3), fields.get(9))
        else {
            continue;
        };
        let Some((address, port)) = local.rsplit_once(':') else {
            continue;
        };
        let (Some(address), Ok(port), Ok(inode)) = (
            proc_net_address(address),
            u16::from_str_radix(port, 16),
            inode.parse::<u64>(),
        ) else {
            continue;
        };
        if let Some(port) = SshdPort::listening_on(SocketAddr::new(address, port), false) {
            into.insert(inode, port);
        }
    }
    Ok(())
}

/// Decode a `/proc/net/tcp{,6}` local address (hex).
///
/// The kernel prints each 32-bit word of the network-order address as a
/// native-endian hex number, so the bytes come back with `to_ne_bytes`.
#[must_use]
pub fn proc_net_address(hex: &str) -> Option<IpAddr> {
    let words = hex
        .as_bytes()
        .chunks(8)
        .map(|word| {
            std::str::from_utf8(word)
                .ok()
                .and_then(|word| u32::from_str_radix(word, 16).ok())
        })
        .collect::<Option<Vec<_>>>()?;
    match words.as_slice() {
        [word] if hex.len() == 8 => Some(IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))),
        words if hex.len() == 32 && words.len() == 4 => {
            let mut bytes = [0_u8; 16];
            for (chunk, word) in bytes.chunks_mut(4).zip(words) {
                chunk.copy_from_slice(&word.to_ne_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

/// Unit tests for the sshd port sources, their parsers and the admission check.
#[cfg(all(test, target_os = "linux"))]
#[expect(
    clippy::expect_used,
    reason = "a failed fixture step should name the step that failed"
)]
mod tests {
    use super::{
        AllowRule, SshdPort, SshdPortSource, SshdPorts, admits_sshd, check_sshd_admission,
        expand_word, listener_arguments, parse_environment_file, proc_net_address,
        socket_unit_ports, split_quoted, sshd_config_ports, uncovered_sshd_ports,
    };
    use crate::host_firewall::PolicyError;
    use std::collections::HashMap;

    /// Parse rule strings for a test.
    fn rules(values: &[&str]) -> Vec<AllowRule> {
        values
            .iter()
            .map(|value| value.parse().expect("rule"))
            .collect()
    }

    /// Dual-stack ports, the common sshd shape.
    fn dual(ports: &[u16]) -> Vec<SshdPort> {
        ports.iter().copied().map(SshdPort::dual_stack).collect()
    }

    /// A TCP rule on one of sshd's ports is needed; no port known never passes.
    #[test]
    fn console_install_needs_a_rule_for_sshd() {
        assert!(!admits_sshd(&rules(&["*,*,tcp,443"]), &dual(&[22])));
        assert!(admits_sshd(
            &rules(&["*,*,tcp,443", "*,*,tcp,22"]),
            &dual(&[22])
        ));
        assert!(!admits_sshd(&rules(&["*,*,udp,22"]), &dual(&[22])));
        // J658: every port sshd uses needs a rule, not just one of them.
        assert!(!admits_sshd(&rules(&["*,*,tcp,2222"]), &dual(&[22, 2222])));
        assert!(admits_sshd(
            &rules(&["*,*,tcp,2222", "eth0,*,tcp,22"]),
            &dual(&[22, 2222])
        ));
        assert!(!admits_sshd(&rules(&["*,*,tcp,22"]), &dual(&[2222])));
        // J608 (P2): with no port learned, 22 is not assumed.
        assert!(!admits_sshd(&rules(&["*,*,tcp,22"]), &[]));
    }

    /// J608 (P3): a rule limited to `lo` or to one source address is no SSH path.
    ///
    /// A real interface or a source network is a deliberate admin path
    /// (prod's is netbird's `wt0` /24) and counts.
    #[test]
    fn console_admin_path_ignores_loopback_and_single_source_rules() {
        let ssh = dual(&[22]);
        assert!(!admits_sshd(&rules(&["lo,*,tcp,22"]), &ssh));
        assert!(!admits_sshd(&rules(&["*,10.255.255.1/32,tcp,22"]), &ssh));
        assert!(!admits_sshd(&rules(&["eth9,10.255.255.1,tcp,22"]), &ssh));
        assert!(!admits_sshd(&rules(&["*,2001:db8::1/128,tcp,22"]), &ssh));
        assert!(admits_sshd(&rules(&["wt0,10.69.69.0/24,tcp,22"]), &ssh));
        assert!(admits_sshd(&rules(&["eth0,*,tcp,22"]), &ssh));
        assert!(admits_sshd(&rules(&["lo,*,tcp,22", "*,*,tcp,22"]), &ssh));
    }

    /// J658 (P3): a loopback source network is no SSH path, whatever its prefix length.
    #[test]
    fn review_j658_loopback_networks_are_no_ssh_path() {
        for loopback in [
            "*,127.0.0.0/8,tcp,22",
            "*,127.1.0.0/16,tcp,22",
            "*,::1/127,tcp,22",
            "*,::ffff:127.0.0.0/104,tcp,22",
            "eth0,127.0.0.0/8,tcp,22",
        ] {
            assert!(
                !admits_sshd(&rules(&[loopback]), &dual(&[22])),
                "{loopback} counted as an SSH path"
            );
        }
        assert!(admits_sshd(&rules(&["*,64.0.0.0/2,tcp,22"]), &dual(&[22])));
        assert!(admits_sshd(&rules(&["*,::/0,tcp,22"]), &dual(&[22])));
        assert!(admits_sshd(&rules(&["*,0.0.0.0/0,tcp,22"]), &dual(&[22])));
    }

    /// J670 (P3): a rule only counts in an address family sshd accepts on that port.
    ///
    /// An IPv6-only sshd on 2201 (`AddressFamily inet6`) cannot be reached
    /// through `*,10.0.0.0/8,tcp,2201`: no packet matches both. The reverse
    /// holds for an IPv4-only sshd. Any-source and interface-only rules
    /// reach every family, and a dual-stack port takes either.
    #[test]
    fn review_j670_rule_family_must_match_sshd() {
        let v6 = [SshdPort::ipv6(2201)];
        let v4 = [SshdPort::ipv4(2201)];
        assert!(!admits_sshd(&rules(&["*,10.0.0.0/8,tcp,2201"]), &v6));
        assert!(!admits_sshd(&rules(&["*,fd00::/64,tcp,2201"]), &v4));
        assert!(admits_sshd(&rules(&["*,fd00::/64,tcp,2201"]), &v6));
        assert!(admits_sshd(&rules(&["*,10.0.0.0/8,tcp,2201"]), &v4));
        assert!(admits_sshd(&rules(&["*,*,tcp,2201"]), &v6));
        assert!(admits_sshd(&rules(&["eth0,*,tcp,2201"]), &v4));
        // prod's shape: an IPv4 admin network on a dual-stack sshd stays valid.
        assert!(admits_sshd(
            &rules(&["wt0,10.69.69.0/24,tcp,22"]),
            &dual(&[22])
        ));
        // The refusal says which family the port is limited to.
        let missing = uncovered_sshd_ports(&rules(&["*,10.0.0.0/8,tcp,2201"]), &v6);
        assert_eq!(missing[0].to_string(), "2201 (IPv6 only)");
    }

    /// J658 (P2): every source's ports are required; one source never hides another's.
    #[test]
    fn review_j658_sshd_sources_are_combined_not_first_wins() {
        let combined = SshdPorts::combine(vec![
            ("sshd's systemd socket unit".to_owned(), Ok(Vec::new())),
            ("sshd's configuration".to_owned(), Ok(dual(&[22]))),
            (
                "running sshd processes".to_owned(),
                Ok(vec![
                    SshdPort::ipv4(2222),
                    SshdPort::ipv6(2222),
                    SshdPort::ipv4(0),
                ]),
            ),
        ]);
        assert_eq!(
            combined,
            SshdPorts::Known(vec![
                SshdPortSource {
                    source: "sshd's configuration".to_owned(),
                    ports: dual(&[22]),
                },
                SshdPortSource {
                    source: "running sshd processes".to_owned(),
                    ports: dual(&[2222]),
                },
            ])
        );
        assert_eq!(combined.required(), dual(&[22, 2222]));
        assert_eq!(
            combined.describe(),
            "22 (from sshd's configuration); 2222 (from running sshd processes)"
        );
        assert_eq!(
            uncovered_sshd_ports(&rules(&["*,*,tcp,22"]), &combined.required()),
            dual(&[2222])
        );
    }

    /// J671: one unreadable source makes the answer unknown, even when others named ports.
    ///
    /// J662 combined only the sources that answered, so a failed `sshd -G`
    /// next to a live sshd on 22 still produced "22 is enough" while the
    /// configuration said 2222. Now any failure refuses, and the refusal
    /// names the failure and the ports already seen.
    #[test]
    fn review_j671_an_unreadable_source_refuses_even_with_other_answers() {
        let partial = SshdPorts::combine(vec![
            ("running sshd processes".to_owned(), Ok(dual(&[22]))),
            (
                "sshd's configuration".to_owned(),
                Err("sshd -G: Permission denied".to_owned()),
            ),
        ]);
        assert_eq!(partial.required(), Vec::<SshdPort>::new());
        let error = check_sshd_admission(&rules(&["*,*,tcp,22"]), &partial)
            .expect_err("a failed source must refuse");
        let PolicyError::SshdPortsUnknown { failed, seen } = &error else {
            panic!("unexpected error {error:?}");
        };
        assert!(failed.contains("sshd's configuration: sshd -G: Permission denied"));
        assert_eq!(seen, "22 (from running sshd processes)");
        let silent =
            SshdPorts::combine(vec![("running sshd processes".to_owned(), Ok(Vec::new()))]);
        assert!(matches!(silent, SshdPorts::Unknown { .. }), "{silent:?}");
        assert!(check_sshd_admission(&rules(&["*,*,tcp,22"]), &silent).is_err());
    }

    /// `sshd -G`/`-T` output: `listenaddress` lines are exact and carry the family.
    #[test]
    fn sshd_config_ports_prefer_listen_addresses() {
        let both = "port 2222\nport 2200\naddressfamily any\n\
                    listenaddress [::]:2222\nlistenaddress 0.0.0.0:2222\n\
                    listenaddress 192.0.2.1:2200\n";
        assert_eq!(
            sshd_config_ports(both),
            vec![SshdPort::ipv4(2200), SshdPort::dual_stack(2222)]
        );
        // A ListenAddress with its own port overrides Port.
        let listen = "port 22\nlistenaddress 0.0.0.0:2022\n";
        assert_eq!(sshd_config_ports(listen), vec![SshdPort::ipv4(2022)]);
        // `AddressFamily inet6` with `-p 2222` (seen on dev-02's OpenSSH 9.6).
        let inet6 = "port 2222\naddressfamily inet6\nlistenaddress [::]:2222\n";
        assert_eq!(sshd_config_ports(inet6), vec![SshdPort::ipv6(2222)]);
        // Loopback binds need no rule, and do not fall back to `port`.
        let loopback = "port 22\nlistenaddress 127.0.0.1:2202\nlistenaddress [::1]:2202\n";
        assert_eq!(sshd_config_ports(loopback), Vec::<SshdPort>::new());
        // No listenaddress line: `port` in the `addressfamily` families.
        assert_eq!(sshd_config_ports("Port 2222\n"), dual(&[2222]));
        assert_eq!(
            sshd_config_ports("port 2222\naddressfamily inet\n"),
            vec![SshdPort::ipv4(2222)]
        );
        assert_eq!(
            sshd_config_ports("usedns no\nport 0\n"),
            Vec::<SshdPort>::new()
        );
    }

    /// `systemctl show`: only active or enabled socket units count, with `BindIPv6Only` applied.
    #[test]
    fn socket_unit_ports_come_from_live_units_only() {
        // dev-02's real ssh.socket (Ubuntu 24.04).
        let active = "BindIPv6Only=ipv6-only\nListen=0.0.0.0:2222 (Stream)\n\
                      Listen=[::]:2222 (Stream)\nActiveState=active\nUnitFileState=enabled\n\n\
                      BindIPv6Only=default\nActiveState=inactive\nUnitFileState=\n";
        assert_eq!(socket_unit_ports(active, true), dual(&[2222]));
        // Enabled but not started yet (before the next boot) still counts.
        let enabled = "Listen=2200 (Stream)\nListen=/run/x.sock (Stream)\n\
                       Listen=[::]:5353 (Datagram)\nActiveState=inactive\n\
                       UnitFileState=enabled\nBindIPv6Only=default\n";
        assert_eq!(socket_unit_ports(enabled, true), dual(&[2200]));
        assert_eq!(
            socket_unit_ports(enabled, false),
            vec![SshdPort::ipv6(2200)]
        );
        let v6only = "Listen=[::]:2201 (Stream)\nActiveState=active\nBindIPv6Only=ipv6-only\n";
        assert_eq!(socket_unit_ports(v6only, true), vec![SshdPort::ipv6(2201)]);
        // A stock, disabled ssh.socket next to a plain ssh.service is ignored.
        let disabled = "Listen=[::]:22 (Stream)\nActiveState=inactive\n\
                        UnitFileState=disabled\n";
        assert_eq!(socket_unit_ports(disabled, true), Vec::<SshdPort>::new());
    }

    /// J670 (P3): `$SSHD_OPTS`, `${OPTIONS}` and drop-in arguments reach `sshd -G` as the manager passes them.
    #[test]
    fn review_j670_service_arguments_are_expanded_and_filtered() {
        let environment = HashMap::from([
            ("SSHD_OPTS".to_owned(), "-p 2299 -oPort=2297".to_owned()),
            ("OPTIONS".to_owned(), "-p 2296".to_owned()),
        ]);
        let words = "-D $SSHD_OPTS ${OPTIONS} $UNSET -e -E /var/log/x -4"
            .split_ascii_whitespace()
            .flat_map(|word| expand_word(word, &environment))
            .collect::<Vec<_>>();
        assert_eq!(
            words,
            [
                "-D",
                "-p",
                "2299",
                "-oPort=2297",
                "-p 2296",
                "-e",
                "-E",
                "/var/log/x",
                "-4"
            ]
        );
        // `${OPTIONS}` stays one word, so sshd sees `-p 2296` as -p with value " 2296".
        assert_eq!(
            listener_arguments(&words).expect("arguments"),
            ["-p", "2299", "-o", "Port=2297", "-p", " 2296", "-4"]
        );
        assert_eq!(
            listener_arguments(&["-Dp2222".to_owned()]).expect("clustered"),
            ["-p", "2222"]
        );
        assert!(listener_arguments(&["-p".to_owned()]).is_err());
        assert!(listener_arguments(&["stray".to_owned()]).is_err());
    }

    /// The manager's `Environment=` quoting and environment-file syntax are read back exactly.
    #[test]
    fn environment_values_are_read_like_the_manager_does() {
        // Exactly what systemd 255 printed on dev-02 for a probe unit.
        assert_eq!(
            split_quoted("\"SSHD_OPTS=-p 2299\" B=x").expect("split"),
            ["SSHD_OPTS=-p 2299", "B=x"]
        );
        assert!(split_quoted("\"open").is_err());
        let file = "# comment\n; also\n\nSSHD_OPTS=\"-p 2298\"\nOPTIONS='-p 2297'\n\
                    PLAIN = -p 2296  \nLONG=-p \\\n2295\n";
        assert_eq!(
            parse_environment_file(file).expect("parse"),
            [
                ("SSHD_OPTS".to_owned(), "-p 2298".to_owned()),
                ("OPTIONS".to_owned(), "-p 2297".to_owned()),
                ("PLAIN".to_owned(), "-p 2296".to_owned()),
                ("LONG".to_owned(), "-p 2295".to_owned()),
            ]
        );
    }

    /// `systemctl show` `ExecStart=` values give each command's binary and arguments.
    #[test]
    fn exec_start_values_are_split_into_commands() {
        let value = "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $SSHD_OPTS ; \
                     ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; \
                     code=(null) ; status=0/0 }";
        assert_eq!(
            super::exec_commands(value),
            [(
                "/usr/sbin/sshd".to_owned(),
                "/usr/sbin/sshd -D $SSHD_OPTS".to_owned()
            )]
        );
    }

    /// `/proc/net/tcp{,6}` addresses decode in both families, including mapped IPv4.
    #[test]
    fn proc_net_addresses_decode() {
        let v4 = |address: [u8; 4]| format!("{:08X}", u32::from_ne_bytes(address));
        // Each 32-bit word of an IPv6 address is printed like a whole IPv4 one.
        let v6 = |address: std::net::Ipv6Addr| {
            address
                .octets()
                .chunks(4)
                .map(|word| v4(word.try_into().expect("word")))
                .collect::<String>()
        };
        assert_eq!(
            proc_net_address(&v4([127, 0, 0, 1])),
            Some("127.0.0.1".parse().expect("ip"))
        );
        assert_eq!(
            proc_net_address(&v4([10, 0, 0, 1])),
            Some("10.0.0.1".parse().expect("ip"))
        );
        assert_eq!(
            proc_net_address(&v6("::ffff:127.0.0.1".parse().expect("mapped"))),
            Some("::ffff:127.0.0.1".parse().expect("ip"))
        );
        assert_eq!(proc_net_address("zz"), None);
        let at = |address: &str| {
            SshdPort::listening_on(
                std::net::SocketAddr::new(address.parse().expect("ip"), 22),
                false,
            )
        };
        assert_eq!(at("127.0.0.1"), None);
        assert_eq!(at("::1"), None);
        assert_eq!(at("::ffff:127.0.0.1"), None);
        assert_eq!(at("::ffff:192.0.2.1"), Some(SshdPort::ipv4(22)));
        // sshd's own `[::]` socket is IPv6 only.
        assert_eq!(at("::"), Some(SshdPort::ipv6(22)));
        assert_eq!(at("0.0.0.0"), Some(SshdPort::ipv4(22)));
    }

    /// J658 (P3): a process named `sshd` counts only when its account is allowed.
    ///
    /// The holder is a copy of the system shell renamed `sshd`, blocked in
    /// `read` on a pipe this test keeps open, with the listener as its
    /// stdout. It must be alive and named `sshd` when the ports are read:
    /// J635's first version copied `sleep`, which under Nix is a link to
    /// multi-call coreutils, so its copy exited at once and the test passed
    /// without a holder. Allowed owners exclude root here, so the host's
    /// real root sshd (whose descriptors an unprivileged runner cannot
    /// read) is not consulted.
    #[test]
    fn review_j658_a_non_root_process_named_sshd_sets_no_port() {
        use std::os::{fd::OwnedFd, unix::fs::MetadataExt};
        use std::process::{Command, Stdio};
        let own = std::fs::metadata("/proc/self").expect("proc").uid();
        if own == 0 {
            eprintln!("SKIP: running as root; the holder would be root-owned");
            return;
        }
        // A real, single-program binary: a multi-call one exits when renamed.
        let shell = std::fs::canonicalize("/bin/sh").expect("resolve /bin/sh");
        let scratch = std::env::temp_dir().join(format!("j658-sshd-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch");
        let fake = scratch.join("sshd");
        std::fs::copy(&shell, &fake).expect("copy the shell as sshd");
        // Wildcard, not loopback: loopback-only listeners are skipped by design.
        let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("listener");
        let port = listener.local_addr().expect("address").port();
        let mut holder = Command::new(&fake)
            .args(["-c", "read line"])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(OwnedFd::from(listener)))
            .stderr(Stdio::null())
            .spawn()
            .expect("start the fake sshd");
        let comm = format!("/proc/{}/comm", holder.id());
        for _ in 0..100 {
            if std::fs::read_to_string(&comm).is_ok_and(|name| name.trim_end() == "sshd") {
                break;
            }
            // sleep: poll until the child has exec'd and its comm reads `sshd`.
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let alive = holder.try_wait().expect("holder state").is_none();
        let named = std::fs::read_to_string(&comm).unwrap_or_default();
        // Control: counted as its own account, the holder's port is seen.
        let as_service_account = super::sshd_listening_ports(&[own]);
        // An account no process runs as: the holder must not count.
        let ports = super::sshd_listening_ports(&[u32::MAX - 7]);
        let _ = holder.kill();
        let _ = holder.wait();
        let _ = std::fs::remove_dir_all(&scratch);
        assert!(
            alive && named.trim_end() == "sshd",
            "the holder is not a live process named sshd (alive {alive}, comm {named:?}); \
             the check below would prove nothing"
        );
        assert!(
            as_service_account
                .as_ref()
                .is_ok_and(|ports| ports.contains(&SshdPort::ipv4(port))),
            "the holder's port {port} was not seen even for its own account \
             ({as_service_account:?}); the check below would prove nothing"
        );
        assert!(
            ports
                .as_ref()
                .is_ok_and(|ports| !ports.iter().any(|seen| seen.port == port)),
            "a process named sshd outside the allowed accounts set sshd's port to {port} ({ports:?})"
        );
    }
}
