//! Owns one stateful mesh packet filter; nft transactions are atomic and use indexed sets [164,216], #129.
//!
//! Every firewall program is found by [`crate::firewall_tools`] at a fixed, root-owned path,
//! including Nix profile and store paths, and never through `PATH` [D384].
use crate::{
    dataplane::Config,
    firewall_tools::{self, Tool},
    policy::rules::{Protocol, TrafficPolicy},
    wireguard::INTERFACE,
};
use std::{
    fmt::Write as _,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
const TABLE: &str = "infraternal_mesh";
/// Kernel-only protections shown when a `GotaTun` guard cannot be installed.
const MISSING_KERNEL_PROTECTIONS: [&str; 3] = [
    "mesh-address anti-spoofing on non-mesh interfaces",
    "forwarding drops",
    "public TCP/80 and TCP/443 gate",
];
// Only peers with an inbound TCP grant can reach an entry point. Traefik's exact-host
// middleware then checks the source against that route's original backend-port grant.

// These plans only remove previously validated permissions. Changed identity,
// routes, bindings or concrete rules require the ordinary two-family preflight.
fn removes_only_permissions(old: &Config, next: &Config) -> bool {
    old.node == next.node
        && old.local_key == next.local_key
        && old.server == next.server
        && old.addresses == next.addresses
        && old.peers.len() == next.peers.len()
        && old.peers.iter().all(|(id, previous)| {
            next.peers.get(id).is_some_and(|peer| {
                peer.peer == previous.peer
                    && (peer.inbound == TrafficPolicy::None || peer.inbound == previous.inbound)
                    && (peer.outbound == TrafficPolicy::None || peer.outbound == previous.outbound)
            })
        })
}

/// The two owner-selected Linux frontends; kernel policy is retained independently of processes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Backend {
    Nft,
    NfTables,
}

/// The live state of the optional kernel-only guard for a `GotaTun` node.
#[derive(Clone, Debug, serde::Serialize)]
pub struct KernelGuardStatus {
    /// Whether the guard is installed, missing, or waiting for mesh addresses.
    pub state: &'static str,
    /// The protections that are not currently active.
    pub missing: Vec<&'static str>,
    /// The exact tool/path result or installation error.
    pub detail: String,
}

impl Default for KernelGuardStatus {
    fn default() -> Self {
        Self {
            state: "pending",
            missing: MISSING_KERNEL_PROTECTIONS.to_vec(),
            detail: "waiting for the mesh addresses needed by the kernel guard".to_owned(),
        }
    }
}

/// Selects whether the kernel owns full peer policy or only guards the host edges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FirewallMode {
    /// Keep the complete peer policy in the selected firewall frontend.
    #[default]
    FullPolicy,
    /// Keep only kernel-visible protections and let `GotaTun` decide mesh access.
    OptionalKernelGuard,
    /// Keep full peer policy in nft for the kernel `WireGuard` opt-out.
    RequiredNft,
}

/// Select an optional fixed-path frontend only when its complete command set is trusted.
fn optional_backend(nft: bool, iptables_ipv4: bool, iptables_ipv6: bool) -> Option<Backend> {
    if nft {
        Some(Backend::Nft)
    } else if iptables_ipv4 && iptables_ipv6 {
        Some(Backend::NfTables)
    } else {
        None
    }
}

/// Name each unavailable tool and every place searched, so a missing optional guard is visible.
fn missing_guard_tool_detail(nft: bool, iptables_ipv4: bool, iptables_ipv6: bool) -> String {
    let mut missing = Vec::new();
    if !nft {
        missing.push("nft");
    }
    if !iptables_ipv4 {
        missing.push("iptables-nft and iptables-nft-restore");
    }
    if !iptables_ipv6 {
        missing.push("ip6tables-nft and ip6tables-nft-restore");
    }
    format!(
        "{} were not found as root-owned executables in {}",
        missing.join("; "),
        firewall_tools::searched_places("{nftables,iptables}")
    )
}

/// Find nft at its fixed, root-owned path.
///
/// # Errors
/// The error starts with `nft ` and names every place searched; D346's refusal relies on that.
pub(crate) fn nft() -> io::Result<PathBuf> {
    Ok(firewall_tools::find(Tool::Nft)?)
}

/// Keep command failures readable when the found tool races or refuses access.
fn tool_error(path: &Path, operation: &str, error: &io::Error) -> io::Error {
    let name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("firewall tool");
    io::Error::new(
        error.kind(),
        format!(
            "{name} at {} could not {operation}: {error}",
            path.display()
        ),
    )
}

/// An owned inet table with input, output and forwarded packet enforcement.
#[derive(Default)]
pub struct Firewall {
    installed: bool,
    fallback_complete: bool,
    previous: Option<Config>,
    previous_aliases: Vec<crate::policy::model::Addresses>,
    backend: Option<Backend>,
    accepted: Option<Config>,
    proxy_ingress: infraternal_mesh::proxy_ports::MeshProxyIngress,
    // The configuration the proxy's routes were last confirmed against. Comparing with it,
    // not with the last Mesh change, finds a lost route again after Traefik's reload, which
    // closes the window in which a revoked peer could open a new connection [#281].
    proxy_config: Option<Config>,
    previous_fence: bool,
    mode: FirewallMode,
    guard_status: KernelGuardStatus,
}
impl Firewall {
    /// Select the declared compatibility backend explicitly for real-engine validation.
    #[must_use]
    pub fn nf_tables() -> Self {
        Self::for_backend(Backend::NfTables)
    }
    /// Retain the chosen compatibility frontend across a process restart.
    #[must_use]
    pub fn for_backend(backend: Backend) -> Self {
        Self {
            backend: Some(backend),
            ..Self::default()
        }
    }
    /// Configure the firewall mode selected by the node's engine.
    #[must_use]
    pub(crate) fn for_node(
        backend: Option<Backend>,
        engine: crate::gotatun_node::EngineKind,
    ) -> Self {
        let mode = match engine {
            crate::gotatun_node::EngineKind::GotaTun => FirewallMode::OptionalKernelGuard,
            crate::gotatun_node::EngineKind::Kernel => FirewallMode::RequiredNft,
        };
        let backend = if mode == FirewallMode::RequiredNft {
            Some(Backend::Nft)
        } else {
            backend
        };
        Self {
            backend,
            mode,
            ..Self::default()
        }
    }
    /// Read the selected frontend for public-state persistence.
    #[must_use]
    pub fn backend(&self) -> Option<Backend> {
        self.backend
    }
    /// Keep the chosen frontend, or pick nft when one is found at a fixed root-owned path and
    /// the iptables-nft compatibility frontend otherwise.
    fn select(&mut self) {
        self.backend.get_or_insert_with(|| {
            if firewall_tools::find(Tool::Nft).is_ok() {
                Backend::Nft
            } else {
                Backend::NfTables
            }
        });
    }
    /// How host uninstall names this filter when it leaves it in place (#235).
    #[must_use]
    pub fn name(&self) -> &'static str {
        if self.is_fallback() {
            "the IFM_* iptables chains"
        } else {
            TABLE
        }
    }
    /// Whether the last `adopt` found our marked filter installed.
    #[must_use]
    pub fn installed(&self) -> bool {
        self.installed
    }
    /// Read the optional kernel guard state for status and user-facing diagnostics.
    #[must_use]
    pub fn kernel_guard_status(&self) -> Option<&KernelGuardStatus> {
        self.guard_only().then_some(&self.guard_status)
    }

    /// Whether the selected node engine moves peer access decisions into `GotaTun`.
    fn guard_only(&self) -> bool {
        self.mode == FirewallMode::OptionalKernelGuard
    }

    /// Whether the selected node engine requires the fixed nft frontend.
    fn nft_required(&self) -> bool {
        self.mode == FirewallMode::RequiredNft
    }

    /// Require a fixed, root-owned nft for the kernel-WireGuard opt-out (D346).
    ///
    /// # Errors
    /// Names `nft` and every place searched when none holds a trusted executable.
    pub(crate) fn require_nft(&mut self) -> io::Result<()> {
        nft()?;
        self.backend = Some(Backend::Nft);
        self.mode = FirewallMode::RequiredNft;
        Ok(())
    }
    /// Resolve the fixed root-owned tool paths without consulting `PATH`.
    fn select_optional_backend(&mut self) -> bool {
        let found = |tool| firewall_tools::find(tool).is_ok();
        let nft = found(Tool::Nft);
        let ipv4 = found(Tool::IptablesNft) && found(Tool::IptablesNftRestore);
        let ipv6 = found(Tool::Ip6tablesNft) && found(Tool::Ip6tablesNftRestore);
        self.select_optional_backend_with_tools(nft, ipv4, ipv6)
    }
    /// Record the available fixed-path frontend, or the exact missing-tool state for `GotaTun`.
    fn select_optional_backend_with_tools(
        &mut self,
        nft: bool,
        iptables_ipv4: bool,
        iptables_ipv6: bool,
    ) -> bool {
        let available_at = |backend| match backend {
            Backend::Nft => nft,
            Backend::NfTables => iptables_ipv4 && iptables_ipv6,
        };
        let selected = self
            .backend
            .filter(|backend| available_at(*backend))
            .or_else(|| optional_backend(nft, iptables_ipv4, iptables_ipv6));
        if let Some(selected) = selected {
            self.backend = Some(selected);
            true
        } else {
            self.guard_status = KernelGuardStatus {
                state: "missing",
                missing: MISSING_KERNEL_PROTECTIONS.to_vec(),
                detail: missing_guard_tool_detail(nft, iptables_ipv4, iptables_ipv6),
            };
            false
        }
    }
    /// Keep the exact missing protections and tool path in status after a best-effort failure.
    fn report_guard_failure(&mut self, operation: &str, error: &io::Error) {
        self.guard_status = KernelGuardStatus {
            state: "failed",
            missing: MISSING_KERNEL_PROTECTIONS.to_vec(),
            detail: format!("{operation}: {error}"),
        };
    }
    /// Report whether the last best-effort guard transaction is active.
    fn refresh_guard_status(&mut self) {
        self.guard_status = if self.installed {
            let at = |tool| {
                firewall_tools::find(tool).map_or_else(
                    |_| "its fixed path".to_owned(),
                    |path| path.display().to_string(),
                )
            };
            let detail = match self.backend {
                Some(Backend::Nft) => {
                    format!("nft at {} installed the kernel-only guard", at(Tool::Nft))
                }
                Some(Backend::NfTables) => format!(
                    "iptables-nft-restore at {} and ip6tables-nft-restore at {} installed the kernel-only guard",
                    at(Tool::IptablesNftRestore),
                    at(Tool::Ip6tablesNftRestore)
                ),
                None => "the kernel-only guard is not installed".to_owned(),
            };
            KernelGuardStatus {
                state: "installed",
                missing: Vec::new(),
                detail,
            }
        } else {
            KernelGuardStatus::default()
        };
    }
    fn is_fallback(&self) -> bool {
        matches!(self.backend, Some(Backend::NfTables))
    }
    /// Recover the owned table after a daemon restart; an unrelated table is refused.
    /// # Errors
    /// Reports missing tools, privilege failures or unrelated rules with the same name.
    pub fn adopt(&mut self) -> io::Result<()> {
        let optional_guard = self.guard_only();
        if self.nft_required() {
            self.require_nft()?;
        } else if optional_guard {
            if !self.select_optional_backend() {
                self.installed = false;
                self.fallback_complete = false;
                return Ok(());
            }
        } else {
            self.select();
        }
        match self.adopt_selected_backend() {
            Ok(()) => {
                if self.guard_only() {
                    self.refresh_guard_status();
                }
                Ok(())
            }
            Err(error) if optional_guard => {
                self.installed = false;
                self.fallback_complete = false;
                self.report_guard_failure("inspect the kernel-only guard", &error);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
    /// Inspect the selected frontend without changing which protections it owns.
    fn adopt_selected_backend(&mut self) -> io::Result<()> {
        if self.is_fallback() {
            if self.guard_only() {
                let guard = crate::iptables::guard_presence()?;
                self.installed = guard.iter().any(|family| family.any());
                self.fallback_complete = guard.iter().all(|family| family.complete());
            } else {
                let families = crate::iptables::presence()?;
                self.installed = families.into_iter().any(crate::iptables::Ownership::any);
                self.fallback_complete = families
                    .into_iter()
                    .all(crate::iptables::Ownership::complete);
            }
        } else {
            let nft = nft()?;
            let tables = Command::new(&nft)
                .args(["-j", "list", "tables"])
                .stderr(Stdio::null())
                .output()
                .map_err(|error| tool_error(&nft, "inspect tables", &error))?;
            if !tables.status.success() {
                return Err(tool_error(
                    &nft,
                    "inspect tables",
                    &io::Error::new(io::ErrorKind::PermissionDenied, "the command failed"),
                ));
            }
            let tables: serde_json::Value =
                serde_json::from_slice(&tables.stdout).map_err(io::Error::other)?;
            let exists = tables["nftables"].as_array().is_some_and(|tables| {
                tables
                    .iter()
                    .any(|item| item["table"]["family"] == "inet" && item["table"]["name"] == TABLE)
            });
            self.installed = false;
            if exists {
                let output = Command::new(&nft)
                    .args(["-j", "list", "table", "inet", TABLE])
                    .stderr(Stdio::null())
                    .output()
                    .map_err(|error| tool_error(&nft, "inspect the mesh table", &error))?;
                if !output.status.success() {
                    return Err(tool_error(
                        &nft,
                        "inspect the mesh table",
                        &io::Error::new(io::ErrorKind::PermissionDenied, "the command failed"),
                    ));
                }
                let state: serde_json::Value =
                    serde_json::from_slice(&output.stdout).map_err(io::Error::other)?;
                // Only the table's own complete comment establishes ownership.
                // A rule/set comment or an operator's longer comment cannot do so.
                if !state["nftables"].as_array().is_some_and(|items| {
                    items.iter().any(|item| {
                        let table = &item["table"];
                        table["family"] == "inet"
                            && table["name"] == TABLE
                            && table["comment"] == "infraternal.mesh.v1"
                    })
                }) {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                self.installed = true;
            }
        }
        Ok(())
    }
    /// Install final network access rules and retire exactly the state no longer permitted.
    /// # Errors
    /// Reports installation or retirement errors. Once installed, the new rules
    /// remain restrictive on a cleanup error; the caller retries completion.
    pub fn apply(&mut self, config: &Config) -> io::Result<()> {
        self.install_pending(config)?;
        self.complete(config)
    }
    /// Replace the active proxy route grants after Traefik confirms its dynamic snapshot.
    ///
    /// # Errors
    /// Returns a failed firewall transaction without claiming the new proxy ingress policy.
    ///
    /// Called after every confirmed route snapshot, also an unchanged one: a source that lost
    /// a route since the last confirmation has its proxied flows retired here.
    ///
    /// Only a `confirmed` call moves that reference to `config`. A gate-only or other local
    /// update may run while Traefik still serves routes rendered from an older configuration
    /// (a crash restart from retained routes, say). Moving the reference then would let a
    /// source reconnect under the old routes and keep that flow past the next confirmation.
    pub fn apply_proxy_ingress(
        &mut self,
        config: &Config,
        proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
        confirmed: bool,
    ) -> io::Result<()> {
        if self.guard_only() {
            self.install(config, &[], false, config, proxy_ingress)?;
            self.proxy_ingress = proxy_ingress.clone();
            self.accepted = Some(config.clone());
            if confirmed {
                self.proxy_config = Some(config.clone());
            }
            return Ok(());
        }
        if self.proxy_ingress != *proxy_ingress || self.accepted.as_ref() != Some(config) {
            self.install(config, &[], false, config, proxy_ingress)?;
        }
        let previous = std::mem::replace(&mut self.proxy_ingress, proxy_ingress.clone());
        let reference = self.proxy_config.clone().or_else(|| self.accepted.clone());
        crate::connection_state::retire(
            self.accepted.as_ref(),
            config,
            reference.as_ref().map(|reference| (reference, &previous)),
            &self.proxy_ingress,
        )?;
        self.accepted = Some(config.clone());
        if confirmed {
            self.proxy_config = Some(config.clone());
        }
        Ok(())
    }
    // The node persists public intent between installation and irreversible retirement.
    pub(crate) fn install_pending(&mut self, config: &Config) -> io::Result<()> {
        let proxy_ingress = self.proxy_ingress.clone();
        self.install(config, &[], false, config, &proxy_ingress)
    }
    /// Retire revoked conntrack entries after the full policy snapshot has committed.
    pub(crate) fn complete(&mut self, config: &Config) -> io::Result<()> {
        if self.guard_only() {
            self.accepted = Some(config.clone());
            if crate::proxy_access::selected_ports(&self.proxy_ingress).is_none() {
                self.proxy_config = Some(config.clone());
            }
            return Ok(());
        }
        let reference = self.proxy_config.as_ref().or(self.accepted.as_ref());
        crate::connection_state::retire(
            self.accepted.as_ref(),
            config,
            reference.map(|reference| (reference, &self.proxy_ingress)),
            &self.proxy_ingress,
        )?;
        if crate::proxy_access::selected_ports(&self.proxy_ingress).is_none() {
            // No proxied flow exists to protect; keep the reference current.
            self.proxy_config = Some(config.clone());
        }
        self.accepted = Some(config.clone());
        Ok(())
    }
    /// Fence both accepted and proposed addresses during an authorized replacement.
    pub(crate) fn apply_with_aliases(
        &mut self,
        config: &Config,
        aliases: &[crate::policy::model::Addresses],
        connections: &Config,
    ) -> io::Result<()> {
        let proxy_ingress = self.proxy_ingress.clone();
        self.install(config, aliases, true, connections, &proxy_ingress)
    }
    /// Install the selected full policy, or only its kernel guard for `GotaTun`.
    fn install(
        &mut self,
        config: &Config,
        aliases: &[crate::policy::model::Addresses],
        fence: bool,
        connections: &Config,
        proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
    ) -> io::Result<()> {
        if self.guard_only() {
            return self.install_guard_only(config, aliases, proxy_ingress);
        }
        if self.nft_required() {
            self.require_nft()?;
        }
        self.select();
        // A table declaration can extend an existing table. First application
        // must therefore validate ownership even when no adapter called adopt.
        if !self.installed && !self.is_fallback() {
            self.adopt()?;
        }
        if self.is_fallback() {
            let retain_guard = self.fallback_complete
                && self
                    .previous
                    .as_ref()
                    .is_some_and(|old| old.addresses == config.addresses)
                && self.previous_aliases == aliases;
            let removal_only = retain_guard
                && !fence
                && !self.previous_fence
                && connections == config
                && self.proxy_ingress == *proxy_ingress
                && self
                    .previous
                    .as_ref()
                    .is_some_and(|old| removes_only_permissions(old, config));
            if let Err(error) = crate::iptables::apply_with_aliases(
                config,
                self.fallback_complete,
                aliases,
                fence,
                connections,
                proxy_ingress,
                if removal_only {
                    crate::iptables::Update::VerifiedRemoval
                } else if retain_guard {
                    crate::iptables::Update::RetainGuard
                } else {
                    crate::iptables::Update::Full
                },
            ) {
                if let Some(old) = &self.previous {
                    crate::iptables::apply_with_aliases(
                        old,
                        true,
                        &self.previous_aliases,
                        self.previous_fence,
                        old,
                        &self.proxy_ingress,
                        crate::iptables::Update::Full,
                    )?;
                } else {
                    crate::iptables::remove()?;
                }
                return Err(error);
            }
        } else {
            run(
                &nft()?,
                &["-f", "-"],
                &render_with_aliases(
                    config,
                    self.installed,
                    aliases,
                    fence,
                    connections,
                    proxy_ingress,
                ),
            )?;
        }
        // A fence has no new-connection rules. Its saved view therefore only
        // needs the committed tuple rules plus the union of guarded addresses.
        self.previous = self.is_fallback().then(|| {
            if fence {
                connections.clone()
            } else {
                config.clone()
            }
        });
        self.previous_fence = fence;
        self.previous_aliases = if self.is_fallback() {
            let mut saved = aliases.to_vec();
            if fence && config.addresses != connections.addresses {
                saved.push(config.addresses);
            }
            saved
        } else {
            Vec::new()
        };
        self.installed = true;
        self.fallback_complete = self.is_fallback();
        Ok(())
    }
    /// Apply only kernel-visible protections while `GotaTun` enforces all access grants itself.
    fn install_guard_only(
        &mut self,
        config: &Config,
        aliases: &[crate::policy::model::Addresses],
        proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
    ) -> io::Result<()> {
        if self.nft_required() {
            self.require_nft()?;
        } else if !self.select_optional_backend() {
            return Ok(());
        }
        if !self.installed
            && let Err(error) = self.adopt()
        {
            if self.nft_required() {
                return Err(error);
            }
            self.report_guard_failure("inspect the existing guard", &error);
            return Ok(());
        }
        let applied = if self.is_fallback() {
            crate::iptables::apply_guard_only(config, aliases, proxy_ingress)
        } else {
            run(
                &nft()?,
                &["-f", "-"],
                &render_guard_only(config, self.installed, aliases, proxy_ingress),
            )
        };
        match applied {
            Ok(()) => {
                self.installed = true;
                self.fallback_complete = self.is_fallback();
                self.previous = Some(config.clone());
                self.previous_aliases = aliases.to_vec();
                self.previous_fence = false;
                self.refresh_guard_status();
                Ok(())
            }
            Err(error) if self.nft_required() => Err(error),
            Err(error) => {
                self.report_guard_failure("apply the kernel-only guard", &error);
                Ok(())
            }
        }
    }
    /// Remove only the owned table, leaving the host firewall intact.
    /// # Errors
    /// Returns a failed kernel deletion without claiming the component is off.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.guard_only() {
            if self.installed {
                if self.nft_required() {
                    self.require_nft()?;
                } else if !self.select_optional_backend() {
                    return Ok(());
                }
                if self.is_fallback() {
                    crate::iptables::remove_guard_only()?;
                } else {
                    self.adopt()?;
                    if self.installed {
                        run(
                            &nft()?,
                            &["-f", "-"],
                            &format!("delete table inet {TABLE}\n"),
                        )?;
                    }
                }
            }
            self.installed = false;
            self.fallback_complete = false;
            self.previous = None;
            self.accepted = None;
            self.proxy_config = None;
            self.proxy_ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
            self.previous_aliases.clear();
            self.refresh_guard_status();
            return Ok(());
        }
        if self.installed {
            if self.nft_required() {
                self.require_nft()?;
            }
            if self.is_fallback() {
                crate::iptables::remove()?;
            } else {
                // Recheck ownership before deletion. Confirmed absence is an
                // idempotent cleanup; privilege or foreign-table failures stay visible.
                self.adopt()?;
                if self.installed {
                    run(
                        &nft()?,
                        &["-f", "-"],
                        &format!("delete table inet {TABLE}\n"),
                    )?;
                }
            }
            self.installed = false;
            self.fallback_complete = false;
            self.previous = None;
            self.accepted = None;
            self.proxy_config = None;
            self.proxy_ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
            self.previous_aliases.clear();
        }
        Ok(())
    }
}
/// Run one fixed firewall command with a public rule script supplied on standard input.
fn run(program: &Path, args: &[&str], script: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| tool_error(program, "run", &error))?;
    // Policy contains public typed addresses/ports only. No shell or secret in argv/stdout.
    let write = child
        .stdin
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .write_all(script.as_bytes());
    let status = child.wait()?;
    write?;
    if !status.success() {
        return Err(tool_error(
            program,
            "apply the requested rules",
            &io::Error::new(io::ErrorKind::PermissionDenied, "the command failed"),
        ));
    }
    Ok(())
}
/// Render constant-time hash-set membership, independent of the peer count on the packet path.
#[must_use]
pub fn render(config: &Config, replace: bool) -> String {
    render_with_aliases(
        config,
        replace,
        &[],
        false,
        config,
        &infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
    )
}
// Keep the complete owned inet transaction visible as one atomic batch.
fn render_with_aliases(
    config: &Config,
    replace: bool,
    aliases: &[crate::policy::model::Addresses],
    fence: bool,
    connections: &Config,
    proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
) -> String {
    let connections = if fence { connections } else { config };
    let mut script = String::new();
    if replace {
        let _ = writeln!(script, "delete table inet {TABLE}");
    }
    let _ = writeln!(
        script,
        "table inet {TABLE} {{\n comment \"infraternal.mesh.v1\";"
    );
    let proxy_ingress_ports = crate::proxy_access::selected_ports(proxy_ingress)
        .map_or_else(String::new, |[http, https]| {
            format!(" elements = {{ {http}, {https} }};")
        });
    // nft rejects an empty `elements = { }` list, so an empty set omits the clause.
    let _ = writeln!(
        script,
        " set proxy_ingress_ports {{ type inet_service;{proxy_ingress_ports} }}"
    );
    for (direction, inbound) in [("incoming", true), ("outgoing", false)] {
        for (family, ipv6) in [("ipv4_addr", false), ("ipv6_addr", true)] {
            let suffix = if ipv6 { "6" } else { "4" };
            for protocol in [None, Some(Protocol::Tcp), Some(Protocol::Udp)] {
                let name = match protocol {
                    None => "all",
                    Some(Protocol::Tcp) => "tcp",
                    Some(Protocol::Udp) => "udp",
                };
                let mut entries = Vec::new();
                for peer in connections.peers.values() {
                    let address = if ipv6 {
                        peer.peer.addresses.ipv6.to_string()
                    } else {
                        peer.peer.addresses.ipv4.to_string()
                    };
                    match if inbound {
                        &peer.inbound
                    } else {
                        &peer.outbound
                    } {
                        TrafficPolicy::All if protocol.is_none() => entries.push(address),
                        TrafficPolicy::Ports(ports) => {
                            for port in ports {
                                if Some(port.protocol) == protocol {
                                    entries.push(format!("{address} . {}", port.number));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                let ty = if protocol.is_none() {
                    family.to_owned()
                } else {
                    format!("{family} . inet_service")
                };
                let elements = if entries.is_empty() {
                    String::new()
                } else {
                    format!(" elements = {{ {} }};", entries.join(", "))
                };
                let _ = writeln!(
                    script,
                    " set {direction}{suffix}_{name} {{ type {ty};{elements} }}"
                );
            }
            if inbound {
                let proxy_sources: Vec<_> =
                    crate::proxy_access::sources(connections, proxy_ingress)
                        .map(|peer| {
                            if ipv6 {
                                peer.peer.addresses.ipv6.to_string()
                            } else {
                                peer.peer.addresses.ipv4.to_string()
                            }
                        })
                        .collect();
                let elements = if proxy_sources.is_empty() {
                    String::new()
                } else {
                    format!(" elements = {{ {} }};", proxy_sources.join(", "))
                };
                let _ = writeln!(
                    script,
                    " set incoming{suffix}_proxy_sources {{ type {family};{elements} }}"
                );
            }
        }
        let _ = writeln!(script, " chain {direction} {{");
        // Exact retirement removes both kernel tuple directions. Loose TCP
        // tracking can nevertheless classify a continuation as a fresh flow.
        // Only an initiating SYN may create replacement TCP state [164,242].
        let _ = writeln!(
            script,
            "  ct state new tcp flags & (fin | syn | rst | ack) != syn drop"
        );
        // Recovery must never reopen entries refused by saved intent [242].
        let _ = writeln!(
            script,
            "  ct state established,related jump {direction}_state"
        );
        if !fence {
            let field = if inbound { "saddr" } else { "daddr" };
            for (family, suffix) in [("ip", "4"), ("ip6", "6")] {
                let _ = writeln!(script, "  {family} {field} @{direction}{suffix}_all accept");
                if inbound {
                    let _ = writeln!(
                        script,
                        "  ct original protocol tcp ct original {family} saddr @incoming{suffix}_proxy_sources ct original proto-dst @proxy_ingress_ports accept"
                    );
                }
                for protocol in ["tcp", "udp"] {
                    // Input filtering runs after destination NAT. Keep the mesh
                    // grant tied to the service the peer addressed, not a
                    // redirect's private listener port [#221].
                    let selector = if inbound {
                        format!(
                            "ct original protocol {protocol} ct original {family} {field} . ct original proto-dst"
                        )
                    } else {
                        format!("{family} {field} . {protocol} dport")
                    };
                    let _ = writeln!(
                        script,
                        "  {selector} @{direction}{suffix}_{protocol} accept"
                    );
                }
            }
        }
        // ICMP errors are RELATED; unsolicited ICMP and all other protocols obey All or deny.
        let _ = writeln!(script, "  drop\n }}");
    }
    render_connection_checks(&mut script, connections);
    // Destination NAT has completed at input/forward. Check delivery before
    // policy or conntrack acceptance: an underlay packet has no mesh identity.
    // Loopback delivery is node-local. Translation never turns an underlay
    // incoming interface into lo, so this preserves the ingress refusal [231].
    let mut delivery = String::new();
    for addresses in std::iter::once(&config.addresses).chain(aliases) {
        let _ = write!(
            delivery,
            "iifname != {{ \"{INTERFACE}\", \"lo\" }} ip daddr {} drop; iifname != {{ \"{INTERFACE}\", \"lo\" }} ip6 daddr {} drop;",
            addresses.ipv4, addresses.ipv6
        );
    }
    for (name, hook, interface, direction) in [
        ("input", "input", "iifname", "incoming"),
        ("output", "output", "oifname", "outgoing"),
    ] {
        let guard = if hook == "input" { &delivery } else { "" };
        // The proxy binds its public pair with Go's wildcard listener, which is one dual-stack
        // socket for 0.0.0.0, so the gate matches both families in this inet table. It exists
        // only while a proxy child holds that pair; the supervisor clears it after reaping.
        let public_gate = if hook == "input" && !proxy_ingress.public_route_active {
            proxy_ingress
                .public_listener_pair
                .filter(|pair| {
                    pair.http != pair.https
                        && infraternal_mesh::proxy_ports::PROXY_INGRESS_PORT_RANGES
                            .iter()
                            .any(|range| range.contains(pair.http))
                        && infraternal_mesh::proxy_ports::PROXY_INGRESS_PORT_RANGES
                            .iter()
                            .any(|range| range.contains(pair.https))
                })
                .map_or_else(String::new, |pair| {
                    format!(
                        "iifname != \"lo\" tcp dport {{ {}, {} }} drop;",
                        pair.http, pair.https
                    )
                })
        } else {
            String::new()
        };
        let _ = writeln!(
            script,
            " chain {name} {{ type filter hook {hook} priority -10; policy accept; {guard} {public_gate} {interface} \"{INTERFACE}\" jump {direction}; }}"
        );
    }
    let _ = writeln!(
        script,
        " chain forward {{ type filter hook forward priority -10; policy accept; {delivery} iifname \"{INTERFACE}\" drop; oifname \"{INTERFACE}\" drop; }}"
    );
    // Mesh-bound services must receive authenticated tunnel packets. Fence
    // underlay delivery early as well as at the final destination check above.
    // Subnet transit
    // has no owner in this slice, even when a host enables IP forwarding.
    let _ = writeln!(
        script,
        " chain ingress {{ type filter hook prerouting priority -310; policy accept; {delivery} }}\n}}"
    );
    script
}

/// Render only the protections the `GotaTun` packet filter cannot see.
///
/// Access grants stay in userspace. This table rejects mesh-address spoofing on other
/// interfaces, stops forwarding through the host, and closes the public listener pair until
/// a public route is active.
fn render_guard_only(
    config: &Config,
    replace: bool,
    aliases: &[crate::policy::model::Addresses],
    proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
) -> String {
    let addresses = std::iter::once(&config.addresses)
        .chain(aliases)
        .chain(config.peers.values().map(|peer| &peer.peer.addresses))
        .flat_map(|address| {
            [
                std::net::IpAddr::V4(address.ipv4),
                std::net::IpAddr::V6(address.ipv6),
            ]
        })
        .collect::<std::collections::BTreeSet<_>>();
    let ipv4 = addresses
        .iter()
        .filter_map(|address| match address {
            std::net::IpAddr::V4(address) => Some(address.to_string()),
            std::net::IpAddr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    let ipv6 = addresses
        .iter()
        .filter_map(|address| match address {
            std::net::IpAddr::V4(_) => None,
            std::net::IpAddr::V6(address) => Some(address.to_string()),
        })
        .collect::<Vec<_>>();
    let mut script = String::new();
    if replace {
        let _ = writeln!(script, "delete table inet {TABLE}");
    }
    let _ = writeln!(
        script,
        "table inet {TABLE} {{ comment \"infraternal.mesh.v1\";"
    );
    let ipv4_entries = ipv4.join(", ");
    let ipv6_entries = ipv6.join(", ");
    let _ = writeln!(
        script,
        " set mesh4 {{ type ipv4_addr; elements = {{ {ipv4_entries} }}; }}"
    );
    let _ = writeln!(
        script,
        " set mesh6 {{ type ipv6_addr; elements = {{ {ipv6_entries} }}; }}"
    );
    let _ = writeln!(
        script,
        " chain ingress {{ type filter hook prerouting priority -310; policy accept; iifname != \"{INTERFACE}\" ip saddr @mesh4 drop; iifname != \"{INTERFACE}\" ip6 saddr @mesh6 drop; }}"
    );
    let _ = writeln!(
        script,
        " chain forward {{ type filter hook forward priority -10; policy accept; iifname \"{INTERFACE}\" drop; oifname \"{INTERFACE}\" drop; }}"
    );
    let public_gate = if proxy_ingress.public_route_active {
        String::new()
    } else {
        proxy_ingress
            .public_listener_pair
            .filter(|pair| {
                pair.http != pair.https
                    && infraternal_mesh::proxy_ports::PROXY_INGRESS_PORT_RANGES
                        .iter()
                        .any(|range| range.contains(pair.http))
                    && infraternal_mesh::proxy_ports::PROXY_INGRESS_PORT_RANGES
                        .iter()
                        .any(|range| range.contains(pair.https))
            })
            .map_or_else(String::new, |pair| {
                format!(
                    "iifname != \"lo\" tcp dport {{ {}, {} }} drop;",
                    pair.http, pair.https
                )
            })
    };
    let _ = writeln!(
        script,
        " chain input {{ type filter hook input priority -10; policy accept; {public_gate} }}"
    );
    script.push_str("}\n");
    script
}

// Both packet directions consult the initiating tuple. A reply's ephemeral
// destination port is never interpreted as permission to initiate [164,242].
fn render_connection_checks(script: &mut String, config: &Config) {
    for (chain, incoming) in [("incoming", true), ("outgoing", false)] {
        let _ = writeln!(script, " chain {chain}_state {{");
        for (reply, direction, field, local_field) in if incoming {
            [
                ("original", "incoming", "saddr", "daddr"),
                ("reply", "outgoing", "daddr", "saddr"),
            ]
        } else {
            [
                ("original", "outgoing", "daddr", "saddr"),
                ("reply", "incoming", "saddr", "daddr"),
            ]
        } {
            for (family, suffix, local) in [
                ("ip", "4", config.addresses.ipv4.to_string()),
                ("ip6", "6", config.addresses.ipv6.to_string()),
            ] {
                let selector =
                    format!("ct direction {reply} ct original {family} {local_field} {local}");
                let _ = writeln!(
                    script,
                    "  {selector} ct original {family} {field} @{direction}{suffix}_all accept"
                );
                if direction == "incoming" {
                    // A proxied flow was admitted by the listener-pair exception, not by a
                    // per-port grant. Its later packets in both directions need the same test,
                    // or only the initiating SYN would pass [#281].
                    let _ = writeln!(
                        script,
                        "  {selector} ct original protocol tcp ct original {family} saddr @incoming{suffix}_proxy_sources ct original proto-dst @proxy_ingress_ports accept"
                    );
                }
                for protocol in ["tcp", "udp"] {
                    let _ = writeln!(
                        script,
                        "  {selector} ct original protocol {protocol} ct original {family} {field} . ct original proto-dst @{direction}{suffix}_{protocol} accept"
                    );
                }
            }
        }
        let _ = writeln!(script, "  drop\n }}");
    }
}

/// Firewall compilation and ownership checks.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{
        dataplane::{DefaultPolicy, Peer, PeerPolicy},
        policy::model::{Addresses, NodeId, PublicKey},
    };
    #[test]
    fn removal_plan_cannot_add_permissions_or_change_identity() {
        let old = config();
        let mut next = old.clone();
        for peer in next.peers.values_mut() {
            peer.inbound = TrafficPolicy::None;
        }
        assert!(removes_only_permissions(&old, &next));
        assert!(!removes_only_permissions(&next, &old));
        let mut changed = next.clone();
        changed.server = Some(NodeId(u64::MAX));
        assert!(!removes_only_permissions(&old, &changed));
        changed = next.clone();
        changed.local_key = Some(PublicKey([9; 32]));
        assert!(!removes_only_permissions(&old, &changed));
        changed = next.clone();
        changed.addresses.ipv4 = "192.0.2.9".parse().expect("IPv4");
        assert!(!removes_only_permissions(&old, &changed));
        changed = next.clone();
        changed.peers.values_mut().next().expect("peer").peer.key = PublicKey([9; 32]);
        assert!(!removes_only_permissions(&old, &changed));
        changed = next.clone();
        changed.peers.remove(&NodeId(2));
        assert!(!removes_only_permissions(&old, &changed));
        changed = next;
        changed.peers.values_mut().next().expect("peer").inbound =
            TrafficPolicy::Ports(std::collections::BTreeSet::new());
        assert!(!removes_only_permissions(&old, &changed));
    }

    /// A two-peer configuration with stable test addresses.
    fn config() -> Config {
        let address = |id: u32| Addresses {
            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
            ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
        };
        Config {
            authority_epoch: None,
            local_key: None,
            server: None,
            node: NodeId(1),
            #[cfg(feature = "mesh-dns")]
            name: None,
            #[cfg(feature = "mesh-dns")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: address(1),
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            peers: (2..=1001)
                .map(|id| {
                    (
                        NodeId(u64::from(id)),
                        PeerPolicy {
                            peer: Peer {
                                key: PublicKey([1; 32]),
                                previous_key: None,
                                previous_active: false,
                                addresses: address(id),
                                endpoint: None,
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                            access_ssh: None,
                        },
                    )
                })
                .collect(),
            #[cfg(feature = "mesh-dns")]
            peer_names: std::collections::BTreeMap::new(),
        }
    }

    /// The `GotaTun` optional guard contains only rules the packet filter cannot see.
    #[test]
    fn gotatun_guard_contains_only_mesh_spoof_forward_and_public_port_rules() {
        let config = config();
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress {
            public_listener_pair: Some(infraternal_mesh::proxy_ports::ListenerPortPair {
                http: 80,
                https: 443,
            }),
            public_route_active: false,
            ..infraternal_mesh::proxy_ports::MeshProxyIngress::default()
        };

        let rules = render_guard_only(&config, true, &[], &ingress);

        for rule in [
            "ip saddr @mesh4 drop",
            "ip6 saddr @mesh6 drop",
            "iifname \"infraternal0\" drop",
            "oifname \"infraternal0\" drop",
            "tcp dport { 80, 443 } drop",
        ] {
            assert!(rules.contains(rule), "missing {rule}: {rules}");
        }
        for policy_rule in ["incoming4_", "outgoing4_", "ct state", "ct original"] {
            assert!(
                !rules.contains(policy_rule),
                "unexpected {policy_rule}: {rules}"
            );
        }
    }

    /// A first guard install adds a table directly; only an owned replacement deletes it first.
    #[test]
    fn gotatun_guard_rendering_distinguishes_first_install_from_replacement() {
        let config = config();
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();

        let first = render_guard_only(&config, false, &[], &ingress);
        let replacement = render_guard_only(&config, true, &[], &ingress);

        assert!(!first.starts_with("delete table"));
        assert!(replacement.starts_with("delete table inet infraternal_mesh\n"));
    }

    /// Optional guard selection uses only complete fixed-path frontends and names every gap.
    #[test]
    fn optional_guard_selects_fixed_tools_and_names_every_missing_path() {
        assert_eq!(optional_backend(true, false, false), Some(Backend::Nft));
        assert_eq!(optional_backend(false, true, true), Some(Backend::NfTables));
        assert_eq!(optional_backend(false, true, false), None);

        let detail = missing_guard_tool_detail(false, false, false);
        for part in [
            "nft; iptables-nft and iptables-nft-restore; ip6tables-nft and ip6tables-nft-restore were not found",
            "/usr/sbin, /usr/bin, /run/current-system/sw/bin",
            "/nix/store/*-{nftables,iptables}-<version>/bin",
        ] {
            assert!(detail.contains(part), "missing {part}: {detail}");
        }
        assert!(
            detail.len() <= 512,
            "the UI shows details up to 512 bytes: {detail}"
        );
        assert!(!missing_guard_tool_detail(true, false, true).contains("ip6tables"));
    }

    /// D346's refusal for kernel `WireGuard` keeps the `nft ` prefix the plugin maps to its reason.
    #[test]
    fn missing_nft_errors_start_with_the_tool_name() {
        let error = io::Error::from(firewall_tools::Missing(Tool::Nft));
        assert!(
            error.to_string().starts_with("nft was not found"),
            "{error}"
        );
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        let error = tool_error(
            Path::new("/nix/store/a-nftables-1.1.7/bin/nft"),
            "run",
            &io::Error::from(io::ErrorKind::PermissionDenied),
        );
        assert!(
            error
                .to_string()
                .starts_with("nft at /nix/store/a-nftables-1.1.7/bin/nft could not run"),
            "{error}"
        );
    }

    /// A missing optional guard is reported without refusing a userspace mesh node.
    #[test]
    fn gotatun_guard_without_trusted_tools_is_nonfatal_and_lists_missing_protections() {
        let mut firewall = Firewall::for_node(None, crate::gotatun_node::EngineKind::GotaTun);

        assert!(!firewall.select_optional_backend_with_tools(false, false, false));

        let status = firewall
            .kernel_guard_status()
            .expect("GotaTun guard status");
        assert_eq!(status.state, "missing");
        assert_eq!(status.missing, MISSING_KERNEL_PROTECTIONS);
        for part in [
            "nft",
            "iptables-nft-restore",
            "ip6tables-nft-restore",
            "/nix/store",
        ] {
            assert!(
                status.detail.contains(part),
                "missing {part}: {}",
                status.detail
            );
        }
    }
    #[test]
    fn rule_count_is_independent_of_membership_and_policy_data_is_in_sets() {
        let mut config = config();
        let rules = render(&config, false);
        assert_eq!(
            rules.matches(" accept").count(),
            46,
            "the fixed rule set includes proxy listener accepts for IPv4 and IPv6"
        );
        assert_eq!(rules.matches(" drop").count(), 14);
        assert_eq!(
            rules
                .matches("ct state new tcp flags & (fin | syn | rst | ack) != syn drop")
                .count(),
            2
        );
        let peer = config.peers.get_mut(&NodeId(2)).expect("member");
        peer.outbound = TrafficPolicy::Ports(std::collections::BTreeSet::from([
            crate::policy::rules::Port {
                protocol: Protocol::Tcp,
                number: 5432,
            },
        ]));
        let rules = render(&config, true);
        assert!(rules.contains("10.254.0.2 . 5432"));
        assert!(rules.starts_with("delete table inet infraternal_mesh\n"));
    }
    #[test]
    fn incoming_port_rules_match_the_original_service_after_translation() {
        let mut config = config();
        let peer = config.peers.get_mut(&NodeId(2)).expect("peer");
        peer.inbound = TrafficPolicy::Ports(std::collections::BTreeSet::from([
            crate::policy::rules::Port {
                protocol: Protocol::Tcp,
                number: 22,
            },
        ]));
        peer.outbound = TrafficPolicy::Ports(std::collections::BTreeSet::from([
            crate::policy::rules::Port {
                protocol: Protocol::Tcp,
                number: 443,
            },
        ]));

        let rules = render(&config, false);
        assert!(rules.contains(
            "ct original protocol tcp ct original ip saddr . ct original proto-dst @incoming4_tcp accept"
        ));
        assert!(!rules.contains("ip saddr . tcp dport @incoming4_tcp accept"));
        assert!(rules.contains("ip daddr . tcp dport @outgoing4_tcp accept"));
    }
    #[test]
    fn proxy_listener_exception_is_closed_without_a_published_route() {
        let mut config = config();
        for peer in config.peers.values_mut() {
            peer.inbound = TrafficPolicy::None;
        }
        config.peers.get_mut(&NodeId(2)).expect("tcp peer").inbound =
            TrafficPolicy::Ports(std::collections::BTreeSet::from([
                crate::policy::rules::Port {
                    protocol: Protocol::Tcp,
                    number: 3000,
                },
            ]));
        config.peers.get_mut(&NodeId(3)).expect("udp peer").inbound =
            TrafficPolicy::Ports(std::collections::BTreeSet::from([
                crate::policy::rules::Port {
                    protocol: Protocol::Udp,
                    number: 53,
                },
            ]));

        let rules = render(&config, false);
        assert!(rules.contains("set proxy_ingress_ports { type inet_service; }"));
        assert!(rules.contains("set incoming4_proxy_sources { type ipv4_addr; }"));
        assert!(!rules.contains("10080-10335"));
    }
    #[test]
    fn proxy_exception_uses_only_selected_pair_and_a_published_route_grant() {
        let mut config = config();
        for peer in config.peers.values_mut() {
            peer.inbound = TrafficPolicy::None;
        }
        for (node, port) in [(2, 3000), (3, 8080)] {
            config.peers.get_mut(&NodeId(node)).expect("peer").inbound =
                TrafficPolicy::Ports(std::collections::BTreeSet::from([
                    crate::policy::rules::Port {
                        protocol: Protocol::Tcp,
                        number: port,
                    },
                ]));
        }
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress {
            public_listener_pair: None,
            public_route_active: false,
            listener_pair: Some(selected),
            backend_ports: std::collections::BTreeSet::from([8080]),
        };
        let rules = super::render_with_aliases(&config, false, &[], false, &config, &ingress);

        assert!(rules.contains(&format!(
            "set proxy_ingress_ports {{ type inet_service; elements = {{ {}, {} }}; }}",
            selected.http, selected.https
        )));
        assert!(rules.contains(
            "set incoming4_proxy_sources { type ipv4_addr; elements = { 10.254.0.3 }; }"
        ));
        assert!(
            !rules
                .contains("set incoming4_proxy_sources { type ipv4_addr; elements = { 10.254.0.2")
        );
        assert!(!rules.contains("10082"));
        assert!(rules.contains("ct original protocol tcp ct original ip saddr @incoming4_proxy_sources ct original proto-dst @proxy_ingress_ports accept"));
    }

    #[test]
    fn proxied_flows_keep_passing_the_state_chains_after_their_syn() {
        let mut config = config();
        for peer in config.peers.values_mut() {
            peer.inbound = TrafficPolicy::None;
        }
        config.peers.get_mut(&NodeId(3)).expect("peer").inbound =
            TrafficPolicy::Ports(std::collections::BTreeSet::from([
                crate::policy::rules::Port {
                    protocol: Protocol::Tcp,
                    number: 8080,
                },
            ]));
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress {
            listener_pair: Some(infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1]),
            backend_ports: std::collections::BTreeSet::from([8080]),
            ..Default::default()
        };
        let rules = super::render_with_aliases(&config, false, &[], false, &config, &ingress);
        let chain = |name: &str| {
            let start = rules
                .find(&format!(" chain {name} {{"))
                .expect("state chain");
            let end = start + rules[start..].find("  drop\n }").expect("chain end");
            rules[start..end].to_owned()
        };
        for (name, direction) in [("incoming_state", "original"), ("outgoing_state", "reply")] {
            for (family, suffix, local) in [("ip", "4", "10.254.0.1"), ("ip6", "6", "fd01::1")] {
                assert!(
                    chain(name).contains(&format!(
                        "ct direction {direction} ct original {family} daddr {local} ct original protocol tcp ct original {family} saddr @incoming{suffix}_proxy_sources ct original proto-dst @proxy_ingress_ports accept"
                    )),
                    "{name} must admit {direction} packets of a proxied {family} flow"
                );
            }
        }
    }

    #[test]
    fn wildcard_public_listener_is_blocked_until_a_public_route_is_applied() {
        let config = config();
        let pair = infraternal_mesh::proxy_ports::CONVENTIONAL_LISTENER_PAIR;
        let mut ingress = infraternal_mesh::proxy_ports::MeshProxyIngress {
            public_listener_pair: Some(pair),
            ..Default::default()
        };
        let gate = "iifname != \"lo\" tcp dport { 80, 443 } drop";

        let closed = super::render_with_aliases(&config, false, &[], false, &config, &ingress);
        assert!(closed.contains(gate));

        ingress.public_route_active = true;
        let open = super::render_with_aliases(&config, false, &[], false, &config, &ingress);
        assert!(!open.contains(gate));
    }

    /// Real nft: a foreign table is refused, a broken batch changes nothing, and a large
    /// policy applies; nft is found through the same fixed-path lookup as the product.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn real_nft_ownership_atomicity_and_scaled_apply() {
        run(
            &nft().expect("nft"),
            &["-f", "-"],
            &format!("add table inet {TABLE}\n"),
        )
        .expect("unrelated fixture");
        let mut unrelated = Firewall::default();
        assert_eq!(
            unrelated.adopt().expect_err("unowned table").kind(),
            io::ErrorKind::AlreadyExists
        );
        run(
            &nft().expect("nft"),
            &["-f", "-"],
            &format!("delete table inet {TABLE}\n"),
        )
        .expect("fixture cleanup");
        let mut filter = Firewall::default();
        filter.adopt().expect("empty namespace");
        let mut config = config();
        let started = std::time::Instant::now();
        filter.apply(&config).expect("scaled install");
        let initial = started.elapsed().as_micros();
        let broken = format!("delete table inet {TABLE}\ninvalid syntax\n");
        assert!(run(&nft().expect("nft"), &["-f", "-"], &broken).is_err());
        let mut recovered = Firewall::default();
        recovered
            .adopt()
            .expect("atomic failed batch retained old table");
        assert!(recovered.installed);
        config.peers.get_mut(&NodeId(500)).expect("member").outbound = TrafficPolicy::None;
        let started = std::time::Instant::now();
        filter.apply(&config).expect("policy replacement");
        println!(
            "METRIC nft_policy machine=infraternal-dev peers=1000 apply_us={initial} single_peer_us={} load={}",
            started.elapsed().as_micros(),
            std::fs::read_to_string("/proc/loadavg")
                .expect("load")
                .trim()
        );
        filter.remove().expect("off");
        let mut absent = Firewall::default();
        absent.adopt().expect("clean namespace");
        assert!(!absent.installed);
    }
    /// Removing a table someone already deleted still lets the component finish cleanup.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn already_removed_owned_table_does_not_block_component_cleanup() {
        let mut filter = Firewall::default();
        filter.adopt().expect("empty namespace");
        filter.apply(&config()).expect("install");
        run(
            &nft().expect("nft"),
            &["-f", "-"],
            &format!("delete table inet {TABLE}\n"),
        )
        .expect("external removal");
        filter.remove().expect("already absent owned table");
        assert!(!filter.installed);
    }
    /// A first apply checks ownership itself and refuses a same-named table it did not create.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn initial_apply_without_adoption_refuses_a_foreign_table() {
        run(
            &nft().expect("nft"),
            &["-f", "-"],
            &format!("add table inet {TABLE}\n"),
        )
        .expect("foreign fixture");
        let mut filter = Firewall::default();
        assert_eq!(
            filter.apply(&config()).expect_err("foreign table").kind(),
            io::ErrorKind::AlreadyExists
        );
        run(
            &nft().expect("nft"),
            &["-f", "-"],
            &format!("delete table inet {TABLE}\n"),
        )
        .expect("fixture cleanup");
    }

    /// Real kernel, both frontends: the optional `GotaTun` guard installs through the tool the
    /// fixed-path lookup found, its status names that exact path, and removal leaves no guard.
    ///
    /// Run as real root under a systemd unit that hides the distribution tools, it proves the
    /// Nix store path is the one executed (#265 J560 proof).
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn real_optional_guard_runs_and_reports_the_found_tool_for_both_frontends() {
        for (backend, tool) in [
            (Backend::Nft, Tool::Nft),
            (Backend::NfTables, Tool::IptablesNftRestore),
        ] {
            let path = firewall_tools::find(tool).expect("frontend at a fixed path");
            let mut firewall =
                Firewall::for_node(Some(backend), crate::gotatun_node::EngineKind::GotaTun);
            firewall.apply(&config()).expect("guard install");
            assert_eq!(firewall.backend(), Some(backend));
            let status = firewall
                .kernel_guard_status()
                .expect("guard status")
                .clone();
            assert_eq!(status.state, "installed", "{}", status.detail);
            assert!(status.missing.is_empty(), "{:?}", status.missing);
            assert!(
                status.detail.contains(&path.display().to_string()),
                "{}",
                status.detail
            );
            println!("GUARD backend={backend:?} detail={}", status.detail);
            firewall.remove().expect("guard removal");
            assert_eq!(
                firewall.kernel_guard_status().expect("status").state,
                "pending"
            );
            let mut probe =
                Firewall::for_node(Some(backend), crate::gotatun_node::EngineKind::GotaTun);
            probe.adopt().expect("inspect after removal");
            let after = probe.kernel_guard_status().expect("status after removal");
            assert_ne!(after.state, "failed", "{}", after.detail);
            assert!(!probe.installed(), "{backend:?} guard left behind");
        }
    }
}
