//! Owns one stateful mesh packet filter; nft transactions are atomic and use indexed sets [164,216], #129.
//!
//! Every firewall program is found by [`crate::firewall_tools`] at a fixed, root-owned path,
//! including Nix profile entry points, and never through `PATH` or a Nix store scan [D384].
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
const MISSING_KERNEL_PROTECTIONS: [&str; 4] = [
    "mesh-address anti-spoofing on non-mesh interfaces",
    "underlay delivery to mesh addresses",
    "forwarding drops",
    "public TCP/80 and TCP/443 gate",
];
// Only peers with an inbound TCP grant can reach an entry point. Traefik's exact-host
// middleware then checks the source against that route's original backend-port grant.

// These plans only remove previously validated permissions. Changed identity,
// routes, bindings or concrete rules require the ordinary two-family preflight.
/// Whether `next` only narrows `old`'s grants with the same identity, peers and subnet routes, so the cheaper removal-only update is enough.
fn removes_only_permissions(old: &Config, next: &Config) -> bool {
    old.node == next.node
        && old.local_key == next.local_key
        && old.server == next.server
        && old.addresses == next.addresses
        && old.peers.len() == next.peers.len()
        && old.peers.iter().all(|(id, previous)| {
            next.peers.get(id).is_some_and(|peer| {
                peer.peer == previous.peer
                    // Subnet routes change the guard's forward and NAT rules (D197 M3).
                    && peer.networks == previous.networks
                    && (peer.inbound == TrafficPolicy::None || peer.inbound == previous.inbound)
                    && (peer.outbound == TrafficPolicy::None || peer.outbound == previous.outbound)
            })
        })
}

/// The Linux frontend selected in a saved mesh snapshot.
pub use infraternal_mesh_node::node_state::Backend;

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
        firewall_tools::searched_places()
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
    // The UDP port the node's socket actually bound, as reported by the node through
    // `set_listen_port`. It is the single source of the host table's mesh UDP rule (D386).
    listen_port: Option<u16>,
    // The port last written to the host input table by this process. `None` after a
    // restart, so the first install re-checks the host table once and self-heals it.
    host_listener: Option<u16>,
    mode: FirewallMode,
    guard_status: KernelGuardStatus,
    // The nft `GotaTun` guard as this process last installed it, so the next install sends only
    // what changed (#260 J1240). `None` whenever the table's content is not known exactly: before
    // the first install, after `adopt` or `remove`, after any failed transaction, and for the
    // iptables frontend.
    guard_script: Option<GuardScript>,
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
    /// Whether the last `adopt` found our filter table installed.
    #[must_use]
    pub fn installed(&self) -> bool {
        self.installed
    }
    /// Whether this process opened the mesh listener in the host input table.
    ///
    /// A `GotaTun` node opens it even when no kernel guard is installed, so
    /// cleanup must call [`Self::remove`] when either this or
    /// [`Self::installed`] holds (D384, D386).
    #[must_use]
    pub(crate) fn host_ingress_open(&self) -> bool {
        self.host_listener.is_some()
    }
    /// Read the optional kernel guard state for status and user-facing diagnostics.
    #[must_use]
    pub fn kernel_guard_status(&self) -> Option<&KernelGuardStatus> {
        self.guard_only().then_some(&self.guard_status)
    }

    /// Whether the installed `GotaTun` guard forwards and masquerades this node's served networks
    /// (D197 M3): only the nft guard carries those rules, so the iptables fallback never forwards.
    #[must_use]
    pub(crate) fn forwards_served(&self) -> bool {
        self.guard_only() && self.installed && self.backend == Some(Backend::Nft)
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
    /// Recover the owned table after a daemon restart.
    ///
    /// D386 makes every `infraternal_*` table product-owned, so a table with this
    /// name is adopted with or without the old `infraternal.mesh.v1` marker.
    /// # Errors
    /// Reports missing tools, privilege failures or unrelated rules with the same name.
    pub fn adopt(&mut self) -> io::Result<()> {
        // What is installed now is only known by name; the next install replaces it whole.
        self.guard_script = None;
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
                // D386 defines the infraternal_* namespace as product-owned.
                // The stable table name is sufficient for takeover; an old
                // marker is not a prerequisite for updating a hand-built table.
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
        // Open host ingress only after the grant filter above is in place, so
        // the newly admitted UDP port and `infraternal0` are already filtered.
        self.sync_host_listener()
    }
    /// Tell the firewall which UDP port the node's socket actually bound.
    ///
    /// The node calls this whenever its identity changes: after the data plane
    /// binds, after a rebind to another port, and with `None` when it stops.
    /// While the grant filter is in place, a changed port is written to the
    /// host input table at once; otherwise the next install writes it. For a
    /// `GotaTun` node the grant filter is the engine's own deny-by-default
    /// packet filter, which exists before the engine reports its port, so the
    /// port is written at once whether or not the optional kernel guard is
    /// installed (D384, D386).
    ///
    /// # Errors
    /// Returns a failed host policy update; the previous host table stays active.
    pub(crate) fn set_listen_port(&mut self, port: Option<u16>) -> io::Result<()> {
        self.listen_port = port;
        if self.installed || self.guard_only() {
            self.sync_host_listener()?;
        }
        Ok(())
    }
    /// Admit the bound mesh port in the host input table when it differs from the last write.
    ///
    /// Skipping unchanged ports keeps ordinary grant updates free of host nft
    /// transactions. Without a bound port there is nothing to admit yet.
    fn sync_host_listener(&mut self) -> io::Result<()> {
        let Some(port) = self.listen_port else {
            return Ok(());
        };
        if self.host_listener == Some(port) {
            return Ok(());
        }
        publish_host_listener(Some(port))?;
        self.host_listener = Some(port);
        Ok(())
    }
    /// Apply only kernel-visible protections while `GotaTun` enforces all access grants itself.
    fn install_guard_only(
        &mut self,
        config: &Config,
        aliases: &[crate::policy::model::Addresses],
        proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
    ) -> io::Result<()> {
        self.install_kernel_guard(config, aliases, proxy_ingress)?;
        // `GotaTun` enforces every grant in userspace, so the host input table
        // admits the mesh port and `infraternal0` whether or not the optional
        // kernel guard could be installed. Without this a server-role host
        // with a default-drop host table would drop all mesh traffic (D386, F5).
        self.sync_host_listener()
    }
    /// Install the kernel-only guard on a best-effort basis; failures stay visible in status.
    fn install_kernel_guard(
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
            self.guard_script = None;
            crate::iptables::apply_guard_only(config, aliases, proxy_ingress)
        } else {
            self.install_nft_guard(GuardScript::new(config, aliases, proxy_ingress))
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
    /// Install the nft guard `script`, sending only what differs from the table this process
    /// last installed (#260 J1240).
    ///
    /// An unchanged table sends nothing, and changed address sets send one element transaction;
    /// anything else, or a table whose content is not known, is replaced whole, as before. When
    /// the element transaction is refused (someone changed the table under us), the table is
    /// replaced whole as well, so the result is always exactly `script`.
    /// # Errors
    /// Reports a missing nft or a refused full replacement; the recorded table is then unknown.
    fn install_nft_guard(&mut self, script: GuardScript) -> io::Result<()> {
        let installed = self.guard_script.take().filter(|_| self.installed);
        let nft = nft()?;
        let update = installed
            .as_ref()
            .map_or(GuardUpdate::Replace, |installed| {
                script.update_from(installed)
            });
        let done = match update {
            GuardUpdate::Unchanged => Ok(()),
            GuardUpdate::Elements(changes) => run(&nft, &["-f", "-"], &changes)
                .or_else(|_| run(&nft, &["-f", "-"], &script.render(true))),
            GuardUpdate::Replace => run(&nft, &["-f", "-"], &script.render(self.installed)),
        };
        if done.is_ok() {
            self.guard_script = Some(script);
        }
        done
    }
    /// Test seam (#260 J1240): forget the recorded guard content, so the next install replaces
    /// the whole table the way a first install after a restart does. Only the namespace tests
    /// that need `test-support` call it.
    #[cfg(all(test, feature = "test-support"))]
    pub(crate) fn forget_installed_guard(&mut self) {
        self.guard_script = None;
    }
    /// Remove only the owned table, leaving the host firewall intact.
    /// # Errors
    /// Returns a failed kernel deletion without claiming the component is off.
    pub fn remove(&mut self) -> io::Result<()> {
        self.guard_script = None;
        if self.installed || self.host_listener.is_some() {
            // Close host ingress before retiring the mesh grant filter. If the
            // host transaction fails, leave the mesh filter installed and retry.
            // A `GotaTun` node may have opened it without any kernel guard, so
            // an open listener alone also calls for this step (D384, D386).
            publish_host_listener(None)?;
            self.host_listener = None;
        }
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

/// Write the mesh listener (or its absence) to the host input table; grants stay in the mesh filter.
fn publish_host_listener(udp_port: Option<u16>) -> io::Result<()> {
    match crate::host_firewall::set_mesh_listener(udp_port) {
        Ok(Some(report)) => {
            tracing::info!(report = %report, "host firewall mesh policy updated");
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "host firewall mesh policy update failed: {error}"
        ))),
    }
}

/// Run one fixed firewall command with a public rule script supplied on standard input.
///
/// A refused batch reports the tool, its path and the tool's own stderr, so a
/// rejected rule names its cause instead of a bare permission error.
fn run(program: &Path, args: &[&str], script: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| tool_error(program, "run", &error))?;
    // Policy contains public typed addresses/ports only. No shell or secret in argv/stdout.
    let write = child
        .stdin
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .write_all(script.as_bytes());
    let output = child.wait_with_output()?;
    write?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        let reason = if stderr.is_empty() {
            "the command failed"
        } else {
            stderr
        };
        return Err(tool_error(
            program,
            "apply the requested rules",
            &io::Error::new(io::ErrorKind::PermissionDenied, reason.to_owned()),
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
/// Render the full kernel policy (grants, connection checks, delivery fence, forwarding drops
/// and the public gate) as one atomic `nft -f` batch.
///
/// `aliases` are extra local addresses a rotation still owns; they get the same delivery fence
/// as `config.addresses`. With `fence`, peer access comes from `config` (a deny-new fence) while
/// open connections are checked against `connections`. Keep the complete owned inet transaction
/// visible as one batch.
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
    let delivery = delivery_fence(config, aliases);
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

/// Rules that drop packets for this node's own mesh addresses unless they came in on the mesh
/// interface or loopback.
///
/// An underlay packet has no mesh identity, so it must never be delivered to a mesh address
/// [231]. Both the full policy and the `GotaTun` guard use this one rendering, so the two can
/// never drift apart (J592 P1, #265).
///
/// Each rule tests the destination address before the interface name. nftables evaluates a
/// rule's matches in order and stops at the first that fails, and almost every packet these
/// hooks see is not addressed to this node's mesh address (every encrypted underlay datagram
/// passes prerouting and input), so the one-word address compare fails first and the
/// interface-name set lookup runs only for packets that are actually for a mesh address. The
/// rule matches exactly the same packets in either order. On the 2-core perf receiver this order
/// raised reverse `GotaTun` throughput by 4-5% (#260, J1160).
fn delivery_fence(config: &Config, aliases: &[crate::policy::model::Addresses]) -> String {
    let mut delivery = String::new();
    for addresses in std::iter::once(&config.addresses).chain(aliases) {
        let _ = write!(
            delivery,
            "ip daddr {} iifname != {{ \"{INTERFACE}\", \"lo\" }} drop; ip6 daddr {} iifname != {{ \"{INTERFACE}\", \"lo\" }} drop;",
            addresses.ipv4, addresses.ipv6
        );
    }
    delivery
}

/// Rules that let this node talk to itself from its own mesh addresses (#578, J1154).
///
/// A packet a local process sends from the node's own mesh address to a local address (the
/// system resolver asking the node's mesh DNS, a health check on a mesh-bound service) re-enters
/// through `lo`. Without this rule the anti-spoofing drops below take it for a spoofed mesh
/// source and the query never gets an answer. Only `lo` is trusted, and only for the node's own
/// addresses: a packet cannot arrive on `lo` from outside the host, while a peer's address on `lo`
/// or any mesh address on another interface stays dropped. The rule ends the chain with
/// `accept`; the delivery fence that follows already lets `lo` through, so it skips nothing.
fn own_loopback_sources(config: &Config, aliases: &[crate::policy::model::Addresses]) -> String {
    let own = std::iter::once(&config.addresses).chain(aliases);
    let ipv4 = own.clone().map(|a| a.ipv4.to_string()).collect::<Vec<_>>();
    let ipv6 = own.map(|a| a.ipv6.to_string()).collect::<Vec<_>>();
    format!(
        "iifname \"lo\" ip saddr {{ {} }} accept; iifname \"lo\" ip6 saddr {{ {} }} accept;",
        ipv4.join(", "),
        ipv6.join(", ")
    )
}

/// Render only the protections the `GotaTun` packet filter cannot see.
///
/// Access grants stay in userspace. This table rejects mesh-address spoofing on other
/// interfaces, refuses underlay delivery to this node's mesh addresses, stops forwarding
/// through the host, and closes the public listener pair until a public route is active.
/// The node installs it through [`Firewall::install_nft_guard`]; tests read the script here.
#[cfg(test)]
fn render_guard_only(
    config: &Config,
    replace: bool,
    aliases: &[crate::policy::model::Addresses],
    proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
) -> String {
    GuardScript::new(config, aliases, proxy_ingress).render(replace)
}

/// The `GotaTun` guard table split into what grows with the peer count, the two sets of mesh
/// addresses, and everything else, so a new snapshot can be applied as set-element changes
/// (#260 J1240).
///
/// A snapshot that adds or removes peers changes only the sets; rewriting the whole table for it
/// cost a process start and a kernel commit of every element (6,180 ruleset lines at 4,096
/// peers). [`GuardScript::update_from`] turns two scripts into that smaller transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GuardScript {
    /// Every mesh IPv4 address the guard fences: this node's, its aliases', and each peer's.
    mesh4: std::collections::BTreeSet<std::net::Ipv4Addr>,
    /// The IPv6 addresses of the same owners.
    mesh6: std::collections::BTreeSet<std::net::Ipv6Addr>,
    /// The rest of the table after the two sets: served-network sets and every chain, ending
    /// with the table's closing brace.
    rest: String,
}

/// What it takes to move the installed guard table from one [`GuardScript`] to another.
#[derive(Debug, PartialEq, Eq)]
enum GuardUpdate {
    /// Both scripts produce the same table: nothing to send.
    Unchanged,
    /// Only set elements differ: this one `nft -f` transaction adds and deletes them.
    Elements(String),
    /// The chains or other sets differ: the whole table is replaced, as on a first install.
    Replace,
}

impl GuardScript {
    /// Build the guard for `config` with the old addresses `aliases` still fenced.
    fn new(
        config: &Config,
        aliases: &[crate::policy::model::Addresses],
        proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
    ) -> Self {
        let owners = std::iter::once(&config.addresses)
            .chain(aliases)
            .chain(config.peers.values().map(|peer| &peer.peer.addresses));
        let mut mesh4 = std::collections::BTreeSet::new();
        let mut mesh6 = std::collections::BTreeSet::new();
        for address in owners {
            mesh4.insert(address.ipv4);
            mesh6.insert(address.ipv6);
        }
        Self {
            mesh4,
            mesh6,
            rest: render_guard_rest(config, aliases, proxy_ingress),
        }
    }

    /// The complete table as one `nft -f` script; `replace` deletes the installed table first,
    /// in the same transaction.
    fn render(&self, replace: bool) -> String {
        let mut script = String::new();
        if replace {
            let _ = writeln!(script, "delete table inet {TABLE}");
        }
        let _ = writeln!(
            script,
            "table inet {TABLE} {{ comment \"infraternal.mesh.v1\";"
        );
        let _ = writeln!(
            script,
            " set mesh4 {{ type ipv4_addr; elements = {{ {} }}; }}",
            join_addresses(self.mesh4.iter())
        );
        let _ = writeln!(
            script,
            " set mesh6 {{ type ipv6_addr; elements = {{ {} }}; }}",
            join_addresses(self.mesh6.iter())
        );
        script.push_str(&self.rest);
        script
    }

    /// How to turn the table `installed` left into this one.
    ///
    /// The element changes run as one nft transaction, so the packet path sees the old sets or
    /// the new ones, never a mix. Deleting an element the kernel no longer holds fails the whole
    /// transaction; the caller then replaces the table.
    fn update_from(&self, installed: &Self) -> GuardUpdate {
        if self.rest != installed.rest {
            return GuardUpdate::Replace;
        }
        let mut script = String::new();
        set_changes(&mut script, "mesh4", &installed.mesh4, &self.mesh4);
        set_changes(&mut script, "mesh6", &installed.mesh6, &self.mesh6);
        if script.is_empty() {
            GuardUpdate::Unchanged
        } else {
            GuardUpdate::Elements(script)
        }
    }
}

/// Write the `add element` and `delete element` commands that turn set `name` from `old` into
/// `new`; nothing when they are equal.
fn set_changes<T: Ord + std::fmt::Display>(
    script: &mut String,
    name: &str,
    old: &std::collections::BTreeSet<T>,
    new: &std::collections::BTreeSet<T>,
) {
    for (verb, elements) in [
        ("add", new.difference(old).collect::<Vec<_>>()),
        ("delete", old.difference(new).collect::<Vec<_>>()),
    ] {
        if !elements.is_empty() {
            let _ = writeln!(
                script,
                "{verb} element inet {TABLE} {name} {{ {} }}",
                join_addresses(elements.into_iter())
            );
        }
    }
}

/// The comma-separated element list nft expects inside `{ }`.
fn join_addresses<T: std::fmt::Display>(addresses: impl Iterator<Item = T>) -> String {
    let mut list = String::new();
    for (index, address) in addresses.enumerate() {
        if index > 0 {
            list.push_str(", ");
        }
        let _ = write!(list, "{address}");
    }
    list
}

/// Render the part of the `GotaTun` guard after its two address sets: the served-network sets
/// and the chains, which name the sets but hold no per-peer data.
fn render_guard_rest(
    config: &Config,
    aliases: &[crate::policy::model::Addresses],
    proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
) -> String {
    let mut script = String::new();
    // Linux accepts a packet for any local address on any interface (the weak host model), so a
    // LAN neighbour that routes this node's mesh address via its LAN address would reach
    // mesh-bound services without passing the `GotaTun` filter. Only the node's own addresses are
    // fenced, so LAN-to-LAN traffic is untouched (J592 P1, the full policy's [231] fence).
    let delivery = delivery_fence(config, aliases);
    let own = own_loopback_sources(config, aliases);
    let _ = writeln!(
        script,
        " chain ingress {{ type filter hook prerouting priority -310; policy accept; {own} iifname != \"{INTERFACE}\" ip saddr @mesh4 drop; iifname != \"{INTERFACE}\" ip6 saddr @mesh6 drop; {delivery} }}"
    );
    let ServedRules {
        forward: served,
        input: served_fence,
    } = render_served_networks(config, &mut script);
    let _ = writeln!(
        script,
        " chain forward {{ type filter hook forward priority -10; policy accept; {delivery} {served} iifname \"{INTERFACE}\" drop; oifname \"{INTERFACE}\" drop; }}"
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
        " chain input {{ type filter hook input priority -10; policy accept; {delivery} {served_fence} {public_gate} }}"
    );
    script.push_str("}\n");
    script
}

/// The networks this node serves as a subnet router (D197 M3): every IPv4 network that some peer may
/// start into, and the ones among them whose forwarded traffic is masqueraded. Sorted and unique.
pub(crate) fn served_networks(
    config: &Config,
) -> (
    Vec<infraternal_mesh::networks::Network>,
    Vec<infraternal_mesh::networks::Network>,
) {
    let mut served = std::collections::BTreeSet::new();
    let mut masqueraded = std::collections::BTreeSet::new();
    for policy in config.peers.values() {
        for network in &policy.networks.served {
            if !network.network.is_ipv4() || network.inbound == TrafficPolicy::None {
                continue;
            }
            served.insert(network.network);
            if !network.keep_source {
                masqueraded.insert(network.network);
            }
        }
    }
    (
        served.into_iter().collect(),
        masqueraded.into_iter().collect(),
    )
}

/// The rules a subnet router adds to the `GotaTun` guard's chains; both are empty when this node
/// serves nothing.
struct ServedRules {
    /// Rules that go in front of the forward chain's mesh drops.
    forward: String,
    /// The fence that keeps the mesh off this node's own addresses inside the served networks.
    input: String,
}

/// Add the subnet-router part of the `GotaTun` guard to `script` (D197 M3, D384) and return the
/// rules it puts in the forward and input chains.
///
/// The `GotaTun` packet filter has already decided, per peer and port, which packets from the mesh
/// interface may enter a served network, so the kernel accepts exactly two things: packets from the
/// mesh interface to a served network, and replies on the mesh interface of connections that were
/// opened toward a served network. Everything else through the mesh interface is still dropped, so
/// a host on the network can never start a connection into the mesh. Masqueraded networks get a
/// `srcnat` chain that rewrites the source of mesh traffic leaving toward them to the router's own
/// address on that network; it lives in the same owned table, so removing the table removes it.
///
/// Invariant (#580, J1179): a network grant reaches the hosts on the network, never this node's
/// own services. A router usually owns an address inside the network it serves (its LAN
/// address), and Linux delivers a packet for that address locally instead of forwarding it, so
/// the packet filter's routed verdict, which only knows the router's mesh addresses as local,
/// would open the router's own listeners on every granted port, even with node access `None`.
/// The input chain therefore drops everything from the mesh interface addressed into a served
/// network. The router's own services stay reachable at its mesh address, under the node grant
/// and the packet filter's node rules; the mesh never reaches them through a served address. The
/// interface is matched first: almost every packet input sees is underlay traffic on another
/// interface, and the name compare rejects it before the interval-set lookup.
fn render_served_networks(config: &Config, script: &mut String) -> ServedRules {
    let (served, masqueraded) = served_networks(config);
    if served.is_empty() {
        return ServedRules {
            forward: String::new(),
            input: String::new(),
        };
    }
    let list = |networks: &[infraternal_mesh::networks::Network]| {
        networks
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let _ = writeln!(
        script,
        " set served4 {{ type ipv4_addr; flags interval; elements = {{ {} }}; }}",
        list(&served)
    );
    if !masqueraded.is_empty() {
        let _ = writeln!(
            script,
            " set masquerade4 {{ type ipv4_addr; flags interval; elements = {{ {} }}; }}",
            list(&masqueraded)
        );
        let _ = writeln!(
            script,
            " chain served_nat {{ type nat hook postrouting priority srcnat; policy accept; iifname \"{INTERFACE}\" oifname != \"{INTERFACE}\" ip daddr @masquerade4 masquerade; }}"
        );
    }
    ServedRules {
        forward: format!(
            "iifname \"{INTERFACE}\" oifname != \"{INTERFACE}\" ip daddr @served4 accept; oifname \"{INTERFACE}\" iifname != \"{INTERFACE}\" ct state established,related ct original ip daddr @served4 accept;"
        ),
        input: format!("iifname \"{INTERFACE}\" ip daddr @served4 drop;"),
    }
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
            rotation_operation: None,
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
                                candidates: Vec::new(),
                                ipv4_only: false,
                                side_port: false,
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                            access_ssh: None,
                            networks: crate::dataplane::PeerNetworks::default(),
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
            // The node's own addresses may arrive on loopback (#578), nothing else may.
            "iifname \"lo\" ip saddr { 10.254.0.1 } accept;",
            "iifname \"lo\" ip6 saddr { fd01::1 } accept;",
            "iifname \"infraternal0\" drop",
            "oifname \"infraternal0\" drop",
            "tcp dport { 80, 443 } drop",
        ] {
            assert!(rules.contains(rule), "missing {rule}: {rules}");
        }
        // The loopback exemption must come before the drop it exempts from, and name only this
        // node's own addresses, never a peer's.
        let accept = rules
            .find("iifname \"lo\" ip saddr { 10.254.0.1 } accept;")
            .expect("loopback exemption rendered");
        assert!(
            accept
                < rules
                    .find("ip saddr @mesh4 drop")
                    .expect("loopback exemption rendered"),
            "{rules}"
        );
        assert!(
            !rules.contains("iifname \"lo\" ip saddr { 10.254.0.1, "),
            "{rules}"
        );
        // The underlay delivery fence covers this node's own addresses in prerouting, input and
        // forward, and never a peer's (J592 P1): LAN traffic to other addresses is untouched.
        // The address is matched before the interface-name set, so the cheap compare rejects
        // the many underlay packets first (#260, J1160).
        for fence in [
            "ip daddr 10.254.0.1 iifname != { \"infraternal0\", \"lo\" } drop;",
            "ip6 daddr fd01::1 iifname != { \"infraternal0\", \"lo\" } drop;",
        ] {
            for chain in ["chain ingress", "chain input", "chain forward"] {
                let line = rules
                    .lines()
                    .find(|line| line.contains(chain))
                    .expect("guard chain");
                assert!(line.contains(fence), "{chain} lacks {fence}: {line}");
            }
        }
        assert!(!rules.contains("daddr 10.254.0.2 "), "{rules}");
        for policy_rule in ["incoming4_", "outgoing4_", "ct state", "ct original"] {
            assert!(
                !rules.contains(policy_rule),
                "unexpected {policy_rule}: {rules}"
            );
        }
    }

    /// A subnet router's guard keeps the mesh off its own addresses inside the networks it serves
    /// (#580, J1179): the input chain drops mesh packets for a served network, while the forward
    /// chain still lets them through to the hosts. A node that serves nothing gets no such rule.
    #[test]
    fn a_served_network_is_forwarded_but_never_delivered_to_the_router_itself() {
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
        let input = |rules: &str| {
            rules
                .lines()
                .find(|line| line.contains("chain input"))
                .expect("guard input chain")
                .to_owned()
        };
        let fence = "iifname \"infraternal0\" ip daddr @served4 drop;";

        let plain = render_guard_only(&config(), true, &[], &ingress);
        assert!(!input(&plain).contains("@served4"), "{plain}");

        let mut router = config();
        router
            .peers
            .values_mut()
            .next()
            .expect("peer")
            .networks
            .served
            .push(crate::dataplane::ServedNetwork {
                network: "198.51.100.0/24".parse().expect("network"),
                inbound: TrafficPolicy::All,
                keep_source: false,
            });
        let rules = render_guard_only(&router, true, &[], &ingress);
        let input = input(&rules);
        assert!(input.contains(fence), "{input}");
        // The mesh-address delivery fence still comes first, unchanged.
        assert!(
            input.find("ip daddr 10.254.0.1 ").expect("delivery fence")
                < input.find(fence).expect("served fence"),
            "{input}"
        );
        let forward = rules
            .lines()
            .find(|line| line.contains("chain forward"))
            .expect("guard forward chain");
        assert!(
            forward.contains(
                "iifname \"infraternal0\" oifname != \"infraternal0\" ip daddr @served4 accept;"
            ),
            "{forward}"
        );
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

    /// The guard keeps its exact rendering, now built from [`GuardScript`] (#260 J1240): the two
    /// address sets list every owner once, sorted, and the table ends after the chains.
    #[test]
    fn guard_script_renders_sorted_unique_address_sets() {
        let mut config = config();
        config.peers.retain(|id, _| id.0 <= 3);
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
        // An alias equal to a peer's addresses is listed once.
        let alias = config.peers.values().next().expect("peer").peer.addresses;
        let rules = render_guard_only(&config, false, &[alias], &ingress);
        let lines: Vec<_> = rules.lines().collect();
        assert_eq!(
            lines[0],
            "table inet infraternal_mesh { comment \"infraternal.mesh.v1\";"
        );
        assert_eq!(
            lines[1],
            " set mesh4 { type ipv4_addr; elements = { 10.254.0.1, 10.254.0.2, 10.254.0.3 }; }"
        );
        assert_eq!(
            lines[2],
            " set mesh6 { type ipv6_addr; elements = { fd01::1, fd01::2, fd01::3 }; }"
        );
        assert_eq!(lines.last(), Some(&"}"));
    }

    /// A snapshot that only changes which peers exist becomes one element transaction, one
    /// that changes nothing the guard holds sends nothing, and one that changes the chains or
    /// the served networks replaces the table (#260 J1240).
    #[test]
    fn guard_updates_send_only_changed_elements() {
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress::default();
        let old = config();
        let installed = GuardScript::new(&old, &[], &ingress);
        assert_eq!(installed.update_from(&installed), GuardUpdate::Unchanged);

        // Policy lives in the packet filter, not in the guard.
        let mut closed = old.clone();
        closed.peers.values_mut().next().expect("peer").inbound = TrafficPolicy::None;
        assert_eq!(
            GuardScript::new(&closed, &[], &ingress).update_from(&installed),
            GuardUpdate::Unchanged
        );

        let mut moved = old.clone();
        moved.peers.remove(&NodeId(2));
        moved
            .peers
            .get_mut(&NodeId(3))
            .expect("peer")
            .peer
            .addresses = Addresses {
            ipv4: "10.254.200.1".parse().expect("IPv4"),
            ipv6: "fd01::c8:1".parse().expect("IPv6"),
        };
        assert_eq!(
            GuardScript::new(&moved, &[], &ingress).update_from(&installed),
            GuardUpdate::Elements(
                "add element inet infraternal_mesh mesh4 { 10.254.200.1 }\n\
                 delete element inet infraternal_mesh mesh4 { 10.254.0.2, 10.254.0.3 }\n\
                 add element inet infraternal_mesh mesh6 { fd01::c8:1 }\n\
                 delete element inet infraternal_mesh mesh6 { fd01::2, fd01::3 }\n"
                    .to_owned()
            )
        );

        let mut router = old.clone();
        router
            .peers
            .values_mut()
            .next()
            .expect("peer")
            .networks
            .served
            .push(crate::dataplane::ServedNetwork {
                network: "198.51.100.0/24".parse().expect("network"),
                inbound: TrafficPolicy::All,
                keep_source: false,
            });
        assert_eq!(
            GuardScript::new(&router, &[], &ingress).update_from(&installed),
            GuardUpdate::Replace
        );
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
            "/usr/sbin, /usr/bin, /sbin, /bin, /run/current-system/sw/bin",
            "/nix/var/nix/profiles/default/bin",
        ] {
            assert!(detail.contains(part), "missing {part}: {detail}");
        }
        assert!(!detail.contains("/nix/store"), "no store scan: {detail}");
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
            "/nix/var/nix/profiles/default/bin",
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

    /// Snapshot the host input table as nft JSON objects, without `metainfo`.
    ///
    /// Comparing these values, handles included, proves that a mesh update
    /// left the host table's kernel objects untouched, independent of how a
    /// given nft version prints them as text.
    fn host_table_json(nft: &std::path::Path) -> Vec<serde_json::Value> {
        let output = Command::new(nft)
            .args(["-j", "list", "table", "inet", "infraternal_host"])
            .output()
            .expect("list the host input table");
        assert!(
            output.status.success(),
            "list the host input table: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("nft JSON listing");
        let objects: Vec<serde_json::Value> = document["nftables"]
            .as_array()
            .expect("nft JSON has an nftables array")
            .iter()
            .filter(|object| object.get("metainfo").is_none())
            .cloned()
            .collect();
        assert!(
            objects.iter().any(|object| object.get("rule").is_some()),
            "host table snapshot must contain its rules: {objects:?}"
        );
        objects
    }

    /// Real nft: an unmarked `infraternal_mesh` table is adopted (D386), mesh changes leave the
    /// host input table untouched, a broken batch changes nothing, and a large policy applies.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn real_nft_ownership_atomicity_and_scaled_apply() {
        let _nft_override = crate::host_firewall::NftTestPathOverride::with_fixed_nft_fixture();
        let nft = super::nft().expect("fixed root-owned nft path");
        run(&nft, &["-f", "-"], &format!("add table inet {TABLE}\n")).expect("unrelated fixture");
        run(
            &nft,
            &["-f", "-"],
            "add table inet infraternal_host\nadd chain inet infraternal_host input { type filter hook input priority filter - 10; policy drop; }\nadd rule inet infraternal_host input iifname \"lo\" accept\n",
        )
        .expect("host policy fixture");
        let host_before = host_table_json(&nft);
        let mut named_table = Firewall::default();
        named_table
            .adopt()
            .expect("prefixed table is product-owned");
        assert!(named_table.installed());
        named_table.remove().expect("takeover fixture cleanup");
        assert_eq!(
            host_before,
            host_table_json(&nft),
            "mesh ownership must preserve the separately owned host table"
        );
        let mut filter = Firewall::default();
        filter.adopt().expect("empty namespace");
        let mut config = config();
        let started = std::time::Instant::now();
        filter.apply(&config).expect("scaled install");
        let initial = started.elapsed().as_micros();
        assert_eq!(
            host_before,
            host_table_json(&nft),
            "mesh policy updates must leave host input rules unchanged"
        );
        let broken = format!("delete table inet {TABLE}\ninvalid syntax\n");
        assert!(run(&nft, &["-f", "-"], &broken).is_err());
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
        assert_eq!(
            host_before,
            host_table_json(&nft),
            "mesh policy removal must leave host input rules unchanged"
        );
        let mut absent = Firewall::default();
        absent.adopt().expect("clean namespace");
        assert!(!absent.installed);
    }
    /// Cleanup succeeds when the product-owned mesh table is already absent.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn already_removed_owned_table_does_not_block_component_cleanup() {
        let _nft_override = crate::host_firewall::NftTestPathOverride::with_fixed_nft_fixture();
        let nft = super::nft().expect("fixed root-owned nft path");
        let mut filter = Firewall::default();
        filter.adopt().expect("empty namespace");
        filter.apply(&config()).expect("install");
        run(&nft, &["-f", "-"], &format!("delete table inet {TABLE}\n")).expect("external removal");
        filter.remove().expect("already absent owned table");
        assert!(!filter.installed);
    }
    /// First adoption replaces an unmarked product-owned mesh table safely.
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn initial_apply_takes_over_an_unmarked_infraternal_table() {
        let _nft_override = crate::host_firewall::NftTestPathOverride::with_fixed_nft_fixture();
        let nft = super::nft().expect("fixed root-owned nft path");
        run(&nft, &["-f", "-"], &format!("add table inet {TABLE}\n")).expect("legacy fixture");
        let mut filter = Firewall::default();
        filter
            .apply(&config())
            .expect("product takes over its named table");
        assert!(filter.installed());
        filter.remove().expect("product table cleanup");
    }

    /// Real kernel, both frontends: the optional `GotaTun` guard installs through the tool the
    /// fixed-path lookup found, its status names that exact path, and removal leaves no guard.
    ///
    /// Run as real root under a systemd unit that hides the distribution tools, it proves a Nix
    /// profile entry point is the one executed (#265 J560 proof).
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

    /// Run one fixture command and fail with its stderr.
    fn review_j592_run(program: &str, args: &[&str]) {
        let output = Command::new(program)
            .args(args)
            .output()
            .expect("fixture command");
        assert!(
            output.status.success(),
            "{program} {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Connect from `source` to `destination` inside the neighbour namespace `pid`; true when
    /// the TCP handshake completes within 1.5 s.
    fn review_j592_open(pid: &str, source: &str, destination: std::net::SocketAddr) -> bool {
        const PROBE: &str = "import socket, sys
family = socket.AF_INET6 if ':' in sys.argv[2] else socket.AF_INET
s = socket.socket(family); s.bind((sys.argv[1], 0)); s.settimeout(1.5)
try:
    s.connect((sys.argv[2], int(sys.argv[3]))); print('OPEN')
except OSError:
    print('BLOCKED')";
        let output = Command::new("nsenter")
            .args(["-t", pid, "-n", "python3", "-c", PROBE, source])
            .arg(destination.ip().to_string())
            .arg(destination.port().to_string())
            .output()
            .expect("probe");
        String::from_utf8_lossy(&output.stdout).trim() == "OPEN"
    }

    /// J592 review (P1, security, D384 vs [231], #265): the `GotaTun` kernel-only guard dropped
    /// the underlay delivery fence the full policy has. Linux accepts a packet for any local
    /// address on any interface, so a neighbour on a non-mesh link only has to route the node's
    /// mesh address via the node's LAN address: its packets reach services bound to the mesh
    /// address without ever passing the `GotaTun` packet filter, so no grant is checked. The full
    /// policy refuses this with `iifname != { infraternal0, lo } ip daddr <own mesh address>
    /// drop` ("an underlay packet has no mesh identity"); both guard renderings must as well.
    ///
    /// Controls in the same run: plain LAN traffic to the node's LAN address still passes (no
    /// over-blocking) and a neighbour spoofing a peer's mesh source is dropped (anti-spoofing).
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn review_j592_guard_refuses_underlay_delivery_to_the_node_mesh_address() {
        use std::net::{SocketAddr, TcpListener};
        let neighbour = Command::new("unshare")
            .args(["-n", "sleep", "120"])
            .spawn()
            .expect("neighbour namespace");
        // sleep: let the child enter its own network namespace before it is configured.
        std::thread::sleep(std::time::Duration::from_millis(200));
        let pid = neighbour.id().to_string();
        let inside = |args: &[&str]| {
            let mut full = vec!["-t", pid.as_str(), "-n"];
            full.extend_from_slice(args);
            review_j592_run("nsenter", &full);
        };
        // The mesh interface holds the node's mesh addresses; its far end stays here unused.
        for args in [
            &["link", "set", "lo", "up"][..],
            &[
                "link", "add", INTERFACE, "type", "veth", "peer", "name", "j592mesh",
            ],
            &["addr", "add", "10.254.0.1/16", "dev", INTERFACE],
            &["-6", "addr", "add", "fd01::1/64", "dev", INTERFACE, "nodad"],
            &["link", "set", INTERFACE, "up"],
            &["link", "set", "j592mesh", "up"],
            // The underlay link to the neighbour.
            &[
                "link", "add", "j592lan", "type", "veth", "peer", "name", "j592nbr",
            ],
            &["link", "set", "j592nbr", "netns", pid.as_str()],
            &["addr", "add", "192.0.2.1/24", "dev", "j592lan"],
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:592::1/64",
                "dev",
                "j592lan",
                "nodad",
            ],
            &["link", "set", "j592lan", "up"],
            // Replies to the spoofed peer address go back over the LAN, so only the guard
            // can stop that handshake.
            &["route", "add", "10.254.0.2/32", "via", "192.0.2.2"],
            &[
                "-6",
                "route",
                "add",
                "fd01::2/128",
                "via",
                "2001:db8:592::2",
            ],
        ] {
            review_j592_run("ip", args);
        }
        for args in [
            &["ip", "link", "set", "lo", "up"][..],
            &["ip", "addr", "add", "192.0.2.2/24", "dev", "j592nbr"],
            &["ip", "addr", "add", "10.254.0.2/32", "dev", "j592nbr"],
            &[
                "ip",
                "-6",
                "addr",
                "add",
                "2001:db8:592::2/64",
                "dev",
                "j592nbr",
                "nodad",
            ],
            &[
                "ip",
                "-6",
                "addr",
                "add",
                "fd01::2/128",
                "dev",
                "j592nbr",
                "nodad",
            ],
            &["ip", "link", "set", "j592nbr", "up"],
            &["ip", "route", "add", "10.254.0.1/32", "via", "192.0.2.1"],
            &[
                "ip",
                "-6",
                "route",
                "add",
                "fd01::1/128",
                "via",
                "2001:db8:592::1",
            ],
        ] {
            inside(args);
        }
        // Listening sockets complete the handshake from the kernel backlog; nobody accepts.
        let listen = |address: &str| {
            let listener = TcpListener::bind((address, 0)).expect("listener");
            let bound = listener.local_addr().expect("bound address");
            (listener, bound)
        };
        let (_mesh4, mesh4) = listen("10.254.0.1");
        let (_mesh6, mesh6) = listen("fd01::1");
        let (_lan4, lan4) = listen("192.0.2.1");
        let (_lan6, lan6) = listen("2001:db8:592::1");
        // Expected handshakes per probe: with no rules at all, under the full kernel policy
        // (the pre-D384 reference, which keeps its [231] fence), and under the GotaTun guard.
        // `None` means "not asserted": the full policy has no source anti-spoofing chain.
        let probes: [(&str, &str, SocketAddr, [Option<bool>; 3]); 6] = [
            (
                "LAN to LAN address (control)",
                "192.0.2.2",
                lan4,
                [Some(true); 3],
            ),
            (
                "LAN to LAN address (control)",
                "2001:db8:592::2",
                lan6,
                [Some(true); 3],
            ),
            (
                "spoofed peer source (control)",
                "10.254.0.2",
                lan4,
                [Some(true), None, Some(false)],
            ),
            (
                "spoofed peer source (control)",
                "fd01::2",
                lan6,
                [Some(true), None, Some(false)],
            ),
            (
                "LAN to the node's mesh address",
                "192.0.2.2",
                mesh4,
                [Some(true), Some(false), Some(false)],
            ),
            (
                "LAN to the node's mesh address",
                "2001:db8:592::2",
                mesh6,
                [Some(true), Some(false), Some(false)],
            ),
        ];
        let mut wrong = Vec::new();
        let mut check = |label: &str, column: usize| {
            for (what, source, destination, expected) in probes {
                let open = review_j592_open(&pid, source, destination);
                println!("J592 {label}: {what}: {source} -> {destination} open={open}");
                if expected[column].is_some_and(|expected| expected != open) {
                    wrong.push(format!(
                        "{label}: {what}: {source} -> {destination} open={open}, expected {:?}",
                        expected[column]
                    ));
                }
            }
        };
        check("no rules (baseline)", 0);
        for backend in [Backend::Nft, Backend::NfTables] {
            let mut full = Firewall::for_backend(backend);
            full.apply(&config()).expect("full policy install");
            check(&format!("{backend:?} full policy (reference)"), 1);
            full.remove().expect("full policy removal");

            let mut guard =
                Firewall::for_node(Some(backend), crate::gotatun_node::EngineKind::GotaTun);
            guard.apply(&config()).expect("guard install");
            let state = guard.kernel_guard_status().expect("status").state;
            check(&format!("{backend:?} GotaTun guard ({state})"), 2);
            guard.remove().expect("guard removal");
        }
        let _ = Command::new("ip")
            .args(["link", "delete", "j592lan"])
            .status();
        let _ = Command::new("ip")
            .args(["link", "delete", INTERFACE])
            .status();
        let mut neighbour = neighbour;
        let _ = neighbour.kill();
        let _ = neighbour.wait();
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}
