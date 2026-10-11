//! Owns one stateful mesh packet filter; nft transactions are atomic and use indexed sets [164,216], #129.
use crate::{
    dataplane::Config,
    policy::rules::{Protocol, TrafficPolicy},
    wireguard::INTERFACE,
};
use std::{
    fmt::Write as _,
    io::{self, Write},
    process::{Command, Stdio},
};
const NFT: &str = "/usr/sbin/nft";
const TABLE: &str = "infraternal_mesh";

/// The two owner-selected Linux frontends; kernel policy is retained independently of processes.
#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum Backend {
    Nft,
    NfTables,
}
/// An owned inet table with input, output and forwarded packet enforcement.
#[derive(Default)]
pub struct Firewall {
    installed: bool,
    fallback_complete: bool,
    previous: Option<Config>,
    backend: Option<Backend>,
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
    /// Read the selected frontend for public-state persistence.
    #[must_use]
    pub fn backend(&self) -> Option<Backend> {
        self.backend
    }
    fn select(&mut self) {
        self.backend.get_or_insert_with(|| {
            if std::path::Path::new(NFT).exists() {
                Backend::Nft
            } else {
                Backend::NfTables
            }
        });
    }
    fn is_fallback(&self) -> bool {
        matches!(self.backend, Some(Backend::NfTables))
    }
    /// Recover the owned table after a daemon restart; an unrelated table is refused.
    /// # Errors
    /// Reports missing tools, privilege failures or unrelated rules with the same name.
    pub fn adopt(&mut self) -> io::Result<()> {
        self.select();
        if self.is_fallback() {
            let families = crate::iptables::presence()?;
            self.installed = families.into_iter().any(crate::iptables::Ownership::any);
            self.fallback_complete = families
                .into_iter()
                .all(crate::iptables::Ownership::complete);
        } else {
            let tables = Command::new(NFT)
                .args(["-j", "list", "tables"])
                .stderr(Stdio::null())
                .output()?;
            if !tables.status.success() {
                return Err(io::ErrorKind::PermissionDenied.into());
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
                let output = Command::new(NFT)
                    .args(["list", "table", "inet", TABLE])
                    .stderr(Stdio::null())
                    .output()?;
                if !output.status.success() {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                if !String::from_utf8_lossy(&output.stdout).contains("infraternal.mesh.v1") {
                    return Err(io::ErrorKind::AlreadyExists.into());
                }
                self.installed = true;
            }
        }
        Ok(())
    }
    /// Atomically replace the entire node policy. Nothing runs between requests.
    /// # Errors
    /// Refuses unavailable nft or a failed transaction; an existing table stays unchanged.
    pub fn apply(&mut self, config: &Config) -> io::Result<()> {
        self.select();
        // A table declaration can extend an existing table. First application
        // must therefore validate ownership even when no adapter called adopt.
        if !self.installed && !self.is_fallback() {
            self.adopt()?;
        }
        if self.is_fallback() {
            if let Err(error) = crate::iptables::apply(config, self.fallback_complete) {
                if let Some(old) = &self.previous {
                    crate::iptables::apply(old, true)?;
                } else {
                    crate::iptables::remove()?;
                }
                return Err(error);
            }
        } else {
            run(NFT, &["-f", "-"], &render(config, self.installed))?;
        }
        self.previous = self.is_fallback().then(|| config.clone());
        self.installed = true;
        self.fallback_complete = self.is_fallback();
        Ok(())
    }
    /// Remove only the owned table, leaving the host firewall intact.
    /// # Errors
    /// Returns a failed kernel deletion without claiming the component is off.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.installed {
            if self.is_fallback() {
                crate::iptables::remove()?;
            } else {
                // Recheck ownership before deletion. Confirmed absence is an
                // idempotent cleanup; privilege or foreign-table failures stay visible.
                self.adopt()?;
                if self.installed {
                    run(NFT, &["-f", "-"], &format!("delete table inet {TABLE}\n"))?;
                }
            }
            self.installed = false;
            self.fallback_complete = false;
            self.previous = None;
        }
        Ok(())
    }
}
fn run(program: &str, args: &[&str], script: &str) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // Policy contains public typed addresses/ports only. No shell or secret in argv/stdout.
    let write = child
        .stdin
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .write_all(script.as_bytes());
    let status = child.wait()?;
    write?;
    if !status.success() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}
/// Render constant-time hash-set membership, independent of the peer count on the packet path.
#[must_use]
pub fn render(config: &Config, replace: bool) -> String {
    let mut script = String::new();
    if replace {
        let _ = writeln!(script, "delete table inet {TABLE}");
    }
    let _ = writeln!(
        script,
        "table inet {TABLE} {{\n comment \"infraternal.mesh.v1\";"
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
                for peer in config.peers.values() {
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
        }
        let _ = writeln!(script, " chain {direction} {{");
        let _ = writeln!(script, "  ct state established,related accept");
        let field = if inbound { "saddr" } else { "daddr" };
        for (family, suffix) in [("ip", "4"), ("ip6", "6")] {
            let _ = writeln!(script, "  {family} {field} @{direction}{suffix}_all accept");
            for protocol in ["tcp", "udp"] {
                let _ = writeln!(
                    script,
                    "  {family} {field} . {protocol} dport @{direction}{suffix}_{protocol} accept"
                );
            }
        }
        // ICMP errors are RELATED; unsolicited ICMP and all other protocols obey All or deny.
        let _ = writeln!(script, "  drop\n }}");
    }
    for (name, hook, interface, direction) in [
        ("input", "input", "iifname", "incoming"),
        ("output", "output", "oifname", "outgoing"),
    ] {
        let _ = writeln!(
            script,
            " chain {name} {{ type filter hook {hook} priority -10; policy accept; {interface} \"{INTERFACE}\" jump {direction}; }}"
        );
    }
    let _ = writeln!(
        script,
        " chain forward {{ type filter hook forward priority -10; policy accept; iifname \"{INTERFACE}\" drop; oifname \"{INTERFACE}\" drop; }}"
    );
    // Mesh-bound services must receive authenticated tunnel packets. Fence
    // underlay delivery before destination NAT, independently of conntrack.
    // Loopback remains available for the node's own services. Subnet transit
    // has no owner in this slice, even when a host enables IP forwarding.
    let _ = writeln!(
        script,
        " chain ingress {{ type filter hook prerouting priority -310; policy accept; iifname != {{ \"{INTERFACE}\", \"lo\" }} ip daddr {} drop; iifname != {{ \"{INTERFACE}\", \"lo\" }} ip6 daddr {} drop; }}\n}}",
        config.addresses.ipv4, config.addresses.ipv6
    );
    script
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{
        dataplane::{DefaultPolicy, Peer, PeerPolicy},
        policy::model::{Addresses, NodeId, PublicKey},
    };
    fn config() -> Config {
        let address = |id: u32| Addresses {
            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
            ipv6: std::net::Ipv6Addr::from((0xfd01_u128 << 112) + u128::from(id)),
        };
        Config {
            server: None,
            node: NodeId(1),
            version: 1,
            addresses: address(1),
            default_policy: DefaultPolicy::Allow,
            peers: (2..=1001)
                .map(|id| {
                    (
                        NodeId(u64::from(id)),
                        PeerPolicy {
                            peer: Peer {
                                key: PublicKey([1; 32]),
                                addresses: address(id),
                                endpoint: None,
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                        },
                    )
                })
                .collect(),
        }
    }
    #[test]
    fn rule_count_is_independent_of_membership_and_policy_data_is_in_sets() {
        let mut config = config();
        let rules = render(&config, false);
        assert_eq!(rules.matches(" accept").count(), 18);
        assert_eq!(rules.matches(" drop").count(), 6);
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
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn real_nft_ownership_atomicity_and_scaled_apply() {
        run(NFT, &["-f", "-"], &format!("add table inet {TABLE}\n")).expect("unrelated fixture");
        let mut unrelated = Firewall::default();
        assert_eq!(
            unrelated.adopt().expect_err("unowned table").kind(),
            io::ErrorKind::AlreadyExists
        );
        run(NFT, &["-f", "-"], &format!("delete table inet {TABLE}\n")).expect("fixture cleanup");
        let mut filter = Firewall::default();
        filter.adopt().expect("empty namespace");
        let mut config = config();
        let started = std::time::Instant::now();
        filter.apply(&config).expect("scaled install");
        let initial = started.elapsed().as_micros();
        let broken = format!("delete table inet {TABLE}\ninvalid syntax\n");
        assert!(run(NFT, &["-f", "-"], &broken).is_err());
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
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn already_removed_owned_table_does_not_block_component_cleanup() {
        let mut filter = Firewall::default();
        filter.adopt().expect("empty namespace");
        filter.apply(&config()).expect("install");
        run(NFT, &["-f", "-"], &format!("delete table inet {TABLE}\n")).expect("external removal");
        filter.remove().expect("already absent owned table");
        assert!(!filter.installed);
    }
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn initial_apply_without_adoption_refuses_a_foreign_table() {
        run(NFT, &["-f", "-"], &format!("add table inet {TABLE}\n")).expect("foreign fixture");
        let mut filter = Firewall::default();
        assert_eq!(
            filter.apply(&config()).expect_err("foreign table").kind(),
            io::ErrorKind::AlreadyExists
        );
        run(NFT, &["-f", "-"], &format!("delete table inet {TABLE}\n")).expect("fixture cleanup");
    }
}
