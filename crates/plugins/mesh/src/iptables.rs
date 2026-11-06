//! Compatibility filter for hosts with only the iptables `nf_tables` frontend [216]; owns only Mesh chains.
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
const TOOLS: [&str; 2] = [
    "/usr/sbin/iptables-nft-restore",
    "/usr/sbin/ip6tables-nft-restore",
];
const CHAINS: [&str; 3] = ["IFM_IN", "IFM_OUT", "IFM_FWD"];
const GUARD: &str = "IFM_GUARD";
const DELIVERY: &str = "IFM_DELIVERY";
// Only peers with an inbound TCP grant can reach an entry point. Traefik's exact-host
// middleware then checks the source against that route's original backend-port grant.
/// Restore is atomic per table, so adoption records interrupted tables separately.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ownership {
    filter: bool,
    guard: bool,
    delivery: bool,
}
impl Ownership {
    #[must_use]
    pub fn any(self) -> bool {
        self.filter || self.guard || self.delivery
    }
    #[must_use]
    pub fn complete(self) -> bool {
        self.filter && self.guard && self.delivery
    }
}
/// Narrow installation plans are selected only after ownership and typed old/new comparison.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Update {
    Full,
    RetainGuard,
    VerifiedRemoval,
}
/// Restore both address families. The caller retains a restrictive fence until both succeed.
/// # Errors
/// Refuses missing `nf_tables` executables or failed restore batches.
pub fn apply(config: &Config, installed: bool) -> io::Result<()> {
    apply_with_aliases(
        config,
        installed,
        &[],
        false,
        config,
        &infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
        Update::Full,
    )
}
pub(crate) fn apply_with_aliases(
    config: &Config,
    installed: bool,
    aliases: &[crate::policy::model::Addresses],
    fence: bool,
    connections: &Config,
    proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
    update: Update,
) -> io::Result<()> {
    // Ownership and backend validation belong to first installation/adoption.
    // Repeated updates reuse the owned two-family state and avoid discovery processes.
    let installed = if installed {
        [Ownership {
            filter: true,
            guard: true,
            delivery: true,
        }; 2]
    } else {
        presence()?
    };
    let scripts = std::array::from_fn(|index| {
        let script = render_with_aliases(
            config,
            index == 1,
            installed[index],
            aliases,
            fence,
            connections,
            proxy_ingress,
        );
        if update == Update::Full {
            script
        } else {
            // Only a complete, unchanged owned guard permits this selection.
            // Filter rules and translated delivery checks still replace together.
            script
                .split_once("COMMIT\n")
                .map_or_else(|| script.clone(), |(_, filter)| filter.to_owned())
        }
    });
    // Both families must pass preflight before either mutates. Keep serial
    // commits: simultaneous frontend caches contend on one namespace generation.
    // A proven typed removal introduces no new match form or untrusted text.
    // Final transactions still validate; the owner rolls back partial failure.
    if update != Update::VerifiedRemoval {
        execute_families(&scripts, true)?;
    }
    execute_families(&scripts, false)?;
    Ok(())
}
fn execute_families(scripts: &[String; 2], preflight: bool) -> io::Result<()> {
    for (tool, script) in TOOLS.iter().zip(scripts) {
        execute(tool, script, preflight)?;
    }
    Ok(())
}
/// Delete only Mesh hooks and chains in both families.
/// # Errors
/// Returns incomplete cleanup rather than claiming the node component is off.
pub fn remove() -> io::Result<()> {
    let installed = presence()?;
    for (index, tool) in TOOLS.iter().enumerate() {
        let owner = installed[index];
        if !owner.any() {
            continue;
        }
        let mut script = String::new();
        if owner.guard {
            let _ = writeln!(
                script,
                "*raw\n-D PREROUTING -j {GUARD}\n-F {GUARD}\n-X {GUARD}\nCOMMIT"
            );
        }
        if owner.filter {
            script.push_str("*filter\n");
            for (chain, hook, flag) in hooks() {
                let _ = writeln!(script, "-D {hook} {flag} {INTERFACE} -j {chain}");
            }
            for chain in CHAINS {
                let _ = writeln!(script, "-F {chain}\n-X {chain}");
            }
            if owner.delivery {
                let _ = writeln!(
                    script,
                    "-D INPUT -j {DELIVERY}\n-D FORWARD -j {DELIVERY}\n-F {DELIVERY}\n-X {DELIVERY}"
                );
            }
            script.push_str("COMMIT\n");
        }
        run(tool, &script)?;
    }
    Ok(())
}
fn hooks() -> [(&'static str, &'static str, &'static str); 4] {
    [
        (CHAINS[0], "INPUT", "-i"),
        (CHAINS[1], "OUTPUT", "-o"),
        (CHAINS[2], "FORWARD", "-i"),
        (CHAINS[2], "FORWARD", "-o"),
    ]
}
/// Detect owned tables independently in each family, including interrupted setup.
/// # Errors
/// Refuses unrelated chains, unavailable tools and privilege failures.
pub fn presence() -> io::Result<[Ownership; 2]> {
    let mut present = [Ownership::default(); 2];
    for (index, tool) in ["/usr/sbin/iptables-nft", "/usr/sbin/ip6tables-nft"]
        .iter()
        .enumerate()
    {
        let version = Command::new(tool)
            .arg("--version")
            .stderr(Stdio::null())
            .output()?;
        if !version.status.success()
            || !String::from_utf8_lossy(&version.stdout).contains("nf_tables")
        {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let mut filter = [false; 3];
        for (slot, chain) in filter.iter_mut().zip(CHAINS) {
            *slot = owned(tool, "filter", chain)?;
        }
        if filter.iter().any(|exists| *exists) != filter.iter().all(|exists| *exists) {
            // All filter chains share an atomic table transaction. A subset
            // cannot be our interrupted install and must not be overwritten.
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let delivery = owned(tool, "filter", DELIVERY)?;
        if delivery && !filter[0] {
            // Delivery and policy chains commit in one filter transaction.
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        present[index] = Ownership {
            filter: filter[0],
            guard: owned(tool, "raw", GUARD)?,
            delivery,
        };
    }
    Ok(present)
}
fn owned(tool: &str, table: &str, chain: &str) -> io::Result<bool> {
    let output = Command::new(tool)
        .args(["-t", table, "-S", chain])
        .stderr(Stdio::null())
        .output()?;
    // -S emits one canonical rule per line. Match the complete marker rule,
    // including its table-selected chain, interface/state selector and verdict.
    // Neither a containing comment nor a marker on another rule is authority.
    let marker = match (table, chain) {
        ("raw", GUARD) | ("filter", DELIVERY) => format!(
            "-A {chain} -i {INTERFACE} -m comment --comment \"infraternal.mesh.v1\" -j RETURN"
        ),
        ("filter", "IFM_IN" | "IFM_OUT") => format!(
            "-A {chain} -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"infraternal.mesh.v1\" -j ACCEPT"
        ),
        ("filter", "IFM_FWD") => {
            format!("-A {chain} -m comment --comment \"infraternal.mesh.v1\" -j DROP")
        }
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    match output.status.code() {
        Some(0)
            if String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == marker) =>
        {
            Ok(true)
        }
        Some(0) => Err(io::ErrorKind::AlreadyExists.into()),
        Some(1) => Ok(false),
        _ => Err(io::ErrorKind::PermissionDenied.into()),
    }
}
fn run(tool: &str, script: &str) -> io::Result<()> {
    execute(tool, script, false)
}
fn execute(tool: &str, script: &str, preflight: bool) -> io::Result<()> {
    let mut command = Command::new(tool);
    command.arg("--noflush");
    if preflight {
        command.arg("--test");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let written = child
        .stdin
        .take()
        .ok_or(io::ErrorKind::BrokenPipe)?
        .write_all(script.as_bytes());
    let status = child.wait()?;
    written?;
    if status.success() {
        Ok(())
    } else {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}
// Keep the complete per-family atomic restore batch visible together.
#[cfg(test)]
fn render(config: &Config, ipv6: bool, installed: Ownership) -> String {
    render_with_aliases(
        config,
        ipv6,
        installed,
        &[],
        false,
        config,
        &infraternal_mesh::proxy_ports::MeshProxyIngress::default(),
    )
}
// A rotation temporarily owns both local addresses; keep their ingress fences in one batch.
fn render_with_aliases(
    config: &Config,
    ipv6: bool,
    installed: Ownership,
    aliases: &[crate::policy::model::Addresses],
    fence: bool,
    connections: &Config,
    proxy_ingress: &infraternal_mesh::proxy_ports::MeshProxyIngress,
) -> String {
    let connections = if fence { connections } else { config };
    let mut script = String::from("*raw\n");
    if installed.guard {
        let _ = writeln!(script, "-F {GUARD}");
    } else {
        let _ = writeln!(script, ":{GUARD} - [0:0]");
    }
    let addresses: Vec<_> = std::iter::once(&config.addresses)
        .chain(aliases)
        .map(|addresses| {
            if ipv6 {
                addresses.ipv6.to_string()
            } else {
                addresses.ipv4.to_string()
            }
        })
        .collect();
    let _ = writeln!(
        script,
        "-A {GUARD} -i {INTERFACE} -m comment --comment infraternal.mesh.v1 -j RETURN\n-A {GUARD} -i lo -j RETURN"
    );
    for address in &addresses {
        let _ = writeln!(script, "-A {GUARD} -d {address} -j DROP");
    }
    if !installed.guard {
        let _ = writeln!(script, "-I PREROUTING 1 -j {GUARD}");
    }
    script.push_str("COMMIT\n*filter\n");
    if installed.delivery {
        let _ = writeln!(script, "-F {DELIVERY}");
    } else {
        let _ = writeln!(script, ":{DELIVERY} - [0:0]");
    }
    // Filter hooks see the translated destination. Run before conntrack or
    // peer grants, including packets which never entered the mesh interface.
    // Translation preserves the incoming interface; lo remains node-local [231].
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
                    "-A {DELIVERY} ! -i lo -m addrtype --dst-type LOCAL -p tcp -m multiport --dports {},{} -j DROP\n",
                    pair.http, pair.https
                )
            })
    };
    let _ = writeln!(
        script,
        "{public_gate}-A {DELIVERY} -i {INTERFACE} -m comment --comment infraternal.mesh.v1 -j RETURN\n-A {DELIVERY} -i lo -j RETURN"
    );
    for address in &addresses {
        let _ = writeln!(script, "-A {DELIVERY} -d {address} -j DROP");
    }
    if !installed.delivery {
        // Older owned filter chains remain valid; add this fence atomically
        // when adopting them rather than duplicating their interface hooks.
        let _ = writeln!(
            script,
            "-I INPUT 1 -j {DELIVERY}\n-I FORWARD 1 -j {DELIVERY}"
        );
    }
    for chain in CHAINS {
        if installed.filter {
            let _ = writeln!(script, "-F {chain}");
        } else {
            let _ = writeln!(script, ":{chain} - [0:0]");
        }
        if chain == CHAINS[2] {
            // Direct node paths do not grant transit through a forwarding host.
            let _ = writeln!(
                script,
                "-A {chain} -m comment --comment infraternal.mesh.v1 -j DROP"
            );
        }
    }
    // Compact contiguous equal grants. An open 1,000-node allocation becomes
    // one range match per direction/family, without granting a gap in membership.
    let mut groups = Groups::new();
    for peer in connections.peers.values() {
        let address = if ipv6 {
            u128::from(peer.peer.addresses.ipv6)
        } else {
            u128::from(u32::from(peer.peer.addresses.ipv4))
        };
        for (direction, policy) in [(0, &peer.inbound), (1, &peer.outbound)] {
            match policy {
                TrafficPolicy::All => {
                    groups.entry((direction, None)).or_default().insert(address);
                }
                TrafficPolicy::Ports(ports) => {
                    for port in ports {
                        groups
                            .entry((direction, Some(*port)))
                            .or_default()
                            .insert(address);
                    }
                }
                TrafficPolicy::None => {}
            }
        }
    }
    let proxy_sources: std::collections::BTreeSet<u128> =
        crate::proxy_access::sources(connections, proxy_ingress)
            .map(|peer| {
                if ipv6 {
                    u128::from(peer.peer.addresses.ipv6)
                } else {
                    u128::from(u32::from(peer.peer.addresses.ipv4))
                }
            })
            .collect();
    let selected_ports: Vec<u16> = crate::proxy_access::selected_ports(proxy_ingress)
        .map(Vec::from)
        .unwrap_or_default();
    render_connection_checks(&mut script, connections, ipv6, &groups);
    render_proxy_connection_checks(
        &mut script,
        connections,
        ipv6,
        &proxy_sources,
        &selected_ports,
    );
    for chain in &CHAINS[..2] {
        // Retired original and reply indexes must not be recreated by loose
        // tracking of a continuation packet. Preserve established permitted
        // streams, but require an initiating SYN for fresh TCP state [242].
        let _ = writeln!(
            script,
            "-A {chain} -p tcp -m conntrack --ctstate NEW ! --syn -j DROP"
        );
        {
            // State with no current initiating permission must never fall
            // through to the ordinary destination-port rules [242].
            let _ = writeln!(
                script,
                "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j DROP"
            );
        }
        // Keep the exact v1 ownership marker for adoption of retained tables.
        // On accepted revisions the preceding state check makes it unreachable.
        let _ = writeln!(
            script,
            "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment infraternal.mesh.v1 -j ACCEPT"
        );
    }
    if !fence {
        for ((direction, port), addresses) in groups {
            let chain = CHAINS[direction];
            let flag = if direction == 0 { "-s" } else { "-d" };
            let range_flag = if direction == 0 {
                "--src-range"
            } else {
                "--dst-range"
            };
            let ranges = address_ranges(addresses);
            for (start, end) in ranges {
                let display = |address| display_address(address, ipv6);
                let selector = if start == end {
                    format!("{flag} {}", display(start))
                } else {
                    format!(
                        "-m iprange {range_flag} {}-{}",
                        display(start),
                        display(end)
                    )
                };
                let service = port.map_or_else(String::new, |port| {
                    let protocol = if port.protocol == Protocol::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    };
                    if direction == 0 {
                        // The IFM_IN hook runs after DNAT; enforce the original
                        // service rather than its translated listener [#221].
                        format!(
                            " -p {protocol} -m conntrack --ctorigdstport {}",
                            port.number
                        )
                    } else {
                        format!(" -p {protocol} --dport {}", port.number)
                    }
                });
                let _ = writeln!(script, "-A {chain} {selector}{service} -j ACCEPT");
            }
        }
        for (start, end) in address_ranges(proxy_sources.iter().copied()) {
            let display = |address| display_address(address, ipv6);
            let selector = if start == end {
                format!("-s {}", display(start))
            } else {
                format!("-m iprange --src-range {}-{}", display(start), display(end))
            };
            for destination_port in &selected_ports {
                let _ = writeln!(
                    script,
                    "-A {} {selector} -p tcp -m conntrack --ctorigdstport {destination_port} -j ACCEPT",
                    CHAINS[0]
                );
            }
        }
    }
    for chain in &CHAINS[..2] {
        let _ = writeln!(script, "-A {chain} -j DROP");
    }
    if !installed.filter {
        for (chain, hook, flag) in hooks() {
            let _ = writeln!(script, "-I {hook} 1 {flag} {INTERFACE} -j {chain}");
        }
    }
    script.push_str("COMMIT\n");
    script
}

type Groups = std::collections::BTreeMap<
    (usize, Option<crate::policy::rules::Port>),
    std::collections::BTreeSet<u128>,
>;
fn address_ranges(addresses: impl IntoIterator<Item = u128>) -> Vec<(u128, u128)> {
    let mut ranges = Vec::<(u128, u128)>::new();
    for address in addresses {
        if let Some((_, end)) = ranges.last_mut()
            && end.checked_add(1) == Some(address)
        {
            *end = address;
        } else {
            ranges.push((address, address));
        }
    }
    ranges
}
fn display_address(address: u128, ipv6: bool) -> String {
    if ipv6 {
        std::net::Ipv6Addr::from(address).to_string()
    } else {
        let bytes = address.to_be_bytes();
        std::net::Ipv4Addr::from([bytes[12], bytes[13], bytes[14], bytes[15]]).to_string()
    }
}
// Conntrack selectors accept CIDRs, not address intervals. Cover an interval
// exactly with aligned prefixes, never including a gap in member ownership.
fn prefixes(mut start: u128, end: u128, ipv6: bool) -> Vec<String> {
    let width = if ipv6 { 128 } else { 32 };
    let mut result = Vec::new();
    loop {
        let remaining = end - start;
        let size_bits = if remaining == u128::MAX {
            128
        } else {
            (remaining + 1).ilog2()
        };
        let bits = start.trailing_zeros().min(size_bits).min(width);
        result.push(format!("{}/{}", display_address(start, ipv6), width - bits));
        if bits == 128 {
            break;
        }
        let size = 1_u128 << bits;
        if remaining < size {
            break;
        }
        start += size;
    }
    result
}
// A proxied flow is admitted by the listener-pair exception, not by a per-port
// grant. Its later packets in both directions need the same source test, or
// only the initiating SYN would pass [#281].
fn render_proxy_connection_checks(
    script: &mut String,
    config: &Config,
    ipv6: bool,
    sources: &std::collections::BTreeSet<u128>,
    ports: &[u16],
) {
    let local = if ipv6 {
        config.addresses.ipv6.to_string()
    } else {
        config.addresses.ipv4.to_string()
    };
    for (start, end) in address_ranges(sources.iter().copied()) {
        for prefix in prefixes(start, end, ipv6) {
            for port in ports {
                for (chain, packet_direction) in [(CHAINS[0], "ORIGINAL"), (CHAINS[1], "REPLY")] {
                    let _ = writeln!(
                        script,
                        "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir {packet_direction} --ctorigsrc {prefix} --ctorigdst {local} --ctproto tcp --ctorigdstport {port} -j ACCEPT"
                    );
                }
            }
        }
    }
}
fn render_connection_checks(script: &mut String, config: &Config, ipv6: bool, groups: &Groups) {
    let local = if ipv6 {
        config.addresses.ipv6.to_string()
    } else {
        config.addresses.ipv4.to_string()
    };
    for ((direction, port), addresses) in groups {
        let (peer_field, local_field) = if *direction == 0 {
            ("--ctorigsrc", "--ctorigdst")
        } else {
            ("--ctorigdst", "--ctorigsrc")
        };
        let service = port.map_or_else(String::new, |port| {
            format!(
                " --ctproto {} --ctorigdstport {}",
                if port.protocol == Protocol::Tcp {
                    "tcp"
                } else {
                    "udp"
                },
                port.number
            )
        });
        for (start, end) in address_ranges(addresses.iter().copied()) {
            for prefix in prefixes(start, end, ipv6) {
                for (chain, packet_direction) in [
                    (CHAINS[*direction], "ORIGINAL"),
                    (CHAINS[1 - *direction], "REPLY"),
                ] {
                    let _ = writeln!(
                        script,
                        "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir {packet_direction} {peer_field} {prefix} {local_field} {local}{service} -j ACCEPT"
                    );
                }
            }
        }
    }
}

/// iptables backend compilation and ownership checks.
#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{
        dataplane::{DefaultPolicy, Peer, PeerPolicy},
        policy::model::{Addresses, NodeId, PublicKey},
    };
    /// A configuration with one peer per id in `ids`.
    fn config(ids: &[u32]) -> Config {
        let address = |id| Addresses {
            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
            ipv6: std::net::Ipv6Addr::from((0xfd01u128 << 112) + u128::from(id)),
        };
        Config {
            local_key: None,
            server: None,
            node: NodeId(0),
            #[cfg(feature = "mesh-dns-spike")]
            name: None,
            #[cfg(feature = "mesh-dns-spike")]
            dns_suffix: crate::dataplane::DEFAULT_DNS_SUFFIX.to_owned(),
            version: 1,
            addresses: address(1),
            default_policy: DefaultPolicy::Allow,
            exposure: None,
            peers: ids
                .iter()
                .map(|id| {
                    (
                        NodeId(u64::from(*id)),
                        PeerPolicy {
                            peer: Peer {
                                key: PublicKey([1; 32]),
                                previous_key: None,
                                previous_active: false,
                                addresses: address(*id),
                                endpoint: None,
                            },
                            inbound: TrafficPolicy::All,
                            outbound: TrafficPolicy::All,
                            access_ssh: None,
                        },
                    )
                })
                .collect(),
            #[cfg(feature = "mesh-dns-spike")]
            peer_names: std::collections::BTreeMap::new(),
        }
    }
    #[test]
    fn initiating_prefixes_cover_only_owned_intervals_even_at_family_boundaries() {
        assert_eq!(prefixes(2, 3, false), ["0.0.0.2/31"]);
        assert_eq!(prefixes(5, 6, false), ["0.0.0.5/32", "0.0.0.6/32"]);
        assert_eq!(prefixes(0, u128::from(u32::MAX), false), ["0.0.0.0/0"]);
        assert_eq!(prefixes(0, u128::MAX, true), ["::/0"]);
        assert_eq!(
            prefixes(u128::MAX, u128::MAX, true),
            ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"]
        );
    }
    #[test]
    fn contiguous_open_members_use_ranges_without_opening_gaps() {
        let thousand: Vec<_> = (2..=1001).collect();
        let rules = render(&config(&thousand), false, Ownership::default());
        assert_eq!(rules.matches("-m iprange").count(), 2);
        assert!(rules.contains("--src-range 10.254.0.2-10.254.3.233"));
        let gaps = render(&config(&[2, 3, 5, 6]), false, Ownership::default());
        assert!(gaps.contains("10.254.0.2-10.254.0.3"));
        assert!(gaps.contains("10.254.0.5-10.254.0.6"));
        assert!(!gaps.contains("10.254.0.2-10.254.0.6"));
    }
    #[test]
    fn incoming_port_rules_match_original_destination_and_keep_outbound_match() {
        let mut config = config(&[2]);
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

        let rules = render(&config, false, Ownership::default());
        assert!(
            rules.contains(
                "-A IFM_IN -s 10.254.0.2 -p tcp -m conntrack --ctorigdstport 22 -j ACCEPT"
            )
        );
        assert!(!rules.contains("-A IFM_IN -s 10.254.0.2 -p tcp --dport 22 -j ACCEPT"));
        assert!(rules.contains("-A IFM_OUT -d 10.254.0.2 -p tcp --dport 443 -j ACCEPT"));
    }
    #[test]
    fn proxy_listener_exception_is_closed_without_a_published_route() {
        let mut config = config(&[2, 3]);
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

        let rules = render(&config, false, Ownership::default());
        assert!(!rules.contains("--ctorigdstport 10080:10335"));
        assert!(!rules.contains("--ctorigdstport 10082"));
        assert!(!rules.contains(
            "-A IFM_IN -s 10.254.0.2 -p tcp -m conntrack --ctorigdstport 10082 -j ACCEPT"
        ));
    }
    #[test]
    fn proxy_exception_uses_only_selected_pair_and_a_published_route_grant() {
        let mut config = config(&[2, 3]);
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
        let rules = super::render_with_aliases(
            &config,
            false,
            Ownership::default(),
            &[],
            false,
            &config,
            &ingress,
        );

        assert!(rules.contains(&format!(
            "-A IFM_IN -s 10.254.0.3 -p tcp -m conntrack --ctorigdstport {} -j ACCEPT",
            selected.http
        )));
        assert!(rules.contains(&format!(
            "-A IFM_IN -s 10.254.0.3 -p tcp -m conntrack --ctorigdstport {} -j ACCEPT",
            selected.https
        )));
        assert!(!rules.contains(&format!(
            "-A IFM_IN -s 10.254.0.2 -p tcp -m conntrack --ctorigdstport {} -j ACCEPT",
            selected.http
        )));
        assert!(!rules.contains("--ctorigdstport 10082"));
    }

    #[test]
    fn proxied_flows_keep_passing_the_state_checks_after_their_syn() {
        let mut config = config(&[2, 3]);
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
        let selected = infraternal_mesh::proxy_ports::MIXED_LISTENER_PAIRS[1];
        let ingress = infraternal_mesh::proxy_ports::MeshProxyIngress {
            listener_pair: Some(selected),
            backend_ports: std::collections::BTreeSet::from([8080]),
            ..Default::default()
        };
        let rules = super::render_with_aliases(
            &config,
            false,
            Ownership::default(),
            &[],
            false,
            &config,
            &ingress,
        );
        let state_drop = "-A IFM_IN -m conntrack --ctstate ESTABLISHED,RELATED -j DROP";
        let before_drop = &rules[..rules.find(state_drop).expect("state drop")];
        for port in [selected.http, selected.https] {
            for (chain, direction) in [("IFM_IN", "ORIGINAL"), ("IFM_OUT", "REPLY")] {
                assert!(
                    before_drop.contains(&format!(
                        "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED --ctdir {direction} --ctorigsrc 10.254.0.3/32 --ctorigdst 10.254.0.1 --ctproto tcp --ctorigdstport {port} -j ACCEPT"
                    )),
                    "{chain} must admit {direction} packets of a proxied flow to {port}"
                );
            }
        }
        assert!(!rules.contains("--ctorigsrc 10.254.0.2/32 --ctorigdst 10.254.0.1 --ctproto tcp"));
    }

    #[test]
    fn wildcard_public_listener_is_blocked_until_a_public_route_is_applied() {
        let config = config(&[]);
        let pair = infraternal_mesh::proxy_ports::CONVENTIONAL_LISTENER_PAIR;
        let mut ingress = infraternal_mesh::proxy_ports::MeshProxyIngress {
            public_listener_pair: Some(pair),
            ..Default::default()
        };
        let expected = format!(
            "-A {DELIVERY} ! -i lo -m addrtype --dst-type LOCAL -p tcp -m multiport --dports {},{} -j DROP",
            pair.http, pair.https
        );
        let closed = super::render_with_aliases(
            &config,
            false,
            Ownership::default(),
            &[],
            false,
            &config,
            &ingress,
        );
        assert!(closed.contains(&expected));

        ingress.public_route_active = true;
        let open = super::render_with_aliases(
            &config,
            false,
            Ownership::default(),
            &[],
            false,
            &config,
            &ingress,
        );
        assert!(!open.contains(&expected));
    }

    #[test]
    fn replacement_retains_established_rules_and_does_not_duplicate_hooks() {
        let mut config = config(&[2]);
        for peer in config.peers.values_mut() {
            peer.inbound = TrafficPolicy::None;
            peer.outbound = TrafficPolicy::None;
        }
        let rules = render(
            &config,
            true,
            Ownership {
                filter: true,
                guard: true,
                delivery: true,
            },
        );
        assert_eq!(rules.matches("ESTABLISHED,RELATED").count(), 4);
        assert_eq!(rules.matches("-j DROP").count(), 9);
        assert_eq!(
            rules
                .matches("-p tcp -m conntrack --ctstate NEW ! --syn -j DROP")
                .count(),
            2
        );
        assert!(!rules.contains("-I INPUT"));
        assert!(!rules.contains("-m iprange"));
    }
    #[test]
    #[ignore = "Run inside a dedicated network namespace with CAP_NET_ADMIN."]
    fn real_nf_tables_ownership_partial_family_and_scaled_apply() {
        assert!(
            presence()
                .expect("empty namespace")
                .into_iter()
                .all(|o| !o.any())
        );
        let tool = "/usr/sbin/iptables-nft";
        assert!(
            Command::new(tool)
                .args(["-N", CHAINS[1]])
                .status()
                .expect("unrelated chain")
                .success()
        );
        assert_eq!(
            presence().expect_err("unrelated output chain").kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(
            Command::new(tool)
                .args(["-X", CHAINS[1]])
                .status()
                .expect("fixture cleanup")
                .success()
        );
        let mut config = config(&(2..=1001).collect::<Vec<_>>());
        run(TOOLS[0], &render(&config, false, Ownership::default()))
            .expect("single-family interrupted install");
        let partial = presence().expect("partial families");
        assert!(partial[0].complete() && !partial[1].any());
        let started = std::time::Instant::now();
        apply(&config, false).expect("complete both families");
        let initial = started.elapsed().as_micros();
        assert!(
            presence()
                .expect("owned families")
                .into_iter()
                .all(Ownership::complete)
        );
        config.peers.get_mut(&NodeId(500)).expect("member").inbound = TrafficPolicy::None;
        let started = std::time::Instant::now();
        apply(&config, true).expect("one policy change");
        println!(
            "METRIC nf_tables_policy machine=infraternal-dev peers=1000 apply_us={initial} single_peer_us={} load={}",
            started.elapsed().as_micros(),
            std::fs::read_to_string("/proc/loadavg")
                .expect("load")
                .trim()
        );
        remove().expect("owned cleanup");
        assert!(presence().expect("off").into_iter().all(|o| !o.any()));
        // The raw table commits before the filter table. Recover that exact
        // interrupted state without treating it as a complete family.
        let batch = render(&config, false, Ownership::default());
        let raw = batch.split("*filter").next().expect("raw transaction");
        run(TOOLS[0], raw).expect("interrupted raw table");
        let partial = presence().expect("partial tables");
        assert!(partial[0].guard && !partial[0].filter);
        apply(&config, false).expect("recover partial tables");
        assert!(
            presence()
                .expect("complete tables")
                .into_iter()
                .all(Ownership::complete)
        );
        remove().expect("partial-table recovery cleanup");
        assert!(
            presence()
                .expect("off after recovery")
                .into_iter()
                .all(|o| !o.any())
        );
    }
}
