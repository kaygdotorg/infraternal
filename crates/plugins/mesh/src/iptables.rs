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
/// Restore is atomic per table, so adoption records interrupted tables separately.
#[derive(Clone, Copy, Debug, Default)]
pub struct Ownership {
    filter: bool,
    guard: bool,
}
impl Ownership {
    #[must_use]
    pub fn any(self) -> bool {
        self.filter || self.guard
    }
    #[must_use]
    pub fn complete(self) -> bool {
        self.filter && self.guard
    }
}
/// Restore both address families. The caller retains a restrictive fence until both succeed.
/// # Errors
/// Refuses missing `nf_tables` executables or failed restore batches.
pub fn apply(config: &Config, installed: bool) -> io::Result<()> {
    // Ownership and backend validation belong to first installation/adoption.
    // Repeated updates reuse the owned two-family state and avoid discovery processes.
    let installed = if installed {
        [Ownership {
            filter: true,
            guard: true,
        }; 2]
    } else {
        presence()?
    };
    // Preflight both families before mutating either. Restore batches are atomic
    // per table; an interrupted table/family is fenced or rolled back by the caller.
    for (index, tool) in TOOLS.iter().enumerate() {
        test(tool, &render(config, index == 1, installed[index]))?;
    }
    for (index, tool) in TOOLS.iter().enumerate() {
        run(tool, &render(config, index == 1, installed[index]))?;
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
        present[index] = Ownership {
            filter: filter[0],
            guard: owned(tool, "raw", GUARD)?,
        };
    }
    Ok(present)
}
fn owned(tool: &str, table: &str, chain: &str) -> io::Result<bool> {
    let output = Command::new(tool)
        .args(["-t", table, "-S", chain])
        .stderr(Stdio::null())
        .output()?;
    match output.status.code() {
        Some(0) if String::from_utf8_lossy(&output.stdout).contains("infraternal.mesh.v1") => {
            Ok(true)
        }
        Some(0) => Err(io::ErrorKind::AlreadyExists.into()),
        Some(1) => Ok(false),
        _ => Err(io::ErrorKind::PermissionDenied.into()),
    }
}
fn test(tool: &str, script: &str) -> io::Result<()> {
    execute(tool, script, true)
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
#[allow(clippy::too_many_lines)]
fn render(config: &Config, ipv6: bool, installed: Ownership) -> String {
    let mut script = String::from("*raw\n");
    if installed.guard {
        let _ = writeln!(script, "-F {GUARD}");
    } else {
        let _ = writeln!(script, ":{GUARD} - [0:0]");
    }
    let address = if ipv6 {
        config.addresses.ipv6.to_string()
    } else {
        config.addresses.ipv4.to_string()
    };
    let _ = writeln!(
        script,
        "-A {GUARD} -i {INTERFACE} -m comment --comment infraternal.mesh.v1 -j RETURN\n-A {GUARD} -i lo -j RETURN\n-A {GUARD} -d {address} -j DROP"
    );
    if !installed.guard {
        let _ = writeln!(script, "-I PREROUTING 1 -j {GUARD}");
    }
    script.push_str("COMMIT\n*filter\n");
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
            continue;
        }
        let _ = writeln!(
            script,
            "-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment infraternal.mesh.v1 -j ACCEPT"
        );
    }
    // Compact contiguous equal grants. An open 1,000-node allocation becomes
    // one range match per direction/family, without granting a gap in membership.
    let mut groups = std::collections::BTreeMap::<
        (usize, Option<crate::policy::rules::Port>),
        std::collections::BTreeSet<u128>,
    >::new();
    for peer in config.peers.values() {
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
    for ((direction, port), addresses) in groups {
        let chain = CHAINS[direction];
        let flag = if direction == 0 { "-s" } else { "-d" };
        let range_flag = if direction == 0 {
            "--src-range"
        } else {
            "--dst-range"
        };
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
        for (start, end) in ranges {
            let display = |address: u128| {
                if ipv6 {
                    std::net::Ipv6Addr::from(address).to_string()
                } else {
                    {
                        // v4 groups are populated only from u32 addresses above.
                        let bytes = address.to_be_bytes();
                        std::net::Ipv4Addr::from([bytes[12], bytes[13], bytes[14], bytes[15]])
                            .to_string()
                    }
                }
            };
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
                format!(
                    " -p {} --dport {}",
                    if port.protocol == Protocol::Tcp {
                        "tcp"
                    } else {
                        "udp"
                    },
                    port.number
                )
            });
            let _ = writeln!(script, "-A {chain} {selector}{service} -j ACCEPT");
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use super::*;
    use crate::{
        dataplane::{DefaultPolicy, Peer, PeerPolicy},
        policy::model::{Addresses, NodeId, PublicKey},
    };
    fn config(ids: &[u32]) -> Config {
        let address = |id| Addresses {
            ipv4: std::net::Ipv4Addr::from(0x0afe_0000 + id),
            ipv6: std::net::Ipv6Addr::from((0xfd01u128 << 112) + u128::from(id)),
        };
        Config {
            server: None,
            node: NodeId(0),
            version: 1,
            addresses: address(1),
            default_policy: DefaultPolicy::Allow,
            peers: ids
                .iter()
                .map(|id| {
                    (
                        NodeId(u64::from(*id)),
                        PeerPolicy {
                            peer: Peer {
                                key: PublicKey([1; 32]),
                                addresses: address(*id),
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
            },
        );
        assert_eq!(rules.matches("ESTABLISHED,RELATED").count(), 2);
        assert_eq!(rules.matches("-j DROP").count(), 4);
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
