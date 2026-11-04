//! Standalone scale test harness: fresh processes isolate RSS; weighted scopes record CPU and wall time.
use infraternal_mesh::{
    address::AddressAllocator,
    coordinator::{Change, Coordinator},
    model::{MeshError, MeshSettings, Node, NodeId, PublicKey},
    rules::{Arrow, Endpoint, RuleId, TrafficPolicy},
    view::{Peer, PeerKeys, PeerView},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    hint::black_box,
    time::Instant,
};

/// Result type of every measurement step: any error aborts the run.
type Measurement<T> = Result<T, Box<dyn Error>>;
/// A synthetic public key whose first 8 bytes are `value`, so keys are unique.
fn key(value: u64) -> PublicKey {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    PublicKey(bytes)
}
/// A synthetic node numbered `value`, named `host-<value>`, in one of ten tags
/// (`tag-0` to `tag-9`).
fn node(value: u64) -> Node {
    Node {
        id: NodeId(value),
        public_key: key(value),
        host: format!("host-{value}"),
        tags: BTreeSet::from([format!("tag-{}", value % 10)]),
    }
}
/// A one-way arrow from node `from` to node `to` allowing all ports.
fn arrow(id: u64, from: u64, to: u64) -> Arrow {
    Arrow {
        id: RuleId(id),
        from: Endpoint::Node(NodeId(from)),
        to: Endpoint::Node(NodeId(to)),
        both_ways: false,
        ports: TrafficPolicy::All,
    }
}
/// CPU time used by this process so far, in nanoseconds.
fn cpu_ns() -> Measurement<u128> {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_PROCESS_CPUTIME_ID)?;
    Ok(u128::try_from(time.tv_sec())? * 1_000_000_000 + u128::try_from(time.tv_nsec())?)
}
/// Reads a memory field of `/proc/self/status`, such as `VmRSS:` (current) or
/// `VmHWM:` (peak), and returns it in bytes.
fn memory(field: &str) -> Measurement<usize> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with(field))
        .ok_or("missing process memory field")?;
    Ok(line
        .split_whitespace()
        .nth(1)
        .ok_or("missing process memory value")?
        .parse::<usize>()?
        * 1024)
}
/// Builds a coordinator with `count` nodes where each node has an arrow to the
/// next `arrows` nodes (wrapping around). Prints the join cost as a `METRIC`
/// line.
fn fixture(count: u64, arrows: u64) -> Measurement<Coordinator> {
    let mut state = Coordinator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[], node(0))?;
    let start = Instant::now();
    let cpu_start = cpu_ns()?;
    for id in 1..count {
        black_box(state.join(node(id))?);
    }
    println!(
        "METRIC join nodes={count} total_ns={} cpu_total_ns={} per_node_ns={}",
        start.elapsed().as_nanos(),
        cpu_ns()? - cpu_start,
        start.elapsed().as_nanos() / u128::from(count - 1)
    );
    for from in 0..count {
        for offset in 1..=arrows {
            black_box(state.add_arrow(arrow(
                1 + from * arrows + offset,
                from,
                (from + offset) % count,
            ))?);
        }
    }
    Ok(state)
}
/// Runs one coordinator change and prints a `METRIC` line named `name` with
/// its wall time, CPU time, the size of the change as JSON and how many nodes
/// and peers it touched. The JSON size is for comparison only; it is not the
/// production encoding.
fn change(
    name: &str,
    state: &mut Coordinator,
    operation: impl FnOnce(&mut Coordinator) -> Result<Change, MeshError>,
) -> Measurement<()> {
    let start = Instant::now();
    let cpu_start = cpu_ns()?;
    let diff = black_box(operation(state)?);
    let ns = start.elapsed().as_nanos();
    let cpu_elapsed = cpu_ns()? - cpu_start;
    // These bytes are whole JSON changes, not a selected production transport encoding.
    let bytes = serde_json::to_vec(&diff)?.len();
    println!(
        "METRIC {name} ns={ns} cpu_ns={cpu_elapsed} bytes_json={bytes} nodes_touched={} peers_upserted={} peers_removed={}",
        diff.peers.len(),
        diff.peers.values().map(|p| p.upserted.len()).sum::<usize>(),
        diff.peers.values().map(|p| p.removed.len()).sum::<usize>()
    );
    Ok(())
}
/// Entry point: `measure <compile|incremental|view> [nodes] [arrows]`.
///
/// Defaults are `compile`, 10000 nodes and 20 arrows per node. Run each mode in
/// a fresh process so its memory numbers are not mixed with another mode's.
/// Results are printed as `METRIC` lines.
fn main() -> Measurement<()> {
    let args: Vec<_> = std::env::args().collect();
    let mode = args.get(1).map_or("compile", String::as_str);
    let count: u64 = args.get(2).map_or("10000", String::as_str).parse()?;
    let arrows: u64 = args.get(3).map_or("20", String::as_str).parse()?;
    if !(2..=60_000).contains(&count)
        || arrows >= count
        || !matches!(mode, "compile" | "incremental" | "view")
    {
        return Err("expected compile|incremental|view, 2..60000 nodes, arrows < nodes".into());
    }
    let baseline = memory("VmRSS:")?;
    if mode == "view" {
        return measure_view(count);
    }
    let mut state = fixture(count, arrows)?;
    let rss = memory("VmRSS:")?;
    let peers: usize = state.views().values().map(|view| view.peers.len()).sum();
    println!(
        "METRIC coordinator_memory nodes={count} arrows_per_node={arrows} peer_entries={peers} rss_bytes={rss} incremental_rss_bytes={} bytes_per_node={}",
        rss.saturating_sub(baseline),
        rss.saturating_sub(baseline) / usize::try_from(count)?
    );
    if mode == "compile" {
        for sample in 0..5 {
            let start = Instant::now();
            let cpu_start = cpu_ns()?;
            let views = black_box(state.full_compile());
            let ns = start.elapsed().as_nanos();
            let cpu_elapsed = cpu_ns()? - cpu_start;
            println!(
                "METRIC full_compile sample={sample} nodes={count} arrows_per_node={arrows} ns={ns} cpu_ns={cpu_elapsed} peak_rss_bytes={}",
                memory("VmHWM:")?
            );
            black_box(views);
        }
    } else {
        measure_changes(&mut state, count)?;
    }
    let mut allocator = AddressAllocator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[])?;
    let start = Instant::now();
    let cpu_start = cpu_ns()?;
    for id in 0..count {
        black_box(allocator.allocate(NodeId(id))?);
    }
    println!(
        "METRIC address_allocate nodes={count} per_node_ns={} cpu_per_node_ns={}",
        start.elapsed().as_nanos() / u128::from(count),
        (cpu_ns()? - cpu_start) / u128::from(count)
    );
    let name = format!("host-{}.internal", count / 2);
    let start = Instant::now();
    let cpu_start = cpu_ns()?;
    for _ in 0..100_000 {
        black_box(state.names().lookup(black_box(&name)));
    }
    println!(
        "METRIC name_lookup iterations=100000 per_lookup_ns={} cpu_per_lookup_ns={} peak_rss_bytes={}",
        start.elapsed().as_nanos() / 100_000,
        (cpu_ns()? - cpu_start) / 100_000,
        memory("VmHWM:")?
    );
    Ok(())
}
/// Measures the memory one node's peer view needs when it has `count` peers,
/// as growth of resident memory per peer.
fn measure_view(count: u64) -> Measurement<()> {
    let mut allocator = AddressAllocator::new(MeshSettings::new([1, 2, 3, 4, 5]), &[])?;
    let addresses: Vec<_> = (0..count)
        .map(|id| allocator.allocate(NodeId(id)))
        .collect::<Result<_, _>>()?;
    // Keep bookkeeping live so freed allocator blocks cannot hide peer-view allocation in RSS.
    let before = memory("VmRSS:")?;
    let mut view = PeerView {
        node: NodeId(count),
        rule_version: 1,
        peers: BTreeMap::new(),
    };
    for id in 0..count {
        view.peers.insert(
            NodeId(id),
            Peer {
                node: NodeId(id),
                keys: PeerKeys {
                    current: key(id),
                    previous: None,
                },
                allowed_ips: addresses[usize::try_from(id)?],
                inbound: TrafficPolicy::All,
                outbound: TrafficPolicy::All,
            },
        );
    }
    let bytes = memory("VmRSS:")?.saturating_sub(before);
    println!(
        "METRIC view_memory peers={count} incremental_rss_bytes={bytes} bytes_per_peer={} peak_rss_bytes={}",
        bytes / usize::try_from(count)?,
        memory("VmHWM:")?
    );
    black_box(view);
    black_box(allocator);
    Ok(())
}
/// Repeats 20 samples of the common changes (add an arrow, remove a node, rotate
/// a key, ...) on a built coordinator and prints each as a `METRIC` line.
fn measure_changes(state: &mut Coordinator, count: u64) -> Measurement<()> {
    let target = NodeId(count / 2);
    for sample in 0..20 {
        println!("SAMPLE {sample}");
        change("arrow_added", state, |state| {
            state.add_arrow(arrow(u64::MAX, 1, count / 2))
        })?;
        state.remove_arrow(RuleId(u64::MAX))?;
        change("node_removed", state, |state| state.remove_node(target))?;
        state.join(node(target.0))?;
        change("key_rotated", state, |state| {
            state.rotate_key(target, key(count + sample), sample * 1000)
        })?;
        let versions: Vec<_> = state
            .view(target)
            .ok_or(MeshError::UnknownNode)?
            .peers
            .keys()
            .map(|id| {
                state
                    .view(*id)
                    .map(|view| (*id, view.rule_version))
                    .ok_or(MeshError::UnknownNode)
            })
            .collect::<Result<_, _>>()?;
        for (id, version) in versions {
            state.acknowledge(id, version)?;
        }
        state.finish_rotation(target, sample * 1000 + 120)?;
    }
    for sample in 0..20 {
        change("server_key_rotated", state, |state| {
            state.rotate_key(NodeId(0), key(count * 3 + sample), sample * 1000)
        })?;
        let versions: Vec<_> = state
            .views()
            .iter()
            .map(|(id, view)| (*id, view.rule_version))
            .collect();
        for (id, version) in versions {
            state.acknowledge(id, version)?;
        }
        state.finish_rotation(NodeId(0), sample * 1000 + 120)?;
    }
    Ok(())
}
