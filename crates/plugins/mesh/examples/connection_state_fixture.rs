//! Disposable public-state node fixture for journal failure and connection-state rollback [242], #173.
#[cfg(all(feature = "agent", target_os = "linux"))]
use infraternal_plugin_mesh::{dataplane::Chunk, node::Node};
#[cfg(all(feature = "agent", target_os = "linux"))]
use std::{
    io::{BufRead, Write},
    os::unix::fs::PermissionsExt,
};
#[cfg(all(feature = "agent", target_os = "linux"))]
fn main() -> std::io::Result<()> {
    let parent =
        std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").ok_or(std::io::ErrorKind::InvalidInput)?;
    let root = std::path::PathBuf::from(parent).join(format!("state-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    if std::env::args().any(|s| s == "--nf-tables") {
        let p = root.join("mesh-public.json");
        std::fs::write(
            &p,
            br#"{"enabled":true,"config":null,"backend":"NfTables"}"#,
        )?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut node = Node::restore(&root)?;
    let identity = node.up()?;
    println!("{}", serde_json::to_string(&identity)?);
    std::io::stdout().flush()?;
    let obstruction = root.join(format!("mesh-public.{}.new", std::process::id()));
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        if line == "stats" {
            println!(
                "{}",
                serde_json::to_string(
                    &infraternal_plugin_mesh::wireguard::Device::counters()?
                        .values()
                        .collect::<Vec<_>>()
                )?
            );
        } else if line == "obstruct" {
            std::fs::write(&obstruction, b"public fixture obstruction")?;
            println!("{{\"obstructed\":true}}");
        } else if line == "unobstruct" {
            std::fs::remove_file(&obstruction)?;
            println!("{{\"obstructed\":false}}");
        } else if line == "commit-narrow" {
            // Model persisted intent with a cleanup error: rules are restrictive,
            // but established entries remain for restart to reconcile.
            let mut config = node
                .config()
                .ok_or(std::io::ErrorKind::InvalidInput)?
                .clone();
            config.version += 1;
            for peer in config.peers.values_mut() {
                peer.inbound = infraternal_plugin_mesh::policy::rules::TrafficPolicy::None;
            }
            let fallback = std::env::args().any(|s| s == "--nf-tables");
            if fallback {
                infraternal_plugin_mesh::iptables::apply(&config, true)?;
            } else {
                let mut child = std::process::Command::new("/usr/sbin/nft")
                    .args(["-f", "-"])
                    .stdin(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::null())
                    .spawn()?;
                child
                    .stdin
                    .take()
                    .ok_or(std::io::ErrorKind::BrokenPipe)?
                    .write_all(
                        infraternal_plugin_mesh::firewall::render(&config, true).as_bytes(),
                    )?;
                assert!(child.wait()?.success());
            }
            let (store, _) = infraternal_plugin_mesh::node_state::Store::open(&root)?;
            store.save(&infraternal_plugin_mesh::node_state::State {
                enabled: true,
                config: Some(config),
                authority_reset_pending: false,
                backend: Some(if fallback {
                    infraternal_plugin_mesh::firewall::Backend::NfTables
                } else {
                    infraternal_plugin_mesh::firewall::Backend::Nft
                }),
            })?;
            println!("{{\"committed_without_cleanup\":true}}");
        } else if line == "restore" {
            drop(node);
            node = Node::restore(&root)?;
            println!("{{\"restored\":true}}");
        } else if line == "quit" {
            node.down()?;
            println!("{{\"off\":true}}");
            break;
        } else {
            apply(&mut node, &line)?;
        }
        std::io::stdout().flush()?;
    }
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(not(all(feature = "agent", target_os = "linux")))]
fn main() {}

/// Return the final installed-rule timestamp only after durable success, never after rollback.
#[cfg(all(feature = "agent", target_os = "linux"))]
fn apply(node: &mut Node, line: &str) -> std::io::Result<()> {
    let chunk: Chunk = serde_json::from_str(line)?;
    let started = std::time::Instant::now();
    let result = node.chunk(chunk);
    #[cfg(feature = "cutoff-measure")]
    let refusing_ns = node.refusing_at_ns();
    #[cfg(not(feature = "cutoff-measure"))]
    let refusing_ns: Option<u64> = None;
    match result {
        Ok(applied) => println!(
            "{{\"applied\":{applied},\"apply_us\":{},\"refusing_ns\":{}}}",
            started.elapsed().as_micros(),
            if applied {
                refusing_ns.map_or_else(|| "null".to_owned(), |ns| ns.to_string())
            } else {
                "null".to_owned()
            }
        ),
        Err(e) => println!("{{\"failed\":true,\"error_kind\":\"{:?}\"}}", e.kind()),
    }
    Ok(())
}
