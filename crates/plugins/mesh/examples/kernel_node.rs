//! Namespace-only Linux mesh fixture for both engines. Private keys stay in each process, and
//! stdin/stdout carry public configurations.
#[cfg(feature = "agent")]
/// Run one selected mesh engine inside a disposable network namespace.
fn main() -> std::io::Result<()> {
    use infraternal_plugin_mesh::{
        dataplane::Chunk,
        node::{EngineKind, Node},
        wireguard::Device,
    };
    use std::io::{BufRead, Write};
    let engine_choice = std::env::var("INFRATERNAL_MESH_ENGINE").ok();
    let engine = EngineKind::parse(engine_choice.as_deref())?;
    let node = if std::env::args().any(|arg| arg == "--nf-tables") {
        Node::with_firewall(infraternal_plugin_mesh::firewall::Firewall::nf_tables())
    } else {
        Node::default()
    };
    let mut node = node.with_engine(engine);
    let identity = node.up()?;
    if engine == EngineKind::GotaTun && !Device::owned_tun()? {
        return Err(std::io::Error::other(
            "namespace proof did not start GotaTun",
        ));
    }
    let mut identity = serde_json::to_value(identity)?;
    identity["engine"] = match engine {
        EngineKind::GotaTun => "gotatun",
        EngineKind::Kernel => "kernel",
    }
    .into();
    println!("{identity}");
    std::io::stdout().flush()?;
    for line in std::io::stdin().lock().lines() {
        let line = line?;
        match line.as_str() {
            "quit" => {
                node.down()?;
                println!("{{\"off\":true}}");
                break;
            }
            "stats" => println!(
                "{}",
                serde_json::to_string(&node.counters()?.values().collect::<Vec<_>>())?
            ),
            _ => {
                let chunk: Chunk = serde_json::from_str(&line)?;
                let started = std::time::Instant::now();
                let applied = node.chunk(chunk)?;
                println!(
                    "{{\"applied\":{applied},\"apply_us\":{}}}",
                    started.elapsed().as_micros()
                );
            }
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
#[cfg(not(feature = "agent"))]
/// Do nothing when the mesh agent feature is not enabled.
fn main() {}
