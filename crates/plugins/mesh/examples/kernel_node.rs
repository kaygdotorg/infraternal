//! Namespace-only `GotaTun` mesh fixture; private keys stay in each process, stdin/stdout carry public configurations.
#[cfg(feature = "agent")]
fn main() -> std::io::Result<()> {
    use infraternal_plugin_mesh::{dataplane::Chunk, node::Node, wireguard::Device};
    use std::io::{BufRead, Write};
    let mut node = if std::env::args().any(|arg| arg == "--nf-tables") {
        Node::with_firewall(infraternal_plugin_mesh::firewall::Firewall::nf_tables())
    } else {
        Node::default()
    };
    let identity = node.up()?;
    if !Device::owned_tun()? {
        return Err(std::io::Error::other(
            "namespace proof did not start GotaTun",
        ));
    }
    let mut identity = serde_json::to_value(identity)?;
    identity["engine"] = "gotatun".into();
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
fn main() {}
