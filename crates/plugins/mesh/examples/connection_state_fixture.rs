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
        if line == "obstruct" {
            std::fs::write(&obstruction, b"public fixture obstruction")?;
            println!("{{\"obstructed\":true}}");
        } else if line == "unobstruct" {
            std::fs::remove_file(&obstruction)?;
            println!("{{\"obstructed\":false}}");
        } else if line == "quit" {
            node.down()?;
            println!("{{\"off\":true}}");
            break;
        } else {
            let chunk: Chunk = serde_json::from_str(&line)?;
            match node.chunk(chunk) {
                Ok(applied) => println!("{{\"applied\":{applied},\"apply_us\":0}}"),
                Err(e) => println!("{{\"failed\":true,\"error_kind\":\"{:?}\"}}", e.kind()),
            }
        }
        std::io::stdout().flush()?;
    }
    let _ = std::fs::remove_dir_all(root);
    Ok(())
}

#[cfg(not(all(feature = "agent", target_os = "linux")))]
fn main() {}
