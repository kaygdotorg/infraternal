//! Exercise D395's durable frontiers through the real per-user systemd start job.

#![cfg(all(target_os = "linux", feature = "plugin-server"))]

use std::process::Command;

/// The runtime unit fixture needs an available Linux user manager.
#[test]
fn server_start_owns_move_recovery_and_readiness() -> std::io::Result<()> {
    if std::env::var_os("XDG_RUNTIME_DIR").is_none()
        || !Command::new("/usr/bin/systemctl")
            .args(["--user", "show", "-p", "Version", "--value"])
            .output()
            .is_ok_and(|output| output.status.success())
    {
        eprintln!("D395 systemd matrix requires a reachable user manager");
        return Ok(());
    }
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/server_move_systemd.py"
        ))
        .env("BIN", env!("CARGO_BIN_EXE_infraternal"))
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
