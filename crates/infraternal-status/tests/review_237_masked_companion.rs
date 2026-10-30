//! Checks retained server data beside a healthy companion service (#237, D299/D303).
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_status::{Activity, Roots, probe};
use std::{fs, path::PathBuf};

#[test]
fn masked_server_beside_a_running_host_has_a_partial_setup_headline() {
    let base = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("home directory"))
                .join(".cache/codex-scratch/review-status-crash-loop-237-r2")
        },
        PathBuf::from,
    );
    let root = base.join(format!("masked-companion-{}", std::process::id()));
    for directory in ["system", "user", "data"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
    fs::write(root.join("data/infraternal.sqlite"), []).unwrap();
    std::os::unix::fs::symlink("/dev/null", root.join("system/infraternal-server.service"))
        .unwrap();
    fs::write(
        root.join("user/infraternal-agent.service"),
        "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
    )
    .unwrap();
    let status = probe(
        &Roots {
            system_units: vec![root.join("system")],
            user_units: Some(root.join("user")),
            run_dir: None,
            data_dirs: vec![root.join("data")],
            net_class: root.join("net"),
        },
        &["server".to_owned(), "agent".to_owned()],
        &|_, _| Activity::Active,
    );
    fs::remove_dir_all(root).unwrap();
    assert_eq!(status.components[0].state, "Stopped");
    assert_eq!(status.components[1].state, "Running");
    assert_eq!(
        status.headline().1,
        "Part of this machine's setup is not running.",
        "a healthy host daemon must not make the masked server healthy"
    );
}
