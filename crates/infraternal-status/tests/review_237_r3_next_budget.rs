//! Round-3 review of #237: masked-server recovery guidance must obey the CLI next-step cap.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use infraternal_status::{Activity, Roots, probe};
use std::{fs, os::unix::fs::symlink};

#[test]
fn masked_server_recovery_keeps_next_steps_within_the_cli_limit() {
    let root = std::env::temp_dir().join(format!(
        "r237-next-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let system = root.join("system");
    let user = root.join("user");
    let data = root.join("data");
    fs::create_dir_all(&system).unwrap();
    fs::create_dir_all(&user).unwrap();
    fs::create_dir_all(&data).unwrap();
    symlink("/dev/null", system.join("infraternal-server.service")).unwrap();
    fs::write(data.join("infraternal.sqlite"), []).unwrap();

    // Two installed host services in separate manager scopes make two valid
    // unit diagnostics compete with the server restoration action.
    let agent_unit = "[Service]\nExecStart=/usr/bin/infraternal agent run\n";
    fs::write(system.join("infraternal-agent.service"), agent_unit).unwrap();
    fs::write(user.join("infraternal-agent-extra.service"), agent_unit).unwrap();

    let status = probe(
        &Roots {
            system_units: vec![system],
            user_units: Some(user),
            run_dir: None,
            data_dirs: vec![data],
            net_class: root.join("net"),
        },
        &[],
        &|_, _| Activity::Inactive,
    );
    let next = status.headline().2;
    let next_count = next.len();
    let next_text = next.join("\n");
    fs::remove_dir_all(root).unwrap();

    assert!(
        next_count <= 3,
        "CLI contract allows at most three follow-ups, got {next_count}:\n{next_text}"
    );
}
