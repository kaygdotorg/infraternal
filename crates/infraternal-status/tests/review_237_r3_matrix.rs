//! Round-3 review of #237: the module's role/state table, driven through the
//! real `probe_local` path with manager-shaped `systemctl show` answers (D299/D303).
//!
//! The in-crate table test injects `Activity` values directly, so it never
//! exercises property parsing, mask discovery or the bounded query workers.
//! Here a stub `systemctl` on `PATH` answers each unit with the properties a
//! real manager prints for that state, and every documented cell is checked in
//! both scope assignments (server in the system manager and the infraternal
//! agent in the user manager, then swapped).
//!
//! The masked infraternal-agent cells are left out on purpose: whether a mask
//! alone establishes a host role is disputed in `review_237_r3_masks.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_status::{Role, Roots, probe_local};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

/// Re-run one test in a child process whose `PATH` holds only the stub manager.
fn isolated(name: &str, check: impl FnOnce(&Path)) {
    if let Some(root) = std::env::var_os("STATUS_R3_MATRIX_ROOT") {
        check(Path::new(&root));
        return;
    }
    let base = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("home directory"))
                .join(".cache/codex-scratch/review-status-crash-loop-237-r3/fixtures")
        },
        PathBuf::from,
    );
    let root = base.join(format!("r3-matrix-{}", std::process::id()));
    fs::create_dir_all(root.join("bin")).unwrap();
    let manager = root.join("bin/systemctl");
    // The unit is the last argument. REFUSE stands for a manager that cannot be
    // reached (for example no user bus): systemctl exits nonzero, prints nothing.
    fs::write(
        &manager,
        r#"#!/bin/sh
for unit; do :; done
case "$unit" in *server*) role=server;; *) role=agent;; esac
file="$STATUS_R3_MATRIX_ROOT/$role.properties"
read -r first < "$file"
[ "$first" = REFUSE ] && exit 1
while IFS= read -r line; do printf '%s\n' "$line"; done < "$file"
"#,
    )
    .unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("STATUS_R3_MATRIX_ROOT", &root)
        .env("PATH", root.join("bin"))
        .output()
        .unwrap();
    fs::remove_dir_all(root).unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

const ACTIVE: usize = 0;
const MASKED: usize = 3;
const MISSING: usize = 4;
const UNKNOWN: usize = 6;

/// What a systemd 249–257 manager prints for each documented state, in table order:
/// active, crash-looping, failed, masked, missing, disabled, unknown.
fn properties(state: usize) -> &'static str {
    match state {
        ACTIVE => {
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=4242\nNRestarts=0\nExecMainStartTimestampMonotonic=1\nExecMainCode=0\nExecMainStatus=0\n"
        }
        1 => {
            "LoadState=loaded\nActiveState=activating\nSubState=auto-restart\nMainPID=0\nNRestarts=45\nExecMainStartTimestampMonotonic=1\nExecMainCode=1\nExecMainStatus=7\n"
        }
        2 => {
            "LoadState=loaded\nActiveState=failed\nSubState=failed\nMainPID=0\nNRestarts=0\nExecMainStartTimestampMonotonic=1\nExecMainCode=1\nExecMainStatus=7\n"
        }
        MASKED => {
            "LoadState=masked\nUnitFileState=masked\nActiveState=inactive\nSubState=dead\nMainPID=0\nNRestarts=0\nExecMainStartTimestampMonotonic=0\n"
        }
        // A unit file on disk the manager has not loaded (no daemon-reload yet).
        MISSING => {
            "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nNRestarts=0\nExecMainStartTimestampMonotonic=0\n"
        }
        5 => {
            "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive\nSubState=dead\nMainPID=0\nNRestarts=0\nExecMainStartTimestampMonotonic=0\n"
        }
        _ => "REFUSE\n",
    }
}

/// Build one machine. `server`/`agent` are table states or `None` for an
/// unconfigured role. A missing server keeps its data but has no unit file.
fn machine(root: &Path, server: Option<usize>, agent: Option<usize>, swap: bool) -> Roots {
    for dir in ["system", "user", "data"] {
        let path = root.join(dir);
        if path.exists() {
            fs::remove_dir_all(&path).unwrap();
        }
        fs::create_dir_all(path).unwrap();
    }
    if server.is_some() {
        fs::write(root.join("data/infraternal.sqlite"), []).unwrap();
    }
    for (role, state, user, exec) in [
        ("server", server, swap, "server"),
        ("agent", agent, !swap, "agent run"),
    ] {
        let Some(state) = state else { continue };
        let unit = root
            .join(if user { "user" } else { "system" })
            .join(format!("infraternal-{role}.service"));
        if state == MASKED {
            symlink("/dev/null", unit).unwrap();
        } else if !(state == MISSING && role == "server") {
            fs::write(
                unit,
                format!("[Service]\nExecStart=/usr/bin/infraternal {exec}\n"),
            )
            .unwrap();
        }
        fs::write(root.join(format!("{role}.properties")), properties(state)).unwrap();
    }
    Roots {
        system_units: vec![root.join("system")],
        user_units: Some(root.join("user")),
        run_dir: None,
        data_dirs: vec![root.join("data")],
        net_class: root.join("net"),
    }
}

fn paired(label: char) -> &'static str {
    match label {
        'R' => "The server and the infraternal agent are running on this machine.",
        'L' => "The server and the infraternal agent are restarting repeatedly on this machine.",
        'F' => "The server and the infraternal agent have failed on this machine.",
        'D' => "The server and the infraternal agent are not running on this machine.",
        'Q' => "Part of this machine's setup is restarting repeatedly.",
        'U' => "The status of part of this machine's setup is unknown.",
        'X' => "Part of this machine's setup is not running; another status is unknown.",
        _ => "Part of this machine's setup is not running.",
    }
}

#[test]
fn manager_shaped_answers_follow_every_documented_cell() {
    isolated(
        "manager_shaped_answers_follow_every_documented_cell",
        |root| {
            // Copied from the module doc: rows=server, columns=infraternal agent.
            let table = [
                "RPPPPPU", "PLQQQQX", "PQFPPPX", "PQPDDDX", "PQPDDDX", "PQPDDDX", "UXXXXXU",
            ];
            let ids = ["server".to_owned(), "agent".to_owned()];
            let mut checked = 0;
            for swap in [false, true] {
                for (server, row) in table.iter().enumerate() {
                    for (agent, label) in row.chars().enumerate() {
                        if agent == MASKED {
                            continue;
                        }
                        let node =
                            probe_local(&machine(root, Some(server), Some(agent), swap), &ids);
                        let cell = format!("server={server} agent={agent} swap={swap}");
                        assert_eq!(node.role, Role::Both, "{cell}");
                        assert_eq!(node.headline().1, paired(label), "{cell}");
                        assert_eq!(
                            node.confirmed_down_count() > 0,
                            !matches!(label, 'R' | 'U'),
                            "{cell}: exit"
                        );
                        checked += 1;
                    }
                }
                for server_role in [true, false] {
                    for state in 0..7 {
                        if !server_role && state == MASKED {
                            continue;
                        }
                        let node = probe_local(
                            &machine(
                                root,
                                server_role.then_some(state),
                                (!server_role).then_some(state),
                                swap,
                            ),
                            &ids,
                        );
                        let (role, who) = if server_role {
                            (Role::Server, "server")
                        } else {
                            (Role::Host, "infraternal agent")
                        };
                        let cell = format!("standalone {who} state={state} swap={swap}");
                        assert_eq!(node.role, role, "{cell}");
                        let predicate = match state {
                            ACTIVE => "is running",
                            1 => "is restarting repeatedly",
                            2 => "has failed",
                            _ => "is not running",
                        };
                        let expected = if state == UNKNOWN {
                            paired('U').to_owned()
                        } else {
                            format!("The {who} {predicate} on this machine.")
                        };
                        assert_eq!(node.headline().1, expected, "{cell}");
                        assert_eq!(
                            node.confirmed_down_count() > 0,
                            !matches!(state, ACTIVE | UNKNOWN),
                            "{cell}: exit"
                        );
                        checked += 1;
                    }
                }
            }
            // A machine with nothing configured is not down.
            let node = probe_local(&machine(root, None, None, false), &ids);
            assert_eq!(node.role, Role::None);
            assert_eq!(node.confirmed_down_count(), 0);
            println!("{checked} manager-shaped cells plus the unconfigured machine passed");
        },
    );
}
