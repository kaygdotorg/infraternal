//! Drives the real `server init` binary to check its folder choices end to end (#516, D395).
//!
//! Every run uses a private fake `HOME`, user unit folder and system unit
//! folder (`INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR`, debug builds only), so
//! nothing on the machine is read or written, and only `--dry-run` plans are
//! produced, except the root refusal, which stops before any write.
#![cfg(all(unix, feature = "plugin-server"))]
#![allow(clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

/// A throwaway machine: a home, a user unit folder and a system unit folder.
struct Machine {
    /// Root of the fixture tree, removed on drop.
    root: PathBuf,
}

impl Machine {
    /// Make an empty fixture tree under the temp dir.
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("init-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for dir in ["home", "config/systemd/user", "system"] {
            fs::create_dir_all(root.join(dir)).expect("create fixture dir");
        }
        Self { root }
    }

    /// The fake `$HOME`.
    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    /// The fixture system data base that stands in for `/var/lib/infraternal`.
    fn system_base(&self) -> PathBuf {
        self.root.join("system-base")
    }

    /// Where a per-user unit named `infraternal-server` lives.
    fn user_unit(&self) -> PathBuf {
        self.root
            .join("config/systemd/user/infraternal-server.service")
    }

    /// Where a system unit named `infraternal-server` lives.
    fn system_unit(&self) -> PathBuf {
        self.root.join("system/infraternal-server.service")
    }

    /// Run the CLI with `args` in this machine's environment plus `extra` variables.
    fn run(&self, args: &[&str], extra: &[(&str, &str)]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_infraternal"));
        command
            .args(args)
            .current_dir(&self.root)
            .env_clear()
            .env("HOME", self.home())
            // The system base is a fixture: `server init --system` plans must not depend on the host's /var/lib.
            .env("INFRATERNAL_TEST_LINUX_SYSTEM_BASE", self.system_base())
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env(
                "INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR",
                self.root.join("system"),
            );
        for (key, value) in extra {
            command.env(key, value);
        }
        command.output().expect("run server init")
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Everything the command printed, for message checks.
fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The unit text a successful `--json --dry-run` would write.
fn planned_unit(output: &Output) -> String {
    assert!(output.status.success(), "{}", text(output));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let plan = plan["data"]["plan"].as_str().expect("plan text");
    plan[plan.find("[Unit]").expect("unit header")..plan.find("\nWould run:").expect("unit end")]
        .to_owned()
}

/// The whole `--json --dry-run` result, after checking it succeeded.
fn planned(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", text(output));
    serde_json::from_slice(&output.stdout).expect("plan JSON")
}

/// A unit written before #516 (custom data, no `--web-root`): a re-run without
/// `--data` now plans the move to the D395 folder (owner, 2026-11-15: "change
/// for existing installs too") and keeps the unit's shape; an explicit `--data`
/// still plans the old unit byte for byte, with or without `--force`.
#[test]
fn rerunning_init_on_an_existing_user_install_plans_the_move() {
    let machine = Machine::new("rerun-user");
    let custom = machine.root.join("custom data");
    fs::create_dir_all(&custom).expect("the old data folder");
    fs::write(custom.join("infraternal.sqlite"), "db").expect("old database");
    let custom = custom.to_str().expect("utf-8 path");
    let first = planned_unit(&machine.run(
        &["--json", "server", "init", "--dry-run", "--data", custom],
        &[],
    ));
    assert!(!first.contains("--web-root"), "{first}");
    fs::write(machine.user_unit(), &first).expect("install the old unit");
    let standard = machine.home().join(".local/state/infraternal");
    let standard = standard.to_str().expect("utf-8 path");

    for args in [
        &["--json", "server", "init", "--dry-run"][..],
        &["--json", "server", "init", "--dry-run", "--force"][..],
    ] {
        let output = machine.run(args, &[]);
        let plan = planned(&output);
        assert_eq!(plan["data"]["data_move"]["from"], custom, "{args:?}");
        assert_eq!(plan["data"]["data_move"]["to"], standard, "{args:?}");
        assert_eq!(plan["data"]["data_move"]["moved"], false, "{args:?}");
        let unit = planned_unit(&output);
        assert_eq!(unit, first.replace(custom, standard), "{args:?}");
    }
    for args in [
        &["--json", "server", "init", "--dry-run", "--data", custom][..],
        &[
            "--json",
            "server",
            "init",
            "--dry-run",
            "--force",
            "--data",
            custom,
        ][..],
    ] {
        let output = machine.run(args, &[]);
        assert!(
            planned(&output)["data"].get("data_move").is_none(),
            "{args:?}"
        );
        assert_eq!(planned_unit(&output), first, "{args:?}");
    }
    // A dry run changed nothing on disk.
    assert_eq!(
        fs::read_to_string(machine.user_unit()).expect("unit"),
        first
    );
    assert!(Path::new(custom).join("infraternal.sqlite").is_file());
    assert!(!Path::new(standard).exists());
}

/// A system unit with a custom folder: without `--data` init plans the move to
/// the system base (a fixture here; `/var/lib/infraternal` on a real machine) (or refuses because that folder is in use on this
/// machine); `--data <custom> --force` keeps the custom folder.
///
/// Both plans use `--host-firewall-off`, so they hold only the server unit: a
/// default-drop plan needs every port sshd uses (J671, #483), which an
/// unprivileged runner cannot read, so it would be refused before the folder
/// choice this test is about. The firewall plan's folder line is covered by
/// `install::tests::system_units_mark_the_scope_used_by_first_run_status`.
#[test]
fn a_system_reinstall_moves_its_custom_folder_unless_data_is_given() {
    let machine = Machine::new("rerun-system");
    let binary = env!("CARGO_BIN_EXE_infraternal");
    let custom = machine.root.join("custom state");
    fs::create_dir_all(&custom).expect("the old data folder");
    let custom = custom.to_str().expect("utf-8 path");
    let base = machine.system_base();
    let base = base.to_str().expect("utf-8 path");
    fs::write(
        machine.system_unit(),
        format!(
            "[Service]\nExecStart=\"{binary}\" \"server\" \"--listen\" \"127.0.0.1:7443\" \"--data\" \"{custom}\"\n"
        ),
    )
    .expect("install a custom system unit");
    let output = machine.run(
        &[
            "--json",
            "server",
            "init",
            "--system",
            "--dry-run",
            "--force",
            "--host-firewall-off",
        ],
        &[],
    );
    let message = text(&output);
    assert!(message.contains(base), "{message}");
    if output.status.success() {
        let plan = planned(&output);
        assert_eq!(plan["data"]["data_move"]["from"], custom);
        assert_eq!(plan["data"]["data_move"]["to"], base);
        assert!(planned_unit(&output).contains(&format!("\"--data\" \"{base}\"")));
    } else {
        assert!(
            message.contains("already holds")
                || message.contains("shared")
                || message.contains("Permission denied")
                || message.contains("Not a directory")
                || message.contains("untrusted"),
            "{message}"
        );
    }
    let unit = planned_unit(&machine.run(
        &[
            "--json",
            "server",
            "init",
            "--system",
            "--dry-run",
            "--force",
            "--host-firewall-off",
            "--data",
            custom,
        ],
        &[],
    ));
    assert!(unit.contains(&format!("\"--data\" \"{custom}\"")), "{unit}");
    assert!(!unit.contains(base), "{unit}");
}

/// A system `server init` unit waits for the network-online target.
#[test]
fn a_generated_system_unit_waits_for_network_online() {
    let machine = Machine::new("network-online");
    let system = planned_unit(&machine.run(
        &[
            "--json",
            "server",
            "init",
            "--system",
            "--dry-run",
            "--host-firewall-off",
        ],
        &[],
    ));
    assert!(
        system.contains("After=network-online.target\nWants=network-online.target\n"),
        "{system}"
    );

    let user = planned_unit(&machine.run(&["--json", "server", "init", "--dry-run"], &[]));
    assert!(user.contains("After=network.target\n"), "{user}");
    assert!(!user.contains("Wants=network-online.target"), "{user}");
}

/// A fresh per-user install with an empty `XDG_STATE_HOME` uses D395's
/// `~/.local/state/infraternal`, and a missing bundled `web/` is not an error.
#[test]
fn a_fresh_user_install_uses_the_xdg_state_default() {
    let machine = Machine::new("fresh-user");
    let output = machine.run(&["server", "init", "--dry-run"], &[("XDG_STATE_HOME", "")]);
    assert!(output.status.success(), "{}", text(&output));
    let expected = machine.home().join(".local/state/infraternal");
    assert!(
        text(&output).contains(&format!("Data folder: {}\n", expected.display())),
        "{}",
        text(&output)
    );
    let state = machine.root.join("state");
    let output = machine.run(
        &["server", "init", "--dry-run"],
        &[("XDG_STATE_HOME", state.to_str().expect("utf-8 path"))],
    );
    assert!(
        text(&output).contains(&format!(
            "Data folder: {}\n",
            state.join("infraternal").display()
        )),
        "{}",
        text(&output)
    );
}

/// A relative `--data` is refused with the absolute path to pass instead.
#[test]
fn a_relative_data_folder_is_refused_with_its_absolute_form() {
    let machine = Machine::new("relative");
    // JSON keeps the message on one line; the terminal output wraps long paths.
    let output = machine.run(
        &["--json", "server", "init", "--dry-run", "--data", "data"],
        &[],
    );
    assert!(!output.status.success());
    let absolute = fs::canonicalize(&machine.root)
        .expect("fixture root")
        .join("data");
    let message = text(&output);
    assert!(
        message.contains(&format!("--data {}", absolute.display()))
            || message.contains(&format!("--data {}", machine.root.join("data").display())),
        "{message}"
    );
}

/// `--system` from a non-root user is refused clearly before anything is written.
#[test]
fn a_system_install_without_root_is_refused() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let machine = Machine::new("no-root");
    let output = machine.run(&["--json", "server", "init", "--system", "--yes"], &[]);
    assert!(!output.status.success());
    assert!(text(&output).contains("needs root"), "{}", text(&output));
    assert!(!Path::new(&machine.system_unit()).exists());
}
