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

/// A unit written before #516 (no `--web-root`, custom data) is planned
/// byte-for-byte unchanged when init is re-run without `--data`, so the real
/// install is a no-op instead of `ExistingUnit` or a moved data folder.
#[test]
fn rerunning_init_on_an_existing_user_install_plans_the_same_unit() {
    let machine = Machine::new("rerun-user");
    let custom = machine.root.join("custom data");
    let custom = custom.to_str().expect("utf-8 path");
    let first = planned_unit(&machine.run(
        &["--json", "server", "init", "--dry-run", "--data", custom],
        &[],
    ));
    assert!(!first.contains("--web-root"), "{first}");
    fs::write(machine.user_unit(), &first).expect("install the old unit");

    for args in [
        &["--json", "server", "init", "--dry-run"][..],
        &["--json", "server", "init", "--dry-run", "--force"][..],
    ] {
        let again = planned_unit(&machine.run(args, &[]));
        assert_eq!(again, first, "{args:?}");
    }
}

/// `--system --force` without `--data` keeps the custom folder of the system
/// unit it replaces instead of pointing it at `/var/lib/infraternal`.
///
/// The plan uses `--host-firewall-off`, so it holds only the server unit: a
/// default-drop plan needs every port sshd uses (J671, #483), which an
/// unprivileged runner cannot read, so it would be refused before the folder
/// choice this test is about. The firewall plan's folder line is covered by
/// `install::tests::system_units_mark_the_scope_used_by_first_run_status`.
#[test]
fn forcing_a_system_reinstall_keeps_its_custom_data_folder() {
    let machine = Machine::new("rerun-system");
    let binary = env!("CARGO_BIN_EXE_infraternal");
    fs::write(
        machine.system_unit(),
        format!(
            "[Service]\nExecStart=\"{binary}\" \"server\" \"--listen\" \"127.0.0.1:7443\" \"--data\" \"/srv/custom state\"\n"
        ),
    )
    .expect("install a custom system unit");
    let unit = planned_unit(&machine.run(
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
    ));
    assert!(unit.contains("\"--data\" \"/srv/custom state\""), "{unit}");
    assert!(!unit.contains("/var/lib/infraternal"), "{unit}");
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
