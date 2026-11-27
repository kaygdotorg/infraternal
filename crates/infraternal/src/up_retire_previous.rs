//! Retire a previous user install after the approved system install is active.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use infraternal_plugin_ssh::{model::InstallMode, previous_attempt::Retirement};
use std::{
    io::{self, IsTerminal, Write},
    process::{Command, Stdio},
};

/// Inspect only this Unix account. Root cannot guess who owns the user install.
pub(super) fn inspect(json_output: bool) -> Option<Retirement> {
    if !may_inspect(
        json_output,
        nix::unistd::Uid::effective().is_root(),
        io::stdin().is_terminal(),
    ) {
        return None;
    }
    let output = Command::new("/bin/sh")
        .args(["-c", &Retirement::inspection_script(InstallMode::Rootless)])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Retirement::parse(&output.stdout).ok()
}

/// Terminal input is needed for interactive consent from the original user.
fn may_inspect(json_output: bool, root: bool, terminal_input: bool) -> bool {
    !json_output && !root && terminal_input
}

#[cfg(test)]
mod tests {
    //! Check the conditions for collecting interactive retirement consent.

    /// JSON mode makes no retirement offer even with a terminal on stdin.
    #[test]
    fn json_mode_skips_retirement_even_with_a_terminal() {
        assert!(!super::may_inspect(true, false, true));
        assert!(super::may_inspect(false, false, true));
        assert!(!super::may_inspect(false, true, true));
        assert!(!super::may_inspect(false, false, false));
    }
}

/// Ask the approval server to verify this exact earlier host and key.
pub(super) fn preference(plan: &Retirement) -> String {
    format!(
        "wait=10, old-install=\"{}/{}/{}\"",
        plan.installed.host.simple(),
        nix::unistd::Uid::effective().as_raw(),
        URL_SAFE_NO_PAD.encode(plan.enrolled.digest),
    )
}

/// Print the exact paths before collecting consent. Enter keeps the old install.
pub(super) fn confirm(plan: &Retirement) -> bool {
    eprintln!(
        "An earlier infraternal installation belongs to the account that approved this join."
    );
    eprintln!(
        "After the new service starts, infraternal can stop and disable the earlier service and remove these paths:"
    );
    for path in plan.review_paths(true) {
        eprintln!("  {path}");
    }
    eprint!("Retire the earlier installation? [y/N] ");
    let mut answer = String::new();
    io::stderr().flush().is_ok()
        && io::stdin().read_line(&mut answer).is_ok()
        && matches!(answer.trim(), "y" | "Y" | "yes" | "Yes")
}

/// Recheck the reviewed installation and retire it as the original user.
pub(super) fn finish(plan: &Retirement) {
    let result = Command::new("/bin/sh")
        .args([
            "-c",
            &plan.execution_script(InstallMode::Rootless, uuid::Uuid::new_v4(), true),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if result.is_ok_and(|status| status.success()) {
        eprintln!("The earlier infraternal installation was retired.");
    } else {
        eprintln!(
            "The new service is active. Retirement of the earlier installation did not finish."
        );
    }
}
