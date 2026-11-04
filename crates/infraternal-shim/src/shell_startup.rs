//! Startup-only multiplexer compatibility without altering login files [241].
//!
//! Only fish supplies a post-configuration command while retaining its genuine
//! login startup order. Other shells remain untouched: an rc-file substitute or
//! replaceable prompt hook cannot guarantee cleanup of synthetic inside markers.

use std::{ffi::OsString, fmt::Write as _, path::Path, process::Command};

/// Placeholder value set on the multiplexer variables for the duration of shell
/// startup. The cleanup script recognises it to tell "still our placeholder"
/// from a value a startup file set itself.
const MARKER: &str = "infraternal-startup";

/// Configure a shell with a guaranteed startup cleanup boundary, if supported.
/// `inherited` describes whether Command retains the caller's environment.
/// False means the caller must not claim that automatic starts were skipped.
pub(crate) fn configure(
    command: &mut Command,
    shell: &Path,
    enabled: bool,
    inherited: bool,
) -> bool {
    if !enabled || shell.file_name().is_none_or(|name| name != "fish") {
        return false;
    }
    let mut cleanup = String::new();
    for name in ["TMUX", "ZELLIJ", "ZELLIJ_SESSION_NAME"] {
        // Explicit Command overrides, including removals, take precedence over
        // PAM's inherited environment. Real inside markers are never replaced.
        let previous = environment(command, name, inherited);
        if previous.as_ref().is_some_and(|value| !value.is_empty()) {
            continue;
        }
        command.env(name, MARKER);
        // If a startup file assigns its own value, retain that value. An empty
        // inherited value is restored as empty rather than silently removed.
        let _ = write!(
            cleanup,
            "if builtin test \"${name}\" = {MARKER}; builtin set {} {name}{}; end;",
            if previous.is_some() { "-gx" } else { "-eg" },
            if previous.is_some() { " ''" } else { "" },
        );
    }
    // This is fish's documented after-config/before-input hook, not a prompt
    // function that configuration can accidentally replace. No rc files,
    // resources, secret values in argv, or subsequent interactive hooks remain.
    if !cleanup.is_empty() {
        command.args(["--init-command", &cleanup]);
    }
    true
}

/// The value `name` will have in the child: an explicit override on `command`
/// (including a removal, which gives `None`) wins, then the caller's own
/// environment when `inherited` is true, otherwise `None`.
fn environment(command: &Command, name: &str, inherited: bool) -> Option<OsString> {
    if let Some((_, value)) = command.get_envs().find(|(key, _)| *key == name) {
        value.map(OsString::from)
    } else if inherited {
        std::env::var_os(name)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        process::Stdio,
    };

    #[test]
    fn fish_gets_startup_markers_and_cleanup() {
        let mut command = Command::new("/bin/fish");
        command.env_clear();
        assert!(configure(&mut command, Path::new("/bin/fish"), true, false));
        assert_eq!(command.get_args().next(), Some("--init-command".as_ref()));
        for name in ["TMUX", "ZELLIJ", "ZELLIJ_SESSION_NAME"] {
            assert!(
                command
                    .get_envs()
                    .any(|(key, value)| key == name && value.is_some())
            );
        }
    }

    #[test]
    fn unsupported_or_disabled_shell_is_unchanged() {
        for (shell, enabled) in [
            ("/bin/zsh", true),
            ("/bin/bash", true),
            ("/bin/sh", true),
            ("/bin/fish", false),
        ] {
            let mut command = Command::new(shell);
            command.env_clear();
            assert!(!configure(&mut command, Path::new(shell), enabled, false));
            assert_eq!(command.get_args().count(), 0);
            assert_eq!(command.get_envs().count(), 0);
        }
    }

    #[test]
    fn real_inside_markers_are_not_overwritten_or_removed() {
        let mut command = Command::new("/bin/fish");
        command.env_clear();
        for name in ["TMUX", "ZELLIJ", "ZELLIJ_SESSION_NAME"] {
            command.env(name, "real-existing-session");
        }
        assert!(configure(&mut command, Path::new("/bin/fish"), true, false));
        assert_eq!(command.get_args().count(), 0);
        for (_, value) in command.get_envs() {
            assert_eq!(value, Some("real-existing-session".as_ref()));
        }
    }

    #[test]
    fn empty_environment_is_restored_without_putting_values_in_argv() {
        let mut command = Command::new("/bin/fish");
        command
            .env_clear()
            .env("TMUX", "")
            .env("ZELLIJ", "real-value");
        assert!(configure(&mut command, Path::new("/bin/fish"), true, false));
        let arguments: Vec<_> = command.get_args().collect();
        let cleanup = arguments[1].to_str().unwrap();
        assert!(cleanup.contains("builtin set -gx TMUX ''"));
        assert!(!cleanup.contains("real-value"));
        assert!(!cleanup.contains("$ZELLIJ\""));
    }

    #[test]
    #[ignore = "requires an installed fish; run in a weighted fixture scope"]
    fn real_fish_skips_startup_but_manual_starts_work() {
        let shell =
            std::env::var_os("INFRATERNAL_TEST_FISH").unwrap_or_else(|| "/usr/bin/fish".into());
        let fixture = fish_fixture();
        let binaries = fixture.join("bin");
        for enabled in [false, true] {
            let mut command = Command::new(&shell);
            command
                .env_clear()
                .env("HOME", &fixture)
                .env("XDG_CONFIG_HOME", fixture.join(".config"))
                .env("PATH", format!("{}:/usr/bin:/bin", binaries.display()))
                .env("TERM", "xterm-256color")
                .env("INFRATERNAL_SESSION", "fixture")
                .env(
                    "LD_LIBRARY_PATH",
                    std::env::var_os("LD_LIBRARY_PATH").unwrap_or_default(),
                );
            configure(&mut command, Path::new(&shell), enabled, false);
            command
                .args(["-il"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(
                    concat!(
                        "fish_prompt\n",
                        "if set -q TMUX; echo DIRTY_INPUT; end\n",
                        "if set -q ZELLIJ; echo DIRTY_INPUT; end\n",
                        "if set -q ZELLIJ_SESSION_NAME; echo DIRTY_INPUT; end\n",
                        "status is-login; echo login:$status\n",
                        "echo session:$INFRATERNAL_SESSION\n",
                        "tmux manual\nzellij manual\nexit\n",
                    )
                    .as_bytes(),
                )
                .unwrap();
            let result = child.wait_with_output().unwrap();
            let stdout = String::from_utf8(result.stdout).unwrap();
            let stderr = String::from_utf8(result.stderr).unwrap();
            assert!(result.status.success(), "{stderr}");
            for automatic in ["tmux:startup", "zellij:startup", "missing-session-name"] {
                assert_eq!(stdout.contains(automatic), !enabled, "{stdout}\n{stderr}");
            }
            for expected in [
                "tmux:manual",
                "zellij:manual",
                "login:0",
                "session:fixture",
                "CLEAN_PROMPT",
            ] {
                assert!(
                    stdout.contains(expected),
                    "missing {expected}: {stdout}\n{stderr}"
                );
            }
            for forbidden in ["DIRTY_INPUT", "DIRTY_PROMPT"] {
                assert!(!stdout.contains(forbidden), "{stdout}\n{stderr}");
            }
        }
        fs::remove_dir_all(&fixture).unwrap();
    }

    fn fish_fixture() -> std::path::PathBuf {
        let scratch = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
            || {
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
                    .join(".cache/codex-scratch/infraternal")
            },
            std::path::PathBuf::from,
        );
        fs::create_dir_all(&scratch).unwrap();
        let fixture = scratch.join(format!("startup-test-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&fixture).unwrap();
        let config = fixture.join(".config/fish");
        fs::create_dir_all(&config).unwrap();
        let binaries = fixture.join("bin");
        fs::create_dir(&binaries).unwrap();
        for name in ["tmux", "zellij"] {
            let file = binaries.join(name);
            fs::write(
                &file,
                format!("#!/bin/sh\nprintf '%s\\n' '{name}:'\"$1\"\n"),
            )
            .unwrap();
            fs::set_permissions(file, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(
            config.join("config.fish"),
            concat!(
                "if not set -q TMUX; tmux startup; end\n",
                "if not set -q ZELLIJ; zellij startup; end\n",
                "if not set -q ZELLIJ_SESSION_NAME; echo missing-session-name; end\n",
                "function fish_prompt\n",
                " if set -q TMUX; echo DIRTY_PROMPT; else; echo CLEAN_PROMPT; end\n",
                "end\n",
            ),
        )
        .unwrap();
        fixture
    }
}
