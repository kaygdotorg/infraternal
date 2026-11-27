//! Renders the explanation shown before an interactive `sudo` password prompt (#616).
//!
//! Whenever an `infraternal` command asks the person at a terminal for administrator
//! privileges, it explains itself in three short parts right above `sudo`'s `Password:`
//! line:
//!
//! 1. What the command will do as root (one concrete action per `→` line, taken from the
//!    code that actually runs).
//! 2. What the person gets if they grant it (one concrete benefit per `→` line).
//! 3. What they won't be able to do if they decline (one sentence).
//!
//! # Terminal, colour and `--json` rules
//!
//! - When stderr is not a terminal (piped, redirected, or CI), nothing is printed so
//!   non-interactive output stays clean.
//! - When `--json` is active on a terminal, the explanation is printed to stderr as plain
//!   text (no ANSI escape sequences) so stdout remains valid JSON while the person still
//!   sees why `sudo` is asking for a password.
//! - Colour is enabled only on a colour-capable terminal (`TERM != "dumb"` and `NO_COLOR`
//!   unset or empty) outside `--json`.

use std::io::{self, IsTerminal, Write};

/// Bold ANSI SGR prefix for section headings.
const ANSI_BOLD: &str = "\u{1b}[1m";
/// Cyan ANSI SGR prefix for the `→` marker on privileged actions.
const ANSI_CYAN: &str = "\u{1b}[36m";
/// Green ANSI SGR prefix for the `→` marker on user benefits.
const ANSI_GREEN: &str = "\u{1b}[32m";
/// ANSI SGR reset sequence.
const ANSI_RESET: &str = "\u{1b}[0m";

/// The shared opening line before the list of privileged actions.
const OPENING_HEADING: &str =
    "Infraternal needs administrator privileges just once for the following:";
/// The shared heading before the list of benefits.
const BENEFIT_HEADING: &str = "If you grant it, you get:";

/// Every interactive elevation (`sudo`) prompt in the `infraternal` CLI.
///
/// Each variant corresponds to one real code path that invokes `sudo` and lists only
/// what that path actually performs as root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElevationPrompt {
    /// Fresh macOS user-mode `infraternal up` installing the on-demand mesh helper.
    MacosUserHelperInstall,
    /// Existing macOS user-mode `infraternal up` updating or migrating the mesh helper
    /// to match the running build.
    MacosUserHelperRefresh,
    /// Linux `infraternal up` installing the system `infraternal-agent` service (and
    /// `infraternal-firewall.service` when `host_firewall` is true).
    LinuxSystemInstall {
        /// Whether this build also installs and enables `infraternal-firewall.service`.
        host_firewall: bool,
    },
    /// macOS `infraternal up --system` installing the machine-wide `LaunchDaemon`.
    MacosSystemInstall,
    /// macOS `infraternal mesh up` enabling and starting the system mesh `LaunchDaemon`.
    MacosMeshServiceUp,
    /// macOS `infraternal mesh down` removing managed DNS resolver files and stopping the
    /// system mesh `LaunchDaemon`.
    MacosMeshServiceDown,
}

/// Structured copy for one [`ElevationPrompt`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromptCopy {
    /// Concrete actions the elevated step performs as root, one per line.
    pub actions: &'static [&'static str],
    /// Concrete outcomes the person gets when they grant elevation, one per line.
    pub benefits: &'static [&'static str],
    /// Concrete loss completing `"If you don't, you won't be able to <loss>."`.
    pub loss: &'static str,
}

/// Output capabilities controlling whether and how an elevation prompt is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PromptOptions {
    /// Whether the destination stream (stderr) is an interactive terminal.
    pub terminal: bool,
    /// Whether ANSI styling is allowed on that terminal.
    pub color: bool,
}

impl PromptOptions {
    /// Inspect stderr, `TERM`, `NO_COLOR`, and `json_output` to decide output options.
    ///
    /// - Non-TTY stderr suppresses the prompt (`terminal: false, color: false`).
    /// - `--json` on a TTY keeps the prompt as plain text (`terminal: true, color: false`).
    /// - `TERM=dumb` or a non-empty `NO_COLOR` keeps plain text on a TTY.
    #[must_use]
    pub fn detect(json_output: bool) -> Self {
        Self::from_env(
            io::stderr().is_terminal(),
            json_output,
            std::env::var_os("TERM").as_deref(),
            std::env::var_os("NO_COLOR").as_deref(),
        )
    }

    /// Pure constructor for [`PromptOptions::detect`], accepting explicit environment values
    /// so tests can exercise every combination without mutating process state.
    #[must_use]
    pub fn from_env(
        stderr_is_terminal: bool,
        json_output: bool,
        term: Option<&std::ffi::OsStr>,
        no_color: Option<&std::ffi::OsStr>,
    ) -> Self {
        if !stderr_is_terminal {
            return Self {
                terminal: false,
                color: false,
            };
        }
        let dumb_term = term.is_some_and(|value| value == "dumb");
        let no_color_set = no_color.is_some_and(|value| !value.is_empty());
        Self {
            terminal: true,
            color: !json_output && !dumb_term && !no_color_set,
        }
    }
}

impl ElevationPrompt {
    /// Return the plain-language actions, benefits, and concrete loss for this prompt.
    #[must_use]
    pub const fn copy(self) -> PromptCopy {
        match self {
            Self::MacosUserHelperInstall => PromptCopy {
                actions: &[
                    "Install the on-demand mesh helper for your account",
                    "Create the mesh network interface and routes",
                    "Add private DNS entries for your mesh",
                ],
                benefits: &[
                    "This Mac joins your mesh and stays connected across restarts",
                    "Other machines on your mesh can reach it by name",
                ],
                loss: "join this Mac to your mesh",
            },
            Self::MacosUserHelperRefresh => PromptCopy {
                actions: &[
                    "Update the on-demand mesh helper for your account",
                    "Reload the helper service so this build can use it",
                ],
                benefits: &[
                    "This Mac stays on your mesh with the new build",
                    "Your existing enrollment and mesh key stay unchanged",
                ],
                loss: "update the mesh helper for this build",
            },
            Self::LinuxSystemInstall {
                host_firewall: true,
            } => PromptCopy {
                actions: &[
                    "Install the infraternal binary and commands under /usr/local/bin",
                    "Save this machine's enrollment under /var/lib/infraternal",
                    "Install and start the infraternal-agent systemd service",
                    "Enable the infraternal-firewall boot service for mesh input",
                ],
                benefits: &[
                    "This machine joins your server and stays connected after reboot",
                    "Authorised people can open shells and reach it on your mesh",
                ],
                loss: "join this machine or install its service",
            },
            Self::LinuxSystemInstall {
                host_firewall: false,
            } => PromptCopy {
                actions: &[
                    "Install the infraternal binary and commands under /usr/local/bin",
                    "Save this machine's enrollment under /var/lib/infraternal",
                    "Install and start the infraternal-agent systemd service",
                ],
                benefits: &[
                    "This machine joins your server and stays connected after reboot",
                    "Authorised people can open shells on this machine",
                ],
                loss: "join this machine or install its service",
            },
            Self::MacosSystemInstall => PromptCopy {
                actions: &[
                    "Install the infraternal binary and commands under /usr/local/bin",
                    "Save this Mac's enrollment under /Library/Application Support",
                    "Install and start the machine-wide background service",
                ],
                benefits: &[
                    "This Mac stays connected even when no one is logged in",
                    "Authorised people can open shells and reach it after any reboot",
                ],
                loss: "install the system service on this Mac",
            },
            Self::MacosMeshServiceUp => PromptCopy {
                actions: &[
                    "Write the system mesh service configuration",
                    "Enable and start the machine-wide mesh service",
                ],
                benefits: &[
                    "This Mac connects to your mesh as a system service",
                    "The mesh stays active across restarts",
                ],
                loss: "start the system mesh service",
            },
            Self::MacosMeshServiceDown => PromptCopy {
                actions: &[
                    "Remove Infraternal's managed mesh DNS resolver files",
                    "Disable and stop the machine-wide mesh service",
                ],
                benefits: &["This Mac disconnects from your mesh and stops the system service"],
                loss: "stop the system mesh service",
            },
        }
    }

    /// Format this prompt as a newline-terminated string, with optional ANSI styling.
    ///
    /// Ends with a single newline (no trailing blank line) so `sudo`'s `Password:` line
    /// appears directly underneath.
    #[must_use]
    pub fn render(self, color: bool) -> String {
        let copy = self.copy();
        let mut out = String::new();
        if color {
            out.push_str(ANSI_BOLD);
            out.push_str(OPENING_HEADING);
            out.push_str(ANSI_RESET);
            out.push('\n');
            for action in copy.actions {
                out.push_str(ANSI_CYAN);
                out.push('→');
                out.push_str(ANSI_RESET);
                out.push(' ');
                out.push_str(action);
                out.push('\n');
            }
            out.push_str(ANSI_BOLD);
            out.push_str(BENEFIT_HEADING);
            out.push_str(ANSI_RESET);
            out.push('\n');
            for benefit in copy.benefits {
                out.push_str(ANSI_GREEN);
                out.push('→');
                out.push_str(ANSI_RESET);
                out.push(' ');
                out.push_str(benefit);
                out.push('\n');
            }
        } else {
            out.push_str(OPENING_HEADING);
            out.push('\n');
            for action in copy.actions {
                out.push_str("→ ");
                out.push_str(action);
                out.push('\n');
            }
            out.push_str(BENEFIT_HEADING);
            out.push('\n');
            for benefit in copy.benefits {
                out.push_str("→ ");
                out.push_str(benefit);
                out.push('\n');
            }
        }
        out.push_str("If you don't, you won't be able to ");
        out.push_str(copy.loss);
        out.push_str(".\n");
        out
    }

    /// Write this prompt to `writer` when `options.terminal` is true, and flush it.
    ///
    /// Returns `Ok(true)` when the prompt was written and `Ok(false)` when suppressed
    /// for a non-TTY stream.
    ///
    /// # Errors
    /// Returns any I/O error from writing or flushing `writer`.
    pub fn write_to<W: Write>(self, writer: &mut W, options: PromptOptions) -> io::Result<bool> {
        if !options.terminal {
            return Ok(false);
        }
        writer.write_all(self.render(options.color).as_bytes())?;
        writer.flush()?;
        Ok(true)
    }

    /// Print this prompt to stderr before invoking `sudo`, respecting TTY, `TERM`,
    /// `NO_COLOR`, and `--json`.
    ///
    /// Write errors are ignored because the elevation itself (`sudo`) is about to run and
    /// will report any terminal failure of its own.
    pub fn print_to_stderr(self, json_output: bool) {
        let options = PromptOptions::detect(json_output);
        let mut stderr = io::stderr().lock();
        let _ = self.write_to(&mut stderr, options);
    }
}

/// Unit tests pinning every elevation prompt's copy, width, styling, and non-TTY silence.
#[cfg(test)]
mod tests {
    use super::{ElevationPrompt, PromptOptions};
    use std::ffi::OsStr;

    /// Every shipping [`ElevationPrompt`] variant, used for cross-cutting layout and TTY checks.
    const ALL_PROMPTS: [ElevationPrompt; 7] = [
        ElevationPrompt::MacosUserHelperInstall,
        ElevationPrompt::MacosUserHelperRefresh,
        ElevationPrompt::LinuxSystemInstall {
            host_firewall: true,
        },
        ElevationPrompt::LinuxSystemInstall {
            host_firewall: false,
        },
        ElevationPrompt::MacosSystemInstall,
        ElevationPrompt::MacosMeshServiceUp,
        ElevationPrompt::MacosMeshServiceDown,
    ];

    /// Pin the plain-text wording of the fresh macOS user-mode helper install prompt.
    #[test]
    fn macos_user_helper_install_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::MacosUserHelperInstall.render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Install the on-demand mesh helper for your account\n",
                "→ Create the mesh network interface and routes\n",
                "→ Add private DNS entries for your mesh\n",
                "If you grant it, you get:\n",
                "→ This Mac joins your mesh and stays connected across restarts\n",
                "→ Other machines on your mesh can reach it by name\n",
                "If you don't, you won't be able to join this Mac to your mesh.\n",
            )
        );
    }

    /// Pin the plain-text wording of the macOS user-mode helper refresh/update prompt.
    #[test]
    fn macos_user_helper_refresh_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::MacosUserHelperRefresh.render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Update the on-demand mesh helper for your account\n",
                "→ Reload the helper service so this build can use it\n",
                "If you grant it, you get:\n",
                "→ This Mac stays on your mesh with the new build\n",
                "→ Your existing enrollment and mesh key stay unchanged\n",
                "If you don't, you won't be able to update the mesh helper for this build.\n",
            )
        );
    }

    /// Pin the plain-text wording of the Linux `up` prompt when the host firewall is enabled.
    #[test]
    fn linux_system_install_with_firewall_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::LinuxSystemInstall {
                host_firewall: true
            }
            .render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Install the infraternal binary and commands under /usr/local/bin\n",
                "→ Save this machine's enrollment under /var/lib/infraternal\n",
                "→ Install and start the infraternal-agent systemd service\n",
                "→ Enable the infraternal-firewall boot service for mesh input\n",
                "If you grant it, you get:\n",
                "→ This machine joins your server and stays connected after reboot\n",
                "→ Authorised people can open shells and reach it on your mesh\n",
                "If you don't, you won't be able to join this machine or install its service.\n",
            )
        );
    }

    /// Pin the plain-text wording of the Linux `up` prompt when built without the host firewall.
    #[test]
    fn linux_system_install_without_firewall_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::LinuxSystemInstall {
                host_firewall: false
            }
            .render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Install the infraternal binary and commands under /usr/local/bin\n",
                "→ Save this machine's enrollment under /var/lib/infraternal\n",
                "→ Install and start the infraternal-agent systemd service\n",
                "If you grant it, you get:\n",
                "→ This machine joins your server and stays connected after reboot\n",
                "→ Authorised people can open shells on this machine\n",
                "If you don't, you won't be able to join this machine or install its service.\n",
            )
        );
    }

    /// Pin the plain-text wording of the macOS `up --system` machine-wide install prompt.
    #[test]
    fn macos_system_install_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::MacosSystemInstall.render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Install the infraternal binary and commands under /usr/local/bin\n",
                "→ Save this Mac's enrollment under /Library/Application Support\n",
                "→ Install and start the machine-wide background service\n",
                "If you grant it, you get:\n",
                "→ This Mac stays connected even when no one is logged in\n",
                "→ Authorised people can open shells and reach it after any reboot\n",
                "If you don't, you won't be able to install the system service on this Mac.\n",
            )
        );
    }

    /// Pin the plain-text wording of the macOS `mesh up` elevation prompt.
    #[test]
    fn macos_mesh_service_up_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::MacosMeshServiceUp.render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Write the system mesh service configuration\n",
                "→ Enable and start the machine-wide mesh service\n",
                "If you grant it, you get:\n",
                "→ This Mac connects to your mesh as a system service\n",
                "→ The mesh stays active across restarts\n",
                "If you don't, you won't be able to start the system mesh service.\n",
            )
        );
    }

    /// Pin the plain-text wording of the macOS `mesh down` elevation prompt.
    #[test]
    fn macos_mesh_service_down_text_is_pinned() {
        assert_eq!(
            ElevationPrompt::MacosMeshServiceDown.render(false),
            concat!(
                "Infraternal needs administrator privileges just once for the following:\n",
                "→ Remove Infraternal's managed mesh DNS resolver files\n",
                "→ Disable and stop the machine-wide mesh service\n",
                "If you grant it, you get:\n",
                "→ This Mac disconnects from your mesh and stops the system service\n",
                "If you don't, you won't be able to stop the system mesh service.\n",
            )
        );
    }

    /// Verify every prompt stays within 80 columns, emits no ANSI in plain mode, and ends cleanly.
    #[test]
    fn every_prompt_fits_an_80_column_terminal_and_has_no_ansi_in_plain_mode() {
        for prompt in ALL_PROMPTS {
            let plain = prompt.render(false);
            assert!(
                !plain.contains('\u{1b}'),
                "plain prompt must not contain ANSI escapes: {prompt:?}"
            );
            assert!(
                plain.ends_with('\n') && !plain.ends_with("\n\n"),
                "prompt must end with exactly one newline so Password: sits beneath it: {prompt:?}"
            );
            for line in plain.lines() {
                assert!(
                    line.chars().count() <= 80,
                    "prompt line exceeds 80 columns ({} chars): {line}",
                    line.chars().count()
                );
            }
        }
    }

    /// Verify colour mode applies ANSI bold/arrow styling while keeping the loss line readable.
    #[test]
    fn color_mode_adds_ansi_only_when_enabled_and_preserves_words() {
        let styled = ElevationPrompt::MacosUserHelperInstall.render(true);
        assert!(styled.contains("\u{1b}[1mInfraternal needs administrator privileges"));
        assert!(styled.contains("\u{1b}[36m→\u{1b}[0m Install the on-demand mesh helper"));
        assert!(styled.contains("\u{1b}[32m→\u{1b}[0m This Mac joins your mesh"));
        assert!(
            styled.ends_with("If you don't, you won't be able to join this Mac to your mesh.\n")
        );
    }

    /// Verify non-TTY runs suppress the interactive prompt completely.
    #[test]
    fn non_tty_runs_do_not_print_any_prompt() {
        let options =
            PromptOptions::from_env(false, false, Some(OsStr::new("xterm-256color")), None);
        assert_eq!(
            options,
            PromptOptions {
                terminal: false,
                color: false
            }
        );
        for prompt in ALL_PROMPTS {
            let mut buffer = Vec::new();
            let wrote = prompt.write_to(&mut buffer, options).unwrap();
            assert!(!wrote);
            assert!(buffer.is_empty());
        }
    }

    /// Verify `--json`, `TERM=dumb`, and non-empty `NO_COLOR` emit plain text on a TTY.
    #[test]
    fn json_dumb_term_and_no_color_keep_plain_text_on_tty() {
        let json_tty =
            PromptOptions::from_env(true, true, Some(OsStr::new("xterm-256color")), None);
        assert_eq!(
            json_tty,
            PromptOptions {
                terminal: true,
                color: false
            }
        );

        let dumb_tty = PromptOptions::from_env(true, false, Some(OsStr::new("dumb")), None);
        assert_eq!(
            dumb_tty,
            PromptOptions {
                terminal: true,
                color: false
            }
        );

        let no_color_tty = PromptOptions::from_env(
            true,
            false,
            Some(OsStr::new("xterm-256color")),
            Some(OsStr::new("1")),
        );
        assert_eq!(
            no_color_tty,
            PromptOptions {
                terminal: true,
                color: false
            }
        );

        let empty_no_color_tty = PromptOptions::from_env(
            true,
            false,
            Some(OsStr::new("xterm-256color")),
            Some(OsStr::new("")),
        );
        assert_eq!(
            empty_no_color_tty,
            PromptOptions {
                terminal: true,
                color: true
            }
        );

        let mut buffer = Vec::new();
        let wrote = ElevationPrompt::MacosSystemInstall
            .write_to(&mut buffer, json_tty)
            .unwrap();
        assert!(wrote);
        let text = String::from_utf8(buffer).unwrap();
        assert!(!text.contains('\u{1b}'));
        assert_eq!(text, ElevationPrompt::MacosSystemInstall.render(false));
    }
}
