//! Parses only a tiny, bounded read-only system sniff; facts are gathered after installation [156].
//!
//! Before installing on a host, a fixed shell script is run there that prints
//! one versioned record: operating system, CPU architecture, init system, user
//! id and a few yes/no capabilities. [`Check::parse`] accepts exactly that
//! shape (at most 256 bytes) and rejects anything else, such as a login banner or
//! extra output, instead of guessing. [`Check::authorize_mode`] then decides
//! whether the requested install mode fits those facts.

use crate::model::{Failure, InstallMode};

/// Shell script that prints the check record. Read-only; it changes nothing on the host.
///
/// No shell expansion of client input occurs in this fixed script.
pub const CHECK_SCRIPT: &str = r#"set -eu
os=$(uname -s)
arch=$(uname -m)
uid=$(id -u)
init=other
[ ! -d /run/systemd/system ] || init=systemd
sudo=no
if [ "$uid" = 0 ] || (command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1); then sudo=yes; fi
user_systemd=no
if command -v systemctl >/dev/null 2>&1 && systemctl --user show --property=Version --value >/dev/null 2>&1; then user_systemd=yes; fi
linger=no
if command -v loginctl >/dev/null 2>&1 && [ "$(loginctl show-user "$uid" -p Linger --value 2>/dev/null || :)" = yes ]; then linger=yes; fi
existing=no
if command -v infraternal >/dev/null 2>&1 || [ -e "$HOME/.local/share/infraternal/bin/current" ]; then existing=yes; fi
printf 'INFRATERNAL_CHECK_V1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$os" "$arch" "$init" "$uid" "$sudo" "$user_systemd" "$linger" "$existing"
"#;

/// The only static binary platforms selected by this bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    /// 64-bit x86 (`uname -m` prints `x86_64`).
    X86_64,
    /// 64-bit Arm (`uname -m` prints `aarch64`).
    Aarch64,
}

/// Parsed check data cannot contain commands, diagnostics or unchecked paths.
#[derive(Clone, Debug, PartialEq, Eq)]
// These are independent observed capabilities, not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct Check {
    /// CPU architecture of the host.
    pub architecture: Architecture,
    /// Numeric id of the SSH user (0 is root).
    pub uid: u32,
    /// The user is root or has passwordless `sudo`. This is only a fact; it is never consent to use it.
    pub sudo: bool,
    /// The user's own systemd manager answers.
    pub user_systemd: bool,
    /// Lingering is on for the user, so user services outlive logins.
    pub linger: bool,
    /// An infraternal install already seems present.
    pub existing: bool,
}

impl Check {
    /// Parse one exact versioned record, rejecting banners/suffixes instead of guessing.
    ///
    /// Only Linux on x86_64 or aarch64 with systemd is supported. A non-systemd
    /// host gets a specific "unsupported" message; every other deviation gets the
    /// generic invalid-check message. The user id must be written canonically
    /// (no leading zeros or plus sign).
    /// # Errors
    /// Refuses invalid UTF-8, oversized/noncanonical output, unsupported OS/arch/init.
    pub fn parse(bytes: &[u8]) -> Result<Self, Failure> {
        if bytes.len() > 256 {
            return Err(invalid());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
        let lines: Vec<_> = text.split('\n').collect();
        let [
            "INFRATERNAL_CHECK_V1",
            "Linux",
            arch,
            init,
            uid,
            sudo,
            user_systemd,
            linger,
            existing,
            "",
        ] = lines.as_slice()
        else {
            return Err(invalid());
        };
        let architecture = match *arch {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            _ => return Err(invalid()),
        };
        let parsed_uid = uid.parse::<u32>().map_err(|_| invalid())?;
        if parsed_uid.to_string() != *uid {
            return Err(invalid());
        }
        let check = Self {
            architecture,
            uid: parsed_uid,
            sudo: flag(sudo)?,
            user_systemd: flag(user_systemd)?,
            linger: flag(linger)?,
            existing: flag(existing)?,
        };
        match *init {
            "systemd" => Ok(check),
            "other" => Err(Failure::unsupported(
                "Host provisioning requires systemd on this target. Use a supported systemd host or add this host for SSH access without installation.",
            )),
            _ => Err(invalid()),
        }
    }

    /// Enforce execution identity after the sniff; sudo availability never grants consent.
    /// # Errors
    /// Refuses rootless as root, absent user systemd, or unavailable consented root access.
    pub fn authorize_mode(&self, mode: InstallMode) -> Result<(), Failure> {
        match mode {
            InstallMode::Rootless if self.uid == 0 => Err(Failure::unsupported(
                "Choose a non-root SSH user for rootless installation.",
            )),
            InstallMode::Rootless if !self.user_systemd => Err(Failure::unsupported(
                "The user systemd manager is unavailable.",
            )),
            InstallMode::Root if self.uid != 0 && !self.sudo => Err(Failure::unsupported(
                "Passwordless sudo is unavailable for this root installation.",
            )),
            _ => Ok(()),
        }
    }
}
/// Read an exact `yes` or `no`; anything else is an invalid record.
fn flag(value: &str) -> Result<bool, Failure> {
    match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(invalid()),
    }
}
/// The user-facing error for any unparsable check; also hints at noisy shell startup files.
fn invalid() -> Failure {
    Failure::unsupported(
        "This host did not return a supported Linux system check. Check the SSH shell startup and run startup programs only in interactive shells, then try again.",
    )
}
