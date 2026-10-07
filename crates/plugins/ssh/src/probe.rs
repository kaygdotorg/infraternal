//! Parses only a tiny, bounded read-only system sniff; facts are gathered after installation [156].

use crate::model::{Failure, InstallMode};

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
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then user_systemd=yes; fi
linger=no
if command -v loginctl >/dev/null 2>&1 && [ "$(loginctl show-user "$uid" -p Linger --value 2>/dev/null || :)" = yes ]; then linger=yes; fi
existing=no
if command -v infraternal >/dev/null 2>&1 || [ -e "$HOME/.local/share/infraternal/bin/current" ]; then existing=yes; fi
printf 'INFRATERNAL_CHECK_V1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' "$os" "$arch" "$init" "$uid" "$sudo" "$user_systemd" "$linger" "$existing"
"#;

/// The only static binary platforms selected by this bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

/// Parsed check data cannot contain commands, diagnostics or unchecked paths.
#[derive(Clone, Debug, PartialEq, Eq)]
// These are independent observed capabilities, not mutually exclusive states.
#[allow(clippy::struct_excessive_bools)]
pub struct Check {
    pub architecture: Architecture,
    pub uid: u32,
    pub sudo: bool,
    pub user_systemd: bool,
    pub linger: bool,
    pub existing: bool,
}

impl Check {
    /// Parse one exact versioned record, rejecting banners/suffixes instead of guessing.
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
            "systemd",
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
        Ok(Self {
            architecture,
            uid: parsed_uid,
            sudo: flag(sudo)?,
            user_systemd: flag(user_systemd)?,
            linger: flag(linger)?,
            existing: flag(existing)?,
        })
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
fn flag(value: &str) -> Result<bool, Failure> {
    match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => Err(invalid()),
    }
}
fn invalid() -> Failure {
    Failure::unsupported("This host did not return a supported Linux system check.")
}
