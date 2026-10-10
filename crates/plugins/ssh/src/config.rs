//! Retains bounded public OpenSSH policy while excluding ambient identity paths from D183 authentication.

use crate::{model::Destination, openssh::scan_destination};
use std::collections::HashSet;
use tokio::process::Command;

/// Effective addressing and public trust/transport policy, never key or credential paths.
pub struct PublicSshConfiguration {
    pub destination: Destination,
    options: Vec<(String, String)>,
    trust_paths: Vec<Vec<String>>,
    alias: Option<String>,
}
impl PublicSshConfiguration {
    /// Parse only the bounded output of trusted system OpenSSH's configuration query.
    /// # Errors
    /// Invalid endpoints, proxy hops, duplicated policy and control bytes refuse parsing.
    #[must_use]
    pub fn parse(original: &Destination, bytes: &[u8]) -> Option<Self> {
        let destination = scan_destination(original, bytes)?;
        let text = std::str::from_utf8(bytes).ok()?;
        let mut options = Vec::new();
        let mut trust_paths = Vec::new();
        let mut seen = HashSet::new();
        let mut alias = None;
        for line in text.lines() {
            let Some((name, value)) = line.split_once(' ') else {
                continue;
            };
            // Everything not explicitly retained uses the engine's safe defaults.
            // In particular IdentityFile/CertificateFile are additive in OpenSSH:
            // passing `none` alongside a normal config does not remove its paths.
            if !matches!(
                name,
                "userknownhostsfile"
                    | "globalknownhostsfile"
                    | "hostkeyalias"
                    | "revokedhostkeys"
                    | "knownhostscommand"
                    | "checkhostip"
                    | "hostkeyalgorithms"
                    | "casignaturealgorithms"
                    | "requiredrsasize"
                    | "ciphers"
                    | "macs"
                    | "kexalgorithms"
                    | "pubkeyacceptedalgorithms"
                    | "bindaddress"
                    | "bindinterface"
                    | "addressfamily"
                    | "ipqos"
                    | "compression"
                    | "rekeylimit"
                    | "tcpkeepalive"
                    | "gssapiauthentication"
                    | "gssapitrustdns"
                    | "preferredauthentications"
            ) {
                continue;
            }
            let value = value.trim();
            if value.is_empty()
                || value.len() > 4096
                || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
                || !seen.insert(name)
            {
                return None;
            }
            let value = original_host_token(value, original.host());
            if name == "hostkeyalias" {
                alias = Some(value.clone());
            }
            let value = if matches!(name, "userknownhostsfile" | "globalknownhostsfile") {
                let paths: Vec<_> = value.split_whitespace().map(str::to_owned).collect();
                if paths.len() > 16 {
                    return None;
                }
                // -G flattens quoted file lists. A multi-path list with expansion
                // tokens cannot be reconstructed unambiguously; refuse it rather
                // than omit an existing trusted key and permit first-contact admission.
                if paths.len() > 1
                    && paths
                        .iter()
                        .any(|path| path.contains('%') || path.starts_with('~'))
                {
                    return None;
                }
                let encoded = paths
                    .iter()
                    .map(|path| quoted(path))
                    .collect::<Vec<_>>()
                    .join(" ");
                trust_paths.push(paths);
                encoded
            } else if name == "knownhostscommand" && value != "none" {
                // OpenSSH retains native token/argument expansion. Only the lookup
                // child loses login-helper access; authentication keeps its helpers.
                format!(
                    "/usr/bin/env -u SSH_AUTH_SOCK -u INFRATERNAL_SSH_ASKPASS_SOCKET -u SSH_ASKPASS -u SSH_ASKPASS_REQUIRE -- {value}"
                )
            } else if matches!(name, "revokedhostkeys" | "hostkeyalias") {
                quoted(&value)
            } else {
                value
            };
            options.push((name.to_owned(), value));
        }
        Some(Self {
            destination,
            options,
            trust_paths,
            alias,
        })
    }

    /// Confirmation requires exact reconstructable public paths and lookup identity.
    #[must_use]
    pub fn trust_policy(&self) -> Option<TrustPolicy> {
        use sha2::{Digest, Sha256};
        if !self.validate_trust_paths() {
            return None;
        }
        let host = self.alias.as_deref().unwrap_or(self.destination.host());
        if host.is_empty()
            || host.len() > 253
            || host.starts_with('-')
            || !host.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'-' | b'_' | b':' | b'[' | b']')
            })
        {
            return None;
        }
        // HostKeyAlias is the complete trust lookup, never bracketed with the port.
        let lookup = if self.alias.is_some() || self.destination.port().unwrap_or(22) == 22 {
            host.to_owned()
        } else {
            format!("[{host}]:{}", self.destination.port().unwrap_or(22))
        };
        let mut paths = Vec::new();
        for path in self.trust_paths.iter().flatten() {
            if matches!(path.as_str(), "none" | "/dev/null") {
                continue;
            }
            let path = std::path::PathBuf::from(path);
            if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&b'%') {
                return None;
            }
            paths.push(path);
        }
        let mut digest = Sha256::new();
        for (name, value) in &self.options {
            digest.update(name);
            digest.update([0]);
            digest.update(value);
            digest.update([0]);
        }
        Some(TrustPolicy {
            destination: self.destination.clone(),
            lookup,
            paths,
            dynamic_trust: self
                .options
                .iter()
                .any(|(name, value)| name == "knownhostscommand" && value != "none"),
            digest: digest.finalize().into(),
        })
    }

    /// Refuse existing public trust filenames hidden by -G's lost whitespace
    /// quoting. This checks only configured public-path metadata, never contents.
    /// # Errors
    /// Ambiguous existing paths or inaccessible metadata cannot preserve strict trust.
    #[must_use]
    pub fn validate_trust_paths(&self) -> bool {
        for paths in &self.trust_paths {
            for begin in 0..paths.len() {
                for end in begin + 2..=paths.len() {
                    match std::fs::metadata(paths[begin..end].join(" ")) {
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                            ) => {}
                        Ok(_) | Err(_) => return false,
                    }
                }
            }
        }
        true
    }

    pub(crate) fn configure_pin(&mut self, path: &std::path::Path) {
        // Admission already checked this exact lookup and configured trust.
        // Retain KRL and crypto policy while selecting only the immutable pin.
        self.options.retain(|(name, _)| {
            !matches!(name.as_str(), "userknownhostsfile" | "globalknownhostsfile")
        });
        self.options
            .push(("userknownhostsfile".into(), quoted(&path.to_string_lossy())));
        self.options
            .push(("globalknownhostsfile".into(), "/dev/null".into()));
    }

    /// Empty config prevents configured keys/certificates from being appended.
    /// Only public policy is re-applied; credential policy follows separately.
    pub fn configure(&self, command: &mut Command) {
        command.args(["-F", "/dev/null"]);
        for (name, value) in &self.options {
            command.arg("-o").arg(format!("{name}={value}"));
        }
    }
}

/// The final child uses the effective hostname, so preserve the original-host
/// expansion in public paths. Keep %% escaped for OpenSSH's own token parser.
fn original_host_token(value: &str, host: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        result.push(character);
        if character == '%' {
            match characters.next() {
                Some('n') => {
                    result.pop();
                    result.push_str(host);
                }
                Some(next) => result.push(next),
                None => {}
            }
        }
    }
    result
}

/// Re-quote public filenames after -G removes their original quoting. Never
/// interpret them as a shell command or append additional OpenSSH directives.
fn quoted(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;

/// Only public addressing/trust policy is retained across first-contact confirmation.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustPolicy {
    pub destination: Destination,
    pub lookup: String,
    pub paths: Vec<std::path::PathBuf>,
    /// Dynamic trust cannot be proven absent by querying static public files.
    pub dynamic_trust: bool,
    digest: [u8; 32],
}
