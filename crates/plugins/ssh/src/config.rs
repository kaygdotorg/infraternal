//! Retains bounded public OpenSSH policy while excluding ambient identity paths from D183 authentication.
//!
//! The server user's own SSH configuration may name identity files, certificates
//! or hardware providers. Those must never leak into an authentication attempt,
//! because the attempt is supposed to use only the credentials we hand over.
//! This module reads the effective configuration (the output of `ssh -G`) and
//! keeps a small allow-list of public policy: host-key trust files, key
//! algorithms, ciphers, address binding and similar. Every other option is
//! dropped and the final SSH child runs with `-F /dev/null` plus only the kept
//! options. A policy that cannot be reconstructed unambiguously is refused
//! (fails closed) rather than guessed, because a wrong guess could ignore an
//! existing trusted host key and so allow first-contact admission.
//!
//! [`TrustPolicy`] is the part that survives first-contact confirmation.

use crate::{model::Destination, openssh::scan_destination};
use std::collections::HashSet;
use tokio::process::Command;

/// Effective addressing and public trust/transport policy, never key or credential paths.
pub struct PublicSshConfiguration {
    /// Where to connect after OpenSSH applied host aliases and proxy rules.
    pub destination: Destination,
    /// Kept options as lower-case `(name, value)` pairs, already quoted for `-o name=value`.
    options: Vec<(String, String)>,
    /// One list per `UserKnownHostsFile` / `GlobalKnownHostsFile` line, unquoted, for existence checks.
    trust_paths: Vec<Vec<String>>,
    /// The `HostKeyAlias`, if configured; it replaces the host name in trust lookups.
    alias: Option<String>,
}
impl PublicSshConfiguration {
    /// True when the configuration asks for nothing beyond default routing.
    ///
    /// The descriptor helper implements default routing only. Let native SSH
    /// apply source/interface and family restrictions before contacting a host.
    /// So a bind address, bind interface or restricted address family makes this false.
    #[must_use]
    pub(crate) fn permits_connector(&self) -> bool {
        self.options
            .iter()
            .all(|(name, value)| match name.as_str() {
                "bindaddress" | "bindinterface" => value == "none",
                "addressfamily" => value == "any",
                _ => true,
            })
    }

    /// Parse only the bounded output of trusted system OpenSSH's configuration query.
    ///
    /// `original` is the destination the user asked for; `bytes` is the `ssh -G` output.
    /// Returns `None` (nothing is kept) on invalid endpoints, proxy hops,
    /// duplicated policy lines, over-long values (above 4096 bytes), control bytes,
    /// more than 16 trust files, or a multi-file trust list containing `%` or `~`
    /// tokens. `%n` in kept values is replaced with the original host name.
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

    /// Builds the [`TrustPolicy`] used for first-contact confirmation.
    ///
    /// Returns `None` when the paths are ambiguous (see
    /// [`Self::validate_trust_paths`]), the lookup host name is empty, longer than
    /// 253 bytes, starts with `-` or has unexpected characters, or a trust file is
    /// relative or contains `%`. The lookup name is the `HostKeyAlias` if set,
    /// otherwise the host (written `[host]:port` for non-default ports). The
    /// policy also carries a SHA-256 digest of all kept options so a later change
    /// of policy can be noticed.
    ///
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
            algorithms: self
                .options
                .iter()
                .find(|(name, _)| name == "hostkeyalgorithms")
                .map(|(_, value)| value.split(',').map(str::to_owned).collect()),
            digest: digest.finalize().into(),
        })
    }

    /// Returns false if any trust file name could be hidden by `-G`'s lost whitespace quoting.
    ///
    /// `-G` prints a quoted list such as `"a b"` as two words. For every run of two or more
    /// consecutive words this joins them with spaces and checks whether such a file
    /// exists; if it does, or if its metadata cannot be read, the answer is false
    /// (fail closed). This checks only configured public-path metadata, never contents.
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

    /// Switches the options to trust exactly one confirmed key file.
    ///
    /// Replaces the known-hosts files with `path` (user file) and `/dev/null`
    /// (global file) and limits host-key algorithms to `algorithms`. Other
    /// policy, such as revoked keys and cipher choices, is kept.
    pub(crate) fn configure_pin(&mut self, path: &std::path::Path, algorithms: &str) {
        // Admission already checked this exact lookup and configured trust.
        // Retain KRL and crypto policy while selecting the confirmed key family.
        self.options.retain(|(name, _)| {
            !matches!(
                name.as_str(),
                "userknownhostsfile" | "globalknownhostsfile" | "hostkeyalgorithms"
            )
        });
        self.options
            .push(("hostkeyalgorithms".into(), algorithms.into()));
        self.options
            .push(("userknownhostsfile".into(), quoted(&path.to_string_lossy())));
        self.options
            .push(("globalknownhostsfile".into(), "/dev/null".into()));
    }

    /// Adds `-F /dev/null` and the kept public options to an OpenSSH command line.
    ///
    /// Empty config prevents configured keys/certificates from being appended.
    /// Only public policy is re-applied; credential policy follows separately.
    /// Nothing secret is placed in argv here.
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
    /// The endpoint the policy applies to.
    pub destination: Destination,
    /// Name under which the host key is looked up: the host, `[host]:port`, or the `HostKeyAlias`.
    pub lookup: String,
    /// Absolute known-hosts files to consult (`none` and `/dev/null` removed).
    pub paths: Vec<std::path::PathBuf>,
    /// Dynamic trust cannot be proven absent by querying static public files.
    pub dynamic_trust: bool,
    /// Allowed host-key algorithms if the configuration restricts them; `None` means unrestricted.
    algorithms: Option<Vec<String>>,
    /// SHA-256 over all kept option names and values; makes equal policies comparable.
    digest: [u8; 32],
}

impl TrustPolicy {
    /// Constrain negotiation to the confirmed key without weakening configured crypto policy.
    ///
    /// Returns the comma-separated algorithm names to offer for `key_type`
    /// (RSA keys map to the SHA-2 signature names), intersected with any configured
    /// restriction. `None` if the key type is unknown or nothing is allowed.
    pub(crate) fn key_algorithms(&self, key_type: &str) -> Option<String> {
        let candidates: &[&str] = match key_type {
            "ssh-ed25519" => &["ssh-ed25519"],
            "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256"],
            "ecdsa-sha2-nistp256" => &["ecdsa-sha2-nistp256"],
            "ecdsa-sha2-nistp384" => &["ecdsa-sha2-nistp384"],
            "ecdsa-sha2-nistp521" => &["ecdsa-sha2-nistp521"],
            _ => return None,
        };
        let allowed = candidates
            .iter()
            .filter(|candidate| {
                self.algorithms
                    .as_ref()
                    .is_none_or(|values| values.iter().any(|value| value == **candidate))
            })
            .copied()
            .collect::<Vec<_>>()
            .join(",");
        (!allowed.is_empty()).then_some(allowed)
    }
}
