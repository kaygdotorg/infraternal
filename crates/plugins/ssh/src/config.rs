//! Retains bounded public OpenSSH policy while excluding ambient identity paths from D183 authentication.

use crate::{model::Destination, openssh::scan_destination};
use std::collections::HashSet;
use tokio::process::Command;

/// Effective addressing and public trust/transport policy, never key or credential paths.
pub struct PublicSshConfiguration {
    pub destination: Destination,
    options: Vec<(String, String)>,
    trust_paths: Vec<Vec<String>>,
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
