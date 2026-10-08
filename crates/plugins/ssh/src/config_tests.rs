//! Checks public-policy preservation, bounded parsing and lost-quoting refusal without reading credential files.

use super::*;

#[test]
fn configured_private_sources_are_excluded_and_public_trust_is_retained() {
    let original = Destination::parse("user@alias").unwrap();
    let parsed = PublicSshConfiguration::parse(&original, b"hostname actual.example\nport 2222\nproxyjump none\nproxycommand none\nidentityfile /nonexistent/private-source\ncertificatefile /nonexistent/certificate-source\nidentityagent /nonexistent/agent-source\npkcs11provider /nonexistent/provider-source\nuserknownhostsfile /nonexistent/public-trust-%n\nglobalknownhostsfile /dev/null\nrevokedhostkeys /nonexistent/public-revocation\nhostkeyalias retained-alias\n").unwrap();
    assert_eq!(parsed.destination.host(), "actual.example");
    assert_eq!(parsed.destination.port(), Some(2222));
    assert_eq!(parsed.options.len(), 4);
    assert!(
        parsed
            .options
            .iter()
            .any(|(name, value)| name == "userknownhostsfile"
                && value == "\"/nonexistent/public-trust-alias\"")
    );
    assert!(
        parsed
            .options
            .iter()
            .all(|(name, _)| !name.contains("identity")
                && !name.contains("certificate")
                && !name.contains("provider"))
    );
    assert_eq!(
        original_host_token("%%n-%n-%%h-%h", "original"),
        "%%n-original-%%h-%h"
    );
}

#[test]
fn malformed_public_policy_is_refused_before_it_can_change_command_arguments() {
    let destination = Destination::parse("user@host").unwrap();
    let prefix = b"hostname host\nport 22\n";
    for tail in [
        b"userknownhostsfile /nonexistent/a\nuserknownhostsfile /nonexistent/b\n".as_slice(),
        b"ciphers invalid\x00value\n",
        b"proxycommand inherited-proxy\n",
        b"userknownhostsfile %h/a %h/b\n",
    ] {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(tail);
        assert!(PublicSshConfiguration::parse(&destination, &bytes).is_none());
    }
    let mut oversized = prefix.to_vec();
    oversized.resize(65537, b'a');
    assert!(PublicSshConfiguration::parse(&destination, &oversized).is_none());
}

#[test]
fn flattened_quoted_public_filenames_are_refused_when_existing_trust_would_be_lost() {
    // Only a public placeholder is written; no key/credential material is inspected.
    let root = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap()
        .join(".cache/codex-scratch/ssh-bootstrap");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join(format!("public trust-{}", uuid::Uuid::new_v4().simple()));
    std::fs::write(&path, b"# Public-only ambiguous path fixture\n").unwrap();
    let destination = Destination::parse("user@host").unwrap();
    let configuration = format!(
        "hostname host\nport 22\nuserknownhostsfile {}\n",
        path.display()
    );
    let parsed = PublicSshConfiguration::parse(&destination, configuration.as_bytes()).unwrap();
    assert!(!parsed.validate_trust_paths());
    std::fs::remove_file(path).unwrap();
}
