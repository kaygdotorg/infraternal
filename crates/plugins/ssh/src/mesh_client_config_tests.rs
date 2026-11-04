//! Checks the generated client files, and that stock `ssh -G` applies them only to mesh hosts.
use super::*;
use std::path::PathBuf;

const SOCKET: &str = "/run/infraternal/mesh-ssh-agent.sock";
const KNOWN: &str = "/var/lib/infraternal/mesh-ssh/known_hosts";

fn config() -> String {
    client_config(
        "internal",
        Ipv4Addr::new(10, 254, 0, 0),
        16,
        Path::new(SOCKET),
        Path::new(KNOWN),
    )
    .unwrap()
}

#[test]
fn block_is_scoped_to_mesh_names_and_addresses() {
    let file = config();
    assert!(file.contains("Match host \"*.internal,10.254.*\"\n"));
    assert!(file.contains(&format!("    IdentityAgent \"{SOCKET}\"\n")));
    assert!(file.contains("    StrictHostKeyChecking yes\n"));
    assert!(!file.contains("ForwardAgent yes"));
}

#[test]
fn ranges_off_octet_boundaries_match_names_only() {
    let file = client_config(
        "internal",
        Ipv4Addr::new(100, 64, 0, 0),
        10,
        Path::new(SOCKET),
        Path::new(KNOWN),
    )
    .unwrap();
    assert!(file.contains("Match host \"*.internal\"\n"));
}

#[test]
fn values_that_could_escape_are_refused() {
    let net = Ipv4Addr::new(10, 254, 0, 0);
    for suffix in ["", "Internal", "a b", "x\"", "x,y", "*", "x\n"] {
        assert!(
            client_config(suffix, net, 16, Path::new(SOCKET), Path::new(KNOWN)).is_none(),
            "{suffix:?}"
        );
    }
    for path in ["relative", "/a\"b", "/a\nb"] {
        assert!(client_config("internal", net, 16, Path::new(path), Path::new(KNOWN)).is_none());
    }
}

#[test]
fn known_hosts_trusts_only_the_ca_for_mesh_patterns() {
    let line = known_hosts("internal", Ipv4Addr::new(10, 254, 0, 0), 16, [7; 32]).unwrap();
    assert!(line.starts_with("@cert-authority *.internal,10.254.* ssh-ed25519 "));
    assert_eq!(line.lines().count(), 1);
}

#[test]
fn stock_ssh_applies_the_block_only_to_mesh_hosts() {
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        eprintln!("SKIP: ssh is not installed");
        return;
    }
    let directory: PathBuf =
        std::env::temp_dir().join(format!("j175-config-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let file = directory.join("config");
    std::fs::write(&file, config()).unwrap();
    let resolved = |host: &str| {
        let output = std::process::Command::new("ssh")
            .args(["-G", "-F"])
            .arg(&file)
            .arg(host)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    };
    for mesh in ["db-01.internal", "10.254.0.9"] {
        let settings = resolved(mesh);
        assert!(
            settings.contains(&format!("identityagent {SOCKET}")),
            "{mesh}: {settings}"
        );
        assert!(settings.contains("stricthostkeychecking true"), "{mesh}");
    }
    for other in ["github.com", "10.69.69.89", "internal.example.com"] {
        assert!(
            !resolved(other).contains(SOCKET),
            "{other} must keep the person's own agent"
        );
    }
    std::fs::remove_dir_all(&directory).unwrap();
}
