//! Checks the generated client files, and that stock `ssh -G` applies them only to mesh hosts.
use super::*;
use std::path::PathBuf;

/// The key socket path written into the block.
const SOCKET: &str = "/run/infraternal/mesh-ssh-agent.sock";
/// A known-hosts path written into the block.
const KNOWN: &str = "/var/lib/infraternal/mesh-ssh/known_hosts";

/// The file for one mesh peer, `db-01` at 10.254.0.9.
fn config() -> String {
    client_config_with_hosts(
        "internal",
        Ipv4Addr::new(10, 254, 0, 0),
        16,
        Path::new(SOCKET),
        Path::new(KNOWN),
        &[MeshHost {
            name: "db-01".into(),
            address: Ipv4Addr::new(10, 254, 0, 9),
        }],
    )
    .unwrap()
}

/// Block is scoped to mesh names and addresses.
#[test]
fn block_is_scoped_to_mesh_names_and_addresses() {
    let file = config();
    assert!(file.contains("Match originalhost \"db-01.internal,10.254.*\"\n"));
    assert!(file.contains(&format!("    IdentityAgent \"{SOCKET}\"\n")));
    assert!(file.contains("    StrictHostKeyChecking yes\n"));
    assert!(!file.contains("ForwardAgent yes"));
}

/// Ranges off octet boundaries match names only; with no names there is
/// nothing to scope the block to, so it is refused.
#[test]
fn ranges_off_octet_boundaries_match_names_only() {
    let net = Ipv4Addr::new(100, 64, 0, 0);
    let hosts = [MeshHost {
        name: "db-01".into(),
        address: Ipv4Addr::new(100, 64, 0, 9),
    }];
    let file = client_config_with_hosts(
        "internal",
        net,
        10,
        Path::new(SOCKET),
        Path::new(KNOWN),
        &hosts,
    )
    .unwrap();
    assert!(file.contains("Match originalhost \"db-01.internal\"\n"));
    assert!(client_config("internal", net, 10, Path::new(SOCKET), Path::new(KNOWN)).is_none());
}

/// Values that could escape are refused.
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

/// Known hosts trusts only the ca for mesh patterns.
#[test]
fn known_hosts_trusts_only_the_ca_for_mesh_patterns() {
    let hosts = [MeshHost {
        name: "db-01".into(),
        address: Ipv4Addr::new(10, 254, 0, 9),
    }];
    let line = known_hosts(
        "internal",
        Ipv4Addr::new(10, 254, 0, 0),
        16,
        [7; 32],
        &hosts,
    )
    .unwrap();
    assert!(line.starts_with("@cert-authority db-01.internal,10.254.* ssh-ed25519 "));
    assert_eq!(line.lines().count(), 1);
}

/// Stock ssh applies the block only to mesh hosts.
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
    for other in [
        "github.com",
        "10.69.69.89",
        "internal.example.com",
        "web.internal",
    ] {
        assert!(
            !resolved(other).contains(SOCKET),
            "{other} must keep the person's own agent"
        );
    }
    std::fs::remove_dir_all(&directory).unwrap();
}

/// Mesh names resolve through the file itself, with no DNS: plain
/// `ssh <name>.<suffix>` reaches the peer's mesh address and checks its host
/// certificate under that name, and unsafe names are refused.
#[test]
fn mesh_names_map_to_mesh_addresses_without_dns() {
    let hosts = [MeshHost {
        name: "db-01".into(),
        address: Ipv4Addr::new(10, 254, 0, 9),
    }];
    let file = client_config_with_hosts(
        "internal",
        Ipv4Addr::new(10, 254, 0, 0),
        16,
        Path::new(SOCKET),
        Path::new(KNOWN),
        &hosts,
    )
    .unwrap();
    assert!(file.contains(
        "Host db-01.internal\n    HostName 10.254.0.9\n    HostKeyAlias db-01.internal\n"
    ));
    for bad in ["", "DB", "a b", "x\"y", "*", "-x", "a.b"] {
        let hosts = [MeshHost {
            name: bad.into(),
            address: Ipv4Addr::new(10, 254, 0, 9),
        }];
        assert!(
            client_config_with_hosts(
                "internal",
                Ipv4Addr::new(10, 254, 0, 0),
                16,
                Path::new(SOCKET),
                Path::new(KNOWN),
                &hosts
            )
            .is_none(),
            "{bad:?}"
        );
    }
    if std::process::Command::new("ssh")
        .arg("-V")
        .output()
        .is_err()
    {
        return;
    }
    let directory = std::env::temp_dir().join(format!("j175-names-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("config");
    std::fs::write(&path, &file).unwrap();
    let output = std::process::Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&path)
        .arg("db-01.internal")
        .output()
        .unwrap();
    let settings = String::from_utf8(output.stdout).unwrap();
    assert!(settings.contains("hostname 10.254.0.9"), "{settings}");
    assert!(
        settings.contains("hostkeyalias db-01.internal"),
        "{settings}"
    );
    assert!(
        settings.contains(&format!("identityagent {SOCKET}")),
        "{settings}"
    );
    std::fs::remove_dir_all(&directory).unwrap();
}

/// J236 P3-1 (#221): the suffix comes from the server's public origin, so it
/// can be a whole real domain. The CA trust line and the ssh overrides name
/// exact mesh hosts (and the mesh address range), never `*.<suffix>`, so
/// `ssh www.example.com` keeps the person's own agent and known hosts, and
/// the mesh CA is never trusted for a real host.
#[test]
fn trust_and_overrides_name_exact_mesh_hosts_never_the_whole_domain() {
    let hosts = [MeshHost {
        name: "db-01".into(),
        address: Ipv4Addr::new(10, 254, 0, 9),
    }];
    let net = Ipv4Addr::new(10, 254, 0, 0);
    let file = client_config_with_hosts(
        "example.com",
        net,
        16,
        Path::new(SOCKET),
        Path::new(KNOWN),
        &hosts,
    )
    .unwrap();
    assert!(
        file.contains("Match originalhost \"db-01.example.com,10.254.*\"\n"),
        "{file}"
    );
    assert!(!file.contains("*.example.com"), "{file}");
    let known = known_hosts("example.com", net, 16, [7; 32], &hosts).unwrap();
    assert!(known.starts_with("@cert-authority db-01.example.com,10.254.* ssh-ed25519 "));
    assert!(!known.contains("*.example.com"));
}
