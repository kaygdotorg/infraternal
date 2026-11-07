//! Checks the property/value grammar used by the Linux split-DNS fallback (#266).
use super::*;
use std::process::Command;

/// Every nmcli property consumes one argument, including a list-valued search domain property.
#[test]
fn review_j354_nmcli_search_list_is_one_property_value() {
    let commands = networkmanager_route_commands(
        "infraternal0",
        Ipv4Addr::new(10, 254, 0, 2),
        &["internal".to_owned(), "mesh.j354.test".to_owned()],
    );
    for command in commands {
        assert_eq!(command[0..3], ["device", "modify", "infraternal0"]);
        let mut properties = command[3..].chunks_exact(2);
        for pair in properties.by_ref() {
            assert!(
                ["ipv4.dns", "ipv4.dns-search"].contains(&pair[0].as_str()),
                "nmcli treats this search-domain value as a property: {}",
                pair[0]
            );
        }
        assert!(
            properties.remainder().is_empty(),
            "nmcli requires property/value pairs"
        );
    }
}

/// Parses the generated DNS property values with nmcli without changing a host connection.
#[test]
fn review_j254_nmcli_offline_parser_accepts_generated_dns_properties() {
    let command = networkmanager_route_commands(
        "infraternal0",
        Ipv4Addr::new(10, 254, 0, 2),
        &["internal".to_owned(), "mesh.kayg.org".to_owned()],
    )
    .pop()
    .expect("one NetworkManager command");
    let mut arguments = vec![
        "--offline",
        "connection",
        "add",
        "type",
        "dummy",
        "con-name",
        "j254-mesh-dns-parser",
        "ifname",
        "j254dns",
    ];
    arguments.extend(command[3..].iter().map(String::as_str));
    let required_binary = std::env::var_os("NMCLI_TEST_BIN").is_some();
    let binary = std::env::var_os("NMCLI_TEST_BIN").unwrap_or_else(|| "nmcli".into());
    let output = match Command::new(binary).args(arguments).output() {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required_binary => {
            eprintln!("SKIP: nmcli is not installed; offline property parsing is unavailable");
            return;
        }
        Err(error) => panic!("launch nmcli offline parser: {error}"),
    };
    assert!(
        output.status.success(),
        "nmcli offline parser rejected generated DNS properties: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
