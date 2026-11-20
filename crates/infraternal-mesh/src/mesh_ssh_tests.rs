//! Tests the fixed mesh SSH listener registry used by the packet filter.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A published private port is visible only for its exact mesh address.
#[test]
fn listener_ports_are_address_scoped_and_clear_only_the_owner_value() {
    let address4 = IpAddr::V4(Ipv4Addr::new(10, 254, 1, 1));
    let address6 = IpAddr::V6(Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, 1));
    super::clear_listener(address4, 1001);
    super::clear_listener(address6, 1002);

    assert!(super::publish_listener(address4, 1001).is_ok());
    assert!(super::publish_listener(address6, 1002).is_ok());
    assert_eq!(super::listener_port(address4), Some(1001));
    assert_eq!(super::listener_port(address6), Some(1002));

    super::clear_listener(address4, 1002);
    assert_eq!(super::listener_port(address4), Some(1001));
    super::clear_listener(address4, 1001);
    super::clear_listener(address6, 1002);
    assert_eq!(super::listener_port(address4), None);
    assert_eq!(super::listener_port(address6), None);
}

/// Replacing a live address with a different private port is refused until its owner clears it.
#[test]
fn listener_registry_refuses_a_changed_port_for_an_owned_address() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 254, 1, 2));
    super::clear_listener(address, 1003);
    assert!(super::publish_listener(address, 1003).is_ok());
    assert!(matches!(
        super::publish_listener(address, 1004),
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse
    ));
    super::clear_listener(address, 1003);
}
