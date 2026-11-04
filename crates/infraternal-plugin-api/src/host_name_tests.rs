//! Regressions for shared host-name extraction from destinations and reported hostnames.
use super::{fallback_machine_name, machine_name};

#[test]
fn addresses_and_hostnames_give_a_machine_name() {
    assert_eq!(machine_name("root@minipc01").as_deref(), Some("minipc01"));
    assert_eq!(
        machine_name("kayg@MiniPC01.lan").as_deref(),
        Some("minipc01")
    );
    assert_eq!(machine_name("minipc01:2222").as_deref(), Some("minipc01"));
    assert_eq!(machine_name("monitor01").as_deref(), Some("monitor01"));
    assert_eq!(machine_name("root@0xygen.lan").as_deref(), Some("0xygen"));
}

#[test]
fn numeric_invalid_and_localhost_inputs_give_no_name() {
    for source in [
        "root@10.69.69.217",
        "10.69.69.217:22",
        "root@[fd00::1]:22",
        "fd00::1",
        "",
        "root@",
        "a_b",
        "-x",
        "root@0x0a.0x45.0x45.0x05",
        "0X0A454505",
        "root@010.1",
        "10.69.69.5.",
        "localhost",
        "root@LocalHost.localdomain",
    ] {
        assert_eq!(machine_name(source), None, "{source}");
    }
}

/// D339: the reported hostname is the name, whatever it is; `unnamed` is no longer a reserved word.
#[test]
fn a_hostname_that_looks_like_the_old_placeholder_is_a_real_name() {
    assert_eq!(machine_name("unnamed").as_deref(), Some("unnamed"));
    assert_eq!(machine_name("root@unnamed-3").as_deref(), Some("unnamed-3"));
    assert_eq!(
        machine_name("localhost-nas").as_deref(),
        Some("localhost-nas")
    );
}

/// The fallback is the OS word, a dash and the first six id characters, whatever spelling the id has.
#[test]
fn fallback_is_os_and_first_six_id_characters() {
    let id = "0A1B2C3D-4e5f-6789-abcd-ef0123456789";
    assert_eq!(
        fallback_machine_name(Some("Debian GNU/Linux"), id),
        "linux-0a1b2c"
    );
    assert_eq!(
        fallback_machine_name(Some("macOS 26.5"), id),
        "macos-0a1b2c"
    );
    assert_eq!(fallback_machine_name(Some("Darwin"), id), "macos-0a1b2c");
    assert_eq!(
        fallback_machine_name(Some("Windows 11"), id),
        "windows-0a1b2c"
    );
    assert_eq!(fallback_machine_name(Some("FreeBSD"), id), "freebsd-0a1b2c");
    // Same id, same fallback; a simple (dashless) id gives the same six characters.
    assert_eq!(
        fallback_machine_name(Some("Linux"), "0a1b2c3d4e5f6789abcdef0123456789"),
        "linux-0a1b2c"
    );
}

/// An id that is not a UUID still gives a well-formed label.
#[test]
fn fallback_of_a_non_uuid_id_is_still_a_valid_label() {
    assert_eq!(fallback_machine_name(Some("Linux"), "host"), "linux-host");
    assert_eq!(fallback_machine_name(None, "Ab-c_d.e"), "host-abcde");
}

/// An unknown or missing OS gives `host`, never a guess.
#[test]
fn fallback_never_claims_an_os_the_machine_did_not_report() {
    for os in [None, Some(""), Some("Plan 9")] {
        assert_eq!(
            fallback_machine_name(os, "ffeeddcc-0000"),
            "host-ffeedd",
            "{os:?}"
        );
    }
}

#[test]
fn odd_and_overlong_hostnames_give_no_name() {
    let too_long = "n".repeat(200);
    for source in ["host!name", "two words", "münchen", too_long.as_str()] {
        assert_eq!(machine_name(source), None, "{source}");
    }
}
