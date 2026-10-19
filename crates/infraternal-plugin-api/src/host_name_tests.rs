//! Regressions for shared host-name extraction from destinations and reported hostnames.
use super::machine_name;

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
fn numeric_invalid_and_unnamed_inputs_give_no_name() {
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
        "root@unnamed-3",
    ] {
        assert_eq!(machine_name(source), None, "{source}");
    }
}

#[test]
fn odd_and_overlong_hostnames_give_no_name() {
    let too_long = "n".repeat(200);
    for source in ["host!name", "two words", "münchen", too_long.as_str()] {
        assert_eq!(machine_name(source), None, "{source}");
    }
}
