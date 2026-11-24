//! Real-Mac proof that the root-mode utun MTU and up state are set by ioctls alone (#221).

/// A fresh utun comes up at the requested MTU through ioctls alone, and a later MTU change
/// keeps it up (#221). `ifconfig` is used only to read the result back.
#[test]
#[ignore = "Run on the macOS VM with system service privileges."]
fn utun_ioctls_set_mtu_and_bring_the_interface_up() {
    let open = super::super::OpenUtun::open().expect("open a utun (needs root)");
    // A new utun is already up at MTU 1500 on current macOS, so take it down first: that is
    // the state in which setting IFF_UP has to work.
    let down = std::process::Command::new("/sbin/ifconfig")
        .args([open.name.as_str(), "down"])
        .status()
        .expect("run ifconfig down");
    assert!(down.success(), "ifconfig down failed");
    let before = ifconfig_text(&open.name);
    assert!(
        !before.contains("<UP,"),
        "the utun is down before: {before}"
    );
    assert!(
        !before.contains("mtu 1280"),
        "MTU is not 1280 before: {before}"
    );
    super::super::configure_owned_interface(&open.name, None, 1280).expect("mtu and up by ioctl");
    let after = ifconfig_text(&open.name);
    assert!(after.contains("mtu 1280"), "MTU 1280 expected: {after}");
    assert!(after.contains("<UP,"), "interface up expected: {after}");
    crate::macos_utun_ioctl::set_mtu(&open.name, 1400).expect("mtu change by ioctl");
    let changed = ifconfig_text(&open.name);
    assert!(changed.contains("mtu 1400"), "MTU 1400 expected: {changed}");
    assert!(
        changed.contains("<UP,"),
        "still up after the change: {changed}"
    );
    assert!(
        crate::macos_utun_ioctl::set_mtu("utun999999", 1280).is_err(),
        "no such interface"
    );
}

/// `ifconfig <name>` output, for reading a result back.
fn ifconfig_text(name: &str) -> String {
    let output = std::process::Command::new("/sbin/ifconfig")
        .arg(name)
        .output()
        .expect("run ifconfig");
    String::from_utf8_lossy(&output.stdout).into_owned()
}
