//! Checks first-entry dump protection in a fresh exec image [217], #154.

#[test]
fn process_dumpability_is_disabled_before_dispatch() {
    const NAME: &str = "startup_tests::process_dumpability_is_disabled_before_dispatch";
    if std::env::var_os("INFRATERNAL_DUMP_TEST").is_some() {
        super::harden_startup().unwrap();
        assert!(
            !nix::sys::prctl::get_dumpable().unwrap(),
            "entry must close post-exec dumpability"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_DUMP_TEST", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
