//! Exercise descriptor and signal policy at the single-threaded detachment boundary [13][217], #154.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
#[test]
fn detached_child_restores_default_signals_without_changing_parent() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let result = root.join(format!("target/detach-signals-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&result);
    let before = nix::sys::signal::SigSet::thread_get_mask().unwrap();
    // The shell supplies SIG_IGN without modifying this test process. The
    // standalone probe blocks SIGHUP before its single-threaded double fork.
    assert!(
        std::process::Command::new("/bin/sh")
            .current_dir(&root)
            .args(["-c", "trap '' HUP; exec \"$@\"", "detach-signal-fixture"])
            .arg(env!("CARGO"))
            .args([
                "run",
                "--quiet",
                "-p",
                "infraternal-shim",
                "--example",
                "detach_probe",
                "--"
            ])
            .arg(&result)
            .args(["0", "signals"])
            .status()
            .unwrap()
            .success()
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let output = loop {
        let text = std::fs::read_to_string(&result).unwrap_or_default();
        if text.ends_with('\n') {
            break text;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached signal probe timed out"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    std::fs::remove_file(result).unwrap();
    assert_eq!(output.trim(), "signal_mask_empty=true child_sighup=Some(1)");
    assert_eq!(nix::sys::signal::SigSet::thread_get_mask().unwrap(), before);
}

#[test]
fn closed_standard_descriptors_become_dev_null() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for mask in 1..8 {
        let result = root.join(format!("target/detach-{}-{mask}.log", std::process::id()));
        let _ = std::fs::remove_file(&result);
        // A standalone main is essential: the Rust test harness has threads and
        // is therefore outside detach's documented single-threaded boundary.
        assert!(
            std::process::Command::new(env!("CARGO"))
                .current_dir(&root)
                .args([
                    "run",
                    "--quiet",
                    "-p",
                    "infraternal-shim",
                    "--example",
                    "detach_probe",
                    "--"
                ])
                .arg(&result)
                .arg(mask.to_string())
                .status()
                .unwrap()
                .success()
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let output = loop {
            let text = std::fs::read_to_string(&result).unwrap_or_default();
            if text.ends_with('\n') {
                break text;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "detached probe timed out"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(
            output.trim(),
            "Ok([\"/dev/null\", \"/dev/null\", \"/dev/null\"])",
            "closed mask {mask}"
        );
        std::fs::remove_file(result).unwrap();
    }
}
