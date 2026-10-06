//! Exercise public detachment in a single-threaded subprocess after Rust startup.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]
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
