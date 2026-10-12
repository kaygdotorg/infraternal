//! Real repaint credit deadlines preserve PTY progress and the client cursor [13][41].
#![allow(clippy::unwrap_used)]
use std::{fs, path::PathBuf, process::Command};

#[test]
fn unaffordable_repaints_park_until_sufficient_credit() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target_root = std::env::var_os("CARGO_TARGET_DIR").map_or_else(
        || root.join("target"),
        |target| {
            let target = PathBuf::from(target);
            if target.is_absolute() {
                target
            } else {
                root.join(target)
            }
        },
    );
    let evidence = target_root.join("review-vt3-fixes");
    fs::create_dir_all(&evidence).unwrap();
    for credit in ["1", "16384"] {
        for mode in ["approximate", "faithful"] {
            let output = Command::new("python3")
                .current_dir(&root)
                .arg("scripts/verify-vt-credit.py")
                .args([env!("CARGO_BIN_EXE_infraternal"), credit, mode])
                .output()
                .unwrap();
            let name = format!("t1-gate-{mode}-{credit}");
            fs::write(evidence.join(format!("{name}.stdout.log")), output.stdout).unwrap();
            fs::write(evidence.join(format!("{name}.stderr.log")), output.stderr).unwrap();
            // Keep all subprocess diagnostics in files; report only the case.
            assert!(output.status.success(), "credit probe failed: {name}");
        }
    }
}
