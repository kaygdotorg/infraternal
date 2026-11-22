//! Unit checks for the unit rewrite of `infraternal server update adopt` (#211 S6).
//!
//! The whole command (root, a real unit, a running server, the warm restart) is proved in
//! the root microVM (`scripts/update-proof-vm`, the `adopt` proof); these cover the text.
use super::*;

/// The operator-written production unit before S6, as on 2026-11-22 (paths illustrative).
const OPERATOR_UNIT: &str = "[Unit]\nDescription=infraternal server\nAfter=network-online.target\n\n[Service]\nEnvironment=RUST_LOG=info\nExecStart=/opt/infraternal/0123abcd/infraternal server --listen 172.18.0.1:7011 --data /var/lib/infraternal --public-origin https://infraternal.kayg.org --web-root /opt/infraternal/0123abcd/web --behind-proxy --trusted-proxy 172.18.0.2\nRestart=always\nLimitMEMLOCK=infinity\n\n[Install]\nWantedBy=multi-user.target\n";

/// The `ExecStart` words of `exec`.
fn words(exec: &str) -> Vec<String> {
    infraternal_status::exec_words(exec).unwrap()
}

/// The production unit becomes the boot pointer with every flag but `--web-root`, and a second rewrite is a no-op.
#[test]
fn the_rewrite_starts_the_boot_pointer_and_keeps_every_other_flag() {
    let exec = single_exec(OPERATOR_UNIT).unwrap();
    let pointer = Path::new("/var/lib/infraternal/updates/current/infraternal-x86_64-musl");
    let with_web = rewrite_exec(&words(&exec), pointer, true).unwrap();
    assert_eq!(
        with_web,
        "\"/var/lib/infraternal/updates/current/infraternal-x86_64-musl\" \"server\" \"--listen\" \"172.18.0.1:7011\" \"--data\" \"/var/lib/infraternal\" \"--public-origin\" \"https://infraternal.kayg.org\" \"--behind-proxy\" \"--trusted-proxy\" \"172.18.0.2\""
    );
    // A release without its own web build keeps the operator's web folder.
    let without_web = rewrite_exec(&words(&exec), pointer, false).unwrap();
    assert!(without_web.contains("\"--web-root\" \"/opt/infraternal/0123abcd/web\""));
    // The `=` spelling is dropped too.
    let joined = rewrite_exec(&words("/x server --web-root=/w --data /d"), pointer, true).unwrap();
    assert!(!joined.contains("web-root"), "{joined}");
    // Rewriting the result again is a no-op: a second adopt finds nothing to change.
    assert_eq!(
        rewrite_exec(&words(&with_web), pointer, true).unwrap(),
        with_web
    );
}

/// Only the `ExecStart` line differs after the rewrite; every other line stays byte for byte.
#[test]
fn only_the_exec_start_line_changes() {
    let rewritten = replace_exec(OPERATOR_UNIT, "\"/p\" \"server\"");
    let before: Vec<_> = OPERATOR_UNIT.lines().collect();
    let after: Vec<_> = rewritten.lines().collect();
    assert_eq!(before.len(), after.len());
    let changed: Vec<_> = before
        .iter()
        .zip(&after)
        .filter(|(old, new)| old != new)
        .map(|(_, new)| *new)
        .collect();
    assert_eq!(changed, ["ExecStart=\"/p\" \"server\""]);
    assert!(rewritten.ends_with("WantedBy=multi-user.target\n"));
}

/// Missing, repeated, prefixed and continued `ExecStart` lines are refused.
#[test]
fn units_whose_start_cannot_be_rewritten_exactly_are_refused() {
    assert!(single_exec("[Service]\nRestart=always\n").is_err());
    assert!(single_exec("[Service]\nExecStart=/a server\nExecStart=/b server\n").is_err());
    assert!(single_exec("[Service]\nExecStart=-/a server\n").is_err());
    assert!(single_exec("[Service]\nExecStart=/a server \\\n  --data /d\n").is_err());
    assert_eq!(
        single_exec("[Service]\n  ExecStart=/a server --data /d \n").unwrap(),
        "/a server --data /d"
    );
}

/// `--data value` and `--data=value` both name the data folder.
#[test]
fn the_data_folder_is_read_in_both_spellings() {
    assert_eq!(
        option(&words("/a server --data /srv/x"), "--data"),
        Some(PathBuf::from("/srv/x"))
    );
    assert_eq!(
        option(&words("/a server --data=/srv/y"), "--data"),
        Some(PathBuf::from("/srv/y"))
    );
    assert_eq!(option(&words("/a server"), "--data"), None);
}
