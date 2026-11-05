//! Verifies that sealed recovery retains the installed executable when initial invocation uses PATH [217], #157/#188.
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::DirBuilderExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
#[test]
fn late_recovery_from_path_invocation_keeps_install_target() {
    const NAME: &str =
        "restart::tests::path_review::late_recovery_from_path_invocation_keeps_install_target";
    if let Some(state) = std::env::var_os("REVIEW_RECOVERY_PATH_STATE") {
        let state = PathBuf::from(state);
        if std::env::var_os("REVIEW_RECOVERY_PATH_STAGE").is_some() {
            let expected = std::fs::read_to_string(state.join("installed-path")).unwrap();
            assert_eq!(
                super::super::current_binary().unwrap(),
                PathBuf::from(expected),
                "recovery must retain the installation target for subsequent reloads"
            );
            return;
        }
        let installed = std::env::current_exe().unwrap();
        std::fs::write(
            state.join("installed-path"),
            installed.as_os_str().as_bytes(),
        )
        .unwrap();
        let recovery = crate::restart_binary::Opened::running().unwrap();
        let argv = [
            CString::new(recovery.path.as_os_str().as_bytes()).unwrap(),
            CString::new("--exact").unwrap(),
            CString::new(NAME).unwrap(),
            CString::new("--nocapture").unwrap(),
        ];
        let environment = [
            CString::new(format!("REVIEW_RECOVERY_PATH_STATE={}", state.display())).unwrap(),
            CString::new("REVIEW_RECOVERY_PATH_STAGE=after").unwrap(),
        ];
        let error = recovery.image.execute(&argv, &environment).unwrap_err();
        panic!("recovery exec refused: {error}");
    }
    let state = crate::restart_binary::fixture::scratch_root()
        .join(format!("review-recovery-path-{}", uuid::Uuid::new_v4()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&state)
        .unwrap();
    let mut child = Command::new(crate::restart_binary::fixture::stripped_test_image(
        &std::env::current_exe().unwrap(),
    ))
    .arg0("infraternal")
    .args(["--exact", NAME, "--nocapture"])
    .current_dir(&state)
    .env("REVIEW_RECOVERY_PATH_STATE", &state)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    // A refused or stalled child must not keep this functional review open.
    let deadline = std::time::Instant::now() + super::HANG_BOUND;
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            std::fs::remove_dir_all(&state).unwrap();
            panic!("path recovery child did not complete");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    std::fs::remove_dir_all(state).unwrap();
    assert!(
        output.status.success(),
        "recovery from a PATH invocation changed the install target: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
