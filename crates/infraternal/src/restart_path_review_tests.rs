//! Verifies that sealed recovery retains the installed executable when initial invocation uses PATH [217], #157/#188.
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
#[test]
/// Exercise pathname recovery with a compact image, private state, and panic-safe child ownership.
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
    let fixture = crate::restart_binary::fixture::Directory::new();
    let state = fixture.0.clone();
    let child = Command::new(crate::restart_binary::fixture::stripped_test_image(
        &std::env::current_exe().unwrap(),
    ))
    .arg0("infraternal")
    .args(["--exact", NAME, "--nocapture"])
    .current_dir(&state)
    .env("REVIEW_RECOVERY_PATH_STATE", &state)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .process_group(0)
    .spawn()
    .unwrap();
    let output = super::bounded_output(child, super::HANG_BOUND, NAME);
    std::fs::remove_dir_all(state).unwrap();
    assert!(
        output.status.success(),
        "recovery from a PATH invocation changed the install target: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
