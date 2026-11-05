//! Checks installation-path recovery after an atomic executable replacement [217,250], #188.
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
#[test]
/// Exercise pathname recovery with private state and panic-safe child ownership.
fn relative_recovery_after_atomic_install_keeps_live_install_path() {
    const NAME: &str = "restart::tests::deleted_path_review::relative_recovery_after_atomic_install_keeps_live_install_path";
    if let Some(installed) = std::env::var_os("REVIEW_REPLACED_INSTALL_PATH") {
        let installed = PathBuf::from(installed);
        if std::env::var_os("REVIEW_REPLACED_INSTALL_STAGE").is_some() {
            assert_eq!(
                super::super::current_binary().unwrap(),
                installed,
                "recovery must retain the live install pathname rather than a deleted inode label"
            );
            return;
        }
        // Publish a fresh inode while this process still executes the old one.
        // Only the private fixture is replaced; the Cargo executable is untouched.
        let successor = installed.with_extension("new");
        std::fs::copy(&installed, &successor).unwrap();
        std::fs::rename(successor, &installed).unwrap();
        assert!(
            std::env::current_exe()
                .unwrap()
                .as_os_str()
                .to_string_lossy()
                .ends_with(" (deleted)")
        );
        let recovery = crate::restart_binary::Opened::running().unwrap();
        let argv = [
            CString::new(recovery.path.as_os_str().as_bytes()).unwrap(),
            CString::new("--exact").unwrap(),
            CString::new(NAME).unwrap(),
            CString::new("--nocapture").unwrap(),
        ];
        let environment = [
            CString::new(format!(
                "REVIEW_REPLACED_INSTALL_PATH={}",
                installed.display()
            ))
            .unwrap(),
            CString::new("REVIEW_REPLACED_INSTALL_STAGE=after").unwrap(),
        ];
        let error = recovery.image.execute(&argv, &environment).unwrap_err();
        panic!("recovery exec refused: {error}");
    }
    let fixture = crate::restart_binary::fixture::Directory::new();
    let state = fixture.0.clone();
    let installed = state.join("infraternal");
    let _fixture = crate::restart_binary::fixture::Signed::image(installed.clone());
    let child = Command::new(&installed)
        .arg0("./infraternal")
        .args(["--exact", NAME, "--nocapture"])
        .current_dir(&state)
        .env("REVIEW_REPLACED_INSTALL_PATH", &installed)
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
        "relative recovery lost the live install path: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
