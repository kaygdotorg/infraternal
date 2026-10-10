//! Tests private control endpoints and replacement-path trust before any key is exported [217], #154.

use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/ca-handoff")
            .join(format!(
                "c{}",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            ));
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn private_control_endpoint_cannot_be_stolen_or_created_by_a_client() {
    let directory = Directory::new();
    assert!(request(&directory.0, None).await.is_err());
    assert!(!directory.0.join("restart").exists());
    let control = Control::start(&directory.0).unwrap();
    assert_eq!(
        std::fs::metadata(directory.0.join("restart"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&control.path).unwrap().mode() & 0o777,
        0o600
    );
    assert!(Control::start(&directory.0).is_err());
    assert!(control.path.exists());
    drop(control);
    assert!(!directory.0.join("restart/control.sock").exists());
}

#[tokio::test]
async fn restart_requests_use_the_servers_binary_and_reject_untrusted_paths() {
    let directory = Directory::new();
    let mut control = Control::start(&directory.0).unwrap();
    let (received, requested) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(control.requested(), request(&directory.0, None))
    })
    .await
    .expect("owner restart request deadline");
    assert!(requested.is_ok());
    assert_eq!(received.unwrap(), std::env::current_exe().unwrap());
    let alias = directory.0.join("alias");
    std::os::unix::fs::symlink(std::env::current_exe().unwrap(), &alias).unwrap();
    assert!(executable(&alias).is_err());
    let binary = directory.0.join("binary");
    std::fs::write(&binary, b"fixture").unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(executable(&binary).is_err());
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(executable(&binary).is_ok());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(executable(&binary).is_ok());
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(executable(&binary).is_err());
}

#[tokio::test]
async fn runtime_directory_symlinks_and_public_permissions_are_refused() {
    let directory = Directory::new();
    let external = Directory::new();
    std::os::unix::fs::symlink(&external.0, directory.0.join("restart")).unwrap();
    assert!(Control::start(&directory.0).is_err());
    std::fs::remove_file(directory.0.join("restart")).unwrap();
    std::fs::DirBuilder::new()
        .mode(0o755)
        .create(directory.0.join("restart"))
        .unwrap();
    assert!(Control::start(&directory.0).is_err());
}

#[test]
fn private_path_prefix_cannot_authorize_a_parent_directory_escape() {
    let directory = Directory::new();
    let depth = directory
        .0
        .components()
        .filter(|part| matches!(part, std::path::Component::Normal(_)))
        .count();
    let escaped = directory
        .0
        .join(format!("{}usr/bin/true", "../".repeat(depth)));
    assert!(escaped.exists());
    assert!(executable(&escaped).is_err());
}
