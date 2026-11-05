//! Checks that uninstall removes exactly the mesh SSH client files infraternal wrote.
use super::*;

fn root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "j175-files-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    let _ = std::fs::remove_dir_all(&root);
    for directory in ["etc/ssh/ssh_config.d", "run/infraternal-mesh-ssh"] {
        std::fs::create_dir_all(root.join(directory)).unwrap();
    }
    root
}

fn at(root: &Path, path: &str) -> PathBuf {
    root.join(path.trim_start_matches('/'))
}

/// Our config, known-hosts file and socket directory are removed.
#[test]
fn removes_the_files_infraternal_wrote() {
    let root = root();
    std::fs::write(
        at(&root, CONFIG_PATH),
        format!("{HEADER} for mesh names.\nMatch originalhost \"x\"\n"),
    )
    .unwrap();
    std::fs::write(
        at(&root, KNOWN_HOSTS_PATH),
        "@cert-authority *.x ssh-ed25519 AAAA\n",
    )
    .unwrap();
    std::fs::write(at(&root, SOCKET_PATH), "").unwrap();
    remove_client_files(&root).unwrap();
    assert!(!at(&root, CONFIG_PATH).exists());
    assert!(!at(&root, KNOWN_HOSTS_PATH).exists());
    assert!(!at(&root, SOCKET_DIRECTORY).exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// A file of the same name that infraternal did not write stays.
#[test]
fn leaves_files_it_did_not_write() {
    let root = root();
    std::fs::write(at(&root, CONFIG_PATH), "Host *\n    User someone\n").unwrap();
    std::fs::write(
        at(&root, KNOWN_HOSTS_PATH),
        "example.com ssh-ed25519 AAAA\n",
    )
    .unwrap();
    remove_client_files(&root).unwrap();
    assert!(at(&root, CONFIG_PATH).exists());
    assert!(at(&root, KNOWN_HOSTS_PATH).exists());
    std::fs::remove_dir_all(root).unwrap();
}

/// Nothing to remove is not an error.
#[test]
fn absent_files_are_fine() {
    let root = std::env::temp_dir().join(format!("j175-files-empty-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    remove_client_files(&root).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}
