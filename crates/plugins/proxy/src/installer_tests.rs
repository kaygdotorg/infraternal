//! Installer tests reject archive tampering before files enter the component store [#281].

use super::{
    installer::{ComponentInstaller, SignedComponentBundle},
    manifest::{
        ComponentManifest, ComponentManifestVerifier, TRAEFIK_VERSION, verify_component_manifest,
    },
};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Cursor},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
};

struct TempState(PathBuf);

impl TempState {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("proxy-installer-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).expect("create state directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("private state mode");
        Self(path)
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct AcceptSignature;

impl ComponentManifestVerifier for AcceptSignature {
    fn verify(&self, _signed_checksums: &[u8], signature: &[u8]) -> io::Result<()> {
        if signature == b"valid signature" {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "signature refused",
            ))
        }
    }
}

pub(super) fn archive(executable: &[u8], extra: Option<(&str, tar::EntryType)>) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_size(executable.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    builder
        .append_data(&mut header, "traefik", executable)
        .expect("append Traefik executable");

    let license = b"MIT License\nfixture license text";
    let mut header = tar::Header::new_gnu();
    header.set_size(license.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "LICENSE.md", license.as_slice())
        .expect("append Traefik license");

    if let Some((path, entry_type)) = extra {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_size(0);
        if entry_type.is_symlink() {
            header
                .set_link_name("../outside")
                .expect("set symlink target");
        }
        if path.contains("..") {
            // `Header::set_path` refuses traversal before it reaches the installer;
            // write the malicious archive field directly so the production parser sees it.
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
        } else {
            header.set_path(path).expect("set extra path");
        }
        header.set_mode(0o777);
        header.set_cksum();
        builder
            .append(&header, io::empty())
            .expect("append extra entry");
    }

    builder
        .into_inner()
        .expect("finish tar archive")
        .finish()
        .expect("finish gzip archive")
}

fn verified_manifest(
    archive: &[u8],
    executable: &[u8],
) -> super::manifest::VerifiedComponentManifest {
    let manifest = ComponentManifest {
        component: "traefik".to_owned(),
        version: TRAEFIK_VERSION.to_owned(),
        release_version: "0.1.0".to_owned(),
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        archive_filename: "traefik_v3.7.17_linux_amd64.tar.gz".to_owned(),
        archive_url:
            "https://github.com/traefik/traefik/releases/download/v3.7.17/traefik_v3.7.17_linux_amd64.tar.gz"
                .to_owned(),
        mirror_path:
            "components/0.1.0/proxy/linux/amd64/traefik_v3.7.17_linux_amd64.tar.gz".to_owned(),
        archive_sha256: format!("{:x}", Sha256::digest(archive)),
        archive_size: archive.len() as u64,
        executable: "traefik".to_owned(),
        executable_sha256: format!("{:x}", Sha256::digest(executable)),
        executable_size: executable.len() as u64,
        license: "MIT".to_owned(),
    };
    let bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let checksums = format!("{digest}  proxy-traefik-linux-amd64.json\n");
    verify_component_manifest(
        &bytes,
        "proxy-traefik-linux-amd64.json",
        checksums.as_bytes(),
        b"valid signature",
        "linux",
        "amd64",
        &AcceptSignature,
    )
    .expect("verify component manifest")
}

#[test]
fn installer_extracts_only_the_allowlisted_executable_with_private_mode() {
    let executable = b"signed executable bytes";
    let archive = archive(executable, None);
    let manifest = verified_manifest(&archive, executable);
    let state = TempState::new();
    let path = ComponentInstaller::new(&state.0)
        .install_archive(&manifest, Cursor::new(&archive), "linux", "amd64")
        .expect("install component");

    assert_eq!(
        path,
        state
            .0
            .join("components/proxy")
            .join(&manifest.manifest().executable_sha256)
            .join("bin/traefik")
    );
    assert_eq!(fs::read(&path).expect("installed binary"), executable);
    assert_eq!(
        fs::read_dir(path.parent().expect("bin directory"))
            .unwrap()
            .count(),
        1
    );
    let metadata = fs::symlink_metadata(&path).expect("binary metadata");
    assert_eq!(metadata.uid(), nix::unistd::geteuid().as_raw());
    let expected_gid = crate::identity::child_ids().expect("proxy identity").1;
    let expected_mode = if nix::unistd::Uid::effective().is_root() {
        0o550
    } else {
        0o500
    };
    assert_eq!(metadata.gid(), expected_gid);
    assert_eq!(metadata.mode() & 0o777, expected_mode);
    let repeated = ComponentInstaller::new(&state.0)
        .install_archive(&manifest, Cursor::new(&archive), "linux", "amd64")
        .expect("reuse immutable installed component");
    assert_eq!(repeated, path);
}

#[test]
fn existing_component_is_verified_before_requesting_an_archive_again() {
    let executable = b"signed executable bytes";
    let archive = archive(executable, None);
    let manifest = verified_manifest(&archive, executable);
    let state = TempState::new();
    let installer = ComponentInstaller::new(&state.0);
    let installed_path = installer
        .install_archive(&manifest, Cursor::new(&archive), "linux", "amd64")
        .expect("install component once");

    let reused = installer
        .install_stream(
            &manifest,
            |_output| {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "archive source is offline",
                ))
            },
            "linux",
            "amd64",
        )
        .expect("reuse valid executable before contacting the archive source");

    assert_eq!(reused, installed_path);
}

#[test]
fn installer_accepts_the_signed_release_changelog_without_extracting_it() {
    let executable = b"signed executable bytes";
    let archive = archive(executable, Some(("CHANGELOG.md", tar::EntryType::Regular)));
    let manifest = verified_manifest(&archive, executable);
    let state = TempState::new();
    let path = ComponentInstaller::new(&state.0)
        .install_archive(&manifest, Cursor::new(&archive), "linux", "amd64")
        .expect("accept the signed release changelog");

    assert_eq!(fs::read(&path).expect("installed executable"), executable);
    assert_eq!(
        fs::read_dir(path.parent().expect("bin directory"))
            .expect("list installed files")
            .count(),
        1
    );
}

#[test]
fn installer_rejects_bad_archive_checksum_and_wrong_architecture() {
    let executable = b"signed executable bytes";
    let archive = archive(executable, None);
    let manifest = verified_manifest(&archive, executable);
    let state = TempState::new();
    let installer = ComponentInstaller::new(&state.0);
    let mut tampered = archive.clone();
    tampered[0] ^= 1;

    let bad_digest = installer
        .install_archive(&manifest, Cursor::new(tampered), "linux", "amd64")
        .map(|_| ())
        .unwrap_err();
    assert_eq!(bad_digest.kind(), io::ErrorKind::InvalidData);
    let wrong_arch = installer
        .install_archive(&manifest, Cursor::new(archive), "linux", "arm64")
        .map(|_| ())
        .unwrap_err();
    assert_eq!(wrong_arch.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn installer_rejects_symlink_and_traversal_entries() {
    let executable = b"signed executable bytes";
    for extra in [
        ("traefik-link", tar::EntryType::Symlink),
        ("../outside", tar::EntryType::Regular),
    ] {
        let archive = archive(executable, Some(extra));
        let manifest = verified_manifest(&archive, executable);
        let state = TempState::new();
        let error = ComponentInstaller::new(&state.0)
            .install_archive(&manifest, Cursor::new(&archive), "linux", "amd64")
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!state.0.join("outside").exists());
        assert!(
            !state
                .0
                .join("components/proxy")
                .join(&manifest.manifest().executable_sha256)
                .exists()
        );
    }
}

#[test]
fn installer_refuses_a_state_directory_with_group_access() {
    let executable = b"signed executable bytes";
    let archive = archive(executable, None);
    let manifest = verified_manifest(&archive, executable);
    let state = TempState::new();
    fs::set_permissions(&state.0, fs::Permissions::from_mode(0o750))
        .expect("make state directory unsafe");

    let error = ComponentInstaller::new(&state.0)
        .install_archive(&manifest, Cursor::new(&archive), "linux", "amd64")
        .map(|_| ())
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(!state.0.join("components").exists());
}

#[test]
fn offline_bundle_import_uses_the_signed_manifest_and_archive_path() {
    let executable = b"signed executable bytes";
    let archive = archive(executable, None);
    let manifest = ComponentManifest {
        component: "traefik".to_owned(),
        version: TRAEFIK_VERSION.to_owned(),
        release_version: "0.1.0".to_owned(),
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        archive_filename: "traefik_v3.7.17_linux_amd64.tar.gz".to_owned(),
        archive_url:
            "https://github.com/traefik/traefik/releases/download/v3.7.17/traefik_v3.7.17_linux_amd64.tar.gz"
                .to_owned(),
        mirror_path:
            "components/0.1.0/proxy/linux/amd64/traefik_v3.7.17_linux_amd64.tar.gz".to_owned(),
        archive_sha256: format!("{:x}", Sha256::digest(&archive)),
        archive_size: archive.len() as u64,
        executable: "traefik".to_owned(),
        executable_sha256: format!("{:x}", Sha256::digest(executable)),
        executable_size: executable.len() as u64,
        license: "MIT".to_owned(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let digest = format!("{:x}", Sha256::digest(&manifest_bytes));
    let checksums = format!("{digest}  proxy-traefik-linux-amd64.json\n");
    let state = TempState::new();

    let path = ComponentInstaller::new(&state.0)
        .import_bundle(
            SignedComponentBundle {
                manifest: &manifest_bytes,
                manifest_filename: "proxy-traefik-linux-amd64.json",
                signed_checksums: checksums.as_bytes(),
                signature: b"valid signature",
            },
            "linux",
            "amd64",
            &AcceptSignature,
            Cursor::new(&archive),
        )
        .expect("import verified offline bundle");
    assert_eq!(fs::read(path).expect("imported executable"), executable);
}
