//! Component downloads trust signed release metadata before selecting mirror or upstream bytes [#281].

use super::{
    download::{ComponentDownloader, ComponentTransport},
    installer::ComponentInstaller,
    manifest::{ComponentManifest, ComponentManifestVerifier, TRAEFIK_VERSION},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use url::Url;

struct TempState(PathBuf);

impl TempState {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("proxy-download-{}", uuid::Uuid::new_v4()));
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

#[derive(Clone)]
struct FixtureTransport {
    bodies: BTreeMap<String, Vec<u8>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl ComponentTransport for FixtureTransport {
    fn download(&self, url: &Url, limit: u64, output: &mut dyn Write) -> io::Result<()> {
        let address = url.as_str().to_owned();
        self.requests
            .lock()
            .map_err(|_| io::Error::other("request fixture lock poisoned"))?
            .push(address.clone());
        let body = self
            .bodies
            .get(&address)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "fixture URL is unavailable"))?;
        if u64::try_from(body.len()).unwrap_or(u64::MAX) > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture exceeds its byte limit",
            ));
        }
        output.write_all(body)
    }
}

struct FixtureVerifier(bool);

impl ComponentManifestVerifier for FixtureVerifier {
    fn verify(&self, _signed_checksums: &[u8], signature: &[u8]) -> io::Result<()> {
        if self.0 && signature == b"valid signature" {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "release signature refused",
            ))
        }
    }
}

fn signed_fixture(archive: &[u8]) -> (Vec<(String, Vec<u8>)>, String, String) {
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
        archive_size: u64::try_from(archive.len()).expect("archive fixture size"),
        executable: "traefik".to_owned(),
        executable_sha256: format!("{:x}", Sha256::digest(b"signed executable bytes")),
        executable_size: u64::try_from(b"signed executable bytes".len())
            .expect("executable fixture size"),
        license: "MIT".to_owned(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest JSON");
    let checksum = format!(
        "{:x}  proxy-traefik-linux-amd64.json\n",
        Sha256::digest(&manifest_bytes)
    );
    let base = "https://mirror.example/releases/0.1.0/";
    (
        vec![
            (
                format!("{base}proxy-traefik-linux-amd64.json"),
                manifest_bytes,
            ),
            (format!("{base}SHA256SUMS"), checksum.into_bytes()),
            (format!("{base}SHA256SUMS.sig"), b"valid signature".to_vec()),
        ],
        format!("https://mirror.example/releases/{}", manifest.mirror_path),
        manifest.archive_url,
    )
}

fn fixture_archive() -> Vec<u8> {
    super::installer_tests::archive(b"signed executable bytes", None)
}

fn fixture_transport(
    metadata: Vec<(String, Vec<u8>)>,
    archive_url: &str,
    archive: Option<Vec<u8>>,
) -> FixtureTransport {
    let mut bodies: BTreeMap<_, _> = metadata.into_iter().collect();
    if let Some(archive) = archive {
        bodies.insert(archive_url.to_owned(), archive);
    }
    FixtureTransport {
        bodies,
        requests: Arc::new(Mutex::new(Vec::new())),
    }
}

#[test]
fn mirror_archive_is_streamed_after_the_product_signature_is_verified() {
    let archive = fixture_archive();
    let (metadata, mirror_archive, upstream_archive) = signed_fixture(&archive);
    let transport = fixture_transport(metadata, &mirror_archive, Some(archive));
    let requests = transport.requests.clone();
    let state = TempState::new();
    let installer = ComponentInstaller::new(&state.0);

    let path = ComponentDownloader::new(
        Url::parse("https://mirror.example/releases/").expect("mirror URL"),
        transport,
    )
    .expect("valid mirror")
    .install(
        &installer,
        "0.1.0",
        "linux",
        "amd64",
        &FixtureVerifier(true),
    )
    .expect("install verified mirror archive");

    assert_eq!(
        fs::read(path).expect("installed executable"),
        b"signed executable bytes"
    );
    let requests = requests.lock().expect("request fixture lock");
    assert!(requests.contains(&mirror_archive));
    assert!(!requests.contains(&upstream_archive));
}

#[test]
fn upstream_archive_fallback_uses_the_signed_manifest_and_verified_digest() {
    let archive = fixture_archive();
    let (metadata, mirror_archive, upstream_archive) = signed_fixture(&archive);
    let transport = fixture_transport(metadata, &upstream_archive, Some(archive));
    let requests = transport.requests.clone();
    let state = TempState::new();
    let installer = ComponentInstaller::new(&state.0);

    ComponentDownloader::new(
        Url::parse("https://mirror.example/releases/").expect("mirror URL"),
        transport,
    )
    .expect("valid mirror")
    .install(
        &installer,
        "0.1.0",
        "linux",
        "amd64",
        &FixtureVerifier(true),
    )
    .expect("install verified upstream fallback");

    let requests = requests.lock().expect("request fixture lock");
    let mirror_index = requests
        .iter()
        .position(|request| request == &mirror_archive)
        .expect("mirror archive attempted first");
    let upstream_index = requests
        .iter()
        .position(|request| request == &upstream_archive)
        .expect("signed upstream archive attempted after the mirror");
    assert!(mirror_index < upstream_index);
}

#[test]
fn an_untrusted_manifest_never_triggers_an_archive_request() {
    let archive = fixture_archive();
    let (metadata, mirror_archive, upstream_archive) = signed_fixture(&archive);
    let transport = fixture_transport(metadata, &mirror_archive, Some(archive));
    let requests = transport.requests.clone();
    let state = TempState::new();
    let installer = ComponentInstaller::new(&state.0);

    let error = ComponentDownloader::new(
        Url::parse("https://mirror.example/releases/").expect("mirror URL"),
        transport,
    )
    .expect("valid mirror")
    .install(
        &installer,
        "0.1.0",
        "linux",
        "amd64",
        &FixtureVerifier(false),
    )
    .expect_err("untrusted manifest must fail");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let requests = requests.lock().expect("request fixture lock");
    assert!(!requests.contains(&mirror_archive));
    assert!(!requests.contains(&upstream_archive));
    assert!(!state.0.join("components").exists());
}
