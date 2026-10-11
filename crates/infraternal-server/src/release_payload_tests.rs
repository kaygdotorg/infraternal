//! Real OpenSSH release fixtures and a local bucket exercise architecture selection and verified cache reuse [225].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use std::time::Duration;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

pub(crate) struct Bucket {
    pub(crate) origin: String,
    pub(crate) files: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    pub(crate) requests: Arc<AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}
impl Bucket {
    pub(crate) fn new(files: HashMap<String, Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let files = Arc::new(StdMutex::new(files));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (data, count, stopping) = (files.clone(), requests.clone(), stop.clone());
        let task = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        socket
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut request = [0; 4096];
                        let size = socket.read(&mut request).unwrap();
                        let request = std::str::from_utf8(&request[..size]).unwrap();
                        let path = request.split_whitespace().nth(1).unwrap();
                        count.fetch_add(1, Ordering::Relaxed);
                        let files = data.lock().unwrap();
                        let body = files.get(path);
                        let status = if body.is_some() {
                            "200 OK"
                        } else {
                            "404 Not Found"
                        };
                        let body = body.map_or(&[][..], Vec::as_slice);
                        write!(
                            socket,
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        socket.write_all(body).unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("{error}"),
                }
            }
        });
        Self {
            origin,
            files,
            requests,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for Bucket {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.task.take().unwrap().join().unwrap();
    }
}

pub(crate) struct Release {
    pub(crate) root: PathBuf,
    pub(crate) files: HashMap<String, Vec<u8>>,
    pub(crate) trust: String,
}
impl Release {
    pub(crate) fn new(size: usize) -> Self {
        Self::with_version(size, "0.1.0")
    }
    pub(crate) fn with_version(size: usize, version: &str) -> Self {
        Self::with_manifest_entries(size, version, 0)
    }
    pub(crate) fn with_manifest_entries(size: usize, version: &str, extra: usize) -> Self {
        use sha2::{Digest, Sha256};
        use std::process::Command;
        let root =
            PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()))
                .join(format!("bucket-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let key = root.join("fixture-key");
        assert!(
            Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&key)
                .status()
                .unwrap()
                .success()
        );
        let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
        let fields: Vec<_> = public.split_whitespace().collect();
        let trust = format!(
            "release@infraternal.com namespaces=\"infraternal-release\" {} {} fixture\n",
            fields[0], fields[1]
        );
        let payload = vec![0x42; size];
        let name = "infraternal-aarch64-musl";
        let version_name = version;
        let version = format!("{version}\n").into_bytes();
        let mut sums = format!(
            "{:x}  {name}\n{:x}  VERSION\n",
            Sha256::digest(&payload),
            Sha256::digest(&version)
        )
        .into_bytes();
        for index in 0..extra {
            sums.extend_from_slice(
                format!("{:x}  fixture-{index:04}\n", Sha256::digest([])).as_bytes(),
            );
        }
        let sums_file = root.join("SHA256SUMS");
        std::fs::write(&sums_file, &sums).unwrap();
        assert!(
            Command::new("ssh-keygen")
                .args(["-Y", "sign", "-f"])
                .arg(&key)
                .args(["-n", "infraternal-release"])
                .arg(&sums_file)
                .output()
                .unwrap()
                .status
                .success()
        );
        std::fs::remove_file(key).unwrap();
        let signature = std::fs::read(sums_file.with_extension("sig")).unwrap();
        let files = [
            (name, payload),
            ("VERSION", version),
            ("SHA256SUMS", sums),
            ("SHA256SUMS.sig", signature),
        ]
        .into_iter()
        .map(|(name, bytes)| (format!("/releases/{version_name}/{name}"), bytes))
        .collect();
        Self { root, files, trust }
    }
    fn resolver(&self, origin: String, cache: &str, development: bool) -> ReleasePayload {
        let state = self.root.join(cache);
        std::fs::create_dir(&state).unwrap();
        ReleasePayload {
            executable: self.root.join("running-binary"),
            local: infraternal_plugin_ssh::install::BinaryPaths {
                x86_64: self.root.join("local-x86"),
                aarch64: self.root.join("local-arm"),
            },
            cache: state.join("releases"),
            version: "0.1.0".into(),
            development,
            origin,
            lock: Mutex::new(()),
            trust: Some(self.trust.clone()),
        }
    }
}
impl Drop for Release {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[tokio::test]
async fn signed_download_cache_hit_offline_and_tampered_cache() {
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "valid", false);
    let path = resolver.resolve(Architecture::Aarch64).await.unwrap();
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    assert_eq!(std::fs::read(&path).unwrap(), vec![0x42; 1024]);
    assert_eq!(resolver.resolve(Architecture::Aarch64).await.unwrap(), path);
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    drop(bucket);
    assert_eq!(resolver.resolve(Architecture::Aarch64).await.unwrap(), path);
    std::fs::write(&path, b"tampered").unwrap();
    assert!(resolver.resolve(Architecture::Aarch64).await.is_err());
}

#[tokio::test]
async fn missing_wrong_version_tampered_network_and_development_only_fallback() {
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    bucket.files.lock().unwrap().insert(
        "/releases/0.1.0/infraternal-aarch64-musl".into(),
        b"tampered".to_vec(),
    );
    let resolver = release.resolver(bucket.origin.clone(), "tampered", false);
    let error = resolver.resolve(Architecture::Aarch64).await.err().unwrap();
    assert_eq!(
        error.message,
        "the binary does not match the signed checksum."
    );
    assert!(format!("{error}").starts_with("Get the arm64 binary:"));
    assert!(!resolver.cache.join("0.1.0/aarch64").exists());
    let mut wrong = release.resolver(bucket.origin.clone(), "version", false);
    wrong.version = "0.1.1".into();
    assert!(wrong.resolve(Architecture::Aarch64).await.is_err());
    let empty = Bucket::new(HashMap::new());
    let normal = release.resolver(empty.origin.clone(), "missing", false);
    assert!(normal.resolve(Architecture::Aarch64).await.is_err());
    let dev = release.resolver(empty.origin.clone(), "development", true);
    assert_eq!(
        dev.resolve(Architecture::Aarch64).await.unwrap(),
        dev.local.aarch64
    );
    drop(empty);
    assert!(
        dev.resolve(Architecture::Aarch64).await.is_err(),
        "offline is not an absent release"
    );
    if std::env::consts::ARCH == "x86_64" {
        assert_eq!(
            normal.resolve(Architecture::X86_64).await.unwrap(),
            normal.executable
        );
    }
}

#[tokio::test]
#[ignore = "run release-profile measurements in a weighted scope"]
async fn cross_architecture_cold_and_warm_cache_measurements() {
    let release = Release::new(20 * 1024 * 1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "bench", false);
    let start = std::time::Instant::now();
    resolver.resolve(Architecture::Aarch64).await.unwrap();
    let cold = start.elapsed().as_secs_f64() * 1000.0;
    let mut samples = Vec::new();
    for _ in 0..50 {
        let start = std::time::Instant::now();
        resolver.resolve(Architecture::Aarch64).await.unwrap();
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let burst_start = std::time::Instant::now();
    let resolver = Arc::new(resolver);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            resolver.resolve(Architecture::Aarch64).await.unwrap()
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let eight_warm_ms = burst_start.elapsed().as_secs_f64() * 1000.0;
    samples.sort_by(f64::total_cmp);
    println!(
        "METRIC name=add_host_get_arm64_binary payload_bytes={} cold_ms={cold:.3} warm_p50_ms={:.3} samples=50 concurrent_hosts=8 eight_warm_ms={eight_warm_ms:.3} network_requests={}",
        20 * 1024 * 1024,
        samples[25],
        bucket.requests.load(Ordering::Relaxed)
    );
}

#[tokio::test]
async fn a_valid_older_release_replayed_under_the_requested_version_is_refused() {
    let release = Release::new(1024);
    let replay = release
        .files
        .iter()
        .map(|(path, body)| (path.replace("/0.1.0/", "/0.1.1/"), body.clone()))
        .collect();
    let bucket = Bucket::new(replay);
    let mut resolver = release.resolver(bucket.origin.clone(), "replay", false);
    resolver.version = "0.1.1".into();
    let error = resolver
        .resolve(Architecture::Aarch64)
        .await
        .expect_err("a signed older release must not become this server version");
    assert_eq!(
        error.message,
        "the signed release belongs to another server version."
    );
    assert!(!resolver.cache.join("0.1.1/aarch64").exists());
}

#[tokio::test]
async fn eight_concurrent_add_hosts_share_one_verified_download() {
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = Arc::new(release.resolver(bucket.origin.clone(), "concurrent", false));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            resolver.resolve(Architecture::Aarch64).await.unwrap()
        }));
    }
    let expected = resolver
        .cache
        .join("0.1.0/aarch64/infraternal-aarch64-musl");
    for task in tasks {
        assert_eq!(task.await.unwrap(), expected);
    }
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn a_missing_payload_never_enables_development_fallback() {
    let release = Release::new(1024);
    let mut files = release.files.clone();
    files.remove("/releases/0.1.0/infraternal-aarch64-musl");
    let bucket = Bucket::new(files);
    let resolver = release.resolver(bucket.origin.clone(), "missing-payload", true);
    let error = resolver
        .resolve(Architecture::Aarch64)
        .await
        .expect_err("signed manifest without a payload must stop");
    assert_eq!(error.message, "this version has no matching release file.");
    assert!(!resolver.cache.join("0.1.0/aarch64").exists());
}

#[tokio::test]
async fn cache_symlinks_and_shared_files_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "unsafe", false);
    let path = resolver.resolve(Architecture::Aarch64).await.unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(resolver.resolve(Architecture::Aarch64).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let retained = path.with_extension("retained");
    std::fs::rename(&path, &retained).unwrap();
    symlink(&retained, &path).unwrap();
    assert!(resolver.resolve(Architecture::Aarch64).await.is_err());
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}
// This subprocess helper lets the parent stop a real download without running
// Staging::drop, matching abrupt server termination rather than cancellation.
#[test]
#[ignore = "subprocess helper for release-cache restart verification"]
fn partial_download_restart_child() {
    let Some(state) = std::env::var_os("REVIEW_RELEASE_STATE") else {
        return;
    };
    let resolver = ReleasePayload {
        executable: PathBuf::from("unused"),
        local: infraternal_plugin_ssh::install::BinaryPaths {
            x86_64: PathBuf::from("unused"),
            aarch64: PathBuf::from("unused"),
        },
        cache: PathBuf::from(state).join("releases"),
        version: "0.1.0".into(),
        development: false,
        origin: std::env::var("REVIEW_RELEASE_ORIGIN").unwrap(),
        lock: Mutex::new(()),
        trust: Some(std::env::var("REVIEW_RELEASE_TRUST").unwrap()),
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(resolver.resolve(Architecture::Aarch64))
        .unwrap();
}

#[tokio::test]
async fn restarted_resolution_reclaims_partial_downloads_after_process_stop() {
    use std::process::{Command, Stdio};
    let release = Release::new(2 * 1024 * 1024);
    let bucket = Bucket::new(release.files.clone());
    let restarted = release.resolver(bucket.origin.clone(), "restart", false);
    let version = restarted.cache.join("0.1.0");
    // Repeat the abrupt stop: retention must be bounded across restarts, not
    // merely within one download. Each child writes one MiB before stopping.
    for _ in 0..2 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let files = release.files.clone();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let size = socket.read(&mut request).await.unwrap();
                let path = std::str::from_utf8(&request[..size])
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let body = files.get(path).unwrap();
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                if path.ends_with("infraternal-aarch64-musl") {
                    socket.write_all(&body[..1024 * 1024]).await.unwrap();
                    // The body deliberately remains incomplete until the child
                    // stops; successful verification/publication cannot happen.
                    let mut remaining = Vec::new();
                    let _ = socket.read_to_end(&mut remaining).await;
                } else {
                    socket.write_all(body).await.unwrap();
                }
            }
        });
        let before = partial_payload_bytes(&version);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "release_payload::tests::partial_download_restart_child",
                "--ignored",
            ])
            .env("REVIEW_RELEASE_STATE", restarted.cache.parent().unwrap())
            .env("REVIEW_RELEASE_ORIGIN", origin)
            .env("REVIEW_RELEASE_TRUST", &release.trust)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while partial_payload_bytes(&version) < before + 1024 * 1024 {
            assert!(
                child.try_wait().unwrap().is_none(),
                "download child stopped early"
            );
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("partial download did not reach its retained-byte boundary");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        child.kill().unwrap();
        child.wait().unwrap();
        server.await.unwrap();
    }
    let retained_before = partial_payload_bytes(&version);
    assert_eq!(retained_before, 2 * 1024 * 1024);
    let ready = restarted.resolve(Architecture::Aarch64).await.unwrap();
    assert_eq!(std::fs::metadata(ready).unwrap().len(), 2 * 1024 * 1024);
    let retained_after = partial_payload_bytes(&version);
    println!(
        "RELEASE_CACHE_RESTART abrupt_stops=2 retained_before_bytes={retained_before} retained_after_bytes={retained_after}"
    );
    assert_eq!(
        retained_after, 0,
        "completed restart resolution must reclaim abandoned partial release downloads"
    );
}

// Count only payload files in resolver-owned temporary directories. The
// verified published cache and signed metadata are deliberately excluded.
fn partial_payload_bytes(version: &Path) -> u64 {
    std::fs::read_dir(version)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("download-"))
        .filter_map(|entry| std::fs::metadata(entry.path().join("infraternal-aarch64-musl")).ok())
        .map(|metadata| metadata.len())
        .sum()
}

#[test]
fn resolver_startup_removes_only_owned_inactive_private_staging() {
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::{PermissionsExt, symlink};
    let release = Release::new(1024);
    let resolver = release.resolver("http://127.0.0.1:1".into(), "startup", false);
    private_directory(&resolver.cache).unwrap();
    let version = resolver.cache.join("0.1.0");
    private_directory(&version).unwrap();
    let staging = |name: String| {
        let directory = version.join(name);
        private_directory(&directory).unwrap();
        let payload = directory.join("infraternal-aarch64-musl");
        std::fs::write(&payload, b"partial").unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600)).unwrap();
        directory
    };
    let abandoned = staging(format!("download-{}", uuid::Uuid::new_v4()));
    let active = staging(format!("download-{}", uuid::Uuid::new_v4()));
    let active_lock = Flock::lock(
        std::fs::File::open(&active).unwrap(),
        FlockArg::LockExclusiveNonblock,
    )
    .unwrap();
    let unrelated = staging("download-unrelated".into());
    let shared = staging(format!("download-{}", uuid::Uuid::new_v4()));
    std::fs::hard_link(
        shared.join("infraternal-aarch64-musl"),
        release.root.join("retained"),
    )
    .unwrap();
    let linked = version.join(format!("download-{}", uuid::Uuid::new_v4()));
    symlink(&active, &linked).unwrap();
    let unknown = staging(format!("download-{}", uuid::Uuid::new_v4()));
    std::fs::write(unknown.join("unrelated"), b"keep").unwrap();
    let _started = ReleasePayload::new(
        resolver.executable.clone(),
        resolver.local,
        resolver.cache.parent().unwrap(),
    );
    assert!(
        !abandoned.exists(),
        "startup must remove abandoned staging before any network request"
    );
    for retained in [&active, &unrelated, &shared, &linked, &unknown] {
        assert!(retained.exists(), "preserve {}", retained.display());
    }
    drop(active_lock);
}

#[tokio::test]
async fn edge_add_host_keeps_exact_server_version_and_verified_cache() {
    let version = "edge-20261011T071500Z";
    let release = Release::with_version(1024, version);
    let bucket = Bucket::new(release.files.clone());
    let mut resolver = release.resolver(bucket.origin.clone(), "edge", false);
    resolver.version = version.into();
    assert_eq!(
        resolver.resolve(Architecture::X86_64).await.unwrap(),
        resolver.executable
    );
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 0);
    let payload = resolver.resolve(Architecture::Aarch64).await.unwrap();
    assert!(payload.to_string_lossy().contains(version));
    assert_eq!(std::fs::read(&payload).unwrap(), vec![0x42; 1024]);
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    assert_eq!(
        resolver.resolve(Architecture::Aarch64).await.unwrap(),
        payload
    );
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}
