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

/// Use the nonlocal supported binary so download paths remain covered on both host architectures.
fn remote_arch() -> Architecture {
    match std::env::consts::ARCH {
        "x86_64" => Architecture::Aarch64,
        "aarch64" => Architecture::X86_64,
        architecture => panic!("unsupported release-test host architecture: {architecture}"),
    }
}

fn host_arch() -> Architecture {
    match std::env::consts::ARCH {
        "x86_64" => Architecture::X86_64,
        "aarch64" => Architecture::Aarch64,
        architecture => panic!("unsupported release-test host architecture: {architecture}"),
    }
}

fn architecture_label(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    }
}

fn binary_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "infraternal-x86_64-musl",
        Architecture::Aarch64 => "infraternal-aarch64-musl",
    }
}

/// Reads one HTTP request head from `socket`, waiting for as long as the client
/// takes. Returns `None` only when `stop` is raised first.
///
/// The bucket answers one connection at a time, so a client that connects and
/// is then descheduled (a loaded test host runs many suites at once) must not
/// fail the bucket: a fixed read deadline here measured the *client's*
/// scheduling delay, panicked the bucket thread with `WouldBlock`, and the
/// panic-in-destructor abort took the whole test process down (#509). The
/// short poll below exists only so a stopped bucket can leave its read.
fn read_request(
    socket: &mut std::net::TcpStream,
    stop: &std::sync::atomic::AtomicBool,
) -> Option<String> {
    socket
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut head = Vec::new();
    let mut chunk = [0; 4096];
    while !head.windows(4).any(|end| end == b"\r\n\r\n") {
        match socket.read(&mut chunk) {
            Ok(0) => break,
            Ok(size) => head.extend_from_slice(&chunk[..size]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
            }
            Err(error) => panic!("{error}"),
        }
    }
    Some(String::from_utf8(head).unwrap())
}

pub(crate) struct Bucket {
    pub(crate) origin: String,
    pub(crate) files: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    pub(crate) requests: Arc<AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}
impl Bucket {
    pub(crate) fn new(files: HashMap<String, Vec<u8>>) -> Self {
        Self::with_response(files, false)
    }
    /// Starts a bucket serving `files`; with `refused` it answers every request with an error status.
    fn with_response(files: HashMap<String, Vec<u8>>, refused: bool) -> Self {
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
                        let Some(request) = read_request(&mut socket, &stopping) else {
                            // Stopped before a client finished its request.
                            break;
                        };
                        let request = request.as_str();
                        let path = request.split_whitespace().nth(1).unwrap();
                        count.fetch_add(1, Ordering::Relaxed);
                        let files = data.lock().unwrap();
                        let body = if refused { None } else { files.get(path) };
                        let status = if refused {
                            "403 Forbidden"
                        } else if body.is_some() {
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
        Self::with_artifacts(size, version, extra, false)
    }
    fn with_sessions(version: &str) -> Self {
        Self::with_artifacts(1024, version, 0, true)
    }
    /// Builds a release of `size` bytes plus `extra` filler; `sessions` adds the session-capable artifact.
    fn with_artifacts(size: usize, version: &str, extra: usize, sessions: bool) -> Self {
        use sha2::{Digest, Sha256};
        use std::process::Command;
        // The downloader bounds every write and fsync at 30 s; the slow build disk's
        // fsync stalls exceed that, so the fixture lives on the private TMPDIR (#509).
        let root = std::env::temp_dir().join(format!("bucket-{}", uuid::Uuid::new_v4()));
        // The same fixture root owns latest-check staging and the payload cache.
        super::private_directory(&root).unwrap();
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
        // Both signed binaries let the same test exercise a remote download on x86_64 and aarch64.
        let full_payloads = [
            ("infraternal-aarch64-musl", payload.clone()),
            ("infraternal-x86_64-musl", payload),
        ];
        let version_name = version;
        let version = format!("{version}\n").into_bytes();
        let mut sums = format!("{:x}  VERSION\n", Sha256::digest(&version)).into_bytes();
        for (name, bytes) in &full_payloads {
            sums.extend_from_slice(format!("{:x}  {name}\n", Sha256::digest(bytes)).as_bytes());
        }
        let session_files = if sessions {
            vec![
                ("infraternal-x86_64-session-musl", b"x86 session".to_vec()),
                ("infraternal-aarch64-session-musl", b"arm session".to_vec()),
            ]
        } else {
            Vec::new()
        };
        for (name, bytes) in &session_files {
            sums.extend_from_slice(format!("{:x}  {name}\n", Sha256::digest(bytes)).as_bytes());
        }
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
        let files = full_payloads
            .into_iter()
            .chain([
                ("VERSION", version),
                ("SHA256SUMS", sums),
                ("SHA256SUMS.sig", signature),
            ])
            .chain(session_files)
            .map(|(name, bytes)| (format!("/releases/{version_name}/{name}"), bytes))
            .collect();
        Self { root, files, trust }
    }
    /// Build a release resolver against this test bucket and isolated cache.
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
            progress: tokio::sync::watch::channel(0).0,
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
    let arch = remote_arch();
    let path = resolver.resolve(arch).await.unwrap();
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    assert_eq!(std::fs::read(&path).unwrap(), vec![0x42; 1024]);
    assert_eq!(resolver.resolve(arch).await.unwrap(), path);
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    drop(bucket);
    assert_eq!(resolver.resolve(arch).await.unwrap(), path);
    std::fs::write(&path, b"tampered").unwrap();
    assert!(resolver.resolve(arch).await.is_err());
}

#[tokio::test]
async fn missing_wrong_version_tampered_network_and_development_only_fallback() {
    let release = Release::new(1024);
    let arch = remote_arch();
    let bucket = Bucket::new(release.files.clone());
    bucket.files.lock().unwrap().insert(
        format!("/releases/0.1.0/{}", binary_name(arch)),
        b"tampered".to_vec(),
    );
    let resolver = release.resolver(bucket.origin.clone(), "tampered", false);
    let error = resolver.resolve(arch).await.err().unwrap();
    assert_eq!(
        error.message,
        "the binary does not match the signed checksum."
    );
    let step = match arch {
        Architecture::Aarch64 => "Get the arm64 binary:",
        Architecture::X86_64 => "Get the x86_64 binary:",
    };
    assert!(format!("{error}").starts_with(step));
    assert!(
        !resolver
            .cache
            .join(format!("0.1.0/{}", architecture_label(arch)))
            .exists()
    );
    let mut wrong = release.resolver(bucket.origin.clone(), "version", false);
    wrong.version = "0.1.1".into();
    assert!(wrong.resolve(arch).await.is_err());
    let empty = Bucket::new(HashMap::new());
    let normal = release.resolver(empty.origin.clone(), "missing", false);
    assert!(normal.resolve(arch).await.is_err());
    let dev = release.resolver(empty.origin.clone(), "development", true);
    assert_eq!(
        dev.resolve(arch).await.unwrap(),
        dev.local.get(arch).to_path_buf()
    );
    drop(empty);
    assert!(
        dev.resolve(arch).await.is_err(),
        "offline is not an absent release"
    );
    assert_eq!(
        normal.resolve(host_arch()).await.unwrap(),
        normal.executable
    );
}

#[tokio::test]
#[ignore = "run release-profile measurements in a weighted scope"]
async fn cross_architecture_cold_and_warm_cache_measurements() {
    let release = Release::new(20 * 1024 * 1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "bench", false);
    let start = std::time::Instant::now();
    let arch = remote_arch();
    resolver.resolve(arch).await.unwrap();
    let cold = start.elapsed().as_secs_f64() * 1000.0;
    let mut samples = Vec::new();
    for _ in 0..50 {
        let start = std::time::Instant::now();
        resolver.resolve(arch).await.unwrap();
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let burst_start = std::time::Instant::now();
    let resolver = Arc::new(resolver);
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            resolver.resolve(arch).await.unwrap()
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
    let arch = remote_arch();
    let error = resolver
        .resolve(arch)
        .await
        .expect_err("a signed older release must not become this server version");
    assert_eq!(
        error.message,
        "the signed release belongs to another server version."
    );
    assert!(
        !resolver
            .cache
            .join(format!("0.1.1/{}", architecture_label(arch)))
            .exists()
    );
}

#[tokio::test]
async fn eight_concurrent_add_hosts_share_one_verified_download() {
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = Arc::new(release.resolver(bucket.origin.clone(), "concurrent", false));
    let arch = remote_arch();
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            resolver.resolve(arch).await.unwrap()
        }));
    }
    let expected = resolver.cache.join(format!(
        "0.1.0/{}/{}",
        architecture_label(arch),
        binary_name(arch)
    ));
    for task in tasks {
        assert_eq!(task.await.unwrap(), expected);
    }
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn a_missing_payload_never_enables_development_fallback() {
    let release = Release::new(1024);
    let arch = remote_arch();
    let mut files = release.files.clone();
    files.remove(&format!("/releases/0.1.0/{}", binary_name(arch)));
    let bucket = Bucket::new(files);
    let resolver = release.resolver(bucket.origin.clone(), "missing-payload", true);
    let error = resolver
        .resolve(arch)
        .await
        .expect_err("signed manifest without a payload must stop");
    assert_eq!(error.message, "this version has no matching release file.");
    assert!(
        !resolver
            .cache
            .join(format!("0.1.0/{}", architecture_label(arch)))
            .exists()
    );
}

#[tokio::test]
async fn cache_symlinks_and_shared_files_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "unsafe", false);
    let arch = remote_arch();
    let path = resolver.resolve(arch).await.unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(resolver.resolve(arch).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let retained = path.with_extension("retained");
    std::fs::rename(&path, &retained).unwrap();
    symlink(&retained, &path).unwrap();
    assert!(resolver.resolve(arch).await.is_err());
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}
// This subprocess helper lets the parent stop a real download without running
// Staging::drop, matching abrupt server termination rather than cancellation.
#[test]
#[ignore = "subprocess helper for release-cache restart verification"]
/// Run the isolated interrupted-download side of the restart fixture.
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
        progress: tokio::sync::watch::channel(0).0,
        trust: Some(std::env::var("REVIEW_RELEASE_TRUST").unwrap()),
    };
    tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(resolver.resolve(remote_arch()))
        .unwrap();
}

#[tokio::test]
/// A resolver restarted after the first process stopped mid-download reclaims the partial files and finishes.
async fn restarted_resolution_reclaims_partial_downloads_after_process_stop() {
    use std::process::{Command, Stdio};
    let release = Release::new(2 * 1024 * 1024);
    let bucket = Bucket::new(release.files.clone());
    let restarted = release.resolver(bucket.origin.clone(), "restart", false);
    let arch = remote_arch();
    let payload_name = binary_name(arch);
    let version = restarted.cache.join("0.1.0");
    // Repeat the abrupt stop: retention must be bounded across restarts, not
    // merely within one download. Each child writes one MiB before stopping.
    for _ in 0..2 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let files = release.files.clone();
        // Fired once the server has sent the payload's first MiB to the child.
        let (sent, body_sent) = tokio::sync::oneshot::channel::<()>();
        let mut sent = Some(sent);
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
                if path.ends_with(payload_name) {
                    socket.write_all(&body[..1024 * 1024]).await.unwrap();
                    if let Some(sent) = sent.take() {
                        let _ = sent.send(());
                    }
                    // The body deliberately remains incomplete until the child
                    // stops; successful verification/publication cannot happen.
                    let mut remaining = Vec::new();
                    let _ = socket.read_to_end(&mut remaining).await;
                } else {
                    socket.write_all(body).await.unwrap();
                }
            }
        });
        let before = partial_payload_bytes(&version, arch);
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
        // Starting the child means paging in the whole test executable, which on a
        // loaded host with the build disk stalled can take far longer than any
        // fixed bound; that is setup, not behaviour under test. So the child
        // gets no clock until it has asked for the payload: while it starts, the
        // only failure is the child dying. The 20 s bound then covers only what
        // this test is about, the child saving the MiB it was sent (#509).
        let mut body_sent = body_sent;
        while let Err(tokio::sync::oneshot::error::TryRecvError::Empty) = body_sent.try_recv() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "download child stopped before it asked for the payload"
            );
            // sleep: poll for the child's first payload request; its start has no deadline.
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while partial_payload_bytes(&version, arch) < before + 1024 * 1024 {
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
    let retained_before = partial_payload_bytes(&version, arch);
    assert_eq!(retained_before, 2 * 1024 * 1024);
    let ready = restarted.resolve(arch).await.unwrap();
    assert_eq!(std::fs::metadata(ready).unwrap().len(), 2 * 1024 * 1024);
    let retained_after = partial_payload_bytes(&version, arch);
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
fn partial_payload_bytes(version: &Path, arch: Architecture) -> u64 {
    std::fs::read_dir(version)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("download-"))
        .filter_map(|entry| std::fs::metadata(entry.path().join(binary_name(arch))).ok())
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
        resolver.resolve(host_arch()).await.unwrap(),
        resolver.executable
    );
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 0);
    let arch = remote_arch();
    let payload = resolver.resolve(arch).await.unwrap();
    assert!(payload.to_string_lossy().contains(version));
    assert_eq!(std::fs::read(&payload).unwrap(), vec![0x42; 1024]);
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    assert_eq!(resolver.resolve(arch).await.unwrap(), payload);
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}

/// Optional session artifacts still require this server's signed release on both architectures.
#[tokio::test]
async fn session_payloads_are_signed_on_both_architectures_and_reused_offline() {
    let release = Release::with_sessions("0.1.0");
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "sessions", false);
    for (arch, label, expected) in [
        (Architecture::X86_64, "x86_64", b"x86 session".as_slice()),
        (Architecture::Aarch64, "aarch64", b"arm session".as_slice()),
    ] {
        let path = resolver
            .session(arch)
            .await
            .unwrap()
            .expect("signed session");
        assert_eq!(
            path,
            resolver.cache.join(format!(
                "0.1.0/session/{label}/infraternal-{label}-session-musl"
            ))
        );
        assert_ne!(path, resolver.executable);
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 8);
    drop(bucket);
    for arch in [Architecture::X86_64, Architecture::Aarch64] {
        assert!(resolver.session(arch).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn concurrent_session_requests_publish_one_verified_artifact() {
    let release = Release::with_sessions("0.1.0");
    let bucket = Bucket::new(release.files.clone());
    let resolver = Arc::new(release.resolver(bucket.origin.clone(), "session-concurrent", false));
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let resolver = resolver.clone();
        tasks.push(tokio::spawn(async move {
            resolver
                .session(Architecture::X86_64)
                .await
                .unwrap()
                .unwrap()
        }));
    }
    let expected = resolver
        .cache
        .join("0.1.0/session/x86_64/infraternal-x86_64-session-musl");
    for task in tasks {
        assert_eq!(task.await.unwrap(), expected);
    }
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn signed_session_absence_is_cached_and_reauthenticated_offline() {
    let release = Release::new(1024);
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "session-absent", false);
    for arch in [Architecture::X86_64, Architecture::Aarch64] {
        assert!(resolver.session(arch).await.unwrap().is_none());
    }
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 6);
    drop(bucket);
    assert!(
        resolver
            .session(Architecture::X86_64)
            .await
            .unwrap()
            .is_none()
    );
    let cached = resolver.cache.join("0.1.0/session/x86_64");
    assert!(cached.join("SHA256SUMS.sig").is_file());
    std::fs::write(cached.join("VERSION"), b"another-version\n").unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
}

#[tokio::test]
async fn advertised_session_missing_digest_or_signature_never_falls_back() {
    let release = Release::with_sessions("0.1.0");
    for (case, file, replacement) in [
        ("missing", "infraternal-x86_64-session-musl", None),
        (
            "digest",
            "infraternal-x86_64-session-musl",
            Some(b"tampered".as_slice()),
        ),
        ("signature", "SHA256SUMS.sig", Some(b"invalid".as_slice())),
        ("version-digest", "VERSION", Some(b"other\n".as_slice())),
        ("manifest", "SHA256SUMS", Some(b"invalid\n".as_slice())),
    ] {
        let mut files = release.files.clone();
        let key = format!("/releases/0.1.0/{file}");
        if let Some(bytes) = replacement {
            files.insert(key, bytes.to_vec());
        } else {
            files.remove(&key);
        }
        let bucket = Bucket::new(files);
        let resolver = release.resolver(bucket.origin.clone(), case, true);
        // Even an existing trusted local artifact cannot hide a signed-release failure.
        std::fs::write(
            resolver
                .local
                .x86_64
                .with_file_name("infraternal-x86_64-session-musl"),
            b"local",
        )
        .unwrap();
        assert!(
            resolver.session(Architecture::X86_64).await.is_err(),
            "{case}"
        );
        assert!(
            !resolver.cache.join("0.1.0/session/x86_64").exists(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn signed_session_version_replay_and_untrusted_key_are_refused() {
    let release = Release::with_sessions("0.1.0");
    let replay = release
        .files
        .iter()
        .map(|(path, bytes)| (path.replace("/0.1.0/", "/0.1.1/"), bytes.clone()))
        .collect();
    let bucket = Bucket::new(replay);
    let mut resolver = release.resolver(bucket.origin.clone(), "session-replay", true);
    resolver.version = "0.1.1".into();
    let error = resolver.session(Architecture::X86_64).await.unwrap_err();
    assert_eq!(
        error.message,
        "the signed release belongs to another server version."
    );
    let other = Release::with_sessions("0.1.0");
    let bucket = Bucket::new(release.files.clone());
    let mut resolver = release.resolver(bucket.origin.clone(), "session-untrusted", true);
    resolver.trust = Some(other.trust.clone());
    assert!(resolver.session(Architecture::X86_64).await.is_err());
}

#[tokio::test]
async fn session_cache_refuses_shared_payloads_symlinks_and_unsafe_absence() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let release = Release::with_sessions("0.1.0");
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "session-unsafe", false);
    let path = resolver
        .session(Architecture::X86_64)
        .await
        .unwrap()
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let retained = path.with_extension("retained");
    std::fs::hard_link(&path, &retained).unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
    std::fs::remove_file(&retained).unwrap();
    std::fs::rename(&path, &retained).unwrap();
    symlink(&retained, &path).unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    let absent = Release::new(1024);
    let bucket = Bucket::new(absent.files.clone());
    let resolver = absent.resolver(bucket.origin.clone(), "unsafe-absence", false);
    assert!(
        resolver
            .session(Architecture::X86_64)
            .await
            .unwrap()
            .is_none()
    );
    let parent = resolver.cache.join("0.1.0/session");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
}

#[tokio::test]
async fn development_session_fallback_only_uses_trusted_local_artifacts_for_missing_release() {
    use std::os::unix::fs::symlink;
    let release = Release::new(1024);
    let bucket = Bucket::new(HashMap::new());
    let resolver = release.resolver(bucket.origin.clone(), "session-development", true);
    assert!(
        resolver
            .session(Architecture::X86_64)
            .await
            .unwrap()
            .is_none()
    );
    let session = resolver
        .local
        .x86_64
        .with_file_name("infraternal-x86_64-session-musl");
    std::fs::write(&session, b"trusted local").unwrap();
    assert_eq!(
        resolver.session(Architecture::X86_64).await.unwrap(),
        Some(session.clone())
    );
    std::fs::remove_file(&session).unwrap();
    symlink(&resolver.local.x86_64, &session).unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
    drop(bucket);
    assert!(
        resolver.session(Architecture::X86_64).await.is_err(),
        "offline is not a missing public release"
    );
}

#[test]
fn session_staging_cleanup_preserves_active_and_unknown_files() {
    use std::os::unix::fs::PermissionsExt;
    let release = Release::new(1024);
    let version = release.root.join("session-cleanup");
    private_directory(&version).unwrap();
    let path = version.join(format!("download-{}", uuid::Uuid::new_v4()));
    private_directory(&path).unwrap();
    let active = lock_directory(&path, nix::fcntl::FlockArg::LockExclusiveNonblock).unwrap();
    for name in [
        "infraternal-x86_64-session-musl",
        "infraternal-aarch64-session-musl",
    ] {
        let file = path.join(name);
        std::fs::write(&file, b"partial").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    cleanup_downloads(&version).unwrap();
    assert!(
        path.exists(),
        "active lifetime lock protects the staging directory"
    );
    // Release ownership without executing Staging::drop, as on process termination.
    drop(active);
    cleanup_downloads(&version).unwrap();
    assert!(!path.exists());
    let path = version.join(format!("download-{}", uuid::Uuid::new_v4()));
    private_directory(&path).unwrap();
    std::fs::write(path.join("unrelated"), b"preserve").unwrap();
    cleanup_downloads(&version).unwrap();
    assert!(path.exists());
}

#[tokio::test]
async fn refused_session_release_never_uses_development_fallback() {
    let release = Release::with_sessions("0.1.0");
    let bucket = Bucket::with_response(release.files.clone(), true);
    let resolver = release.resolver(bucket.origin.clone(), "session-refused", true);
    std::fs::write(
        resolver
            .local
            .x86_64
            .with_file_name("infraternal-x86_64-session-musl"),
        b"trusted local",
    )
    .unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn dangling_session_cache_symlink_is_refused_without_publication() {
    use std::os::unix::fs::symlink;
    let release = Release::with_sessions("0.1.0");
    let bucket = Bucket::new(release.files.clone());
    let resolver = release.resolver(bucket.origin.clone(), "session-dangling", false);
    private_directory(&resolver.cache).unwrap();
    private_directory(&resolver.cache.join("0.1.0")).unwrap();
    let session = resolver.cache.join("0.1.0/session");
    private_directory(&session).unwrap();
    let ready = session.join("x86_64");
    symlink(release.root.join("missing-cache"), &ready).unwrap();
    assert!(resolver.session(Architecture::X86_64).await.is_err());
    assert!(
        std::fs::symlink_metadata(&ready)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 0);
}

/// A client that connects and is then descheduled for longer than the old
/// bucket's fixed five-second read deadline is still answered, and the bucket
/// thread does not panic (#509). On a loaded host such a stall crashed the
/// bucket and aborted the whole test process; the bucket must wait for the
/// request for as long as it takes. The stall is real time on purpose: it is the
/// exact interval that failed before, and nothing asserts how fast the answer is.
#[test]
fn a_client_that_connects_then_stalls_is_still_answered() {
    let bucket = Bucket::new(HashMap::from([("/late".to_string(), b"payload".to_vec())]));
    let mut client =
        std::net::TcpStream::connect(bucket.origin.trim_start_matches("http://")).unwrap();
    // sleep: models a client descheduled between connect and send for longer than the old five-second read deadline.
    thread::sleep(Duration::from_millis(5_500));
    client
        .write_all(b"GET /late HTTP/1.1\r\nHost: bucket\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
    assert!(response.ends_with("payload"), "{response}");
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 1);
}
