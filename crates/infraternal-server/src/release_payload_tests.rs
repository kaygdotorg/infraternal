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

struct Bucket {
    origin: String,
    files: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    requests: Arc<AtomicUsize>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}
impl Bucket {
    fn new(files: HashMap<String, Vec<u8>>) -> Self {
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

struct Release {
    root: PathBuf,
    files: HashMap<String, Vec<u8>>,
    trust: String,
}
impl Release {
    fn new(size: usize) -> Self {
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
        let version = b"0.1.0\n".to_vec();
        let sums = format!(
            "{:x}  {name}\n{:x}  VERSION\n",
            Sha256::digest(&payload),
            Sha256::digest(&version)
        )
        .into_bytes();
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
        .map(|(name, bytes)| (format!("/releases/0.1.0/{name}"), bytes))
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
