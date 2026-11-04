//! Caches public payload hashes for the two configured architectures without trusting path names (#190, D17).
//!
//! Provisioning a host needs the SHA-256 of the infraternal binary to upload.
//! Hashing a large file for every host would be wasteful, so digests are cached
//! by file identity (device, inode, size, modification and change times), not by
//! path. A replaced or edited file therefore gets a new identity and is hashed
//! again. The digest is only an offer: the target host still verifies the bytes
//! it receives or reuses before running them.

use crate::model::Failure;
use sha2::{Digest, Sha256};
use std::{os::unix::fs::MetadataExt, path::Path, sync::Arc};
use tokio::sync::Mutex;

// A server has two architectures with full and optional session payloads. Keep this bound even when settings point at new
// files; no host, attempt or version can grow the process cache indefinitely.
static CACHE: PayloadCache = PayloadCache {
    entries: Mutex::const_new(Vec::new()),
};

/// What makes a file "the same file": two files with equal identity are treated as identical content.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Identity {
    /// Device number of the filesystem.
    device: u64,
    /// Inode number.
    inode: u64,
    /// Size in bytes.
    size: u64,
    /// Modification time as seconds and nanoseconds.
    modified: (i64, i64),
    /// Status-change time as seconds and nanoseconds.
    changed: (i64, i64),
}
impl Identity {
    /// Take the identity from file metadata (no file content is read).
    pub(super) fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            // ctime detects in-place edits even when a writer restores mtime.
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}
/// A cached digest for one file identity.
struct Entry {
    /// Identity of the file that was hashed.
    identity: Identity,
    /// Lower-case hex SHA-256, shared between callers.
    digest: Arc<str>,
}
/// Small cache (at most four entries, oldest evicted first).
#[derive(Default)]
struct PayloadCache {
    /// Entries behind an async lock that is also held during a miss's hashing.
    entries: Mutex<Vec<Entry>>,
}

/// Lower-case hex SHA-256 of the file at `path`, from the process-wide cache.
///
/// Fails with an install error if the file is missing, unreadable or changes
/// while being read.
pub(crate) async fn digest(path: &Path) -> Result<Arc<str>, Failure> {
    CACHE.digest(path).await
}

impl PayloadCache {
    /// Look up `path` by identity; on a miss hash it on a blocking thread and store the result.
    async fn digest(&self, path: &Path) -> Result<Arc<str>, Failure> {
        // Local metadata is a short syscall; only the full read leaves the
        // executor. One blocking task per miss replaces a blocking hop per
        // 64 KiB read and keeps async file machinery out of the binary.
        let identity = Identity::of(&std::fs::metadata(path).map_err(|_| {
            Failure::install("The matching static infraternal binary is unavailable.")
        })?);
        // Serialize only cache misses, including their read. Concurrent adds
        // cannot hash the same immutable binary eight times at server startup.
        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.iter().find(|entry| entry.identity == identity) {
            return Ok(entry.digest.clone());
        }
        let path = path.to_path_buf();
        let digest = tokio::task::spawn_blocking(move || hash(&path, identity))
            .await
            .map_err(|_| unreadable())??;
        if entries.len() == 4 {
            entries.remove(0);
        }
        entries.push(Entry {
            identity,
            digest: digest.clone(),
        });
        Ok(digest)
    }
}

/// Hash one exact file identity; a replacement during the read is refused.
fn hash(path: &Path, identity: Identity) -> Result<Arc<str>, Failure> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)
        .map_err(|_| Failure::install("The matching static infraternal binary is unavailable."))?;
    if Identity::of(&file.metadata().map_err(|_| unreadable())?) != identity {
        return Err(changed());
    }
    let mut hash = Sha256::new();
    let mut bytes = vec![0; 64 * 1024];
    loop {
        let count = file.read(&mut bytes).map_err(|_| unreadable())?;
        if count == 0 {
            break;
        }
        hash.update(&bytes[..count]);
    }
    // Never publish a digest assembled across an in-place replacement.
    // The target still verifies the uploaded/reused bytes before execution.
    if Identity::of(&file.metadata().map_err(|_| unreadable())?) != identity {
        return Err(changed());
    }
    Ok(format!("{:x}", hash.finalize()).into())
}

/// Error for a file replaced or edited while it was being hashed.
fn changed() -> Failure {
    Failure::install(
        "The static infraternal binary changed while being read. Retry host provisioning.",
    )
}

/// Generic read failure with no path or system detail.
fn unreadable() -> Failure {
    Failure::install("The static infraternal binary could not be read.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_common as common;

    struct Fixture {
        path: std::path::PathBuf,
        _scratch: common::ScratchRoot,
    }
    impl Fixture {
        fn new() -> Self {
            let scratch = common::scratch();
            let root = scratch.join(format!("payload-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir(&root).unwrap();
            Self {
                path: root,
                _scratch: scratch,
            }
        }
        fn file(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
            let path = self.path.join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn concurrent_adds_share_the_cached_digest_allocation() {
        let fixture = Fixture::new();
        let path = fixture.file("payload", b"public executable bytes");
        let cache = PayloadCache::default();
        let (a, b, c, d) = tokio::join!(
            cache.digest(&path),
            cache.digest(&path),
            cache.digest(&path),
            cache.digest(&path)
        );
        let a = a.unwrap();
        for digest in [b.unwrap(), c.unwrap(), d.unwrap()] {
            assert!(Arc::ptr_eq(&a, &digest));
        }
        assert_eq!(cache.entries.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn same_size_in_place_edits_with_restored_mtime_invalidate_the_digest() {
        let fixture = Fixture::new();
        let path = fixture.file("payload", b"before");
        let cache = PayloadCache::default();
        let original = cache.digest(&path).await.unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        // Linux's filesystem ctime clock can share one tick across rapid writes.
        // Give this fixture a distinct ctime while deliberately restoring mtime;
        // target-side verification remains mandatory even for a cache hit.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        std::fs::write(&path, b"after!").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_ne!(original, cache.digest(&path).await.unwrap());
    }

    #[tokio::test]
    async fn replacement_and_removal_never_reuse_a_path_name_digest() {
        let fixture = Fixture::new();
        let path = fixture.file("payload", b"before");
        let cache = PayloadCache::default();
        let original = cache.digest(&path).await.unwrap();
        let replacement = fixture.file("replacement", b"after!");
        std::fs::rename(replacement, &path).unwrap();
        assert_ne!(original, cache.digest(&path).await.unwrap());
        std::fs::remove_file(&path).unwrap();
        assert!(cache.digest(&path).await.is_err());
    }

    #[tokio::test]
    async fn settings_changes_keep_at_most_four_entries() {
        let fixture = Fixture::new();
        let cache = PayloadCache::default();
        for index in 0..8 {
            let path = fixture.file(&index.to_string(), &[index]);
            cache.digest(&path).await.unwrap();
            assert!(cache.entries.lock().await.len() <= 4);
        }
    }

    #[tokio::test]
    #[ignore = "#190 public payload hash/cache measurements on the locked perf VM only"]
    async fn payload_hash_cache_at_1600_adds() {
        let path =
            std::path::PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
        let mut misses = Vec::new();
        for _ in 0..10 {
            let started = std::time::Instant::now();
            PayloadCache::default().digest(&path).await.unwrap();
            misses.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        let cache = PayloadCache::default();
        let digest = cache.digest(&path).await.unwrap();
        let mut hits = Vec::new();
        for _ in 0..1600 {
            let started = std::time::Instant::now();
            assert!(Arc::ptr_eq(&digest, &cache.digest(&path).await.unwrap()));
            hits.push(started.elapsed().as_secs_f64() * 1000.0);
        }
        misses.sort_by(f64::total_cmp);
        hits.sort_by(f64::total_cmp);
        let entries = cache.entries.lock().await;
        println!(
            "METRIC payload_hash samples=10 miss_p50_ms={:.3} miss_p95_ms={:.3} adds=1600 hit_p50_ms={:.3} hit_p95_ms={:.3} entries={} capacity={} inline_entry_bytes={} digest_bytes={}",
            f64::midpoint(misses[4], misses[5]),
            misses[9],
            f64::midpoint(hits[799], hits[800]),
            hits[1519],
            entries.len(),
            entries.capacity(),
            std::mem::size_of::<Entry>(),
            digest.len(),
        );
        println!(
            "ENVIRONMENT machine={} cores={} load={}",
            std::fs::read_to_string("/proc/sys/kernel/hostname")
                .unwrap()
                .trim(),
            std::thread::available_parallelism().unwrap().get(),
            std::fs::read_to_string("/proc/loadavg").unwrap().trim(),
        );
    }
}
