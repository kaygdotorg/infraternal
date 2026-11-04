//! Prepares bounded public payload encodings once per file identity; no credential enters a compressor (#190).
//!
//! The infraternal binary uploaded to a host is public, so it can be compressed
//! once on the server and reused for every host. The compressor is a fixed
//! system tool run with the file on stdin; nothing secret is ever given to it.
//! Results are cached by file identity (device, inode, size and times), never by
//! path name, and a file that changes while being compressed is refused. Whenever
//! compression does not help (tool missing, failure, output too big or not
//! smaller), the caller gets `None` and streams the raw bytes instead.

use crate::{model::Failure, payload::Identity};
use std::{path::Path, process::Stdio, sync::Arc};
use tokio::{
    io::AsyncReadExt,
    process::Command,
    sync::{Mutex, OnceCell},
};

/// Largest file we compress and largest result we keep in memory (64 MiB).
const LIMIT: usize = 64 * 1024 * 1024;
/// Process-wide cache, at most eight entries, oldest evicted first.
static CACHE: Mutex<Vec<Entry>> = Mutex::const_new(Vec::new());

/// Compression format of an encoded payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    /// Zstandard at level 9, one thread.
    Zstd,
    /// Gzip at level 9 without a stored file name or time, so output is reproducible.
    Gzip,
}
impl Codec {
    /// The compressor command at a fixed absolute path (not found through `PATH`), writing to stdout.
    fn command(self) -> Command {
        match self {
            Self::Zstd => {
                let mut command = Command::new("/usr/bin/zstd");
                command.args(["-q", "-9", "-T1", "-c"]);
                command
            }
            Self::Gzip => {
                let mut command = Command::new("/usr/bin/gzip");
                command.args(["-n", "-9", "-c"]);
                command
            }
        }
    }
}
/// One cached encoding, keyed by file identity and codec.
struct Entry {
    /// Identity of the source file when it was read.
    identity: Identity,
    /// Format of the encoding.
    codec: Codec,
    /// Single-flight cell: concurrent callers wait for the same compression.
    /// Holds `None` when raw streaming should be used instead.
    bytes: Arc<OnceCell<Option<Arc<[u8]>>>>,
}

/// The compressed bytes of the file at `path`, shared and computed at most once per identity.
///
/// Eight bounded entries cover full/session payloads, two architectures and two codecs.
/// Missing tools and oversized/non-improving results preserve raw streaming.
/// Returns `Ok(None)` for that, and for files under 64 KiB or over 64 MiB. Fails
/// if the file cannot be read or changed during compression.
pub(crate) async fn encoded(path: &Path, codec: Codec) -> Result<Option<Arc<[u8]>>, Failure> {
    // Opening and inspecting a local file are short syscalls; the compressor
    // reads the file itself, so no async file machinery is needed here.
    let file = std::fs::File::open(path).map_err(|_| unavailable())?;
    let metadata = file.metadata().map_err(|_| unavailable())?;
    // Small executables do not repay codec/process overhead. Oversized trusted
    // files retain bounded raw streaming instead of occupying the server cache.
    if metadata.len() < 64 * 1024 || metadata.len() > LIMIT as u64 {
        return Ok(None);
    }
    let identity = Identity::of(&metadata);
    // The global index protects only lookup/eviction. Each file/codec has its
    // own single-flight cell, so one slow compressor cannot block other hosts.
    let cell = {
        let mut cache = CACHE.lock().await;
        if let Some(entry) = cache
            .iter()
            .find(|entry| entry.identity == identity && entry.codec == codec)
        {
            entry.bytes.clone()
        } else {
            let cell = Arc::new(OnceCell::new());
            if cache.len() == 8 {
                cache.remove(0);
            }
            cache.push(Entry {
                identity,
                codec,
                bytes: cell.clone(),
            });
            cell
        }
    };
    cell.get_or_try_init(|| compress(path, file, identity, codec))
        .await
        .cloned()
}

/// Run the codec on the already opened `file` and collect at most 64 MiB of output.
///
/// The child's stderr is discarded. Returns `None` if the tool cannot start,
/// exits with failure, exceeds the limit, or its output is not smaller than the
/// input. Errors if the file at `path` no longer has `identity` afterwards,
/// because the encoding might then not match what was hashed or promised.
async fn compress(
    path: &Path,
    file: std::fs::File,
    identity: Identity,
    codec: Codec,
) -> Result<Option<Arc<[u8]>>, Failure> {
    let mut command = codec.command();
    command
        .stdin(Stdio::from(file))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let Ok(mut child) = command.spawn() else {
        return Ok(None);
    };
    let stdout = child.stdout.take().ok_or_else(unavailable)?;
    let mut bytes = Vec::new();
    stdout
        .take(u64::try_from(LIMIT).map_err(|_| unavailable())? + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| unavailable())?;
    if bytes.len() > LIMIT {
        let _ = child.kill().await;
        return Ok(None);
    }
    if !child.wait().await.map_err(|_| unavailable())?.success() {
        return Ok(None);
    }
    let current = std::fs::metadata(path).map_err(|_| unavailable())?;
    if Identity::of(&current) != identity {
        return Err(Failure::install(
            "The static infraternal binary changed while being read. Retry host provisioning.",
        ));
    }
    if bytes.len() as u64 >= current.len() {
        return Ok(None);
    }
    let bytes: Arc<[u8]> = bytes.into();
    Ok(Some(bytes))
}

/// Generic read failure with no path or system detail.
fn unavailable() -> Failure {
    Failure::install("The static infraternal binary could not be read.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    struct Fixture {
        path: std::path::PathBuf,
        _scratch: crate::test_common::ScratchRoot,
    }
    impl Fixture {
        fn new() -> Self {
            let scratch = crate::test_common::scratch();
            let path = scratch.join(format!("encoded-{}", uuid::Uuid::new_v4().simple()));
            std::fs::write(&path, vec![b'x'; 128 * 1024]).unwrap();
            Self {
                path,
                _scratch: scratch,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn unpack(bytes: &[u8]) -> Vec<u8> {
        let mut child = Command::new("/usr/bin/gzip")
            .args(["-dc"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(bytes).await.unwrap();
        drop(input);
        let output = child.wait_with_output().await.unwrap();
        assert!(output.status.success());
        output.stdout
    }

    #[tokio::test]
    async fn gzip_roundtrip_and_repeated_adds_share_one_encoding() {
        let fixture = Fixture::new();
        let (first, second) = tokio::join!(
            encoded(&fixture.path, Codec::Gzip),
            encoded(&fixture.path, Codec::Gzip)
        );
        let first = first.unwrap().unwrap();
        let second = second.unwrap().unwrap();
        let third = encoded(&fixture.path, Codec::Gzip).await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert!(Arc::ptr_eq(&first, &third));
        assert_eq!(unpack(&first).await, std::fs::read(&fixture.path).unwrap());
    }

    #[tokio::test]
    async fn binary_replacement_never_reuses_the_previous_encoding() {
        let fixture = Fixture::new();
        let first = encoded(&fixture.path, Codec::Gzip).await.unwrap().unwrap();
        let next = fixture.path.with_extension("next");
        std::fs::write(&next, vec![b'y'; 128 * 1024]).unwrap();
        std::fs::rename(&next, &fixture.path).unwrap();
        let second = encoded(&fixture.path, Codec::Gzip).await.unwrap().unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(unpack(&second).await, std::fs::read(&fixture.path).unwrap());
    }

    #[tokio::test]
    async fn small_payloads_retain_raw_streaming() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.path, b"small public payload").unwrap();
        assert!(encoded(&fixture.path, Codec::Gzip).await.unwrap().is_none());
    }
}
