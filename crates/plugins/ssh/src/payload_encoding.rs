//! Prepares bounded public payload encodings once per file identity; no credential enters a compressor (#190).

use crate::{model::Failure, payload::Identity};
use std::{path::Path, process::Stdio, sync::Arc};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};

const LIMIT: usize = 64 * 1024 * 1024;
static CACHE: Mutex<Vec<Entry>> = Mutex::const_new(Vec::new());

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    Zstd,
    Gzip,
}
impl Codec {
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
struct Entry {
    identity: Identity,
    codec: Codec,
    bytes: Arc<[u8]>,
}

/// Four bounded entries cover two architectures and two optional codecs.
/// Missing tools and oversized/non-improving results preserve raw streaming.
pub(crate) async fn encoded(path: &Path, codec: Codec) -> Result<Option<Arc<[u8]>>, Failure> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| unavailable())?;
    let metadata = file.metadata().await.map_err(|_| unavailable())?;
    // Small executables do not repay codec/process overhead. Oversized trusted
    // files retain bounded raw streaming instead of occupying the server cache.
    if metadata.len() < 64 * 1024 || metadata.len() > LIMIT as u64 {
        return Ok(None);
    }
    let identity = Identity::of(&metadata);
    let mut cache = CACHE.lock().await;
    if let Some(entry) = cache
        .iter()
        .find(|entry| entry.identity == identity && entry.codec == codec)
    {
        return Ok(Some(entry.bytes.clone()));
    }
    let mut command = codec.command();
    command
        .stdin(Stdio::from(file.into_std().await))
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
    let current = tokio::fs::metadata(path).await.map_err(|_| unavailable())?;
    if Identity::of(&current) != identity {
        return Err(Failure::install(
            "The static infraternal binary changed while being read. Retry host provisioning.",
        ));
    }
    if bytes.len() as u64 >= current.len() {
        return Ok(None);
    }
    let bytes: Arc<[u8]> = bytes.into();
    if cache.len() == 4 {
        cache.remove(0);
    }
    cache.push(Entry {
        identity,
        codec,
        bytes: bytes.clone(),
    });
    Ok(Some(bytes))
}

fn unavailable() -> Failure {
    Failure::install("The static infraternal binary could not be read.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = crate::test_common::scratch()
                .join(format!("encoded-{}", uuid::Uuid::new_v4().simple()));
            std::fs::write(&path, vec![b'x'; 128 * 1024]).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
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
        let first = encoded(&fixture.0, Codec::Gzip).await.unwrap().unwrap();
        let second = encoded(&fixture.0, Codec::Gzip).await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(unpack(&first).await, std::fs::read(&fixture.0).unwrap());
    }

    #[tokio::test]
    async fn binary_replacement_never_reuses_the_previous_encoding() {
        let fixture = Fixture::new();
        let first = encoded(&fixture.0, Codec::Gzip).await.unwrap().unwrap();
        let next = fixture.0.with_extension("next");
        std::fs::write(&next, vec![b'y'; 128 * 1024]).unwrap();
        std::fs::rename(&next, &fixture.0).unwrap();
        let second = encoded(&fixture.0, Codec::Gzip).await.unwrap().unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(unpack(&second).await, std::fs::read(&fixture.0).unwrap());
    }

    #[tokio::test]
    async fn small_payloads_retain_raw_streaming() {
        let fixture = Fixture::new();
        std::fs::write(&fixture.0, b"small public payload").unwrap();
        assert!(encoded(&fixture.0, Codec::Gzip).await.unwrap().is_none());
    }
}
