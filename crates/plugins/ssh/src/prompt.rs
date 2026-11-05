//! Authorizes one private prompt reply to the owned login child's executable helper.

use crate::{model::Failure, transport::Secret};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
    process::Child,
};

#[derive(Clone, Default)]
pub(crate) struct PromptParent(Arc<AtomicU32>);
impl PromptParent {
    pub(crate) fn register(&self, child: &Child) -> Result<PromptLease, Failure> {
        let pid = child
            .id()
            .ok_or_else(|| Failure::install("The SSH prompt parent is unavailable."))?;
        self.0.store(pid, Ordering::Release);
        Ok(PromptLease(self.clone()))
    }

    fn permits(&self, stream: &UnixStream, binary: &crate::prompt_image::PromptImage) -> bool {
        let Ok(peer) = stream.peer_cred() else {
            return false;
        };
        if peer.uid() != nix::unistd::geteuid().as_raw() {
            return false;
        }
        let Some(pid) = peer.pid().filter(|pid| *pid > 0) else {
            return false;
        };
        let parent = self.0.load(Ordering::Acquire);
        if parent == 0 {
            return false;
        }
        // Peer identity comes from SO_PEERCRED, never a request field. Require
        // the exact helper executable and direct parent, not arbitrary members
        // of the login process group (which includes public lookup commands).
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let direct_parent = std::fs::read_to_string(proc.join("status")).is_ok_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .and_then(|value| value.trim().parse::<u32>().ok())
                == Some(parent)
        });
        direct_parent && binary.matches(&proc.join("exe"))
    }
}

pub(crate) struct PromptLease(PromptParent);
impl Drop for PromptLease {
    fn drop(&mut self) {
        self.0.0.store(0, Ordering::Release);
    }
}

pub(crate) async fn serve(
    listener: UnixListener,
    secret: Secret,
    parent: PromptParent,
    binary: crate::prompt_image::PromptImage,
) {
    // An unrelated connection cannot consume the single authorized reply.
    // The session owns the deadline and aborts this task on cancellation.
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        if !parent.permits(&stream, &binary) {
            continue;
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            stream.write_all(secret.expose()).await?;
            stream.shutdown().await
        })
        .await;
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use tokio::io::AsyncReadExt;

    // The helper is verified through /proc/<pid>; without /proc (macOS) every
    // helper is refused, so the "served once" half can only pass on Linux.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn helper_reply_requires_the_registered_parent_and_is_served_once() {
        let root = PathBuf::from(std::env::var_os("HOME").unwrap())
            .join(".cache/codex-scratch/ssh-bootstrap");
        std::fs::create_dir_all(&root).unwrap();
        let socket = root.join(format!(
            "p-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let listener = UnixListener::bind(&socket).unwrap();
        let image_directory = root.join(format!("image-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&image_directory).unwrap();
        let (helper, image) = if std::env::var_os("INFRATERNAL_ANONYMOUS_PROMPT_ORACLE").is_some() {
            let started = std::time::Instant::now();
            let result = crate::prompt_image::materialize(
                std::path::Path::new("/proc/self/exe"),
                &image_directory,
            )
            .unwrap();
            println!(
                "PROMPT_IMAGE bytes={} preparation_ms={:.3}",
                std::fs::metadata(&result.0).unwrap().len(),
                started.elapsed().as_secs_f64() * 1000.0
            );
            result
        } else {
            // The normal oracle needs a real executable, not tens of megabytes
            // of unrelated Rust debug sections. The explicit optimized anonymous
            // oracle separately exercises a copy of the entire running image.
            let helper = image_directory.join("reply");
            assert!(
                std::process::Command::new("cc")
                    .args(["-O2", "-o"])
                    .arg(&helper)
                    .arg(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("tests/fixtures/prompt-reply.c")
                    )
                    .status()
                    .unwrap()
                    .success()
            );
            let image = crate::prompt_image::PromptImage::open(&helper).unwrap();
            (helper, image)
        };
        let parent = PromptParent::default();
        let task = tokio::spawn(serve(
            listener,
            Secret::new(b"synthetic-reply".to_vec()),
            parent.clone(),
            image,
        ));
        // A live registered login parent does not authorize another process
        // with the same executable and uid but a different direct parent.
        let mut unrelated = tokio::process::Command::new("/bin/sleep")
            .arg("10")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let unrelated_lease = parent.register(&unrelated).unwrap();
        let mut foreign = UnixStream::connect(&socket).await.unwrap();
        let mut reply = Vec::new();
        foreign.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply.len(), 0);
        drop(unrelated_lease);
        unrelated.kill().await.unwrap();
        let mut child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(
                r#""$1" --exact prompt::tests::reply_fixture --ignored; result=$?; exit "$result""#,
            )
            .arg("prompt-fixture")
            .arg(helper)
            .env("INFRATERNAL_PROMPT_FIXTURE", &socket)
            .spawn()
            .unwrap();
        let lease = parent.register(&child).unwrap();
        assert!(child.wait().await.unwrap().success());
        task.await.unwrap();
        drop(lease);
        std::fs::remove_file(socket).unwrap();
        std::fs::remove_dir_all(image_directory).unwrap();
    }

    #[test]
    #[ignore = "private subprocess for the one-reply peer oracle"]
    fn reply_fixture() {
        use std::io::Read;
        let path = std::env::var_os("INFRATERNAL_PROMPT_FIXTURE").unwrap();
        let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"synthetic-reply");
        // The listening socket closes after its first authorized reply.
        if let Ok(mut second) = std::os::unix::net::UnixStream::connect(path) {
            second
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reply = Vec::new();
            let _ = second.read_to_end(&mut reply);
            assert_eq!(reply.len(), 0);
        }
    }
}
