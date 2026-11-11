//! Makes a fixed-path nft executable safe to use inside the privileged test sandbox.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Give each test process a private executable directory under its `/run` tmpfs.
static NEXT_NFT_FIXTURE: AtomicU64 = AtomicU64::new(0);

/// A temporary copy of nft owned by the test's mapped root inside its namespace.
pub struct NftFixture {
    /// The private directory that keeps the copied executable's path trusted.
    directory: PathBuf,
    /// The executable path passed to the product's strict root-owned resolver.
    path: PathBuf,
}

impl NftFixture {
    /// Copy an executable from the product's fixed candidates into private `/run` storage.
    ///
    /// The gate maps host root to UID 65534 inside its sandbox, so the host-owned source
    /// cannot pass the product's root-owner check there. The copy is owned by the sandbox
    /// root, remains below private tmpfs, and is still checked by the production resolver.
    #[expect(
        clippy::expect_used,
        reason = "fixture setup failures must identify the unavailable sandbox resource"
    )]
    #[must_use]
    pub fn new(fixed_candidates: &[&str]) -> Self {
        let source = source_candidate(fixed_candidates).expect("fixed-path nft executable");
        let sequence = NEXT_NFT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let directory = Path::new("/run").join(format!(
            "infraternal-nft-fixture-{}-{sequence}",
            std::process::id()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&directory)
            .expect("private nft fixture directory");
        let path = directory.join("nft");
        fs::copy(source, &path).expect("copy fixed nft executable into /run");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("make the test nft executable runnable");
        Self { directory, path }
    }

    /// Return the namespace-local path accepted by the normal root-owner checks.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for NftFixture {
    /// Remove only this test's copied executable and private directory.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// Find one executable among the fixed system candidates and the Nix store.
fn source_candidate(fixed_candidates: &[&str]) -> Option<PathBuf> {
    let fixed = fixed_candidates.iter().copied().map(PathBuf::from);
    let candidates = fixed.chain(nix_store_candidates());
    candidates.into_iter().find_map(|candidate| {
        let resolved = candidate.canonicalize().ok()?;
        let metadata = fs::metadata(&resolved).ok()?;
        (metadata.is_file() && metadata.permissions().mode() & 0o111 != 0).then_some(resolved)
    })
}

/// Read only package paths beneath `/nix/store`, where Nix keeps immutable tools.
fn nix_store_candidates() -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir("/nix/store") else {
        return Vec::new();
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains("-nftables-"))
        .map(|entry| entry.path().join("bin/nft"))
        .collect::<Vec<_>>();
    paths.sort();
    paths.reverse();
    paths
}
