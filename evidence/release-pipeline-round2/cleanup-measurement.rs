//! Appended to the exact release payload test module in the scratch harness to measure startup reclamation.

#[test]
#[ignore = "weighted exact-source cache cleanup measurement"]
fn fifty_abandoned_downloads_startup_measurement() {
    use std::os::unix::fs::OpenOptionsExt;
    let release = Release::new(1024);
    let resolver = release.resolver("http://127.0.0.1:1".into(), "startup-bench", false);
    private_directory(&resolver.cache).unwrap();
    let version = resolver.cache.join("0.1.0");
    private_directory(&version).unwrap();
    for _ in 0..50 {
        let path = version.join(format!("download-{}", uuid::Uuid::new_v4()));
        private_directory(&path).unwrap();
        let file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600)
            .open(path.join("infraternal-aarch64-musl")).unwrap();
        // Sparse payloads isolate directory/file metadata work from fixture I/O.
        // Reclamation unlinks files; it never reads their logical payload bytes.
        file.set_len(20 * 1024 * 1024).unwrap();
    }
    let started = std::time::Instant::now();
    let _new = ReleasePayload::new(resolver.executable.clone(), resolver.local,
        resolver.cache.parent().unwrap());
    let elapsed = started.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(std::fs::read_dir(&version).unwrap().count(), 0);
    println!("METRIC name=release_cache_startup_cleanup abandoned_downloads=50 logical_bytes=1048576000 sparse_fixture=true retained_after_bytes=0 elapsed_ms={elapsed:.3}");
}
