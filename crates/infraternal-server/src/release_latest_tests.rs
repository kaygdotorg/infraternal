//! Loopback OpenSSH fixtures authenticate pointer VERSION before any channel result is trusted [224,226].
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::release_payload::tests::{Bucket, Release};
use infraternal_plugin_release::descriptor::{EDGE_OPT_IN, STABLE_EMPTY};
use infraternal_plugin_release::service::ReleaseLookup;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn stable_empty_reports_opt_in_without_edge_request() {
    let release = Release::new(16);
    let bucket = Bucket::new(release.files.clone());
    let lookup = VerifiedLookup::new(
        release.root.clone(),
        bucket.origin.clone(),
        Arc::new(Engine {
            trust: Some(release.trust.clone()),
        }),
    );
    let result = lookup.latest("stable").await.unwrap();
    assert_eq!(result["message"], STABLE_EMPTY);
    assert_eq!(result["next"], EDGE_OPT_IN);
    assert!(
        result["next"]
            .as_str()
            .unwrap()
            .contains("infraternal server channel edge")
    );
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 1);
    assert_eq!(
        std::fs::read_dir(&release.root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e
                .file_name()
                .to_string_lossy()
                .starts_with("release-check-"))
            .count(),
        0
    );
}
#[tokio::test]
async fn pointer_authenticates_signed_version_and_refuses_replays_tampering_and_duplicates() {
    let release = Release::new(16);
    let bucket = Bucket::new(release.files.clone());
    let pointer = "/releases/channels/stable.json";
    bucket.files.lock().unwrap().insert(
        pointer.into(),
        br#"{"version":"0.1.0","channel":"edge"}"#.to_vec(),
    );
    let lookup = VerifiedLookup::new(
        release.root.clone(),
        bucket.origin.clone(),
        Arc::new(Engine {
            trust: Some(release.trust.clone()),
        }),
    );
    // The unsigned channel field never overrides the authenticated version grammar.
    assert_eq!(lookup.latest("stable").await.unwrap()["version"], "0.1.0");
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
    {
        let mut files = bucket.files.lock().unwrap();
        for name in ["SHA256SUMS", "SHA256SUMS.sig", "VERSION"] {
            let body = files[&format!("/releases/0.1.0/{name}")].clone();
            files.insert(format!("/releases/0.1.1/{name}"), body);
        }
        files.insert(pointer.into(), br#"{"version":"0.1.1"}"#.to_vec());
    }
    assert_eq!(
        lookup.latest("stable").await,
        Err("signed VERSION does not match the release pointer")
    );
    bucket
        .files
        .lock()
        .unwrap()
        .insert(pointer.into(), br#"{"version":"0.1.0"}"#.to_vec());
    bucket
        .files
        .lock()
        .unwrap()
        .insert("/releases/0.1.0/VERSION".into(), b"0.1.1\n".to_vec());
    assert_eq!(
        lookup.latest("stable").await,
        Err("release VERSION could not be verified")
    );
    for body in [
        br#"{"version":"0.1.0","version":"0.1.1"}"#.as_slice(),
        br#"{"version":"edge-20261011T071500Z"}"#,
        br#"{"version":"0.1.0-rc1"}"#,
        br#"{"version":"../0.1.0"}"#,
        br#"["0.1.0"]"#,
        br#"{"version":"0.1.0","files":[{"version":"a","version":"b"}]}"#,
    ] {
        bucket
            .files
            .lock()
            .unwrap()
            .insert(pointer.into(), body.to_vec());
        let before = bucket.requests.load(Ordering::Relaxed);
        assert!(lookup.latest("stable").await.is_err());
        assert_eq!(bucket.requests.load(Ordering::Relaxed), before + 1);
    }
}
#[tokio::test]
async fn edge_pointer_is_verified_in_its_own_channel() {
    let version = "edge-20261011T071500Z";
    let release = Release::with_version(16, version);
    let bucket = Bucket::new(release.files.clone());
    bucket.files.lock().unwrap().insert(
        "/releases/channels/edge.json".into(),
        format!("{{\"version\":\"{version}\"}}").into_bytes(),
    );
    let lookup = VerifiedLookup::new(
        release.root.clone(),
        bucket.origin.clone(),
        Arc::new(Engine {
            trust: Some(release.trust.clone()),
        }),
    );
    assert_eq!(lookup.latest("edge").await.unwrap()["version"], version);
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "local weighted-scope verification latency benchmark"]
async fn bench_bounded_metadata_verification() {
    println!(
        "host={} arch={} cores={} load={}",
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::env::consts::ARCH,
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    for extra in [0, 825] {
        let release = Release::with_manifest_entries(16, "edge-20261011T071500Z", extra);
        let base = "/releases/edge-20261011T071500Z/";
        let file = release.root.join("VERSION");
        std::fs::write(&file, &release.files[&format!("{base}VERSION")]).unwrap();
        let fd = Arc::new(std::fs::File::open(file).unwrap());
        let sums = Arc::new(release.files[&format!("{base}SHA256SUMS")].clone());
        let sig = Arc::new(release.files[&format!("{base}SHA256SUMS.sig")].clone());
        if extra > 0 {
            assert!((65000..=65536).contains(&sums.len()));
        }
        let engine = Arc::new(Engine {
            trust: Some(release.trust.clone()),
        });
        for blocking in [false, true] {
            let mut times = Vec::new();
            for _ in 0..200 {
                let (fd, sums, sig, engine) =
                    (fd.clone(), sums.clone(), sig.clone(), engine.clone());
                let start = std::time::Instant::now();
                if blocking {
                    tokio::task::spawn_blocking(move || engine.verify_version(&fd, &sums, &sig))
                        .await
                        .unwrap()
                        .unwrap();
                } else {
                    engine.verify_version(&fd, &sums, &sig).unwrap();
                }
                times.push(start.elapsed().as_micros());
            }
            times.sort_unstable();
            let start = std::time::Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..50 {
                let (fd, sums, sig, engine) =
                    (fd.clone(), sums.clone(), sig.clone(), engine.clone());
                tasks.spawn(async move {
                    if blocking {
                        tokio::task::spawn_blocking(move || {
                            engine.verify_version(&fd, &sums, &sig)
                        })
                        .await
                        .unwrap()
                        .unwrap();
                    } else {
                        engine.verify_version(&fd, &sums, &sig).unwrap();
                    }
                });
            }
            while let Some(result) = tasks.join_next().await {
                result.unwrap();
            }
            println!(
                "manifest={}B blocking={} samples=200 p50={}us p99={}us max={}us callers=50 workers=4 batch={}us",
                sums.len(),
                blocking,
                times[100],
                times[198],
                times[199],
                start.elapsed().as_micros()
            );
        }
    }
}

fn memory_kib(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)
                .and_then(|value| value.split_whitespace().next())
                .and_then(|value| value.parse().ok())
        })
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "local weighted-scope 50-caller real-engine RSS measurement"]
async fn bench_latest_fifty_callers() {
    let version = "edge-20261011T071500Z";
    let release = Release::with_manifest_entries(16, version, 825);
    assert!(
        (65000..=65536).contains(&release.files[&format!("/releases/{version}/SHA256SUMS")].len())
    );
    let bucket = Bucket::new(release.files.clone());
    bucket.files.lock().unwrap().insert(
        "/releases/channels/edge.json".into(),
        format!("{{\"version\":\"{version}\"}}").into_bytes(),
    );
    let lookup = Arc::new(VerifiedLookup::new(
        release.root.clone(),
        bucket.origin.clone(),
        Arc::new(Engine {
            trust: Some(release.trust.clone()),
        }),
    ));
    assert_eq!(lookup.latest("edge").await.unwrap()["version"], version);
    let rss_before = memory_kib("VmRSS:");
    let hwm_before = memory_kib("VmHWM:");
    let start = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..50 {
        let lookup = lookup.clone();
        tasks.spawn(async move {
            let start = std::time::Instant::now();
            assert_eq!(lookup.latest("edge").await.unwrap()["version"], version);
            start.elapsed().as_micros()
        });
    }
    let mut times = Vec::new();
    while let Some(result) = tasks.join_next().await {
        times.push(result.unwrap());
    }
    times.sort_unstable();
    assert_eq!(bucket.requests.load(Ordering::Relaxed), 204);
    assert_eq!(
        std::fs::read_dir(&release.root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with("release-check-"))
            .count(),
        0
    );
    let hwm_after = memory_kib("VmHWM:");
    println!(
        "METRIC latest callers=50 workers=4 manifest=near64KiB loopback=true verified_requests=200 p50={}us p99={}us batch={}us rss_before={}KiB rss_after={}KiB hwm_before={}KiB hwm_after={}KiB peak_delta_per_caller={}B lookup_handle={}B machine={} cores={} load={}",
        times[25],
        times[49],
        start.elapsed().as_micros(),
        rss_before,
        memory_kib("VmRSS:"),
        hwm_before,
        hwm_after,
        hwm_after.saturating_sub(hwm_before) * 1024 / 50,
        std::mem::size_of::<VerifiedLookup>(),
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap()
            .trim(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
