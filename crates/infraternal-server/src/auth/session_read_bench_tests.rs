//! Measurement only (#559, J1151): the session step every authenticated
//! route runs, under concurrent load, and what it costs other writers.
//!
//! `CONCURRENCY` tasks call `Auth::session` for one live session in a closed
//! loop on an on-disk database shaped like production (WAL,
//! `synchronous=NORMAL`, the D379 pool), with the clock advancing in real
//! time. Meanwhile a probe commits one trivial write on the same pool every
//! 2 ms; its latency is the time another route's write waits for the writer.
//! The file uses only what both the base and the head have, so the same
//! numbers can be taken before and after the change. Run it explicitly:
//! `cargo test -p infraternal-server --lib -- --ignored session_step_under_concurrent_load --nocapture`.

use super::*;

/// Concurrent callers of `Auth::session`.
const CONCURRENCY: usize = 64;
/// Calls per caller.
const CALLS: usize = 500;

/// Nearest-rank percentile of sorted microsecond samples, `per_mille` out of 1,000.
fn percentile(sorted: &[u128], per_mille: usize) -> u128 {
    sorted[(sorted.len() * per_mille / 1_000).min(sorted.len() - 1)]
}

/// Print the session step's and the writer probe's latency under load.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Measurement only: run on a build or performance VM"]
async fn session_step_under_concurrent_load() {
    let _guard = SERIAL.lock_for_measurement().await;
    let (pool, path) = disk_pool("session-bench").await;
    let (auth, token) = empty_with_pool(pool).await;
    let f = fixture_with_bootstrap(auth, token).await;
    let db = f
        .auth
        .database()
        .expect("an on-disk Auth uses the pool")
        .clone();
    let started = Instant::now();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let probe = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut waits = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let began = Instant::now();
                db.write(|tx| {
                    tx.execute(
                        "UPDATE session_login_sequence SET value=value WHERE singleton=1",
                        [],
                    )?;
                    Ok::<_, infraternal_db::Error>(())
                })
                .await
                .unwrap();
                waits.push(began.elapsed().as_micros());
                // sleep: paces the writer probe at about 500 writes per second.
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            waits
        })
    };

    let callers: Vec<_> = (0..CONCURRENCY)
        .map(|_| {
            let auth = f.auth.clone();
            let token = f.session.clone();
            tokio::spawn(async move {
                let mut times = Vec::with_capacity(CALLS);
                for _ in 0..CALLS {
                    let now = NOW + i64::try_from(started.elapsed().as_secs()).unwrap();
                    let began = Instant::now();
                    auth.session(&token, now).await.unwrap();
                    times.push(began.elapsed().as_micros());
                }
                times
            })
        })
        .collect();
    let mut times = Vec::new();
    for caller in callers {
        times.extend(caller.await.unwrap());
    }
    let wall = started.elapsed();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut waits = probe.await.unwrap();
    times.sort_unstable();
    waits.sort_unstable();
    let wal = std::fs::metadata(format!("{}-wal", path.display())).map_or(0, |meta| meta.len());
    println!(
        "SESSION_STEP_BENCH concurrency={CONCURRENCY} calls={} wall_ms={} calls_per_s={:.0} \
         session_p50_us={} session_p99_us={} session_max_us={} \
         writer_probe_n={} writer_probe_p50_us={} writer_probe_p99_us={} writer_probe_max_us={} wal_bytes={wal}",
        times.len(),
        wall.as_millis(),
        f64::from(u32::try_from(times.len()).unwrap()) / wall.as_secs_f64(),
        percentile(&times, 500),
        percentile(&times, 990),
        times.last().copied().unwrap_or(0),
        waits.len(),
        percentile(&waits, 500),
        percentile(&waits, 990),
        waits.last().copied().unwrap_or(0),
    );
    f.auth.close_database().await;
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}
