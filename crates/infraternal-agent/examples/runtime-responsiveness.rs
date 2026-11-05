//! Opt-in performance driver for D351; run on the perf VM through perf-run.
//! Build with `--features bench-probes --example runtime-responsiveness`.

/// Measure real dispatcher response times on its ordinary current-thread runtime.
#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let state = std::env::temp_dir().join(format!(
            "lp-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let result = runtime
            .block_on(infraternal_agent::runtime_probe::agent_ping_under_slow_write(state.clone()));
        let _ = std::fs::remove_dir_all(state);
        samples.push(result?.as_nanos());
    }
    samples.sort_unstable();
    println!(
        "METRIC agent_runtime_slow_write samples=100 p99_ns={} max_ns={}",
        samples[98], samples[99]
    );
    Ok(())
}

/// The Linux dispatcher is measured on Linux, where the host daemon runs.
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("runtime-responsiveness requires Linux");
}
