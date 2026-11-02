//! Check the SSH prompt flight budget using the isolated transport probe on the perf VM.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
#[ignore = "Run only on the perf VM, in a disposable network namespace, with MESH_REVIEW_PROBE set"]
fn prompt_fits_five_round_trips() {
    let hostname = std::fs::read_to_string("/etc/hostname").unwrap();
    assert!(
        hostname.trim().contains("perf"),
        "performance evidence requires the perf VM"
    );
    let probe = std::env::var_os("MESH_REVIEW_PROBE")
        .expect("set MESH_REVIEW_PROBE to the mesh_transport example");
    let output = std::process::Command::new(probe)
        .args(["--matrix", "127.0.0.1:42287"])
        .output()
        .unwrap();
    let metrics = String::from_utf8(output.stdout).unwrap();
    print!("{metrics}");
    assert!(
        output.status.success(),
        "transport probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prompt = metrics
        .lines()
        .find(|line| line.starts_with("METRIC name=tcp_to_prompt modeled_rtt_ms=150 "))
        .unwrap();
    let p50 = prompt
        .split_whitespace()
        .find_map(|field| field.strip_prefix("p50_ms="))
        .unwrap()
        .parse::<f64>()
        .unwrap();
    // Five 150 ms network flights plus 50 ms for local transport/runtime work.
    // The extra allowance keeps this a flight-budget check rather than a CPU benchmark.
    assert!(p50 <= 800.0, "prompt exceeds five round trips: {prompt}");
}
