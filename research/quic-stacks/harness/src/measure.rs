//! Role: Dispatches benchmark workloads and reports repeatable wall and process CPU measurements.
//! SPDX-License-Identifier: AGPL-3.0-only

use std::error::Error;

/// Wall-time samples and process CPU accumulated across client and server work.
pub struct Run {
    pub stack: &'static str,
    pub workload: &'static str,
    pub scenario: &'static str,
    pub units: u64,
    pub samples_us: Vec<u64>,
    pub cpu_us: u64,
    pub bytes: u64,
}

/// Returns process-wide user and system CPU time in microseconds.
pub fn cpu_us() -> Result<u64, Box<dyn Error>> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the supplied rusage structure on success.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: getrusage returned zero and initialized `usage`.
    let usage = unsafe { usage.assume_init() };
    let user = usage.ru_utime.tv_sec as u64 * 1_000_000 + usage.ru_utime.tv_usec as u64;
    let system = usage.ru_stime.tv_sec as u64 * 1_000_000 + usage.ru_stime.tv_usec as u64;
    Ok(user + system)
}

/// Emits one CSV row. A handshake unit is one completed connection; a throughput unit is a byte.
pub fn emit(run: Run) {
    let mut values = run.samples_us;
    values.sort_unstable();
    let min = values.first().copied().unwrap_or_default();
    let max = values.last().copied().unwrap_or_default();
    let median = percentile(&values, 50);
    let p95 = percentile(&values, 95);
    let cpu_per_unit = if run.units == 0 {
        0.0
    } else {
        run.cpu_us as f64 / run.units as f64
    };
    let mib_per_s = if median == 0 {
        0.0
    } else {
        run.bytes as f64 / (1024.0 * 1024.0) / (median as f64 / 1_000_000.0)
    };
    let cpu_seconds_per_gbit = if run.bytes == 0 {
        0.0
    } else {
        run.cpu_us as f64 / 1_000_000.0 * 1_000_000_000.0 / (run.bytes as f64 * 8.0)
    };
    println!(
        "{},{},{},{},{},{},{},{},{},{:.3},{:.3},{:.6}",
        run.stack,
        run.workload,
        run.scenario,
        run.units,
        min,
        median,
        p95,
        max,
        run.cpu_us,
        cpu_per_unit,
        mib_per_s,
        cpu_seconds_per_gbit
    );
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let index = ((values.len() - 1) * percentile).div_ceil(100);
    values[index]
}

pub fn handshake_action() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: bench-handshake <quinn|openssl> <fresh-count>".into());
    }
    let count = args[1].parse::<u32>()?;
    if count == 0 {
        return Err("handshake count must be positive".into());
    }
    println!(
        "stack,workload,scenario,units,min_us,median_us,p95_us,max_us,cpu_us,cpu_per_unit_us,median_MiB_s,cpu_s_per_Gbit"
    );
    match args[0].as_str() {
        "quinn" => crate::quinn_stack::bench_handshake(count),
        "openssl" => crate::openssl_native::bench_handshake(count),
        other => Err(format!("unknown stack: {other}").into()),
    }
}

pub fn throughput_action() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: bench-throughput <quinn|openssl> <streams:1|4> <bytes>".into());
    }
    let streams = args[1].parse::<usize>()?;
    let bytes = args[2].parse::<u64>()?;
    if !matches!(streams, 1 | 4) || bytes == 0 || !bytes.is_multiple_of(streams as u64) {
        return Err("streams must be 1 or 4 and bytes must divide evenly across streams".into());
    }
    println!(
        "stack,workload,scenario,units,min_us,median_us,p95_us,max_us,cpu_us,cpu_per_unit_us,median_MiB_s,cpu_s_per_Gbit"
    );
    match args[0].as_str() {
        "quinn" => crate::quinn_stack::bench_throughput(streams, bytes),
        "openssl" => crate::openssl_native::bench_throughput(streams, bytes),
        other => Err(format!("unknown stack: {other}").into()),
    }
}

pub fn zero_rtt_action() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(2).collect::<Vec<_>>();
    if args.len() != 1 || args[0] != "quinn" {
        return Err("usage: bench-0rtt quinn".into());
    }
    println!(
        "stack,workload,scenario,units,min_us,median_us,p95_us,max_us,cpu_us,cpu_per_unit_us,median_MiB_s,cpu_s_per_Gbit"
    );
    crate::quinn_stack::bench_0rtt()
}

/// Ensures timer units remain monotonic under the loopback and delayed-path measurements.
#[allow(dead_code)]
fn elapsed_us(start: std::time::Instant) -> u64 {
    start.elapsed().as_micros().min(u64::MAX as u128) as u64
}
