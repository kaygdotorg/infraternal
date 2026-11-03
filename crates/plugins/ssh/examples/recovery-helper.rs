//! Runs the shipping runtime guard for isolated installer fixtures (#230).
//! The guard is Linux-only; elsewhere the fixture refuses (#320).
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(
        infraternal_plugin_remote::runtime_lock::command(&mut std::env::args_os().skip(1))
            .unwrap_or(71),
    )
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(71)
}
