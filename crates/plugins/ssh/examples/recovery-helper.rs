//! Runs the shipping runtime guard for isolated installer fixtures (#230).
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(
        infraternal_plugin_remote::runtime_lock::command(
            &std::env::args_os().skip(1).collect::<Vec<_>>(),
        )
        .unwrap_or(71),
    )
}
