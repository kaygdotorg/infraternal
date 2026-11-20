//! Runs the shipping runtime guard for isolated installer fixtures (#230).
//! The guard is Linux-only; elsewhere the fixture refuses (#320).
/// Run the shipping guard and shim for isolated root and unprivileged recovery fixtures.
#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    // The real shim in root fixtures has the same endpoint and PTY ownership as a host terminal.
    if arguments
        .first()
        .is_some_and(|argument| argument == "__shim")
    {
        return std::process::ExitCode::from(u8::from(
            infraternal_shim::startup::Options::spawned(&arguments[1..])
                .is_none_or(|options| options.run().is_err()),
        ));
    }
    // A root fixture's old unit needs a live executable under its own installation.
    // Enrollment and networking are tested by the install suite, not this service stand-in.
    if arguments
        .first()
        .is_some_and(|argument| argument == "agent")
    {
        loop {
            std::thread::park();
        }
    }
    std::process::ExitCode::from(
        infraternal_plugin_remote::runtime_lock::command(&mut std::env::args_os().skip(1))
            .unwrap_or(71),
    )
}

#[cfg(not(target_os = "linux"))]
/// Run the recovery helper fixture used by the SSH runtime tests.
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(71)
}
