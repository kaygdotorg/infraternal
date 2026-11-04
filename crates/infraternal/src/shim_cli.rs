//! Shares the internal shim startup schema and identity checks across executable build profiles (D13, D255).

/// Read only by the entry points compiled with the agent or payload features.
#[cfg_attr(
    not(any(feature = "plugin-agent", feature = "session-payload")),
    allow(dead_code)
)]
pub(crate) const PAYLOAD_ONLY: bool = cfg!(all(
    feature = "session-payload",
    not(any(
        feature = "plugin-server",
        feature = "remote",
        feature = "mesh",
        feature = "plugin-host-facts"
    ))
));
#[cfg(target_os = "linux")]
pub(crate) use infraternal_shim::startup::Options;

/// SSH entrypoints are dispatched first through their existing implementations.
/// This final private route can only start the shim using its shared runner.
#[cfg(all(feature = "session-payload", target_os = "linux"))]
pub(crate) fn payload_entry() -> std::process::ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next().is_none_or(|command| command != "__shim") {
        return crate::output::refuse(
            false,
            "internal.session",
            "Invalid session startup command",
            "Use the full host build for operator commands.",
            2,
        );
    }
    let arguments: Vec<_> = arguments.collect();
    let Some(options) = Options::spawned(&arguments) else {
        return crate::output::refuse(
            false,
            "internal.shim",
            "Invalid session startup arguments",
            "Check the session configuration.",
            2,
        );
    };
    if options.run().is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        crate::output::refuse(
            false,
            "internal.shim",
            "Session startup failed",
            "Check the session configuration.",
            1,
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "shim_cli_tests.rs"]
mod tests;
