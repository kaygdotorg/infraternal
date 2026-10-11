//! Declares the local server replacement action used by CLI help and generated AI skills [16][202][217], #154.

use infraternal_plugin_api::{ActionDef, DryRun, Effect, Permission, SchemaRef, Target};

/// Replace an existing server without writing its unlocked CA to disk.
pub const RESTART: ActionDef = ActionDef {
    id: "remote.server.restart",
    summary: "Restart the running server with an in-memory CA handoff",
    instructions: &[
        "Use the running service account and its existing --data directory.",
        "Stage a verified executable beside the current executable for an update.",
        "Run infraternal server --data <directory> restart; add --binary <path> to switch executables.",
        "Check health, remote host reconnection and administrator CA status after replacement.",
        "Use the same restart command with the retained executable to roll back.",
        "For the current executable, systemd ExecReload may send SIGHUP to the main PID.",
    ],
    input: SchemaRef("remote.server.restart"),
    output: SchemaRef("remote.server.restart.result"),
    target: Target::Global,
    effect: Effect::Write,
    permission: Permission::One("server.configure"),
    dry_run: DryRun::Unsupported,
    opens: None,
};
