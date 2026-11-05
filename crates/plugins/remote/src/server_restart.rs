//! Declares the local server replacement action used by CLI help and generated AI skills [16][202][217], #154.

use infraternal_plugin_api::{ActionDef, DryRun, Effect, Permission, SchemaRef, Target};

/// Replace an existing server without writing its unlocked CA to disk.
pub const RESTART: ActionDef = ActionDef {
    id: "remote.server.restart",
    summary: "Restart the running server without locking its certificate authority.",
    instructions: &[
        "Run it as the account that runs the server, with the server's --data folder.",
        "To update, put the verified new program next to the current one and pass it with --binary.",
        "Run infraternal server --data <folder> restart. The new server takes over without writing its unlocked certificate authority to disk.",
        "Afterwards check that the server answers, that hosts reconnect and that the certificate authority is unlocked.",
        "To go back, run the same command with the previous program.",
        "Without --binary the server restarts itself; a service manager can do the same by sending SIGHUP.",
    ],
    input: SchemaRef("remote.server.restart"),
    output: SchemaRef("remote.server.restart.result"),
    target: Target::Global,
    effect: Effect::Write,
    permission: Permission::One("server.configure"),
    dry_run: DryRun::Unsupported,
    opens: None,
    api_scope: None,
    fresh_passkey: false,
};
