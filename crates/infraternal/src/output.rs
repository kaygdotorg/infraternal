//! Formats operator results as organized human text or JSON lines without invocation-specific login material [202], #78.

use std::process::ExitCode;

/// Every record is a complete line; callers report only confirmed states.
pub(crate) fn report(json: bool, action: &str, state: &str, message: &str, next: &str) {
    if json {
        println!(
            "{}",
            serde_json::json!({"action": action, "state": state, "message": message, "next": next})
        );
    } else {
        let title = if action.starts_with("remote.host.") {
            "Remote infraternal agent"
        } else if action.starts_with("remote.server.") {
            "Remote server capability"
        } else if action.starts_with("server.") {
            "Server"
        } else if action == "agent.embedded" {
            "Infraternal agent"
        } else {
            "Command"
        };
        let text = format!("{title}\n  State   {state}\n  Detail  {message}\n  Next    {next}\n");
        if state == "refused" {
            eprint!("{text}");
        } else {
            print!("{text}");
        }
    }
}

/// Static refusals do not reflect a path, invitation, proof or private identity.
pub(crate) fn refuse(json: bool, action: &str, message: &str, next: &str, exit: u8) -> ExitCode {
    report(json, action, "refused", message, next);
    ExitCode::from(exit)
}
