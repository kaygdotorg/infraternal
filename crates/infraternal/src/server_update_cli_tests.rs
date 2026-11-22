//! Checks `infraternal server update`'s argument parsing, inputs, refusals and readable output (#211, D400).
use super::*;
use crate::cli::actions::registry_for;
use crate::cli::command_tree::{build, selected};
use infraternal_plugin_api::CliHandler;

/// What [`parse`] returns: the command path, then `version`, `quiet_minutes`, `no_wait` and `data`.
type Parsed = (
    Vec<String>,
    Option<String>,
    Option<i64>,
    bool,
    Option<String>,
);

/// Parse `arguments` with the real server command tree and return the selected command path and
/// its inputs as the dispatcher sees them.
fn parse(arguments: &[&str]) -> Result<Parsed, clap::Error> {
    let registry = registry_for(Some("server")).expect("server registry");
    let tree = build(&registry);
    let matches =
        tree.try_get_matches_from(std::iter::once("infraternal").chain(arguments.iter().copied()))?;
    let chosen = selected(&matches);
    let found = chosen.matches;
    Ok((
        chosen.path.clone(),
        found
            .try_get_one::<String>("version")
            .ok()
            .flatten()
            .cloned(),
        found
            .try_get_one::<i64>("quiet_minutes")
            .ok()
            .flatten()
            .copied(),
        found.try_get_one::<bool>("no_wait").ok().flatten() == Some(&true),
        found.get_one::<String>("data").cloned(),
    ))
}

/// Every command exists under `server update`, goes to the server-plugin handler and carries its
/// hosted `release.update.*` action, and its skill says it runs as root without a passkey.
#[test]
fn every_update_command_is_registered_with_its_action_and_skill() {
    let registry = registry_for(Some("server")).expect("server registry");
    for (name, id) in [
        ("status", "release.update.status"),
        ("check", "release.update.check"),
        ("apply", "release.update.apply"),
        ("rollback", "release.update.rollback"),
        ("cancel", "release.update.cancel"),
        ("history", "release.update.history"),
        ("settings", "release.update.settings"),
    ] {
        let action = registry
            .find(&["server", "update", name])
            .unwrap_or_else(|| panic!("server update {name}"))
            .action;
        assert_eq!(action.cli_handler, CliHandler::ServerPlugin, "{name}");
        assert_eq!(action.hosted.map(|source| source.id), Some(id), "{name}");
        let skill = crate::cli::skills::render_action(action).expect("skill");
        // The steps are the local ones; the hosted contract below them keeps the API's own words.
        let (steps, hosted) = skill
            .split_once("## Hosted action contract")
            .expect("the skill shows the hosted contract");
        assert!(steps.contains("as root"), "{name}: {steps}");
        assert!(
            !steps.contains("needs the owner with a recent passkey tap"),
            "{name}: the API's passkey sentence does not apply locally"
        );
        assert!(hosted.contains(id), "{name}");
        assert!(
            skill.contains("`infraternal server update"),
            "{name}: an example"
        );
    }
}

/// Positionals, flags and `--data` before or after the subcommand parse as documented.
#[test]
fn arguments_parse_as_documented() {
    let (path, version, _, no_wait, data) = parse(&["server", "update", "status"]).unwrap();
    assert_eq!(path, ["server", "update", "status"]);
    assert_eq!((version, no_wait, data), (None, false, None));

    let (_, version, ..) = parse(&["server", "update", "check", "edge-20261122T013516Z"]).unwrap();
    assert_eq!(version.as_deref(), Some("edge-20261122T013516Z"));

    let (path, version, _, no_wait, data) = parse(&[
        "server",
        "--data",
        "/var/lib/infraternal",
        "update",
        "apply",
        "edge-20261122T013516Z",
        "--no-wait",
    ])
    .unwrap();
    assert_eq!(path, ["server", "update", "apply"]);
    assert_eq!(version.as_deref(), Some("edge-20261122T013516Z"));
    assert!(no_wait);
    assert_eq!(data.as_deref(), Some("/var/lib/infraternal"));

    let (_, _, _, no_wait, data) =
        parse(&["server", "update", "rollback", "--data", "/srv/x"]).unwrap();
    assert!(!no_wait);
    assert_eq!(data.as_deref(), Some("/srv/x"));

    let (_, _, quiet, ..) =
        parse(&["server", "update", "settings", "--quiet-minutes", "30"]).unwrap();
    assert_eq!(quiet, Some(30));
    // settings with no value parses (the input check refuses it), rollback takes no version, and quiet minutes are whole numbers.
    assert!(parse(&["server", "update", "settings", "--automatic"]).is_err());
    assert!(parse(&["server", "update", "rollback", "edge-20261122T013516Z"]).is_err());
    assert!(parse(&["server", "update", "settings", "--quiet-minutes", "five"]).is_err());
    assert!(parse(&["server", "update", "status", "--no-wait"]).is_err());
}

/// Each command sends exactly its action's input, and out-of-range quiet windows are usage errors.
#[test]
fn inputs_match_the_actions() {
    assert_eq!(input("status", None, None, None).unwrap(), json!({}));
    assert_eq!(input("check", None, None, None).unwrap(), json!({}));
    assert_eq!(
        input("apply", Some("edge-20261122T013516Z"), None, None).unwrap(),
        json!({"version": "edge-20261122T013516Z"})
    );
    assert_eq!(
        input("settings", None, Some(1440), None).unwrap(),
        json!({"quiet_minutes": 1440})
    );
    for bad in [None, Some(0), Some(1441), Some(-5)] {
        assert_eq!(
            input("settings", None, bad, None).unwrap_err().exit,
            Exit::Usage
        );
    }
    // J1130: `--automatic on|off`, alone or with a quiet window; anything else is a usage error.
    assert_eq!(
        input("settings", None, None, Some("off")).unwrap(),
        json!({"automatic": false})
    );
    assert_eq!(
        input("settings", None, Some(10), Some("on")).unwrap(),
        json!({"quiet_minutes": 10, "automatic": true})
    );
    for bad in ["yes", "", "OFF"] {
        assert_eq!(
            input("settings", None, None, Some(bad)).unwrap_err().exit,
            Exit::Usage
        );
    }
    assert_eq!(
        input("deploy", None, None, None).unwrap_err().exit,
        Exit::Usage
    );
}

/// Each control-socket failure gets its own sentence and exit code (D303).
#[test]
fn failures_map_to_their_exit_codes() {
    assert_eq!(
        Failure::from_call(&CallError::NotRunning).exit,
        Exit::Unreachable
    );
    let refused = Failure::from_call(&CallError::NotAllowed);
    assert_eq!(refused.exit, Exit::NotAllowed);
    assert!(refused.message.contains("root"));
    assert_eq!(
        Failure::from_call(&CallError::Closed).exit,
        Exit::Unreachable
    );
    assert_eq!(
        Failure::from_call(&CallError::Refused("invalid input".into())).exit,
        Exit::Usage
    );
    let staged = Failure::from_call(&CallError::Refused("nothing is staged".into()));
    assert_eq!(staged.exit, Exit::Failed);
    assert_eq!(staged.message, "The server refused: nothing is staged.");
}

/// A status like the server's, for the output tests.
fn status() -> Value {
    json!({
        "current": "edge-20261122T013516Z",
        "channel": "edge",
        "available": "edge-20261123T000000Z",
        "staged": "edge-20261123T000000Z",
        "hold": null,
        "last_check": 1_763_785_800,
        "next_check": 1_763_786_700,
        "last_error": null,
        "refused": null,
        "mode": "auto",
        "reason": null,
        "quiet_minutes": 5,
        "applied": {"version": "edge-20261122T013516Z", "outcome": "applied", "reason": null, "at": 1_763_780_000},
        "paused": null,
        "rollback": {"to": "edge-20261121T000000Z", "copy_taken_at": 1_763_779_990},
    })
}

/// The status reads as one sentence plus aligned rows, and says why updates are off.
#[test]
fn status_reads_plainly() {
    let report = present("status", status());
    assert_eq!(
        report.message,
        "Running edge-20261122T013516Z on edge. Updates are on."
    );
    assert_eq!(
        report.body,
        "Newest        edge-20261123T000000Z\n\
         Staged        edge-20261123T000000Z\n\
         Last check    2025-11-22 04:30 UTC\n\
         Next check    2025-11-22 04:45 UTC\n\
         Quiet window  5 minutes\n\
         Last switch   edge-20261122T013516Z applied, 2025-11-22 02:53 UTC\n\
         Roll back     to edge-20261121T000000Z; changes made after 2025-11-22 02:53 UTC would be lost"
    );
    assert_eq!(
        report.next,
        ["Apply it now with infraternal server update apply."]
    );
    assert_eq!(
        report.data,
        status(),
        "the whole answer stays in the envelope"
    );
    let mut off = status();
    off["mode"] = json!("off");
    off["reason"] = json!("the server is not running as root");
    assert_eq!(
        status_message(&off),
        "Running edge-20261122T013516Z on edge. Updates are off: the server is not running as root."
    );
}

/// Check, cancel, settings and history each say what happened in one sentence.
#[test]
fn other_answers_read_plainly() {
    let staged = present(
        "check",
        json!({"outcome": "staged", "version": "edge-20261123T000000Z", "reason": null}),
    );
    assert_eq!(
        staged.message,
        "Staged edge-20261123T000000Z; it applies in the next quiet window."
    );
    assert_eq!(staged.next.len(), 1);
    let refused = present(
        "check",
        json!({"outcome": "refused", "version": null, "reason": "the release is older than the running version"}),
    );
    assert_eq!(
        refused.message,
        "Nothing staged: the release is older than the running version."
    );
    assert_eq!(refused.next, Vec::<String>::new());
    assert_eq!(
        present("settings", json!({"quiet_minutes": 30})).message,
        "Updates now wait for 30 quiet minutes before they apply by themselves."
    );
    assert_eq!(
        present("settings", json!({"quiet_minutes": 30, "automatic": false})).message,
        "Automatic apply is off: updates are staged, and only `server update apply` switches."
    );
    let history = present(
        "history",
        json!({"entries": [
            {"at": 1_763_780_000, "kind": "rolled_back", "version": "edge-20261123T000000Z", "detail": "the owner rolled the update back"},
            {"at": 1_763_779_000, "kind": "staged", "version": "edge-20261123T000000Z", "detail": null},
        ]}),
    );
    assert_eq!(
        history.message,
        "The last 2 things the updater did, newest first."
    );
    assert_eq!(
        history.body,
        "2025-11-22 02:53 UTC  rolled back  edge-20261123T000000Z  the owner rolled the update back\n\
         2025-11-22 02:36 UTC  staged       edge-20261123T000000Z"
    );
    assert_eq!(
        present("history", json!({"entries": []})).message,
        "The updater has done nothing yet."
    );
}

/// `apply` finishes only on a new outcome for its own target; an undo fails with the reason; a
/// roll back finishes when the server runs the target again and says which changes were lost.
#[test]
fn switch_outcomes_are_read_from_the_status() {
    let before = status();
    let target = "edge-20261123T000000Z";
    // Unchanged: the previous switch's outcome is not this one's.
    assert!(finished("apply", &before, &before, target, &Value::Null).is_none());
    // Still on trial: nothing new recorded yet.
    let mut trial = before.clone();
    trial["current"] = json!(target);
    assert!(finished("apply", &before, &trial, target, &Value::Null).is_none());
    let mut applied = trial.clone();
    applied["applied"] =
        json!({"version": target, "outcome": "applied", "reason": null, "at": 1_763_790_000});
    let report = finished("apply", &before, &applied, target, &json!({"to": target})).unwrap();
    assert_eq!(report.exit, Exit::Ok);
    assert_eq!(
        report.message,
        "Updated to edge-20261123T000000Z. It passed its health check; the server restarted warm."
    );
    let mut undone = before.clone();
    undone["applied"] = json!({"version": target, "outcome": "undone", "reason": "the new release failed its health check", "at": 1_763_790_000});
    let report = finished("apply", &before, &undone, target, &Value::Null).unwrap();
    assert_eq!(
        (report.exit, report.state),
        (Exit::Failed, CommandState::Failed)
    );
    assert_eq!(
        report.message,
        "The update to edge-20261123T000000Z was undone: the new release failed its health check. The server runs edge-20261122T013516Z."
    );
    // Roll back: done once the server runs the previous version again after a new undo.
    let back_to = "edge-20261121T000000Z";
    let mut rolled = before.clone();
    rolled["applied"] = json!({"version": "edge-20261122T013516Z", "outcome": "undone", "reason": "the owner rolled the update back", "at": 1_763_790_000});
    assert!(finished("rollback", &before, &rolled, back_to, &Value::Null).is_none());
    rolled["current"] = json!(back_to);
    let report = finished("rollback", &before, &rolled, back_to, &Value::Null).unwrap();
    assert_eq!(report.exit, Exit::Ok);
    assert_eq!(
        report.message,
        "Back on edge-20261121T000000Z. Changes made after 2025-11-22 02:53 UTC were lost."
    );
}
