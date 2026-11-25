//! Defines the process entry point and dispatches metadata-registered actions.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

mod cli;
#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
mod component_cli;
#[cfg(feature = "plugin-agent")]
mod embedded_cli;
#[cfg(feature = "remote")]
mod host_remove;
#[cfg(feature = "release")]
mod release_cli;
/// `infraternal server update adopt`: move an existing server onto the boot pointer (#211 S6).
#[cfg(all(feature = "release", feature = "remote", target_os = "linux"))]
mod server_adopt;
/// `infraternal server mesh routes …` over the server's private control socket (D197 M3, D400).
#[cfg(feature = "release")]
mod server_mesh_routes_cli;
/// `infraternal server update …` over the server's private control socket (#211, D400).
#[cfg(feature = "release")]
mod server_update_cli;
#[cfg(feature = "process-per-user")]
mod user_host_cli;

#[cfg(any(
    feature = "remote",
    feature = "session-payload",
    all(feature = "plugin-agent", target_os = "linux")
))]
mod output;
#[cfg(feature = "remote")]
mod remote;
#[cfg(feature = "plugin-server")]
mod remote_server;
#[cfg(feature = "remote")]
mod remote_service;
#[cfg(all(feature = "remote", feature = "plugin-server"))]
mod restart;
#[cfg(all(feature = "remote", feature = "plugin-server"))]
mod restart_binary;
#[cfg(all(feature = "remote", feature = "plugin-server"))]
mod restart_image;
/// Owns the server's private, credential-checked control endpoint.
#[cfg(all(
    feature = "plugin-server",
    any(feature = "remote", target_os = "linux")
))]
mod server_control;
mod shim_cli;
#[cfg(feature = "remote")]
mod sign_in;
#[cfg(feature = "ssh")]
mod ssh_askpass;
#[cfg(feature = "ssh")]
mod ssh_internal;
#[cfg(test)]
mod test_executable;
/// The one check that a program root will run is one only root can replace (#146).
#[cfg(any(machine_up, feature = "plugin-server"))]
mod trusted_program;
#[cfg(machine_up)]
mod up;

#[cfg(feature = "plugin-server")]
mod install;
/// Moves an existing install's data folder to the D395 default [#516].
#[cfg(feature = "plugin-server")]
mod install_move;
/// OS-standard default folders for `server init` [D395].
#[cfg(feature = "plugin-server")]
mod install_paths;
/// `SELinux` file-context labeling so systemd can start `<data>/updates/current/infraternal` (#211).
#[cfg(all(feature = "plugin-server", target_os = "linux"))]
mod selinux;

use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[cfg(all(
    any(feature = "plugin-server", feature = "plugin-mesh"),
    target_os = "linux"
))]
use infraternal_plugin_mesh::host_firewall;
#[cfg(all(feature = "plugin-server", target_os = "linux"))]
use infraternal_plugin_mesh::host_firewall::{AllowRule, Listener, Policy, Protocol};
#[cfg(feature = "plugin-server")]
use std::net::SocketAddr;

use clap::ArgMatches;
use cli::output::{CommandResult, CommandState, Exit, emit};
#[cfg(feature = "plugin-server")]
use cli::output::{render_json, write_output};
use infraternal_plugin_api::{
    ActionAvailability, ActionDefinition, ActionRegistry, CliHandler, JsonSchema, JsonSchemaType,
};
use serde::Serialize;
use serde_json::json;

/// Server listener and application settings read from a registered action's input schema.
#[cfg(feature = "plugin-server")]
#[derive(Debug)]
struct ServerArgs {
    remote: remote_server::Options,
    listen: SocketAddr,
    data: PathBuf,
    public_origin: Option<String>,
    web_root: Option<PathBuf>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    behind_proxy: bool,
    trusted_proxies: Vec<infraternal_server::ProxyNetwork>,
    /// Interface restriction for the application listener's host firewall rule.
    host_firewall_listen_interface: Option<String>,
    /// Interface restriction for the remote listener's host firewall rule.
    host_firewall_remote_interface: Option<String>,
    /// Peer ranges permitted to use the remote listener.
    host_firewall_remote_sources: Vec<String>,
    /// Interfaces with an explicitly retained broad host input allowance.
    host_firewall_accept_interfaces: Vec<String>,
    /// Extra typed host input rules, including explicit administrator paths.
    host_firewall_allow: Vec<String>,
    /// Clear the server policy from the shared host table during a system install.
    host_firewall_off: bool,
}

/// Options controlling a user or system service installation.
#[cfg(feature = "plugin-server")]
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct InstallArgs {
    system: bool,
    user: bool,
    dry_run: bool,
    force: bool,
    name: String,
}

/// The global allocator of static (musl) builds (#522, owner decision
/// 2026-11-16): mimalloc.
///
/// One static binary serves every product role, so this applies to the
/// server, the infraternal agent (and the `GotaTun` mesh engine inside it) and
/// every per-session shim alike. musl's own allocator returns freed memory to
/// the kernel eagerly and the next burst faults it in again, which ran
/// `GotaTun` at about half of glibc's speed; mimalloc keeps freed memory for
/// reuse and runs it at glibc's speed. glibc and macOS builds use the C
/// library's allocator. Static builds also turn transparent huge pages off
/// first thing (see `harden_startup`), which keeps mimalloc's arenas small.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// The process entry point: initialize OpenSSL, then dispatch the invocation.
fn main() -> ExitCode {
    // OpenSSL's first initialization decides, once for the process, whether it registers
    // `OPENSSL_cleanup` with `atexit` (#578). Some `openssl` crate calls (X25519 key generation,
    // for one) initialize without opting out, so the mesh node's first key used to register
    // the cleanup from the `node-plugins` thread. When the infraternal agent then returned from
    // `main` while that thread was still dropping its plugins, `exit` freed OpenSSL's global
    // tables under it, and musl's `free` crashed (`node-plugins` segfault, about 1 in 100
    // teardowns). Opting out here, before any thread exists, removes the cleanup; the kernel
    // reclaims everything at process exit as usual.
    #[cfg(feature = "remote")]
    let _ = infraternal_shim::openssl_secure::disable_exit_cleanup();
    // Builds without the shim's OpenSSL boundary take the full initialization, which opts out
    // as well.
    #[cfg(all(feature = "plugin-server", not(feature = "remote")))]
    openssl::init();
    run_invocation()
}

/// The mesh SSH node component for one infraternal agent state directory [D235], #221.
#[cfg(all(feature = "ssh", feature = "plugin-mesh", target_os = "linux"))]
fn mesh_ssh_service(state: &std::path::Path) -> Option<infraternal_agent::plugins::MeshService> {
    let node = infraternal_plugin_ssh::mesh_node::MeshSshNode::new(
        state.to_owned(),
        infraternal_agent::logins::account_uid,
    )
    .ok()?;
    let observer = node.mesh_observer();
    let stop = node.stop_hook();
    Some(infraternal_agent::plugins::MeshService {
        plugin: Box::new(node),
        observer,
        stop,
    })
}

/// Re-enter the same action dispatch if both replacement exec attempts are refused.
fn run_invocation() -> ExitCode {
    if harden_startup().is_err() {
        return ExitCode::FAILURE;
    }
    #[cfg(all(
        any(feature = "plugin-server", feature = "plugin-mesh"),
        target_os = "linux"
    ))]
    if let Some(result) = run_internal_host_firewall_command() {
        return result;
    }
    #[cfg(all(feature = "plugin-server", target_os = "linux"))]
    if let Some(result) = install_move::manager::run_if_requested() {
        return result;
    }
    // The macOS PTY child's private entry runs before any runtime or thread
    // exists: it drops privileges and execs the person's shell (D335, #328).
    #[cfg(target_os = "macos")]
    if let Some(result) = infraternal_shim::session_shell::run_if_requested() {
        return result;
    }
    // The root agent's desktop helper entry, also before any runtime or
    // thread: it drops to the console user and execs the helper (D203 C2).
    #[cfg(all(feature = "desktop", target_os = "macos"))]
    if let Some(result) = infraternal_shim::desktop_user::run_if_requested() {
        return result;
    }
    #[cfg(target_os = "linux")]
    if nix::sys::prctl::set_name(c"infraternal").is_err() {
        return ExitCode::FAILURE;
    }
    // Mesh SSH lives in a crate that depends on the infraternal agent, so it
    // joins every agent registry through this hook (#221).
    #[cfg(all(feature = "ssh", feature = "plugin-mesh", target_os = "linux"))]
    infraternal_agent::plugins::set_mesh_service(mesh_ssh_service);
    #[cfg(all(feature = "remote", target_os = "linux"))]
    if let Some(result) =
        infraternal_plugin_remote::runtime_lock::command(&mut std::env::args_os().skip(1))
    {
        return ExitCode::from(result);
    }
    #[cfg(all(feature = "remote", target_os = "linux"))]
    if let Some(result) = remote::uninstall_if_requested() {
        return result;
    }
    // A person removing their own macOS user-mode install (#146); root mode is handled below.
    #[cfg(all(machine_up, target_os = "macos"))]
    if let Some(result) = up::macos_user::uninstall_if_requested() {
        return result;
    }
    // Root mode's removal.
    #[cfg(all(machine_up, target_os = "macos"))]
    if let Some(result) = infraternal_plugin_mesh::macos_service::remove_if_requested() {
        return result;
    }
    // The user-mode mesh helper's root entries (#146): one launchd connection, or its
    // install and removal through sudo. Each refuses to run without root.
    #[cfg(all(machine_up, target_os = "macos"))]
    if let Some(result) = infraternal_plugin_mesh::macos_helper::run_if_requested() {
        return result;
    }
    // The root agent retiring the rootless install it replaced (D376, #399).
    #[cfg(all(feature = "remote", target_os = "linux"))]
    if let Some(result) = remote::promotion_retire_if_requested() {
        return result;
    }
    // An abandoned root upgrade's cleanup, as root (D376, J465 P1).
    #[cfg(all(feature = "remote", feature = "ssh", target_os = "linux"))]
    if let Some(result) = remote::promotion_abandon_if_requested() {
        return result;
    }
    // A root upgrade's relay, started by sudo, doas or su (D376, #399).
    #[cfg(all(feature = "remote", target_os = "linux"))]
    if let Some(result) = infraternal_agent::privilege_relay_host::run_if_requested() {
        return result;
    }
    #[cfg(feature = "plugin-agent")]
    if let Some(result) = infraternal_agent::startup_guard::run_if_requested() {
        return result;
    }
    #[cfg(feature = "plugin-agent")]
    if !shim_cli::PAYLOAD_ONLY
        && let Some(result) = embedded_cli::run_if_requested()
    {
        return result;
    }
    #[cfg(feature = "ssh")]
    if let Some(result) = ssh_internal::run_if_requested() {
        return result;
    }
    // One install step of a root upgrade, bridged to the host's relay (D376).
    #[cfg(feature = "ssh")]
    if let Some(result) = infraternal_plugin_ssh::relay_session::run_if_requested() {
        return result;
    }
    #[cfg(all(feature = "session-payload", target_os = "linux"))]
    if shim_cli::PAYLOAD_ONLY {
        return shim_cli::payload_entry();
    }
    // Global JSON is a flag; plugin ownership selects lazy metadata, while
    // root help and core discovery need all compiled definitions. Parsing and
    // execution still come solely from the resulting action registry.
    let requested_root = std::env::args().skip(1).find(|arg| arg != "--json");
    let requested_root = requested_root
        .as_deref()
        .filter(|arg| !arg.starts_with('-'));
    let registry = match cli::actions::registry_for(requested_root) {
        Ok(registry) => registry,
        Err(error) => {
            return emit(
                CommandResult::new(
                    "infraternal",
                    CommandState::Failed,
                    "The command list could not be loaded.",
                    json!({}),
                )
                .with_details(error.to_string()),
                requested_json_early(),
                Exit::Failed,
            );
        }
    };
    let requested_json = requested_json_early();
    let matches = match cli::command_tree::build(&registry).try_get_matches() {
        Ok(matches) => matches,
        Err(error) => return parse_failure(&registry, &error, requested_json),
    };
    let json_output = matches.get_flag("json");
    let selected = cli::command_tree::selected(&matches);
    if json_output {
        // One envelope per command, also when Ctrl-C stops it (D303/D305).
        let command = if selected.path.is_empty() {
            "infraternal".to_owned()
        } else {
            selected.path.join(" ")
        };
        infraternal_shim::exit_on_interrupt(cli::output::interrupted_notice(&command));
    }
    dispatch_selected_action(&registry, &selected, json_output)
}

/// Handle the systemd-only command that applies the root-owned saved host policy.
#[cfg(all(
    any(feature = "plugin-server", feature = "plugin-mesh"),
    target_os = "linux"
))]
fn run_internal_host_firewall_command() -> Option<ExitCode> {
    let mut arguments = std::env::args_os();
    let _binary = arguments.next();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("__host-firewall-apply")) {
        return None;
    }
    if arguments.next().is_some() {
        eprintln!("infraternal host firewall apply: unexpected argument");
        return Some(ExitCode::FAILURE);
    }
    // Fails open: a saved table that would drop sshd's current ports is not
    // enforced, and the unit fails so the journal says why (J671, #483).
    let result = host_firewall::boot_apply_from_config();
    match result {
        Ok(report) => {
            print!("{report}");
            Some(ExitCode::SUCCESS)
        }
        Err(error @ host_firewall::PolicyError::FailedOpen { .. }) => {
            eprintln!("<2>infraternal host firewall: {error}");
            Some(ExitCode::FAILURE)
        }
        Err(error) => {
            eprintln!("infraternal host firewall apply failed: {error}");
            Some(ExitCode::FAILURE)
        }
    }
}

fn dispatch_selected_action(
    registry: &ActionRegistry,
    selected: &cli::command_tree::SelectedCommand<'_>,
    json_output: bool,
) -> ExitCode {
    let path = selected.path.iter().map(String::as_str).collect::<Vec<_>>();
    if path.is_empty() {
        return run_overview(registry, json_output);
    }
    let Some(registered) = registry.find(&path) else {
        return run_group(registry, &path, json_output)
            .unwrap_or_else(|| missing_action(json_output));
    };
    dispatch_action(registry, registered.action, selected.matches, json_output)
}

// Keep feature-gated command handlers beside their registry mappings.
/// Dispatch one registered action to its local, remote, or server handler.
///
/// Feature-gated handlers share this path so unavailable actions return the same CLI result.
fn dispatch_action(
    registry: &ActionRegistry,
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    match action.cli_handler {
        CliHandler::NodeComponent | CliHandler::Sessions => {
            run_local_action(action, matches, json_output)
        }
        CliHandler::MeshService => run_mesh_service(action, matches, json_output),
        CliHandler::Unavailable => run_unavailable(action, json_output),
        CliHandler::Status => run_status(registry, matches, json_output),
        CliHandler::HostedAction => {
            #[cfg(feature = "remote")]
            {
                cli::api_actions::run(action, matches, json_output)
            }
            #[cfg(not(feature = "remote"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::Skill => run_skill(registry, matches, json_output),
        CliHandler::SignIn => run_sign_in(action, matches, json_output),
        CliHandler::Up | CliHandler::UpSystem => dispatch_up_action(action, matches, json_output),
        CliHandler::ServerPlugin => {
            #[cfg(feature = "release")]
            {
                release_cli::run(action, matches, json_output)
            }
            #[cfg(not(feature = "release"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerRun => {
            #[cfg(feature = "plugin-server")]
            {
                run_server(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerInit => {
            #[cfg(feature = "plugin-server")]
            {
                run_server_init(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerInstallCompatibility => {
            #[cfg(feature = "plugin-server")]
            {
                run_server_install_compat(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::ServerSetupToken => {
            #[cfg(feature = "plugin-server")]
            {
                run_setup_token(matches, json_output)
            }
            #[cfg(not(feature = "plugin-server"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::EmbeddedAgent => {
            #[cfg(feature = "plugin-agent")]
            {
                run_embedded_agent(registry, matches, json_output)
            }
            #[cfg(not(feature = "plugin-agent"))]
            {
                run_unavailable(action, json_output)
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        CliHandler::SessionShim => run_shim_command(matches),
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        CliHandler::SessionShim => run_unavailable(action, json_output),
        CliHandler::SshSession => {
            #[cfg(all(feature = "ssh", feature = "remote", target_os = "linux"))]
            {
                run_ssh_session(matches)
            }
            #[cfg(not(all(feature = "ssh", feature = "remote", target_os = "linux")))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::KeyMemoryCheck => {
            #[cfg(feature = "remote")]
            {
                run_key_memory_check(json_output)
            }
            #[cfg(not(feature = "remote"))]
            {
                run_unavailable(action, json_output)
            }
        }
        CliHandler::RemoteAgent
        | CliHandler::ServerRestart
        | CliHandler::ServerMeshStatus
        | CliHandler::ServerMeshRoutes
        | CliHandler::RemoveHost
        | CliHandler::SshAskpass => run_operator_action(action, matches, json_output),
    }
}

#[cfg(machine_up)]
fn dispatch_up_action(
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    match action.cli_handler {
        CliHandler::Up => run_up(matches, json_output),
        CliHandler::UpSystem => run_up_system(matches, json_output),
        _ => run_unavailable(action, json_output),
    }
}

#[cfg(not(machine_up))]
fn dispatch_up_action(
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let _ = matches;
    run_unavailable(action, json_output)
}

/// Control the fixed macOS system Mesh service, keeping the privileged re-entry silent.
fn run_mesh_service(
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    #[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
    {
        let operation = action.command.last().map_or("", String::as_str);
        let system_service = system_service_requested(matches);
        let command = action.command.join(" ");
        let Ok(executable) = std::env::current_exe() else {
            return report_failure_as(
                &command,
                "The Mesh system service could not be started.",
                "The current executable path is unavailable.".to_owned(),
                json_output,
                Exit::Failed,
            );
        };
        let result =
            infraternal_plugin_mesh::macos_service::control(operation, system_service, &executable);
        if system_service {
            return report_mesh_service_system_result(&command, result, json_output);
        }
        report_mesh_service_status_result(command, operation, result, json_output)
    }
    #[cfg(not(all(feature = "plugin-mesh", target_os = "macos")))]
    {
        let _ = matches;
        run_unavailable(action, json_output)
    }
}

#[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
fn report_mesh_service_system_result(
    command: &str,
    result: io::Result<Option<infraternal_plugin_mesh::macos_service::Status>>,
    json_output: bool,
) -> ExitCode {
    match result {
        Ok(None) => ExitCode::SUCCESS,
        Ok(Some(_)) => report_failure_as(
            command,
            "The internal Mesh service request was invalid.",
            "The privileged request did not complete the fixed service operation.".to_owned(),
            json_output,
            Exit::Failed,
        ),
        Err(error) => report_failure_as(
            command,
            "The Mesh system service operation failed.",
            format!("The service operation was refused ({:?}).", error.kind()),
            json_output,
            if error.kind() == io::ErrorKind::PermissionDenied {
                Exit::NotAllowed
            } else {
                Exit::Failed
            },
        ),
    }
}

#[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
fn report_mesh_service_status_result(
    command: String,
    operation: &str,
    result: io::Result<Option<infraternal_plugin_mesh::macos_service::Status>>,
    json_output: bool,
) -> ExitCode {
    match result {
        Ok(Some(status)) => {
            let (state, message, exit) =
                mesh_status_result(operation, status.loaded, status.running);
            emit(
                CommandResult::new(command, state, message, mesh_status_data(status))
                    .with_details(MESH_ENFORCEMENT_DETAILS),
                json_output,
                exit,
            )
        }
        Ok(None) => report_failure_as(
            &command,
            "The Mesh system service did not report its state.",
            "The fixed service control operation returned no status.".to_owned(),
            json_output,
            Exit::Failed,
        ),
        Err(error) => report_failure_as(
            &command,
            "The Mesh system service operation failed.",
            format!("The service operation failed ({:?}).", error.kind()),
            json_output,
            if error.kind() == io::ErrorKind::PermissionDenied {
                Exit::NotAllowed
            } else {
                Exit::Failed
            },
        ),
    }
}

/// Says where `mesh status` enforces network access on this Mac.
#[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
const MESH_ENFORCEMENT_DETAILS: &str =
    "Mesh access rules are enforced in the GotaTun userspace packet filter on this Mac.";

/// The machine-readable `mesh status` fields; `enforcement` reports the access-rule gap (#265).
#[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
fn mesh_status_data(status: infraternal_plugin_mesh::macos_service::Status) -> serde_json::Value {
    json!({
        "loaded": status.loaded,
        "running": status.running,
        "pid": status.pid,
        "enforcement": infraternal_plugin_mesh::macos_node::ENFORCEMENT,
    })
}

#[cfg(all(feature = "plugin-mesh", any(target_os = "macos", test)))]
fn mesh_status_result(
    operation: &str,
    loaded: bool,
    running: bool,
) -> (CommandState, &'static str, Exit) {
    match operation {
        "status" | "up" if running => (
            CommandState::Running,
            "The Mesh system service is running.",
            Exit::Ok,
        ),
        "status" if loaded => (
            CommandState::Restarting,
            "The Mesh system service is loaded but not running.",
            Exit::Failed,
        ),
        "status" | "down" if !loaded => (
            CommandState::Stopped,
            "The Mesh system service is stopped.",
            Exit::Ok,
        ),
        "up" => (
            CommandState::Restarting,
            "The Mesh system service was installed but has not started.",
            Exit::Failed,
        ),
        "down" if loaded => (
            CommandState::Failed,
            "The Mesh system service is still loaded.",
            Exit::Failed,
        ),
        _ => (
            CommandState::Failed,
            "The Mesh system service action is not supported.",
            Exit::Usage,
        ),
    }
}

#[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
fn system_service_requested(matches: &ArgMatches) -> bool {
    matches
        .try_get_one::<bool>("system_service")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

fn run_sign_in(_action: &ActionDefinition, matches: &ArgMatches, json_output: bool) -> ExitCode {
    #[cfg(feature = "remote")]
    {
        let Some(server) = matches.get_one::<String>("server") else {
            return report_failure_as(
                "sign-in",
                "A server address is required.",
                "provide an HTTPS server origin, for example https://infra.example.org".to_owned(),
                json_output,
                Exit::Usage,
            );
        };
        let scopes = matches
            .get_many::<String>("scope")
            .map(|values| values.map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        sign_in::run(server, &scopes, json_output)
    }
    #[cfg(not(feature = "remote"))]
    {
        run_unavailable(_action, json_output)
    }
}

#[cfg(machine_up)]
/// Run the `up` action with its server origin and typed host rules.
fn run_up(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let Some(server) = matches.get_one::<String>("server") else {
        return report_failure_as(
            "up",
            "A server address is required.",
            "provide an HTTPS server origin, for example https://infra.example.org".to_owned(),
            json_output,
            Exit::Usage,
        );
    };
    #[cfg(all(
        target_os = "linux",
        any(feature = "plugin-server", feature = "plugin-mesh")
    ))]
    let host_firewall_allow = matches
        .get_many::<String>("host_firewall_allow")
        .into_iter()
        .flatten()
        .cloned()
        .collect::<Vec<_>>();
    #[cfg(not(all(
        target_os = "linux",
        any(feature = "plugin-server", feature = "plugin-mesh")
    )))]
    let host_firewall_allow = Vec::new();
    // User mode is the Mac default (#146, owner 2026-11-20); --system keeps root mode.
    #[cfg(target_os = "macos")]
    if !matches.get_flag("system") {
        return up::macos_user::run(server, json_output);
    }
    up::run(server, &host_firewall_allow, json_output)
}

#[cfg(machine_up)]
fn run_up_system(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let Some(server) = matches.get_one::<String>("server") else {
        return report_failure_as(
            "up",
            "A server address is required.",
            "provide an HTTPS server origin, for example https://infra.example.org".to_owned(),
            json_output,
            Exit::Usage,
        );
    };
    up::run_helper(server, json_output)
}

#[cfg(all(feature = "ssh", feature = "remote", target_os = "linux"))]
fn run_ssh_session(matches: &ArgMatches) -> ExitCode {
    let (Some(state), session) = (
        matches.get_one::<String>("state"),
        matches
            .get_one::<String>("session")
            .map(|value| uuid::Uuid::parse_str(value))
            .transpose(),
    ) else {
        return ExitCode::FAILURE;
    };
    let Ok(session) = session else {
        return ExitCode::FAILURE;
    };
    if infraternal_plugin_ssh::session_bridge::run(PathBuf::from(state), session).is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn missing_action(json_output: bool) -> ExitCode {
    emit(
        CommandResult::new(
            "infraternal",
            CommandState::Refused,
            "That is not a command this build has.",
            json!({}),
        )
        .with_next_step("infraternal --help"),
        json_output,
        Exit::Usage,
    )
}

/// Whether `--json` was typed anywhere, known before any parsing so failures can honour it.
fn requested_json_early() -> bool {
    std::env::args_os().any(|argument| argument == "--json")
}

/// What to do with a command line that did not parse (see `cli::usage`).
///
/// Help and version are not failures: people get the parser's text, `--json` callers one envelope
/// that carries the same text. Every real failure is worded by us, in text and in JSON, so the
/// value that was typed (it may be a URL with a token, or a path) is never echoed back.
fn parse_failure(registry: &ActionRegistry, error: &clap::Error, json: bool) -> ExitCode {
    use clap::error::ErrorKind;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let tree = cli::command_tree::build(registry);
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion if json => {
            emit(cli::usage::help_result(&tree, &args, error), true, Exit::Ok)
        }
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayVersion
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
            if !json =>
        {
            error.exit()
        }
        _ => emit(cli::usage::result(&tree, &args, error), json, Exit::Usage),
    }
}

/// The shipping diagnostic refuses partial protection independently of server development policy.
#[cfg(feature = "remote")]
fn run_key_memory_check(json_output: bool) -> ExitCode {
    // D244 requires fully protected pages even for a non-root gate runner.
    if infraternal_shim::openssl_secure::initialize() == 1 {
        output::done(
            json_output,
            "internal.key-memory-check",
            "ready",
            "Key memory initialization=1; locked pages and dump exclusion enabled",
            "",
        )
    } else {
        output::refuse(
            json_output,
            "internal.key-memory-check",
            "Key memory refused",
            "Raise the memlock limit to at least 8 MiB and run the check again.",
            Exit::Failed,
        )
    }
}

/// What this machine runs, as the shared result; the second value is how many installed services are confirmed not running (unknown ones are not counted).
fn status_result(
    registry: &ActionRegistry,
    command: &str,
) -> (CommandResult<serde_json::Value>, usize) {
    use infraternal_status::Activity;
    let ids: Vec<String> = registry
        .plugins()
        .filter(|plugin| plugin.id != "cli")
        .map(|plugin| plugin.id.clone())
        .collect();
    let roots = infraternal_status::Roots::detect();
    let node = infraternal_status::probe_local(&roots, &ids);
    #[cfg(all(feature = "remote", feature = "plugin-server"))]
    let ca_status = infraternal_status::server_data_directory(&roots).map(|data| {
        crate::restart::query_ca_status(&data)
            .unwrap_or_else(|_| infraternal_server::ca_status::CaStatus::unavailable())
    });
    let (activity, message, next) = node.headline();
    let state = match activity {
        Activity::Active => CommandState::Running,
        Activity::Restarting { .. } => CommandState::Restarting,
        Activity::Inactive => CommandState::Stopped,
        Activity::Failed => CommandState::Failed,
        Activity::Unknown => CommandState::Unknown,
    };
    // A component without a runtime yet is not something this machine has.
    // Only server builds with remote access append the CA row below.
    #[cfg_attr(
        not(all(feature = "remote", feature = "plugin-server")),
        allow(unused_mut)
    )]
    let mut components: Vec<_> = node
        .components
        .iter()
        .filter(|c| c.state != "Not available yet")
        .map(|c| json!({"name": c.name, "state": c.state, "state_detail": c.detail}))
        .collect();
    // People get the components table; the role id is a scripting detail.
    let options = cli::output::RenderOptions::detect(io::stdout().is_terminal());
    #[cfg_attr(
        not(all(feature = "remote", feature = "plugin-server")),
        allow(unused_mut)
    )]
    let mut rows: Vec<Vec<String>> = node
        .components
        .iter()
        .filter(|c| c.state != "Not available yet")
        .map(|c| vec![c.name.clone(), c.state.clone(), c.detail.clone()])
        .collect();
    #[cfg(all(feature = "remote", feature = "plugin-server"))]
    if let Some(status) = ca_status {
        let (state, detail) = ca_status_display(&status);
        components.push(json!({"name":"CA", "state":state, "state_detail":detail}));
        rows.push(vec!["CA".to_owned(), state, detail]);
    }
    let tint = |column: usize, text: &str| {
        (options.color && column == 1)
            .then(|| cli::output::state_tint(text))
            .flatten()
    };
    let mut result = CommandResult::new(
        command,
        state,
        message,
        json!({"role": node.role.id(), "components": components}),
    )
    .with_body(infraternal_plugin_api::present::table(
        &["Component", "State", "Detail"],
        &rows,
        0,
        options.usable_width(),
        Some(&tint),
    ));
    for step in next {
        result = result.with_next_step(step);
    }
    let down = node.confirmed_down_count();
    (result, down)
}

/// The CA line `infraternal status` prints: lock state, root generation and expiry warning, or why it is unknown.
#[cfg(all(feature = "remote", feature = "plugin-server"))]
fn ca_status_display(status: &infraternal_server::ca_status::CaStatus) -> (String, String) {
    if !status.available {
        return (
            "Unavailable".to_owned(),
            "Running server CA status is unavailable.".to_owned(),
        );
    }
    if !status.initialized {
        return (
            "Not initialized".to_owned(),
            "No public CA root is retained.".to_owned(),
        );
    }
    let Some(root) = status
        .roots
        .iter()
        .min_by_key(|root| root.remaining_seconds)
    else {
        return (
            "Unknown".to_owned(),
            "The CA root expiry is unavailable.".to_owned(),
        );
    };
    let Some(remaining) = root.remaining_seconds else {
        let lock = match status.locked {
            Some(true) => "CA signing is locked; ",
            Some(false) => "CA signing is available; ",
            None => "CA lock state is unavailable; ",
        };
        return (
            if status.locked == Some(true) {
                "Locked".to_owned()
            } else {
                "Unknown".to_owned()
            },
            format!(
                "{lock}root generation {}; expiry and warning are unknown because the server clock is uncertain.",
                root.generation
            ),
        );
    };
    let expiry = if remaining <= 0 {
        "the public root has expired".to_owned()
    } else {
        let days = remaining.saturating_add(86_399) / 86_400;
        format!("the public root expires in {days} days")
    };
    let warning = root.warning_level.as_str();
    let lock = match status.locked {
        Some(true) => "CA signing is locked; ",
        Some(false) => "CA signing is available; ",
        None => "CA lock state is unavailable; ",
    };
    let state = if status.locked == Some(true) {
        "Locked"
    } else if status.locked.is_none() {
        "Unknown"
    } else {
        match warning {
            "expired" => "Expired",
            "7d" => "Expires within 7 days",
            "30d" => "Expires within 30 days",
            "90d" => "Expires within 90 days",
            "365d" => "Expires within 365 days",
            "none" => "Ready",
            _ => "Unknown",
        }
    };
    (
        state.to_owned(),
        format!(
            "{lock}root generation {}; {expiry}; expiry warning {warning}.",
            root.generation
        ),
    )
}

/// How `infraternal status` renders CA lock and expiry.
#[cfg(all(test, feature = "remote", feature = "plugin-server"))]
mod ca_status_tests {
    use super::ca_status_display;
    use infraternal_server::ca_status::{CaStatus, RootStatus};

    /// A CA status with one root and the given lock state, time left and warning level.
    fn status(locked: Option<bool>, remaining_seconds: Option<i64>, warning: &str) -> CaStatus {
        CaStatus {
            available: true,
            initialized: true,
            locked,
            clock_healthy: remaining_seconds.is_some(),
            roots: vec![RootStatus {
                generation: 4,
                fingerprint: "sha256:test".into(),
                certificate_der: String::new(),
                not_after: 2_000_000_000,
                remaining_seconds,
                warning_level: warning.into(),
            }],
        }
    }

    /// Status shows the root generation, the expiry warning and the lock state.
    #[test]
    fn status_reports_root_generation_expiry_warning_and_lock_state() {
        let (state, detail) = ca_status_display(&status(Some(false), Some(90 * 86_400), "90d"));
        assert_eq!(state, "Expires within 90 days");
        assert!(detail.contains("root generation 4"));
        assert!(detail.contains("expires in 90 days"));
        assert!(detail.contains("expiry warning 90d"));

        let (state, detail) = ca_status_display(&status(Some(true), Some(0), "expired"));
        assert_eq!(state, "Locked");
        assert!(detail.contains("CA signing is locked"));
        assert!(detail.contains("expiry warning expired"));
    }

    /// An untrusted server clock prints no expiry countdown.
    #[test]
    fn unknown_server_clock_does_not_render_a_false_expiry_countdown() {
        let (state, detail) = ca_status_display(&status(None, None, "unknown"));
        assert_eq!(state, "Unknown");
        assert!(detail.contains("root generation 4"));
        assert!(detail.contains("expiry and warning are unknown"));
    }
}

fn run_status(registry: &ActionRegistry, matches: &ArgMatches, json_output: bool) -> ExitCode {
    #[cfg(feature = "remote")]
    if (matches.get_one::<String>("server_override").is_some()
        || sign_in::has_stored_api_credentials())
        && let Some(action) = registry
            .find(&["status"])
            .map(|registered| registered.action)
    {
        return cli::api_actions::run(action, matches, json_output);
    }
    let (result, down) = status_result(registry, "status");
    finish_status(result, down, json_output)
}

/// `status` exits 5 when something that should run is down, so `infraternal status || alert`
/// works in a script (D303). The report itself is information, so it stays on standard output.
fn finish_status(
    result: CommandResult<serde_json::Value>,
    down: usize,
    json_output: bool,
) -> ExitCode {
    if down == 0 {
        return emit(result, json_output, Exit::Ok);
    }
    cli::output::emit_to(
        result.with_error_code("component_down"),
        json_output,
        Exit::Unreachable,
        false,
    )
}

/// Bare `infraternal`: the status overview, or how to join when this machine is not set up (D299).
fn run_overview(registry: &ActionRegistry, json_output: bool) -> ExitCode {
    let (result, down) = status_result(registry, "infraternal");
    finish_status(
        result.with_next_step("infraternal --help"),
        down,
        json_output,
    )
}

/// "1 command", "4 commands".
fn count_commands(count: usize) -> String {
    format!("{count} command{}", if count == 1 { "" } else { "s" })
}

/// A group typed alone (`infraternal mesh`) lists what it can do.
fn run_group(registry: &ActionRegistry, path: &[&str], json_output: bool) -> Option<ExitCode> {
    let commands: Vec<_> = cli::skills::commands(registry)
        .into_iter()
        .filter(|entry| {
            entry
                .command
                .split_whitespace()
                .collect::<Vec<_>>()
                .starts_with(path)
        })
        .collect();
    if commands.is_empty() {
        return None;
    }
    let rows: Vec<Vec<String>> = commands
        .iter()
        .map(|entry| vec![entry.command.clone(), entry.description.clone()])
        .collect();
    let body = infraternal_plugin_api::present::table(
        &["Command", "What it does"],
        &rows,
        0,
        cli::output::RenderOptions::detect(false).usable_width(),
        None,
    );
    let name = path.join(" ");
    Some(emit(
        CommandResult::new(
            name.clone(),
            CommandState::Ready,
            format!("infraternal {name} has {}.", count_commands(commands.len())),
            json!({"commands": commands}),
        )
        .with_body(body)
        .with_next_step(format!("infraternal {name} <command> --help")),
        json_output,
        Exit::Ok,
    ))
}

fn run_skill(registry: &ActionRegistry, matches: &ArgMatches, json_output: bool) -> ExitCode {
    // Preserve hosted dotted action IDs alongside generated command paths.
    let command = matches
        .get_many::<String>("command")
        .into_iter()
        .flatten()
        .flat_map(|part| part.split('.'))
        .collect::<Vec<_>>();
    let write_directory = matches.get_one::<String>("write");
    if write_directory.is_some() && !command.is_empty() {
        return report_failure_as(
            "skill",
            "Choose a command path or a destination directory.",
            "--write cannot be combined with a command path".to_owned(),
            json_output,
            Exit::Usage,
        );
    }

    if let Some(directory) = write_directory {
        return match cli::skills::write_all(registry, Path::new(directory)) {
            Ok(files) => {
                let result = CommandResult::new(
                    "skill",
                    CommandState::Ready,
                    format!("Wrote {} command skill files.", files.len()),
                    json!({"commands": [], "skill": "", "files": files}),
                );
                print_result(&result, json_output, false);
                ExitCode::SUCCESS
            }
            Err(error) => report_failure(
                "skill",
                "The command skill files could not be written.",
                error.to_string(),
                json_output,
            ),
        };
    }

    if command.is_empty() {
        let commands = cli::skills::commands(registry);
        let result = CommandResult::new(
            "skill",
            CommandState::Ready,
            format!(
                "{} {} enabled in this build.",
                count_commands(commands.len()),
                if commands.len() == 1 { "is" } else { "are" }
            ),
            json!({"commands": commands, "skill": "", "files": []}),
        )
        .with_next_step("infraternal skill <command>");
        print_result(&result, json_output, false);
        return ExitCode::SUCCESS;
    }

    if let Some(result) = run_skill_group(registry, &command, json_output) {
        return result;
    }
    let path = command.join(" ");
    let Some(registered) = registry.find(&command).filter(|r| r.action.is_public()) else {
        return report_failure_as(
            "skill",
            "The requested command has no generated skill in this build.",
            "The command path supplied to skill is not a public action.".to_owned(),
            json_output,
            Exit::NotFound,
        );
    };
    let markdown = match cli::skills::render_action(registered.action) {
        Ok(markdown) => markdown,
        Err(error) => {
            return report_failure(
                "skill",
                "The command skill could not be rendered.",
                error.to_string(),
                json_output,
            );
        }
    };
    if json_output {
        let result = CommandResult::new(
            format!("skill {}", command.join(" ")),
            CommandState::Ready,
            format!("Generated the skill for infraternal {path}."),
            json!({"commands": [], "skill": markdown, "files": []}),
        );
        print_result(&result, true, false);
    } else if let Err(error) = io::stdout().write_all(markdown.as_bytes()) {
        return report_failure(
            "skill",
            "The generated command skill could not be printed.",
            error.to_string(),
            false,
        );
    }
    ExitCode::SUCCESS
}

// Component groups list enabled actions from the same registry as help.
fn run_skill_group(
    registry: &ActionRegistry,
    command: &[&str],
    json_output: bool,
) -> Option<ExitCode> {
    if registry.find(command).is_some() {
        return None;
    }
    let commands = cli::skills::commands(registry)
        .into_iter()
        .filter(|entry| {
            entry
                .command
                .split_whitespace()
                .collect::<Vec<_>>()
                .starts_with(command)
        })
        .collect::<Vec<_>>();
    if commands.is_empty() {
        return None;
    }
    let result = CommandResult::new(
        format!("skill {}", command.join(" ")),
        CommandState::Ready,
        "Enabled commands in this component.",
        json!({"commands": commands, "skill": "", "files": []}),
    );
    print_result(&result, json_output, false);
    Some(ExitCode::SUCCESS)
}

fn run_unavailable(action: &ActionDefinition, json_output: bool) -> ExitCode {
    let command = action.command.join(" ");
    let data = empty_action_data(action);
    let (state, message) = if action.availability == ActionAvailability::NotAvailableYet {
        (
            CommandState::Unavailable,
            format!("The {command} command is not available yet."),
        )
    } else {
        (
            CommandState::Failed,
            format!("The {command} command has no handler in this build."),
        )
    };
    let next_step = if action.hosted.is_some() {
        "Use the server UI with an authenticated session to run this plugin action."
    } else {
        "infraternal status"
    };
    emit(
        CommandResult::new(command, state, message, data).with_next_step(next_step),
        json_output,
        Exit::Failed,
    )
}

#[cfg(feature = "plugin-server")]
fn run_server(matches: &ArgMatches, json_output: bool) -> ExitCode {
    if !server_configuration_was_supplied(matches) {
        return emit(
            CommandResult::new(
                "server",
                CommandState::Unavailable,
                "The server is not configured yet.",
                json!({"listen": "127.0.0.1:7443", "public_origin": "https://localhost:7443"}),
            )
            .with_next_step("infraternal server init"),
            json_output,
            Exit::Usage,
        );
    }
    let args = match server_args(matches) {
        Ok(args) => args,
        Err(error) => {
            return report_failure(
                "server",
                "The server configuration is invalid.",
                error,
                json_output,
            );
        }
    };
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return report_failure(
            "server",
            "The server could not start its async runtime.",
            "async runtime initialization failed".to_owned(),
            json_output,
        );
    };
    run_server_foreground(args, runtime, json_output)
}

#[cfg(feature = "plugin-server")]
/// Return whether any server configuration option was supplied on the command line.
fn server_configuration_was_supplied(matches: &ArgMatches) -> bool {
    [
        "listen",
        "data",
        "public_origin",
        "web_root",
        "tls_cert",
        "tls_key",
        "remote_listen",
        "remote_ca_dir",
    ]
    .iter()
    .any(|name| matches.get_one::<String>(name).is_some())
        || matches.get_flag("behind_proxy")
        || matches.get_many::<String>("trusted_proxy").is_some()
        || matches.get_many::<String>("host_firewall_allow").is_some()
        || matches
            .get_many::<String>("host_firewall_accept_interface")
            .is_some()
        || matches
            .get_one::<String>("host_firewall_listen_interface")
            .is_some()
        || matches
            .get_one::<String>("host_firewall_remote_interface")
            .is_some()
        || matches
            .get_many::<String>("host_firewall_remote_source")
            .is_some()
}

#[cfg(feature = "plugin-server")]
/// Parse listener, proxy, persistence and host-policy options into server settings.
fn server_args(matches: &ArgMatches) -> Result<ServerArgs, String> {
    let listen = matches.get_one::<String>("listen").map_or_else(
        || Ok(SocketAddr::from(([127, 0, 0, 1], 7443))),
        |value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| "listener address is invalid".to_owned())
        },
    )?;
    let trusted_proxies = matches
        .get_many::<String>("trusted_proxy")
        .into_iter()
        .flatten()
        .map(|value| {
            value
                .parse::<infraternal_server::ProxyNetwork>()
                .map_err(|_| "trusted proxy address or CIDR is invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let remote_listen = matches
        .try_get_one::<String>("remote_listen")
        .ok()
        .flatten()
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map_err(|_| "remote listener is invalid".to_owned())
        })
        .transpose()?;
    let remote_ca_dir = matches
        .try_get_one::<String>("remote_ca_dir")
        .ok()
        .flatten()
        .map(PathBuf::from);
    if remote_ca_dir.is_some() && remote_listen.is_none() {
        return Err("--remote-ca-dir requires --remote-listen".to_owned());
    }
    Ok(ServerArgs {
        remote: remote_server::Options {
            remote_listen,
            remote_ca_dir,
        },
        listen,
        data: server_data_directory(
            matches.get_one::<String>("data").map(String::as_str),
            infraternal_status::Roots::detect,
        ),
        public_origin: matches.get_one::<String>("public_origin").cloned(),
        web_root: matches.get_one::<String>("web_root").map(PathBuf::from),
        tls_cert: matches.get_one::<String>("tls_cert").map(PathBuf::from),
        tls_key: matches.get_one::<String>("tls_key").map(PathBuf::from),
        behind_proxy: matches.get_flag("behind_proxy"),
        trusted_proxies,
        host_firewall_listen_interface: matches
            .get_one::<String>("host_firewall_listen_interface")
            .cloned(),
        host_firewall_remote_interface: matches
            .get_one::<String>("host_firewall_remote_interface")
            .cloned(),
        host_firewall_remote_sources: matches
            .get_many::<String>("host_firewall_remote_source")
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        host_firewall_accept_interfaces: matches
            .get_many::<String>("host_firewall_accept_interface")
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        host_firewall_allow: matches
            .get_many::<String>("host_firewall_allow")
            .into_iter()
            .flatten()
            .cloned()
            .collect(),
        host_firewall_off: matches
            .try_get_one::<bool>("host_firewall_off")
            .ok()
            .flatten()
            .copied()
            .unwrap_or(false),
    })
}

/// Convert server flags into a root-owned host firewall policy.
#[cfg(all(feature = "plugin-server", target_os = "linux"))]
fn host_firewall_policy(args: &ServerArgs) -> Result<Policy, String> {
    if args.behind_proxy == args.trusted_proxies.is_empty() {
        return Err("--behind-proxy and --trusted-proxy must be configured together".to_owned());
    }
    let mut admin_rules = args
        .host_firewall_allow
        .iter()
        .map(|value| {
            value
                .parse::<AllowRule>()
                .map_err(|_| "host firewall allow rule is invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Any TCP admin rule may be sshd's (it need not listen on 22); the live
    // session, when there is one, is checked port-exactly at install time.
    // Without one, the session's port is admitted from anywhere, as `up` does
    // (J589): never pinned to the installer's address or interface.
    if !admin_rules
        .iter()
        .any(|rule| rule.protocol == Protocol::Tcp)
    {
        let active_ssh = std::env::var("SSH_CONNECTION").map_err(|_| {
            "set an explicit TCP --host-firewall-allow rule for sshd's port".to_owned()
        })?;
        admin_rules.push(
            host_firewall::admin_rule_for_ssh_session(&active_ssh).map_err(|_| {
                "the active SSH path could not be added to the host policy".to_owned()
            })?,
        );
    }
    if args.host_firewall_remote_interface.is_some() && args.remote.remote_listen.is_none()
        || !args.host_firewall_remote_sources.is_empty() && args.remote.remote_listen.is_none()
    {
        return Err("remote host firewall settings need --remote-listen".to_owned());
    }
    let proxy_sources = if args.behind_proxy {
        args.trusted_proxies
            .iter()
            .map(|network| network.to_string().parse())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "trusted proxy firewall source is invalid".to_owned())?
    } else {
        Vec::new()
    };
    let mut listeners = vec![Listener {
        interface: args.host_firewall_listen_interface.clone(),
        address: args.listen,
        protocol: Protocol::Tcp,
        sources: proxy_sources,
    }];
    if let Some(address) = args.remote.remote_listen {
        let sources = args
            .host_firewall_remote_sources
            .iter()
            .map(|source| {
                source
                    .parse()
                    .map_err(|_| "remote host firewall source is invalid".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        listeners.push(Listener {
            interface: args.host_firewall_remote_interface.clone(),
            address,
            protocol: Protocol::Tcp,
            sources: sources.clone(),
        });
        listeners.push(Listener {
            interface: args.host_firewall_remote_interface.clone(),
            address,
            protocol: Protocol::Udp,
            sources,
        });
    }
    let policy = Policy {
        admin_rules,
        accept_interfaces: args.host_firewall_accept_interfaces.clone(),
        listeners,
        mesh_enabled: false,
        mesh_udp_port: None,
    };
    host_firewall::validate(&policy).map_err(|_| {
        "host firewall policy needs valid rules and an explicit TCP admin path for sshd".to_owned()
    })?;
    Ok(policy)
}

/// Plan or perform `server init`: choose absolute folders, confirm, then install the service.
#[cfg(feature = "plugin-server")]
fn run_server_init(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let mut args = match server_args(matches) {
        Ok(args) => args,
        Err(error) => {
            return report_failure(
                "server init",
                "The server configuration is invalid.",
                error,
                json_output,
            );
        }
    };
    let dry_run = matches.get_flag("dry_run");
    let scope = if matches.get_flag("system") {
        install_paths::Scope::System
    } else {
        install_paths::Scope::User
    };
    let environment = install_paths::Environment::detect();
    let name = matches
        .get_one::<String>("name")
        .map_or("infraternal-server", String::as_str);
    // Init, unlike the readers, never falls back to `./data` or the cwd, and a
    // re-run keeps what the installed unit records [#516, D395].
    let roots = infraternal_status::Roots::detect();
    let installed = install_paths::Installed {
        unit: infraternal_status::recorded_server_unit(
            &roots,
            match scope {
                install_paths::Scope::System => infraternal_status::Scope::System,
                install_paths::Scope::User => infraternal_status::Scope::User,
            },
            name,
        ),
        system_data: infraternal_status::server_data_directory(&roots),
        system_unit: infraternal_status::recorded_server_unit(
            &roots,
            infraternal_status::Scope::System,
            name,
        )
        .is_some(),
    };
    if let Some(warning) = install_paths::root_user_scope_warning(scope, &installed, &environment) {
        eprintln!("{warning}");
    }
    let folders = install_paths::check_scope(scope, dry_run, &environment).and_then(|()| {
        install_paths::resolve_server_init(
            scope,
            matches.get_one::<String>("data").map(Path::new),
            matches.get_one::<String>("web_root").map(Path::new),
            &installed,
            &environment,
        )
    });
    match folders {
        Ok(folders) => {
            args.data = folders.data;
            args.web_root = folders.web_root;
        }
        Err(error) => {
            return report_failure(
                "server init",
                "The server folders could not be chosen.",
                error.to_string(),
                json_output,
            );
        }
    }
    // Root runs the units init writes, so they may only name a binary that
    // only root can change (#146, J1087). A dry run shows the problem and
    // still prints the plan; a real run stops here, before anything changes.
    // Without root a real `--system` run was already refused above.
    if scope == install_paths::Scope::System || environment.is_root {
        let checked = install::service_program()
            .map_err(|error| format!("the running binary cannot be found: {error}"))
            .and_then(|program| install::check_root_service_program(&program, 0));
        if let Err(problem) = checked {
            if !dry_run {
                return report_failure(
                    "server init",
                    "The infraternal binary is not safe for a service that root runs.",
                    problem,
                    json_output,
                );
            }
            eprintln!("warning: {problem}; a real install refuses this binary");
        }
        // The same for the web folder the unit will serve: whoever can change
        // it can serve their own script to a signed-in administrator (#146,
        // J1151). Checked here, before any data move rewrites the path, so
        // it judges the folder as it is now.
        // The unit stores the canonical path the check returns, so a link
        // on the path given cannot be repointed afterwards (J1180, F3).
        if let Some(web) = &args.web_root {
            match install::check_root_web_folder(web, 0) {
                Ok(canonical) => args.web_root = Some(canonical),
                Err(problem) => {
                    if !dry_run {
                        return report_failure(
                            "server init",
                            "The web folder is not safe for a service that root runs.",
                            problem,
                            json_output,
                        );
                    }
                    eprintln!("warning: {problem}; a real install refuses this web folder");
                }
            }
        }
    }
    // An existing unit's non-standard folder moves to the D395 one (owner,
    // 2026-11-15: "change for existing installs too"); `--data` keeps any folder.
    let relocation = match plan_server_data_move(
        matches.get_one::<String>("data").is_some(),
        installed
            .unit
            .as_ref()
            .and_then(|unit| unit.data.as_deref()),
        scope,
        &environment,
        &roots,
        name,
    ) {
        Ok(relocation) => relocation,
        Err(error) => {
            return report_failure(
                "server init",
                "The existing data folder cannot be moved to its standard location.",
                error,
                json_output,
            );
        }
    };
    if let Some(relocation) = &relocation {
        args.data.clone_from(&relocation.to);
        relocation.relocate_path(&mut args.web_root);
        relocation.relocate_path(&mut args.tls_cert);
        relocation.relocate_path(&mut args.tls_key);
        relocation.relocate_path(&mut args.remote.remote_ca_dir);
    }
    let yes = matches.get_flag("yes");
    if let Err(error) = confirm_server_setup(
        yes,
        dry_run,
        args.listen,
        &match &relocation {
            Some(relocation) => format!(
                "{} (moved from {})",
                args.data.display(),
                relocation.from.display()
            ),
            _ => args.data.display().to_string(),
        },
        if matches.get_flag("system") {
            "system"
        } else {
            "user"
        },
    ) {
        return report_failure(
            "server init",
            "Server setup needs confirmation.",
            error,
            json_output,
        );
    }
    if matches.get_flag("system") && matches.get_flag("user") {
        return report_failure(
            "server init",
            "Choose one service scope.",
            "--system conflicts with --user".to_owned(),
            json_output,
        );
    }
    let install_args = InstallArgs {
        system: matches.get_flag("system"),
        user: !matches.get_flag("system"),
        dry_run,
        force: matches.get_flag("force"),
        name: name.to_owned(),
    };
    let moved = match &relocation {
        None => None,
        Some(relocation) if dry_run => {
            Some((relocation.describe(), relocation_json(relocation, None)))
        }
        Some(relocation) => {
            let admitted = match install::prepare_move(&args, &install_args, relocation) {
                Ok(admitted) => admitted,
                Err(error) => {
                    return report_failure(
                        "server init",
                        "The data move was refused.",
                        error.to_string(),
                        json_output,
                    );
                }
            };
            let service = install_move::Systemd {
                program: admitted.systemctl.clone(),
                user: !install_args.system,
                service: format!("{name}.service"),
                listen: args.listen,
                tls: args.tls_cert.is_some(),
            };
            #[cfg(target_os = "linux")]
            let result = install_move::manager::trigger(relocation, service, admitted);
            #[cfg(not(target_os = "linux"))]
            let result =
                install_move::apply(relocation, &service, std::time::SystemTime::now(), || {
                    admitted.publish()
                });
            match result {
                Ok(outcome) => {
                    install::finish_move(!install_args.system, &args.data);
                    Some((
                        outcome.describe(relocation),
                        relocation_json(relocation, Some(&outcome)),
                    ))
                }
                Err(error) => {
                    return report_failure(
                        "server init",
                        "The data move could not finish.",
                        error.to_string(),
                        json_output,
                    );
                }
            }
        }
    };
    install_server("server init", &args, &install_args, moved, json_output)
}

/// Plan the move of an existing unit's data folder to the D395 default [#516].
///
/// Nothing is planned for a fresh install, an explicit `--data`, or a unit
/// already at the standard folder with no unfinished move.
#[cfg(feature = "plugin-server")]
fn plan_server_data_move(
    explicit_data: bool,
    recorded: Option<&Path>,
    scope: install_paths::Scope,
    environment: &install_paths::Environment,
    roots: &infraternal_status::Roots,
    name: &str,
) -> Result<Option<install_move::Relocation>, String> {
    let Some(recorded) = recorded else {
        return Ok(None);
    };
    // Rewrite the unit the recorded folder was read from, found the way
    // `recorded_server_unit` finds it, so reading and rewriting never disagree.
    let file = format!("{name}.service");
    let directories: Vec<&PathBuf> = match scope {
        install_paths::Scope::System => roots.system_units.iter().collect(),
        install_paths::Scope::User => roots.user_units.iter().collect(),
    };
    let unit = match directories
        .into_iter()
        .map(|directory| directory.join(&file))
        .find(|path| path.exists())
    {
        Some(path) => path,
        None => install::unit_path(scope == install_paths::Scope::User, name)
            .map_err(|error| error.to_string())?,
    };
    let target =
        install_paths::server_data_dir(scope, environment).map_err(|error| error.to_string())?;
    #[cfg(target_os = "linux")]
    let target = if scope == install_paths::Scope::System
        && target == environment.linux_system_base
    {
        combined_server_move_target(target, recorded, &unit)?
    } else {
        target
    };
    if explicit_data {
        #[cfg(target_os = "linux")]
        let requested =
            install_move::manager::requested(&target).map_err(|error| error.to_string())?;
        #[cfg(not(target_os = "linux"))]
        let requested = false;
        if requested || install_move::pending(&target, &unit).map_err(|error| error.to_string())? {
            return Err("a data move is in progress; run init with the original service flags and without --data to finish it".to_owned());
        }
        return Ok(None);
    }
    install_move::plan(recorded, &target, &unit).map_err(|error| error.to_string())
}

/// Keep the systemd-selected private child or resume a recorded cutover to it.
#[cfg(all(target_os = "linux", feature = "plugin-server"))]
fn combined_server_move_target(
    base: PathBuf,
    recorded: &Path,
    unit: &Path,
) -> Result<PathBuf, String> {
    let child = base.join("server");
    if recorded == child
        || install_move::manager::requested(&child).map_err(|error| error.to_string())?
        || install_move::pending(&child, unit).map_err(|error| error.to_string())?
    {
        Ok(child)
    } else {
        Ok(base)
    }
}

/// The move as JSON for `--json`: folders, method and any leftover to remove.
#[cfg(feature = "plugin-server")]
fn relocation_json(
    relocation: &install_move::Relocation,
    outcome: Option<&install_move::Outcome>,
) -> serde_json::Value {
    json!({
        "from": relocation.from,
        "to": relocation.to,
        "same_filesystem": relocation.same_filesystem,
        "unit_files": relocation.unit_files().collect::<Vec<_>>(),
        "moved": outcome.is_some(),
        "leftover": outcome.and_then(|outcome| outcome.leftover.as_ref()),
        "warning": null,
    })
}

/// Ask before creating the service on a terminal; `--yes` and `--dry-run` skip it.
///
/// `data_dir` is the text shown for the data folder, which names the old
/// folder too when init is about to move it.
#[cfg(feature = "plugin-server")]
fn confirm_server_setup(
    yes: bool,
    dry_run: bool,
    listen: SocketAddr,
    data_dir: &str,
    scope: &str,
) -> Result<(), String> {
    if yes || dry_run {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err("pass --yes in non-interactive mode, or use --dry-run first".to_owned());
    }
    print!(
        "Create and start the {scope} server service on {listen} with data in {data_dir}? [y/N] ",
    );
    io::stdout()
        .flush()
        .map_err(|_| "the confirmation prompt could not be displayed".to_owned())?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|_| "the confirmation could not be read".to_owned())?;
    if response.trim().eq_ignore_ascii_case("y") || response.trim().eq_ignore_ascii_case("yes") {
        Ok(())
    } else {
        Err("setup was cancelled; no server service was created".to_owned())
    }
}

#[cfg(feature = "plugin-server")]
fn run_server_install_compat(_matches: &ArgMatches, json_output: bool) -> ExitCode {
    let result = CommandResult::new(
        "server install",
        CommandState::Unavailable,
        "The legacy server install path is disabled and did not create a service.",
        json!({"service": "", "enabled": false, "dry_run": false}),
    )
    .with_next_step("infraternal server init --dry-run");
    emit(result, json_output, Exit::Usage)
}

/// Install (or plan) the unit and print the result, with any data-folder move told first.
#[cfg(feature = "plugin-server")]
fn install_server(
    command: &str,
    args: &ServerArgs,
    install_args: &InstallArgs,
    moved: Option<(String, serde_json::Value)>,
    json_output: bool,
) -> ExitCode {
    let installed = if moved.is_some() && !install_args.dry_run {
        Ok(String::new())
    } else {
        install::install(args, install_args)
    };
    match installed {
        Ok(plan) => {
            let mut data = json!({
                "service": format!("{}.service", install_args.name),
                "enabled": !install_args.dry_run,
                "dry_run": install_args.dry_run,
            });
            // The move is told first: in a dry run it is the first step, and
            // after a real one its leftover note must not scroll away.
            let (moved_text, plan) = match moved {
                Some((text, value)) => {
                    data["data_move"] = value;
                    (text.clone(), format!("{text}{plan}"))
                }
                None => (String::new(), plan),
            };
            if install_args.dry_run {
                data["plan"] = json!(plan);
            }
            let mut result = CommandResult::new(
                command,
                CommandState::Ready,
                if install_args.dry_run {
                    "The server installation plan is ready."
                } else {
                    "The server service was installed and enabled."
                },
                data,
            )
            .with_next_step(if install_args.dry_run {
                "infraternal server init --yes"
            } else {
                "infraternal status"
            });
            if install_args.dry_run {
                // The unit file is data for a person to read and copy: the generic renderer
                // would reflow its lines into prose and break it.
                result = result.with_body(plan);
            } else if !moved_text.is_empty() {
                result = result.with_body(moved_text);
            }
            print_result(&result, json_output, false);
            ExitCode::SUCCESS
        }
        Err(error) => report_failure(
            command,
            "The server service could not be installed.",
            error.to_string(),
            json_output,
        ),
    }
}

#[cfg(feature = "plugin-server")]
#[derive(Serialize)]
/// Keeps the deployed private setup reader alongside the versioned CLI envelope.
struct SetupTokenOutput<'a> {
    #[serde(flatten)]
    result: &'a CommandResult<serde_json::Value>,
    token: &'a str,
}

#[cfg(feature = "plugin-server")]
fn run_setup_token(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let data_dir = server_data_directory(
        matches.get_one::<String>("data").map(String::as_str),
        infraternal_status::Roots::detect,
    );
    let Ok(runtime) = tokio::runtime::Runtime::new() else {
        return report_failure(
            "server setup-token",
            "The setup capability could not be read.",
            "async runtime initialization failed".to_owned(),
            json_output,
        );
    };
    match block_on(&runtime, read_setup_token(&data_dir)) {
        Ok(token) => {
            let result = CommandResult::new(
                "server setup-token",
                CommandState::Ready,
                "A one-time setup capability is available.",
                json!({"token": &token}),
            );
            if json_output {
                // Both private-pipe readers remain valid; the capability never enters logs or argv.
                write_output(
                    render_json(&SetupTokenOutput {
                        result: &result,
                        token: &token,
                    }),
                    false,
                );
            } else {
                print_result(&result, false, false);
            }
            ExitCode::SUCCESS
        }
        Err(SetupTokenReadError::PermissionDenied) => {
            setup_token_permission_failure(matches, json_output)
        }
        Err(SetupTokenReadError::Unavailable(error)) => report_failure(
            "server setup-token",
            "The setup capability is not available.",
            error.to_owned(),
            json_output,
        ),
    }
}

/// Resolve the server's explicit, installed-service, and fallback data locations in that order.
#[cfg(feature = "plugin-server")]
fn server_data_directory(
    explicit: Option<&str>,
    roots: impl FnOnce() -> infraternal_status::Roots,
) -> PathBuf {
    if let Some(explicit) = explicit {
        return PathBuf::from(explicit);
    }

    infraternal_status::server_data_directory(&roots()).unwrap_or_else(|| PathBuf::from("./data"))
}

/// Keep the non-JSON permission diagnostic to one actionable line.
#[cfg(feature = "plugin-server")]
fn setup_token_permission_failure(matches: &ArgMatches, json_output: bool) -> ExitCode {
    let explicit = matches.get_one::<String>("data");
    let command = setup_token_sudo_command(explicit.map(String::as_str));
    if json_output {
        return report_failure(
            "server setup-token",
            "The server data directory is not readable.",
            format!("run: {command}"),
            true,
        );
    }
    eprintln!("The server data directory is not readable. Run: {command}");
    ExitCode::from(Exit::Failed.code())
}

/// Format the actual action command, preserving an explicit path as a shell-safe argument.
#[cfg(feature = "plugin-server")]
fn setup_token_sudo_command(explicit_data: Option<&str>) -> String {
    let mut command = infraternal_server::cli::setup_token_command(true);
    if let Some(data) = explicit_data {
        command.push_str(" --data ");
        command.push_str(&shell_quote(data));
    }
    command
}

/// Quote a path as one POSIX shell argument when the permission diagnostic is copied.
#[cfg(feature = "plugin-server")]
fn shell_quote(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./-".contains(&byte))
    {
        return argument.to_owned();
    }
    format!("'{}'", argument.replace('\'', "'\\''"))
}

/// Share cold command startup through the existing reactor regardless of result type [243].
/// The result slot outlives its adapter future, which stores the result before
/// completing. Panics propagate to the caller's existing recovery boundary.
#[cfg(any(feature = "plugin-server", feature = "remote"))]
fn block_on<T>(
    runtime: &tokio::runtime::Runtime,
    operation: impl std::future::Future<Output = T>,
) -> T {
    #[cfg(feature = "plugin-agent")]
    {
        let mut outcome = None;
        // One allocation per command keeps its typed result out of another
        // reactor instantiation; terminal frames never cross this adapter.
        let _completion = infraternal_agent::block_on_io(
            runtime,
            Box::pin(async {
                outcome = Some(operation.await);
                Ok(())
            }),
        );
        match outcome {
            Some(value) => value,
            None => unreachable!("a completed startup operation stores its result"),
        }
    }
    #[cfg(not(feature = "plugin-agent"))]
    runtime.block_on(operation)
}

/// How long a stopping server waits for blocking work nobody awaits any more.
#[cfg(feature = "plugin-server")]
const SERVER_STOP_BLOCKING_GRACE: std::time::Duration = std::time::Duration::from_secs(4);

/// Drop the server's runtime with a bound once `serve` has returned.
///
/// By then the server has closed its listener and database, and every step a
/// stop needs has finished. What can remain are detached blocking tasks, for
/// example the payload warm-up hashing a release binary, which Tokio cannot
/// cancel. A plain drop waits for them without limit: a "stopped normally"
/// server then lived on for seconds, and for more than the service manager's
/// patience on a loaded host with a large debug binary (#516). The grace is
/// the same 4 s the same-PID restart gives its own runtime.
#[cfg(feature = "plugin-server")]
fn stop_server_runtime(runtime: tokio::runtime::Runtime) {
    runtime.shutdown_timeout(SERVER_STOP_BLOCKING_GRACE);
}

/// Run the configured server in this process until it stops or restarts into another image.
///
/// A server started from an installed release serves that release's own web build
/// (`serve_release_web`, #211 S6). Returns the command's exit code; a warm restart never
/// returns, because the process execs the replacement.
#[cfg(feature = "plugin-server")]
fn run_server_foreground(
    mut args: ServerArgs,
    runtime: tokio::runtime::Runtime,
    json_output: bool,
) -> ExitCode {
    let options = std::mem::take(&mut args.remote);
    let action_id = options.action_id();
    let remote_requested = options.remote_listen.is_some();
    #[cfg(feature = "release")]
    let release_web = serve_release_web(&mut args);
    let config = match server_config(args) {
        Ok(config) => config,
        Err(error) => {
            return report_failure(
                "server",
                "The server configuration is invalid.",
                error,
                json_output,
            );
        }
    };
    let output = json!({
        "listen": config.listen.to_string(),
        "public_origin": config.public_origin,
    });
    infraternal_server::configure_logging(json_output);
    #[cfg(feature = "release")]
    if let Some((flag, web)) = &release_web {
        tracing::info!(web_root = %web.display(), ignored_web_root = ?flag, outcome = "release_web_root",
            "serving the web build signed with this release");
    }
    let stopped = match block_on(&runtime, remote_server::serve(config, options)) {
        #[cfg(feature = "remote")]
        Ok(remote_server::Outcome::Restart(replacement)) => {
            // Same-PID exec consumes the runtime after cancelling server tasks.
            return restart::replace(runtime, *replacement, json_output);
        }
        Ok(remote_server::Outcome::Stopped) => Ok(()),
        Err(error) => Err(error),
    };
    stop_server_runtime(runtime);
    match stopped {
        Ok(()) => {
            print_result(
                &CommandResult::new(
                    "server",
                    CommandState::Stopped,
                    "The server stopped normally.",
                    output,
                ),
                json_output,
                false,
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            #[cfg(feature = "remote")]
            if remote_requested {
                return output::refuse(
                    json_output,
                    action_id,
                    &error.to_string(),
                    "Check configuration and retained public server trust.",
                    Exit::Failed,
                );
            }
            #[cfg(not(feature = "remote"))]
            let _ = (action_id, remote_requested);
            report_failure(
                "server",
                "The server stopped after an error.",
                error.to_string(),
                json_output,
            )
        }
    }
}

#[cfg(feature = "plugin-agent")]
fn run_embedded_agent(
    registry: &ActionRegistry,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    let Some(fd) = matches
        .get_one::<i64>("fd")
        .and_then(|fd| i32::try_from(*fd).ok())
    else {
        // Typed by a person (the server passes a descriptor), `agent` is a group like the others.
        if let Some(listed) = run_group(registry, &["agent"], json_output) {
            return listed;
        }
        return emit(
            CommandResult::new(
                "agent",
                CommandState::Unavailable,
                "The infraternal agent needs a server connection to start.",
                json!({}),
            )
            .with_next_step("infraternal agent join --help"),
            json_output,
            Exit::Usage,
        );
    };
    let state = matches.get_one::<String>("state").map(PathBuf::from);
    match infraternal_agent::run_embedded(fd, state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => report_failure(
            "agent",
            "The infraternal agent could not start.",
            error.to_string(),
            json_output,
        ),
    }
}

// Parse the paired private handoff capability without reserving fixed slots.
#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
fn prestarted_descriptors(matches: &ArgMatches) -> Result<Option<(i32, i32)>, ExitCode> {
    match (
        matches.get_one::<i64>("login_master_fd"),
        matches.get_one::<i64>("login_lease_fd"),
    ) {
        (None, None) => Ok(None),
        (Some(master), Some(lease)) => match (i32::try_from(*master), i32::try_from(*lease)) {
            (Ok(master), Ok(lease)) if master >= 8 && lease >= 8 && master != lease => {
                Ok(Some((master, lease)))
            }
            _ => Err(ExitCode::from(2)),
        },
        _ => Err(ExitCode::from(2)),
    }
}

/// Run the hidden `__shim` command: decode its options and start the shim.
// This startup entry is absent from a running daemon; keep its code away
// from hot dispatch pages without changing the terminal/worker pump itself.
#[cold]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_shim_command(matches: &ArgMatches) -> ExitCode {
    let options = match (|| {
        Ok::<_, String>(shim_cli::Options {
            session: matches
                .get_one::<String>("session")
                .cloned()
                .unwrap_or_default(),
            uid: shim_integer(matches, "uid", None)?,
            cols: shim_integer(matches, "cols", Some(80))?,
            rows: shim_integer(matches, "rows", Some(24))?,
            state: matches.get_one::<String>("state").map(PathBuf::from),
            detach: matches.get_flag("detach"),
            ring_capacity: shim_integer(matches, "ring_capacity", Some(8 * 1024 * 1024))?,
            exit_retention_ms: matches
                .get_one::<i64>("exit_retention_ms")
                .copied()
                .unwrap_or(600_000)
                .try_into()
                .unwrap_or(600_000),
            readiness: matches.get_flag("readiness"),
            command_stdin: matches.get_flag("command_stdin"),
            retain_output: matches.get_flag("retain_output"),
            // Refuse a number that is not a descriptor, rather than dropping it: a shim must never
            // start without the lifeline its launcher asked it to hold (contracts/shim.md §2).
            lifeline_fd: matches
                .get_one::<i64>("lifeline_fd")
                .map(|descriptor| {
                    i32::try_from(*descriptor)
                        .map_err(|_| "--lifeline-fd is out of range".to_owned())
                })
                .transpose()?,
        })
    })() {
        Ok(options) => options,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            return ExitCode::from(2);
        }
    };
    #[cfg(feature = "process-per-user")]
    if matches.get_one::<i64>("host_sessions").is_some() {
        return user_host_cli::run(matches);
    }
    #[cfg(feature = "process-per-user")]
    if matches.get_one::<String>("host_accounting").is_some() {
        eprintln!("--host-accounting requires --host-sessions");
        return ExitCode::from(2);
    }

    #[cfg(all(feature = "plugin-agent", target_os = "linux"))]
    if let Some(result) = run_login_shim_if_requested(matches, &options) {
        return result;
    }
    match options.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("shim startup/session failed: {error}");
            ExitCode::from(1)
        }
    }
}

/// Dispatch the private login workers only when their authenticated fields are present.
#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
#[cold]
fn run_login_shim_if_requested(
    matches: &ArgMatches,
    options: &shim_cli::Options,
) -> Option<ExitCode> {
    let login_socket = matches.get_one::<String>("login_socket").map(PathBuf::from);
    if matches
        .get_one::<String>("login_worker_proc")
        .is_some_and(|path| infraternal_shim::protect_login_process_at(Path::new(path)).is_err())
    {
        return Some(ExitCode::FAILURE);
    }
    let prestarted = match prestarted_descriptors(matches) {
        Ok(descriptors) => descriptors,
        Err(code) => return Some(code),
    };
    if matches.get_flag("login_worker") || matches.get_flag("login_proxy") {
        if prestarted.is_some() {
            return Some(ExitCode::from(2));
        }
        let Some(endpoint) = login_socket.as_deref() else {
            return Some(ExitCode::from(2));
        };
        return Some(run_login_command(
            matches,
            &options.session,
            options.uid,
            endpoint,
        ));
    }
    let login_cgroup = matches.get_one::<String>("login_cgroup").map(PathBuf::from);
    let login_worker_pid = matches
        .get_one::<i64>("login_worker_pid")
        .and_then(|pid| i32::try_from(*pid).ok());
    let login_worker_parent = matches
        .get_one::<i64>("login_worker_parent")
        .and_then(|pid| i32::try_from(*pid).ok());
    let login_worker_proc = matches
        .get_one::<String>("login_worker_proc")
        .map(PathBuf::from);
    let has_login_config = login_socket.is_some()
        || login_cgroup.is_some()
        || login_worker_pid.is_some()
        || login_worker_parent.is_some()
        || login_worker_proc.is_some()
        || prestarted.is_some();
    if !has_login_config {
        return None;
    }
    if options.command_stdin {
        eprintln!("command startup with a host login is unavailable");
        return Some(ExitCode::from(2));
    }
    Some(
        match run_shim(
            &options.session,
            options.uid,
            options.cols,
            options.rows,
            options.state.clone(),
            options.detach,
            options.ring_capacity,
            login_socket,
            login_cgroup.as_deref(),
            login_worker_pid,
            login_worker_parent,
            login_worker_proc,
            options.exit_retention_ms,
            options.readiness,
            options.retain_output,
            prestarted,
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("shim startup/session failed: {error}");
                ExitCode::from(1)
            }
        },
    )
}

#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
// This startup entry is absent from a running daemon; keep its code away
// from hot dispatch pages without changing the terminal/worker pump itself.
#[cold]
/// Runs the shim's host-login roles: the login worker (on a root-created
/// socket with `--login-listen-fd 0`, or binding its own), or the proxy that
/// starts a terminal inside an authenticated login.
fn run_login_command(
    matches: &ArgMatches,
    session: &str,
    uid: u32,
    endpoint: &std::path::Path,
) -> ExitCode {
    let result = if matches.get_flag("login_worker")
        && let Some(listen) = matches.get_one::<i64>("login_listen_fd")
    {
        // Only the announced, root-launched worker takes a root-created socket,
        // always on standard input (fd 0), never another number.
        if *listen != 0 || matches.get_one::<i64>("login_ready_fd") != Some(&1) {
            return ExitCode::from(2);
        }
        std::os::fd::AsFd::as_fd(&std::io::stdin())
            .try_clone_to_owned()
            .and_then(|bound| {
                infraternal_shim::login::worker_announced_on(
                    endpoint,
                    infraternal_shim::login::GRACE,
                    shim_integer(matches, "controller_uid", Some(0)).unwrap_or(u32::MAX),
                    bound,
                )
            })
            .map(|()| 0)
    } else if matches.get_flag("login_worker") {
        let startup = match matches.get_one::<i64>("login_ready_fd") {
            None => infraternal_shim::login::worker_as_controller,
            Some(1) => infraternal_shim::login::worker_announced,
            Some(_) => return ExitCode::from(2),
        };
        startup(
            endpoint,
            infraternal_shim::login::GRACE,
            shim_integer(matches, "controller_uid", Some(0)).unwrap_or(u32::MAX),
        )
        .map(|()| 0)
    } else {
        let Ok(id) = uuid::Uuid::parse_str(session) else {
            return ExitCode::from(2);
        };
        infraternal_shim::login::proxy_at_parent(
            endpoint,
            uid,
            id.as_bytes(),
            matches
                .get_one::<i64>("login_ready_fd")
                .is_some_and(|fd| *fd == 4),
            matches
                .get_one::<i64>("login_worker_pid")
                .and_then(|pid| i32::try_from(*pid).ok()),
            matches
                .get_one::<String>("login_worker_proc")
                .map(std::path::Path::new),
            matches
                .get_one::<i64>("login_worker_parent")
                .and_then(|pid| i32::try_from(*pid).ok()),
        )
    };
    match result {
        Ok(status) if status < 0 => {
            if let Some(number) = status.checked_neg()
                && let Ok(signal) = nix::sys::signal::Signal::try_from(number)
            {
                let _ = nix::sys::signal::kill(nix::unistd::getpid(), signal);
            }
            ExitCode::FAILURE
        }
        Ok(status) => ExitCode::from(u8::try_from(status).unwrap_or(1)),
        Err(_) => ExitCode::FAILURE,
    }
}

/// Parse schema-generated integer inputs into the shim's platform-specific types.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn shim_integer<T>(matches: &ArgMatches, name: &str, default: Option<T>) -> Result<T, String>
where
    T: TryFrom<i64>,
{
    let Some(value) = matches.get_one::<i64>(name).copied() else {
        return default.ok_or_else(|| format!("--{name} is required"));
    };
    T::try_from(value).map_err(|_| format!("--{name} is outside the supported range"))
}

fn report_failure(command: &str, message: &str, details: String, json_output: bool) -> ExitCode {
    report_failure_as(command, message, details, json_output, Exit::Failed)
}

/// Like [`report_failure`], for a failure that D303 gives its own exit code (not found, usage).
fn report_failure_as(
    command: &str,
    message: &str,
    details: String,
    json_output: bool,
    exit: Exit,
) -> ExitCode {
    emit(
        CommandResult::new(
            command,
            CommandState::Failed,
            message,
            failure_data(command),
        )
        .with_details(details),
        json_output,
        exit,
    )
}

/// Keep failed JSON results typed by the action's declared `data` schema.
fn failure_data(command: &str) -> serde_json::Value {
    let command = command.split_whitespace().collect::<Vec<_>>();
    cli::actions::registry()
        .ok()
        .and_then(|registry| {
            registry
                .find(&command)
                .map(|registered| empty_action_data(registered.action))
        })
        .unwrap_or_else(|| json!({}))
}

/// Build an empty data value matching the registered action's output contract.
fn empty_action_data(action: &ActionDefinition) -> serde_json::Value {
    action
        .output_schema
        .properties
        .get("data")
        .map_or_else(|| json!({}), empty_schema_value)
}

/// Build neutral values recursively, omitting optional fields from objects.
fn empty_schema_value(schema: &JsonSchema) -> serde_json::Value {
    match schema.schema_type {
        JsonSchemaType::String => json!(""),
        JsonSchemaType::Integer | JsonSchemaType::Number => json!(0),
        JsonSchemaType::Boolean => json!(false),
        JsonSchemaType::Array => json!([]),
        JsonSchemaType::Object => {
            let mut object = serde_json::Map::new();
            for field in &schema.required {
                if let Some(field_schema) = schema.properties.get(field) {
                    object.insert(field.clone(), empty_schema_value(field_schema));
                }
            }
            serde_json::Value::Object(object)
        }
    }
}

#[cfg(test)]
mod failure_data_tests {
    //! Keeps JSON error payloads typed to their registered action schemas.

    use super::failure_data;
    use serde_json::json;

    #[test]
    fn skill_errors_keep_the_registered_result_data_shape() {
        assert_eq!(
            failure_data("skill"),
            json!({"commands": [], "skill": "", "files": []})
        );
    }

    #[test]
    fn unavailable_results_keep_registered_data_shapes() {
        #[cfg(all(
            feature = "placeholders",
            not(all(feature = "remote", target_os = "linux"))
        ))]
        assert_eq!(failure_data("up"), json!({}));
        #[cfg(all(feature = "plugin-server", feature = "placeholders"))]
        assert_eq!(failure_data("server features"), json!({"features": []}));
    }

    #[cfg(feature = "plugin-server")]
    #[test]
    fn server_errors_keep_the_registered_result_data_shapes() {
        assert_eq!(
            failure_data("server"),
            json!({"listen": "", "public_origin": ""})
        );
        assert_eq!(
            failure_data("server init"),
            json!({"service": "", "enabled": false, "dry_run": false})
        );
        assert_eq!(failure_data("server setup-token"), json!({"token": ""}));
    }
}

#[cfg(all(test, feature = "plugin-server"))]
mod server_data_resolution_tests {
    //! Checks the CLI's explicit, installed-service and ordinary fallback precedence.

    use super::server_data_directory;
    use infraternal_status::Roots;
    use std::{fs, path::PathBuf};

    fn roots(system_units: Vec<PathBuf>) -> Roots {
        Roots {
            system_units,
            user_units: None,
            run_dir: None,
            data_dirs: Vec::new(),
            net_class: PathBuf::new(),
        }
    }

    #[test]
    fn explicit_data_directory_wins_over_the_installed_service() {
        assert_eq!(
            server_data_directory(Some("/srv/explicit"), || {
                panic!("explicit data path must not scan installed services")
            }),
            PathBuf::from("/srv/explicit")
        );
    }

    #[test]
    fn installed_service_data_directory_is_selected_when_no_override_is_given() {
        let root = std::env::temp_dir().join(format!("setup-data-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("system unit fixture");
        fs::write(
            root.join("infraternal-server.service"),
            "[Service]\nExecStart=/usr/bin/infraternal server --data /srv/installed\n",
        )
        .expect("write system unit fixture");

        assert_eq!(
            server_data_directory(None, || roots(vec![root.clone()])),
            PathBuf::from("/srv/installed")
        );
        fs::remove_dir_all(root).expect("remove system unit fixture");
    }

    #[test]
    fn missing_install_uses_the_existing_default_directory() {
        assert_eq!(
            server_data_directory(None, || roots(Vec::new())),
            PathBuf::from("./data")
        );
    }
}

fn print_result<T: Serialize>(result: &CommandResult<T>, json_output: bool, to_stderr: bool) {
    cli::output::print(result, json_output, to_stderr && !json_output);
}

/// Preserve access refusal separately from sanitized, non-secret protocol failures.
#[cfg(feature = "plugin-server")]
#[derive(Debug)]
enum SetupTokenReadError {
    PermissionDenied,
    Unavailable(&'static str),
}

#[cfg(feature = "plugin-server")]
impl From<&'static str> for SetupTokenReadError {
    fn from(message: &'static str) -> Self {
        Self::Unavailable(message)
    }
}

#[cfg(all(unix, feature = "plugin-server"))]
async fn read_setup_token(data_dir: &Path) -> Result<String, SetupTokenReadError> {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    let mut socket = UnixStream::connect(data_dir.join("setup-token.sock"))
        .await
        .map_err(|error| {
            if error.kind() == io::ErrorKind::PermissionDenied {
                SetupTokenReadError::PermissionDenied
            } else {
                SetupTokenReadError::Unavailable("no active first-run token socket")
            }
        })?;
    socket
        .write_all(b"GET\n")
        .await
        .map_err(|_| "local token request failed")?;
    let mut response = Vec::with_capacity(44);
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        socket.take(45).read_to_end(&mut response),
    )
    .await
    .map_err(|_| "local token request timed out")?
    .map_err(|_| "local token response failed")?;
    if response.len() != 44
        || response[43] != b'\n'
        || !response[..43]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err("no active first-run token".into());
    }
    String::from_utf8(response[..43].to_vec()).map_err(|_| "invalid local token response".into())
}

/// Without Unix sockets there is no local setup-token endpoint, so this always refuses.
#[cfg(all(not(unix), feature = "plugin-server"))]
async fn read_setup_token(_data_dir: &Path) -> Result<String, SetupTokenReadError> {
    Err("local token retrieval requires a Unix socket".into())
}

/// Serve the web build of the release this process runs from, when it runs from one (#211 S6).
///
/// A server started from `<data>/updates/releases/<version>/` (directly, or through the
/// `current` boot pointer) whose folder holds `web/` serves that folder: it is the web
/// build signed with this image. An inherited `--web-root` (a warm switch keeps the
/// process's arguments, so it names the build that ran before) is replaced. Returns the
/// replaced flag value and the folder now served, for the start log; `None` leaves
/// `--web-root` as it was. See `infraternal_plugin_release::web`.
#[cfg(feature = "release")]
fn serve_release_web(args: &mut ServerArgs) -> Option<(Option<PathBuf>, PathBuf)> {
    let executable = std::env::args_os().next().map(PathBuf::from)?;
    let web = infraternal_plugin_release::web::release_web(&executable, &args.data)?;
    let replaced = args.web_root.replace(web.clone());
    Some((replaced, web))
}

#[cfg(feature = "plugin-server")]
fn server_config(args: ServerArgs) -> Result<infraternal_server::ServerConfig, String> {
    let tls = match (args.tls_cert, args.tls_key) {
        (Some(certificate), Some(private_key)) => Some(infraternal_server::TlsFiles {
            certificate,
            private_key,
        }),
        (None, None) => None,
        _ => return Err("both --tls-cert and --tls-key are required".to_owned()),
    };
    let public_origin = args
        .public_origin
        .unwrap_or_else(|| origin_for_listener(args.listen));
    Ok(infraternal_server::ServerConfig {
        listen: args.listen,
        data_dir: args.data,
        public_origin,
        web_root: args.web_root,
        tls,
        behind_proxy: args.behind_proxy,
        trusted_proxies: args.trusted_proxies,
    })
}

#[cfg(feature = "plugin-server")]
fn origin_for_listener(listen: SocketAddr) -> String {
    let host = if listen.ip().is_loopback() {
        "localhost".to_owned()
    } else {
        listen.ip().to_string()
    };
    format!("https://{host}:{}", listen.port())
}

#[cfg(all(test, unix, feature = "plugin-server"))]
mod setup_token_tests {
    //! Verifies the explicit CLI handoff uses the private local request protocol.

    use super::read_setup_token;
    use std::{
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        path::{Path, PathBuf},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };

    struct PrivateDirectory(PathBuf);

    impl PrivateDirectory {
        /// Keep Unix socket fixture paths short even when `TMPDIR` is nested deeply.
        fn new() -> Self {
            let path = Path::new("/tmp").join(format!("itok-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).expect("create token test directory");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("set token test directory permissions");
            Self(path)
        }
    }

    impl Drop for PrivateDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn setup_token_command_reads_only_the_expected_socket_response() {
        let data_dir = PrivateDirectory::new();
        let socket = data_dir.0.join("setup-token.sock");
        assert!(
            socket.as_os_str().as_bytes().len() < 108,
            "token test socket path exceeds the Unix socket path limit"
        );
        let listener = UnixListener::bind(socket).expect("bind token test socket");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept token request");
            let mut request = [0; 4];
            socket
                .read_exact(&mut request)
                .await
                .expect("read token request");
            assert_eq!(&request, b"GET\n");
            socket
                .write_all(format!("{}\n", "A".repeat(43)).as_bytes())
                .await
                .expect("write token response");
        });
        assert_eq!(
            read_setup_token(&data_dir.0)
                .await
                .expect("read setup token"),
            "A".repeat(43)
        );
        server.await.expect("token test socket server");
    }
}

/// Validate identifiers before forking; clamp exited-screen retention inside the shim.
// This startup entry is absent from a running daemon; keep its code away
// from hot dispatch pages without changing the terminal/worker pump itself.
#[cold]
#[cfg(all(feature = "plugin-agent", target_os = "linux"))]
fn run_shim(
    session: &str,
    uid: u32,
    cols: u16,
    rows: u16,
    state: Option<std::path::PathBuf>,
    detach: bool,
    ring_capacity: usize,
    login_socket: Option<PathBuf>,
    login_cgroup: Option<&std::path::Path>,
    login_worker_pid: Option<i32>,
    login_worker_parent: Option<i32>,
    login_worker_proc: Option<PathBuf>,
    exit_retention_ms: u64,
    readiness: bool,
    retain_output: bool,
    prestarted: Option<(i32, i32)>,
) -> std::io::Result<()> {
    if prestarted.is_some() && (readiness || detach) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if session.len() != 32 || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "session must be 32 hexadecimal characters",
        ));
    }
    let mut id = [0; 16];
    for (i, value) in id.iter_mut().enumerate() {
        *value =
            u8::from_str_radix(&session[i * 2..i * 2 + 2], 16).map_err(std::io::Error::other)?;
    }
    if detach && !infraternal_shim::detach()? {
        return Ok(());
    }
    #[cfg(not(feature = "plugin-agent"))]
    if login_cgroup.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "host login support was compiled out",
        ));
    }
    let config = infraternal_shim::Config {
        session: id,
        uid,
        cols,
        rows,
        state,
        ring_capacity,
        login_socket,
        login_worker_pid,
        login_worker_parent,
        login_worker_proc,
        readiness,
        command: Vec::new(),
        retain_output,
    };
    let retention = std::time::Duration::from_millis(exit_retention_ms);
    #[cfg(feature = "plugin-agent")]
    if let Some((master, lease)) = prestarted {
        return infraternal_shim::run_with_prestarted_login(
            config,
            retention,
            login_cgroup,
            master,
            lease,
        );
    }
    #[cfg(not(feature = "plugin-agent"))]
    if prestarted.is_some() {
        return Err(io::ErrorKind::Unsupported.into());
    }
    #[cfg(feature = "plugin-agent")]
    if let Some(group) = login_cgroup {
        return infraternal_shim::run_with_login_group(config, retention, group);
    }
    infraternal_shim::run_with_retention(config, retention)
}

#[cfg(test)]
mod dispatch_tests {
    //! Ensures internal CLI actions resolve and execute through their registered handler.

    #[cfg(feature = "plugin-mesh")]
    use super::mesh_status_result;

    #[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
    /// Mac mesh status reports that GotaTun enforces D164 rules in userspace.
    #[test]
    fn mesh_status_reports_userspace_access_enforcement() {
        let data = super::mesh_status_data(infraternal_plugin_mesh::macos_service::Status {
            loaded: true,
            running: true,
            pid: Some(42),
        });
        assert_eq!(data["enforcement"], "userspace");
        assert_eq!(data["running"], true);
        assert!(super::MESH_ENFORCEMENT_DETAILS.contains("userspace packet filter"));
    }

    /// The Mac's visible status describes its active userspace access filter.
    #[cfg(all(feature = "plugin-mesh", target_os = "macos"))]
    #[test]
    fn mesh_status_says_access_rules_are_enforced_on_this_mac() {
        assert!(
            super::MESH_ENFORCEMENT_DETAILS.contains("userspace packet filter"),
            "{}",
            super::MESH_ENFORCEMENT_DETAILS
        );
    }
    use super::{ExitCode, dispatch_selected_action};
    #[cfg(feature = "plugin-mesh")]
    use crate::cli::output::{CommandState, Exit};
    use crate::cli::{actions, command_tree};

    #[test]
    fn hidden_session_shim_dispatches_from_the_registered_action() {
        let registry = actions::registry().expect("action registry");
        let matches = command_tree::build(&registry)
            .try_get_matches_from([
                "infraternal",
                "__shim",
                "--session",
                "invalid",
                "--uid",
                "1000",
            ])
            .expect("registered session shim input schema");
        let selected = command_tree::selected(&matches);

        assert_eq!(
            dispatch_selected_action(&registry, &selected, false),
            ExitCode::from(1)
        );
    }

    #[cfg(feature = "plugin-mesh")]
    #[test]
    fn mesh_service_status_maps_launchd_state_to_cli_result() {
        assert_eq!(
            mesh_status_result("status", true, true),
            (
                CommandState::Running,
                "The Mesh system service is running.",
                Exit::Ok,
            )
        );
        assert_eq!(
            mesh_status_result("up", true, true),
            (
                CommandState::Running,
                "The Mesh system service is running.",
                Exit::Ok,
            )
        );
        assert_eq!(
            mesh_status_result("status", true, false),
            (
                CommandState::Restarting,
                "The Mesh system service is loaded but not running.",
                Exit::Failed,
            )
        );
        assert_eq!(
            mesh_status_result("status", false, false),
            (
                CommandState::Stopped,
                "The Mesh system service is stopped.",
                Exit::Ok,
            )
        );
        assert_eq!(
            mesh_status_result("up", true, false),
            (
                CommandState::Restarting,
                "The Mesh system service was installed but has not started.",
                Exit::Failed,
            )
        );
        assert_eq!(
            mesh_status_result("down", true, false),
            (
                CommandState::Failed,
                "The Mesh system service is still loaded.",
                Exit::Failed,
            )
        );
        assert_eq!(
            mesh_status_result("down", false, false),
            (
                CommandState::Stopped,
                "The Mesh system service is stopped.",
                Exit::Ok,
            )
        );
        assert_eq!(
            mesh_status_result("unknown", false, false),
            (
                CommandState::Failed,
                "The Mesh system service action is not supported.",
                Exit::Usage,
            )
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "startup_tests.rs"]
mod startup_tests;
#[cfg(all(test, target_os = "macos"))]
#[path = "startup_macos_tests.rs"]
mod startup_tests;

/// First userspace entry protection applies equally to server and child modes.
fn harden_startup() -> Result<(), nix::errno::Errno> {
    // Record the transparent-huge-page policy we were started with before
    // anything can change it: the mesh engine turns THP off for the whole
    // infraternal agent, and the programs this process starts (shims, and
    // through them people's shells) must get the original back (#522). Best
    // effort: a kernel without the flag (before 3.15) leaves nothing to keep.
    #[cfg(all(target_os = "linux", not(target_env = "musl")))]
    let _ = infraternal_shim::record_launcher_thp();
    // Static builds (mimalloc, see `GLOBAL_ALLOCATOR`) then turn THP off for
    // this whole process (#522): on a THP=`always` host mimalloc's arenas would
    // be backed by 2 MiB pages, about five times an idle shim's memory, for no
    // speed gain. The same call records the launcher's policy first, so started
    // programs and an in-place restart still get it back.
    #[cfg(all(target_os = "linux", target_env = "musl"))]
    let _ = infraternal_shim::disable_process_thp();
    // The server and the infraternal agent hold a few descriptors per terminal
    // session, so they raise their soft open-file limit to the hard one; the
    // programs they start (shims, and through them people's shells) get the
    // original back (#562). Best effort: on failure the limit stays as it was.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if std::env::args_os()
        .skip(1)
        .find(|argument| argument != "--json")
        .is_some_and(|argument| argument == "server" || argument == "agent")
    {
        let _ = infraternal_shim::open_files::raise_open_file_limit();
    }
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false)?;
    #[cfg(target_os = "macos")]
    // Darwin has no per-process dumpability flag; deny core files before the remote identity is read.
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)?;
    #[cfg(all(feature = "remote", feature = "plugin-server"))]
    if std::env::args_os()
        .skip(1)
        .find(|argument| argument != "--json")
        .is_some_and(|argument| argument == "server")
    {
        crate::restart::queue_reload().map_err(|_| nix::errno::Errno::EIO)?;
    }
    Ok(())
}

/// Startup reads an invitation once; reconnects use only the private local identity.
#[cfg(feature = "remote")]
// Keep enrollment and its ordered status reporting in one CLI lifecycle.
fn run_remote_agent(
    action: AgentAction,
    has_fd: bool,
    state: Option<PathBuf>,
    data: Option<PathBuf>,
    json: bool,
) -> ExitCode {
    let enroll_only = matches!(
        &action,
        AgentAction::Join {
            enroll_only: true,
            ..
        }
    );
    let operation = match &action {
        AgentAction::Join { .. } => infraternal_plugin_remote::JOIN.id,
        AgentAction::PrepareJoinKey { .. } => "agent.prepare-join-key",
        AgentAction::Run => infraternal_plugin_remote::RUN.id,
    };
    // Remote actions use the enrolled identity; only the hidden parent action consumes this fd.
    if has_fd {
        return output::refuse(
            json,
            operation,
            "These infraternal agent options cannot be used together.",
            "infraternal agent --help",
            Exit::Usage,
        );
    }
    let Ok(data) = data.map_or_else(remote::default_data, Ok) else {
        return output::refuse(
            json,
            operation,
            "The infraternal agent has no private directory for its identity.",
            "Pass --data with a directory only this account can read.",
            Exit::Failed,
        );
    };
    // D356: access records persist beside the identity, inside the install
    // (an installed root agent's data directory is under /var/lib/infraternal).
    infraternal_agent::access_files::keep_records_in(&data.join("access-records"));
    if let AgentAction::PrepareJoinKey { origin } = &action {
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| io::Error::other("runtime unavailable"))
            .and_then(|runtime| runtime.block_on(remote::prepare_join_key(origin, &data)));
        match result {
            Ok(digest) => {
                let encoded = digest
                    .iter()
                    .fold(String::with_capacity(64), |mut hex, byte| {
                        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
                        for digit in [*byte >> 4, *byte & 0x0f] {
                            hex.push(char::from(HEX_DIGITS[usize::from(digit)]));
                        }
                        hex
                    });
                println!("KEY-DIGEST {encoded}");
            }
            Err(error) => {
                let class = match remote::Failure::of(&error) {
                    Some(remote::Failure::Dns(_)) => "DNS",
                    Some(remote::Failure::Connect) => "CONNECT",
                    Some(remote::Failure::Tls) => "TLS",
                    Some(remote::Failure::Upgrade) => "UPGRADE",
                    Some(remote::Failure::Challenge) => "CHALLENGE",
                    Some(
                        remote::Failure::Refused
                        | remote::Failure::IdentityMismatch
                        | remote::Failure::SharedFile,
                    )
                    | None => "REFUSED",
                };
                println!("PREPARE-REFUSED {class}");
            }
        }
        return ExitCode::SUCCESS;
    }
    output::report(
        json,
        operation,
        "starting",
        "Preparing the connection to the server.",
        "",
    );
    let result = (|| -> std::io::Result<()> {
        use std::io::Read;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        if let AgentAction::Join { url, .. } = action {
            let mut invitation = Vec::with_capacity(8192);
            std::io::stdin().take(8193).read_to_end(&mut invitation)?;
            infraternal_agent::block_on_io(
                &runtime,
                Box::pin(remote::join(&url, &data, &invitation)),
            )?;
            // A new enrolment must not inherit the previous one's mesh peers or
            // WireGuard key (#265, #325), but a join into another data directory
            // must not touch the service's (J162 F4). The Mac node runs only as root.
            #[cfg(all(target_os = "macos", feature = "plugin-mesh"))]
            if nix::unistd::Uid::effective().is_root()
                && let Some(mesh_state) =
                    infraternal_plugin_mesh::macos_service::join_state_to_forget(
                        &data,
                        state.as_deref(),
                    )
            {
                infraternal_plugin_mesh::node::forget(&mesh_state)?;
            }
            // SSH publishes staged state only after enrollment returns. Running
            // here would hold its transaction until the service was cancelled.
            if enroll_only {
                return Ok(());
            }
            output::report(
                json,
                operation,
                "enrolled",
                "This machine is enrolled. Connecting now; keep this running.",
                "",
            );
        }
        // A relabel (`restorecon`, autorelabel) resets the install image to its
        // directory's SELinux type, which systemd refuses to start (#401). This
        // start already succeeded, so a failure here only warns: the next start
        // would show the same label problem as `203/EXEC`. A remote agent has no
        // tracing subscriber, so the warning goes to stderr, which is the unit's
        // journal; `<4>` makes journald record it at warning priority.
        if let Err(error) = infraternal_agent::exec_label::heal_running_image() {
            eprintln!(
                "<4>infraternal agent: could not keep the install image executable for SELinux: {error}"
            );
        }
        remote_service::run(runtime, remote::run(&data, state))
    })();
    if result.is_ok() {
        if enroll_only {
            output::done(
                json,
                operation,
                "enrolled",
                "This machine is enrolled. Its identity is saved here.",
                "infraternal agent run",
            )
        } else {
            output::done(
                json,
                operation,
                "stopped",
                "The infraternal agent stopped.",
                "infraternal agent run",
            )
        }
    } else {
        output::refuse(
            json,
            operation,
            result.as_ref().err().map_or(
                "The infraternal agent could not finish.",
                remote::public_error,
            ),
            result
                .as_ref()
                .err()
                .and_then(remote::mesh_restore_failure)
                .map_or(
                    "Check the server address and that this machine is still enrolled, then run the command again.",
                    |(_, recovery)| recovery,
                ),
            result
                .as_ref()
                .err()
                .map_or(Exit::Failed, |error| match remote::Failure::of(error) {
                    Some(remote::Failure::Tls | remote::Failure::IdentityMismatch) => {
                        Exit::NotAllowed
                    }
                    Some(remote::Failure::Dns(_) | remote::Failure::Connect) => Exit::Unreachable,
                    None if remote::mesh_restore_failure(error).is_some() => Exit::NotAllowed,
                    Some(
                        remote::Failure::Refused
                        | remote::Failure::SharedFile
                        | remote::Failure::Upgrade
                        | remote::Failure::Challenge,
                    )
                    | None => Exit::Failed,
                }),
        )
    }
}

/// Remote node modes never create a server or accept an invitation through argv.
#[cfg(feature = "remote")]
enum AgentAction {
    Join { url: String, enroll_only: bool },
    PrepareJoinKey { origin: String },
    Run,
}

/// Adapt schema-parsed operator inputs to the production transport handlers.
fn run_operator_action(action: &ActionDefinition, matches: &ArgMatches, json: bool) -> ExitCode {
    #[cfg(feature = "ssh")]
    if action.cli_handler == CliHandler::SshAskpass {
        return ssh_askpass::run();
    }
    #[cfg(feature = "remote")]
    {
        if action.cli_handler == CliHandler::RemoteAgent {
            let has_fd = matches.try_contains_id("fd").is_ok_and(|present| present);
            let state = matches
                .try_get_one::<String>("state")
                .ok()
                .flatten()
                .map(PathBuf::from);
            let data = matches
                .try_get_one::<String>("data")
                .ok()
                .flatten()
                .map(PathBuf::from);
            let mode = match action.command.last().map(String::as_str) {
                Some("join") => AgentAction::Join {
                    url: matches
                        .get_one::<String>("url")
                        .cloned()
                        .unwrap_or_default(),
                    enroll_only: matches.get_flag("enroll_only"),
                },
                Some("prepare-join-key") => AgentAction::PrepareJoinKey {
                    origin: matches
                        .get_one::<String>("origin")
                        .cloned()
                        .unwrap_or_default(),
                },
                _ => AgentAction::Run,
            };
            return run_remote_agent(mode, has_fd, state, data, json);
        }
        #[cfg(feature = "plugin-server")]
        if action.cli_handler == CliHandler::ServerRestart {
            let data = server_data_directory(
                matches.get_one::<String>("data").map(String::as_str),
                infraternal_status::Roots::detect,
            );
            let options = restart::Options {
                binary: matches.get_one::<String>("binary").map(PathBuf::from),
                rollback: matches.get_flag("rollback"),
            };
            return match tokio::runtime::Runtime::new() {
                Ok(runtime) => restart::run(&runtime, &data, &options, json),
                Err(_) => report_failure(
                    "server restart",
                    "Could not start the async runtime.",
                    "runtime initialization failed".to_owned(),
                    json,
                ),
            };
        }
        #[cfg(feature = "release")]
        if action.cli_handler == CliHandler::ServerMeshRoutes {
            return server_mesh_routes_cli::run(action, matches, json);
        }
        #[cfg(all(feature = "plugin-server", feature = "remote"))]
        if action.cli_handler == CliHandler::ServerMeshStatus {
            let data = server_data_directory(
                matches.get_one::<String>("data").map(String::as_str),
                infraternal_status::Roots::detect,
            );
            return restart::mesh_status(&data, json);
        }
        if action.cli_handler == CliHandler::RemoveHost {
            let host = matches
                .get_one::<String>("host")
                .and_then(|host| host.parse().ok());
            let Some(host) = host else {
                return report_failure_as(
                    "remove-host",
                    "Invalid host identifier.",
                    "expected a host UUID".to_owned(),
                    json,
                    Exit::Usage,
                );
            };
            return host_remove::run(
                matches
                    .get_one::<String>("server_override")
                    .or_else(|| matches.get_one::<String>("server"))
                    .map_or("", String::as_str),
                host,
                host_remove::Step::from_flags(matches.get_flag("finish")),
                matches.get_flag("retain"),
                json,
            );
        }
    }
    let _ = matches;
    run_unavailable(action, json)
}

/// Session automation is removable with the host runtime, including in minimal CLI builds.
fn run_local_action(
    action: &ActionDefinition,
    matches: &ArgMatches,
    json_output: bool,
) -> ExitCode {
    #[cfg(all(feature = "plugin-agent", target_os = "linux"))]
    {
        if action.cli_handler == CliHandler::Sessions {
            cli::sessions::run(action, matches, json_output)
        } else {
            component_cli::run_action(action, matches, json_output)
        }
    }
    #[cfg(not(all(feature = "plugin-agent", target_os = "linux")))]
    {
        let _ = matches;
        run_unavailable(action, json_output)
    }
}

#[cfg(all(test, feature = "plugin-server"))]
mod server_stop_tests {
    //! Pins the bound on a stopping server's runtime (#516).

    /// A blocking task nobody awaits must not keep a stopped server alive. The
    /// task blocks on a channel the test holds, so a plain runtime drop would
    /// never return; the test then fails at its deadline instead of hanging.
    #[test]
    fn a_stopped_server_does_not_wait_for_detached_blocking_work() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .build()
            .expect("build a test runtime");
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let (started, entered) = std::sync::mpsc::channel();
        runtime.spawn_blocking(move || {
            started.send(()).expect("report the blocking task start");
            let _ = blocked.recv();
        });
        entered
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the blocking task started");
        let (done, stopped) = std::sync::mpsc::channel();
        let began = std::time::Instant::now();
        std::thread::spawn(move || {
            super::stop_server_runtime(runtime);
            let _ = done.send(());
        });
        let result = stopped.recv_timeout(super::SERVER_STOP_BLOCKING_GRACE * 5);
        drop(release);
        result.expect("the runtime stop waited for detached blocking work");
        assert!(began.elapsed() < super::SERVER_STOP_BLOCKING_GRACE * 5);
    }
}
