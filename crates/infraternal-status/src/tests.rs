//! Builds whole nodes in a temporary tree and checks the role and every component (#237).
//!
//! The four fixtures are the owner's real cases: the production server (system
//! unit with a drop-in and a plain description), a rootful host, a rootless
//! host, and a machine with nothing installed.

use std::{fs, path::Path};

use super::{Activity, Kind, NodeStatus, Role, Roots, Scope, probe, server_data_directory};

const IDS: [&str; 8] = [
    "release", "server", "agent", "mesh", "host", "relay", "backup", "ssh",
];

#[test]
fn manager_completion_follows_child_exit_even_if_stdout_closes_first() {
    use std::{process::Command, time::Duration, time::Instant};

    let mut child = Command::new("/bin/sh")
        .args(["-c", "exec 1>&-; /bin/sleep 0.02; exit 7"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let result = super::wait_manager_child(&mut child, Instant::now() + Duration::from_secs(1));
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert_eq!(result.unwrap().code(), Some(7));
}

#[test]
#[cfg(target_os = "linux")]
fn manager_completion_handles_an_already_exited_child_and_a_deadline() {
    use std::{process::Command, time::Duration, time::Instant};

    let mut exited = Command::new("/bin/false").spawn().unwrap();
    // Leave the exited child unreaped, exactly as when it exits between spawn
    // and readiness registration. waitid(WNOWAIT) observes without consuming it.
    nix::sys::wait::waitid(
        nix::sys::wait::Id::Pid(nix::unistd::Pid::from_raw(
            i32::try_from(exited.id()).unwrap(),
        )),
        nix::sys::wait::WaitPidFlag::WEXITED | nix::sys::wait::WaitPidFlag::WNOWAIT,
    )
    .unwrap();
    let result = super::wait_manager_child(&mut exited, Instant::now() + Duration::from_secs(1));
    assert_eq!(result.unwrap().code(), Some(1));

    let mut stalled = Command::new("/bin/sleep").arg("5").spawn().unwrap();
    let started = Instant::now();
    let result = super::wait_manager_child(&mut stalled, started + Duration::from_millis(40));
    let _ = stalled.kill();
    stalled.wait().unwrap();
    assert!(
        result.is_err(),
        "a live manager cannot complete after its deadline"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

std::thread_local! {
    /// Manager program for queries made on this test's thread; production
    /// always runs `systemctl`. Thread-local, so parallel tests cannot see it.
    pub(super) static MANAGER_PROGRAM: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// A fresh start needs a second observation, and both share one deadline: a
/// 2.5 s second answer fits a 4 s budget, but a per-observation split (2 s
/// each) would cut it (#312, #334). This lives in this small unit binary
/// rather than the CLI matrix, where a cold 470 MB debug binary under gate load
/// can spend the margin on its own page faults.
#[test]
#[cfg(target_os = "linux")]
fn one_deadline_spans_both_observations_of_a_fresh_start() {
    use nix::sys::time::TimeValLike;
    use std::{os::unix::fs::PermissionsExt, time::Duration, time::Instant};

    let fixture = Fixture::new();
    let seen = fixture.root.join("first-observation");
    let started = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
        .unwrap()
        .num_microseconds();
    let manager = fixture.root.join("systemctl");
    fs::write(
        &manager,
        format!(
            "#!/bin/sh\nif [ -e '{seen}' ]; then /bin/sleep 2.5; fi\n: > '{seen}'\nprintf '%s\\n' ActiveState=active SubState=running MainPID=42 NRestarts=0 ExecMainStartTimestampMonotonic={started}\n",
            seen = seen.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&manager, fs::Permissions::from_mode(0o755)).unwrap();
    MANAGER_PROGRAM.with(|program| *program.borrow_mut() = Some(manager));
    let result = super::manager_activity_before(
        Scope::System,
        "infraternal-server.service",
        Instant::now() + Duration::from_secs(4),
    );
    MANAGER_PROGRAM.with(|program| *program.borrow_mut() = None);
    assert!(seen.exists(), "the manager was never asked");
    assert_eq!(result, Ok(Activity::Active));
}

struct Fixture {
    root: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("infraternal-status-{}", uuid::Uuid::new_v4()));
        for dir in ["etc", "user", "run", "var-lib", "home-data", "net"] {
            fs::create_dir_all(root.join(dir)).expect("create fixture dir");
        }
        Self { root }
    }

    fn roots(&self) -> Roots {
        Roots {
            system_units: vec![self.root.join("etc")],
            user_units: Some(self.root.join("user")),
            run_dir: Some(self.root.join("run")),
            data_dirs: vec![self.root.join("var-lib"), self.root.join("home-data")],
            net_class: self.root.join("net"),
        }
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
        fs::write(path, text).expect("write fixture file");
    }

    fn status(&self, active: &[(Scope, &str)]) -> NodeStatus {
        let ids: Vec<String> = IDS.iter().map(|id| (*id).to_owned()).collect();
        let active: Vec<(Scope, String)> = active
            .iter()
            .map(|(scope, name)| (*scope, (*name).to_owned()))
            .collect();
        probe(&self.roots(), &ids, &|scope, name| {
            if active.iter().any(|(s, n)| *s == scope && n == name) {
                Activity::Active
            } else {
                Activity::Inactive
            }
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(Path::new(&self.root));
    }
}

fn state<'a>(status: &'a NodeStatus, name: &str) -> (&'a str, &'a str) {
    let c = status
        .components
        .iter()
        .find(|c| c.name == name)
        .expect("component present");
    (&c.state, &c.detail)
}

const MESH: &str = r#"{"enabled":true,"config":{"peers":{"3":{},"4":{}}}}"#;

fn production_server(fixture: &Fixture) {
    // The unit description is the bare "infraternal server" and the real
    // command line sits in a drop-in that resets ExecStart.
    fixture.write(
        "etc/infraternal-server.service",
        "[Unit]\nDescription=infraternal server\n[Service]\nExecStart=/usr/local/bin/infraternal server --listen 127.0.0.1:1 --data /old\n",
    );
    fixture.write(
        "etc/infraternal-server.service.d/remote-listen.conf",
        "[Service]\nExecStart=\nExecStart=/usr/local/bin/infraternal server --data /var/lib/infraternal --remote-listen 10.0.0.1:7443\n",
    );
    fixture.write("var-lib/infraternal.sqlite", "");
    fixture.write("run/mesh-public.json", MESH);
    fixture.write("net/infraternal0/.keep", "");
}

#[test]
fn installed_system_server_data_comes_from_its_effective_execstart() {
    let fixture = Fixture::new();
    fixture.write(
        "etc/custom-name.service",
        "[Service]\nExecStart=\"/usr/bin/infraternal\" \"server\" \"--data\" \"/var/lib/infraternal state\"\n",
    );
    fixture.write(
        "etc/custom-name.service.d/data.conf",
        "[Service]\nExecStart=\nExecStart=\"/usr/bin/infraternal\" \"server\" \"--data\" \"/srv/infraternal state\"\n",
    );
    fixture.write(
        "user/infraternal-server.service",
        "[Service]\nExecStart=\"/home/user/infraternal\" \"server\" \"--data\" \"/home/user/data\"\n",
    );

    assert_eq!(
        server_data_directory(&fixture.roots()),
        Some(Path::new("/srv/infraternal state").to_owned())
    );
}

#[test]
fn production_server_is_a_running_server_with_two_mesh_peers() {
    let fixture = Fixture::new();
    production_server(&fixture);
    let status = fixture.status(&[(Scope::System, "infraternal-server.service")]);
    assert_eq!(status.role, Role::Server);
    assert_eq!(status.overall(), Activity::Active);
    assert_eq!(state(&status, "server"), ("Running", "system service"));
    assert_eq!(
        state(&status, "agent"),
        ("Running", "embedded in the server")
    );
    assert_eq!(
        state(&status, "host"),
        ("Running", "embedded in the server")
    );
    assert_eq!(state(&status, "mesh"), ("Running", "peers: 2"));
    assert_eq!(state(&status, "ssh").0, "Ready");
    assert_eq!(state(&status, "release").0, "Ready");
    assert_eq!(state(&status, "relay").0, "Not available yet");
    assert_eq!(state(&status, "backup").0, "Not available yet");
}

#[test]
fn stopped_server_unit_is_stopped_not_unknown() {
    let fixture = Fixture::new();
    production_server(&fixture);
    let status = fixture.status(&[]);
    assert_eq!(status.role, Role::Server);
    assert_eq!(status.overall(), Activity::Inactive);
    assert_eq!(state(&status, "server").0, "Stopped");
}

#[test]
fn rootful_agent_is_a_host_with_its_own_state_directory() {
    let fixture = Fixture::new();
    fixture.write(
        "etc/infraternal-agent.service",
        "[Unit]\nDescription=infraternal host daemon\n[Service]\nExecStart=\"/var/lib/infraternal/bin/live\" agent --data \"/var/lib/infraternal/state\" --state \"/var/lib/infraternal/sessions\" run\n",
    );
    fixture.write("var-lib/sessions/mesh-public.json", MESH);
    fixture.write("net/infraternal0/.keep", "");
    let status = fixture.status(&[(Scope::System, "infraternal-agent.service")]);
    assert_eq!(status.role, Role::Host);
    assert_eq!(status.units[0].0.kind, Kind::Agent);
    assert_eq!(
        status.units[0].0.state.as_deref(),
        Some(Path::new("/var/lib/infraternal/sessions"))
    );
    assert_eq!(state(&status, "agent"), ("Running", "system service"));
    assert_eq!(state(&status, "host").0, "Running");
    assert_eq!(state(&status, "server").0, "Not installed");
    assert_eq!(state(&status, "ssh").0, "Server only");
    assert_eq!(state(&status, "relay").0, "Not available yet");
}

#[test]
fn rootful_agent_reads_mesh_peers_from_its_state_directory() {
    let fixture = Fixture::new();
    let state_dir = fixture.root.join("agent-state");
    fixture.write(
        "etc/infraternal-agent.service",
        &format!(
            "[Service]\nExecStart=/opt/infraternal agent --state={} run\n",
            state_dir.display()
        ),
    );
    fixture.write("agent-state/mesh-public.json", MESH);
    fixture.write("net/infraternal0/.keep", "");
    let status = fixture.status(&[(Scope::System, "infraternal-agent.service")]);
    assert_eq!(state(&status, "mesh"), ("Running", "peers: 2"));
}

#[test]
fn rootless_agent_is_read_from_the_user_manager() {
    let fixture = Fixture::new();
    fixture.write(
        "user/infraternal-agent.service",
        "[Service]\nExecStart=/home/u/.local/share/infraternal/bin/current agent --data /home/u/.local/share/infraternal/state run\n",
    );
    let status = fixture.status(&[(Scope::User, "infraternal-agent.service")]);
    assert_eq!(status.role, Role::Host);
    assert_eq!(state(&status, "agent"), ("Running", "user service"));
    assert_eq!(state(&status, "mesh"), ("Not set up", ""));
}

#[test]
fn server_and_host_on_one_machine_is_both() {
    let fixture = Fixture::new();
    production_server(&fixture);
    fixture.write(
        "user/infraternal-agent.service",
        "[Service]\nExecStart=/x/infraternal agent run\n",
    );
    let status = fixture.status(&[(Scope::System, "infraternal-server.service")]);
    assert_eq!(status.role, Role::Both);
    assert_eq!(state(&status, "agent").0, "Stopped");
    assert_eq!(state(&status, "server").0, "Running");
}

#[test]
fn nothing_installed_says_so() {
    let fixture = Fixture::new();
    // Unrelated units and session scopes never count.
    fixture.write(
        "etc/infraternal-session-abc.service",
        "[Service]\nExecStart=/usr/local/bin/infraternal __shim --session abc\n",
    );
    fixture.write("etc/other.service", "[Service]\nExecStart=/bin/true\n");
    let status = fixture.status(&[]);
    assert_eq!(status.role, Role::None);
    assert!(status.units.is_empty());
    assert_eq!(state(&status, "server").0, "Not installed");
    assert_eq!(state(&status, "agent").0, "Not installed");
    assert_eq!(state(&status, "release").0, "Not installed");
    assert_eq!(state(&status, "mesh").0, "Not set up");
}

#[test]
fn an_unanswering_manager_only_makes_its_own_unit_unknown() {
    let fixture = Fixture::new();
    production_server(&fixture);
    fixture.write(
        "user/infraternal-agent.service",
        "[Service]\nExecStart=/x/infraternal agent run\n",
    );
    let ids: Vec<String> = IDS.iter().map(|id| (*id).to_owned()).collect();
    let status = probe(&fixture.roots(), &ids, &|scope, _| match scope {
        Scope::System => Activity::Active,
        Scope::User => Activity::Unknown,
    });
    assert_eq!(state(&status, "server").0, "Running");
    assert_eq!(state(&status, "agent").0, "Unknown");
    assert_eq!(status.overall(), Activity::Active);
}

#[test]
fn snapshot_scan_counts_peers_through_nesting_strings_and_spacing() {
    use super::peer_count;
    assert_eq!(peer_count(br#"{"enabled":false,"config":null}"#), None);
    assert_eq!(peer_count(br#"{"config":{"peers":{},"x":1}}"#), Some(0));
    let one = br#"{"config": {"peers" : { "3": {"a": [1,2], "b": "x,}\"y"} }}}"#;
    assert_eq!(peer_count(one), Some(1));
    assert_eq!(peer_count(MESH.as_bytes()), Some(2));
    // A truncated file is "unknown", never a guess.
    assert_eq!(peer_count(br#"{"config":{"peers":{"3":{"#), None);
}

#[test]
fn the_headline_says_how_to_join_when_nothing_is_installed() {
    let fixture = Fixture::new();
    let (activity, message, next) = fixture.status(&[]).headline();
    assert_eq!(activity, Activity::Inactive);
    assert_eq!(message, "This machine is not set up yet.");
    assert_eq!(next[0], "infraternal agent join <server-url>");
}

#[test]
fn the_headline_names_what_is_down_and_how_to_look() {
    let fixture = Fixture::new();
    production_server(&fixture);
    let running = fixture.status(&[(Scope::System, "infraternal-server.service")]);
    let (_, message, next) = running.headline();
    assert_eq!(message, "The server is running on this machine.");
    assert!(next.is_empty() && running.down().is_empty());
    let stopped = fixture.status(&[]);
    let (_, message, next) = stopped.headline();
    assert_eq!(message, "The server is not running on this machine.");
    assert_eq!(next, ["systemctl status infraternal-server.service"]);
    assert_eq!(stopped.down().len(), 1);
}

#[test]
fn a_manager_that_does_not_answer_is_unknown_not_down() {
    let fixture = Fixture::new();
    production_server(&fixture);
    // Same node, but the service manager cannot be asked at all.
    let node = probe(&fixture.roots(), &IDS.map(str::to_owned), &|_, _| {
        Activity::Unknown
    });
    assert_eq!(node.overall(), Activity::Unknown);
    assert!(node.confirmed_down().is_empty(), "unknown is not down");
    let stopped = fixture.status(&[]);
    assert_eq!(stopped.confirmed_down().len(), 1);
}

#[test]
fn installed_server_discovery_recognizes_the_running_executable_identity() {
    let fixture = Fixture::new();
    let current = std::env::current_exe().expect("running test executable");
    fixture.write(
        "etc/custom.service",
        &format!(
            "[Service]\nExecStart=\"{}\" server --data /srv/server\n",
            current.display()
        ),
    );
    assert_eq!(
        server_data_directory(&fixture.roots()),
        Some(Path::new("/srv/server").to_owned())
    );
    fixture.write(
        "etc/custom.service",
        "[Service]\nExecStart=/unrelated/infraternal-versioned server --data /srv/other\n",
    );
    assert_eq!(server_data_directory(&fixture.roots()), None);
}

#[test]
#[ignore = "requires the job-owned transient crash-loop user unit"]
fn real_user_crash_loop_is_not_running() {
    assert_eq!(
        super::word(super::manager_activity(
            Scope::User,
            "status-crash-loop-237.service"
        )),
        "Restarting repeatedly"
    );
}

#[test]
fn manager_properties_report_each_role_and_scope_truthfully() {
    use super::Observation;
    let fixtures = [
        (
            "ActiveState=activating\nSubState=auto-restart\nMainPID=0\nResult=exit-code\nNRestarts=45\nExecMainStartTimestampMonotonic=100000000\nExecMainCode=1\nExecMainStatus=1\n",
            "Restarting repeatedly",
        ),
        (
            "ActiveState=active\nSubState=running\nMainPID=42\nNRestarts=46\nExecMainStartTimestampMonotonic=100000000\nExecMainCode=2\nExecMainStatus=11\n",
            "Restarting repeatedly",
        ),
        (
            "ActiveState=active\nSubState=running\nMainPID=42\nNRestarts=0\nExecMainStartTimestampMonotonic=100000000\n",
            "Running",
        ),
        (
            "ActiveState=active\nSubState=running\nMainPID=42\nNRestarts=46\nExecMainStartTimestampMonotonic=80000000\n",
            "Running",
        ),
        (
            "ActiveState=inactive\nSubState=dead\nNRestarts=45\nExecMainStartTimestampMonotonic=100000000\n",
            "Stopped",
        ),
        (
            "ActiveState=failed\nSubState=failed\nNRestarts=45\nExecMainStartTimestampMonotonic=100000000\nExecMainCode=1\nExecMainStatus=1\n",
            "Failed",
        ),
        ("", "Unknown"),
    ];
    for scope in [Scope::System, Scope::User] {
        for role in ["server", "agent"] {
            for (properties, expected) in fixtures {
                let fixture = Fixture::new();
                let directory = if scope == Scope::System {
                    "etc"
                } else {
                    "user"
                };
                let name = format!("infraternal-{role}.service");
                fixture.write(
                    &format!("{directory}/{name}"),
                    &format!("[Service]\nExecStart=/usr/bin/infraternal {role}\n"),
                );
                let activity = Observation::read(properties).activity(None, 101_000_000);
                let status = probe(&fixture.roots(), &IDS.map(str::to_owned), &|s, n| {
                    assert_eq!(s, scope);
                    assert_eq!(n, name);
                    activity
                });
                assert_eq!(
                    state(&status, role).0,
                    expected,
                    "{scope:?}/{role}: {properties}"
                );
                assert_eq!(
                    status.role,
                    if role == "server" {
                        Role::Server
                    } else {
                        Role::Host
                    }
                );
                let (_, message, next) = status.headline();
                if expected == "Restarting repeatedly" {
                    assert_eq!(status.confirmed_down().len(), 1);
                    assert!(message.contains("restarting repeatedly"));
                    assert!(next[0].starts_with("journalctl"));
                    assert_eq!(next[0].contains("--user"), scope == Scope::User);
                    let detail = state(&status, role).1;
                    assert!(detail.contains(if properties.contains("ExecMainCode=2") {
                        "last signal 11"
                    } else {
                        "last exit status 1"
                    }));
                    if role == "server" {
                        assert_eq!(state(&status, "agent").0, expected);
                    }
                }
            }
        }
    }
}

#[test]
fn consecutive_observations_detect_restart_count_and_pid_churn() {
    use super::Observation;
    let first = Observation::read(
        "ActiveState=active\nSubState=running\nNRestarts=1\nMainPID=41\nExecMainStartTimestampMonotonic=100000000\n",
    );
    for properties in [
        "ActiveState=active\nSubState=running\nNRestarts=2\nMainPID=41\nExecMainStartTimestampMonotonic=100000000\n",
        "ActiveState=active\nSubState=running\nNRestarts=1\nMainPID=42\nExecMainStartTimestampMonotonic=100000000\n",
        "ActiveState=activating\nSubState=auto-restart\nNRestarts=1\nMainPID=0\nExecMainStartTimestampMonotonic=100000000\n",
    ] {
        assert!(matches!(
            Observation::read(properties).activity(Some(&first), 101_000_000),
            Activity::Restarting { .. }
        ));
    }
    assert_eq!(first.activity(Some(&first), 101_000_000), Activity::Active);
    assert_eq!(
        Observation::read("ActiveState=activating\nSubState=start\n").activity(None, 101_000_000),
        Activity::Unknown
    );
}

#[test]
fn a_restarting_role_does_not_describe_a_stopped_or_failed_role_as_restarting() {
    let fixture = Fixture::new();
    production_server(&fixture);
    fixture.write(
        "user/infraternal-agent.service",
        "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
    );
    let restarting = Activity::Restarting { code: 1, status: 1 };
    for restarting_scope in [Scope::System, Scope::User] {
        for other in [Activity::Inactive, Activity::Failed] {
            let status = probe(&fixture.roots(), &IDS.map(str::to_owned), &|scope, _| {
                if scope == restarting_scope {
                    restarting
                } else {
                    other
                }
            });
            assert_eq!(
                status.headline().1,
                "Part of this machine's setup is restarting repeatedly."
            );
            let (restarting_role, other_role) = if restarting_scope == Scope::System {
                ("server", "agent")
            } else {
                ("agent", "server")
            };
            assert_eq!(state(&status, restarting_role).0, "Restarting repeatedly");
            assert_eq!(state(&status, other_role).0, super::word(other));
            assert_eq!(status.confirmed_down().len(), 2);
        }
    }
    let both = probe(&fixture.roots(), &IDS.map(str::to_owned), &|_, _| {
        restarting
    });
    assert_eq!(
        both.headline().1,
        "The server and the infraternal agent are restarting repeatedly on this machine."
    );
}

#[test]
fn restart_age_uses_only_comparable_monotonic_microseconds() {
    let observation = super::Observation::read(
        "ActiveState=active\nSubState=running\nNRestarts=3\nExecMainStartTimestampMonotonic=100000000\nExecMainStartTimestamp=@9999999999\n",
    );
    assert!(matches!(
        observation.activity(None, 110_000_000),
        Activity::Restarting { .. }
    ));
    assert_eq!(observation.activity(None, 110_000_001), Activity::Active);
    assert_eq!(observation.activity(None, 99_000_000), Activity::Unknown);
    assert_eq!(
        super::Observation::read("ActiveState=active\nNRestarts=3\n").activity(None, 110_000_000),
        Activity::Unknown
    );
}

#[test]
fn retained_data_has_an_honest_headline_and_repair_step() {
    for masked in [false, true] {
        for user in [false, true] {
            let fixture = Fixture::new();
            fixture.write("var-lib/infraternal.sqlite", "");
            if masked {
                std::os::unix::fs::symlink(
                    "/dev/null",
                    fixture.root.join(if user {
                        "user/infraternal-server.service"
                    } else {
                        "etc/infraternal-server.service"
                    }),
                )
                .unwrap();
            }
            let status = fixture.status(&[]);
            let (activity, headline, next) = status.headline();
            assert_eq!(activity, Activity::Inactive);
            assert_eq!(headline, "The server is not running on this machine.");
            assert_eq!(state(&status, "server").0, "Stopped");
            if masked {
                assert_eq!(
                    next[0],
                    if user {
                        "systemctl --user unmask infraternal-server.service"
                    } else {
                        "systemctl unmask infraternal-server.service"
                    }
                );
            } else {
                assert!(next[0].contains("Restore the server service"));
            }
        }
    }
}

#[test]
fn stopped_and_failed_services_keep_distinct_headlines_and_diagnostics() {
    let fixture = Fixture::new();
    production_server(&fixture);
    for activity in [Activity::Inactive, Activity::Failed, Activity::Unknown] {
        let status = probe(&fixture.roots(), &IDS.map(str::to_owned), &|_, _| activity);
        let (_, headline, next) = status.headline();
        assert!(headline.contains(match activity {
            Activity::Inactive => "not running",
            Activity::Failed => "has failed",
            _ => "unknown",
        }));
        assert_eq!(next, ["systemctl status infraternal-server.service"]);
    }
}

/// The module's role/state table is checked for both standalone roles and all
/// 49 server/companion combinations, including absent and masked server files.
#[test]
fn configured_role_state_table_controls_headline_and_exit() {
    use Activity::{Active, Failed, Inactive, Restarting, Unknown};
    let activities = [
        Active,
        Restarting { code: 1, status: 7 },
        Failed,
        Inactive,
        Inactive,
        Inactive,
        Unknown,
    ];
    // R=running, L=all looping, F=all failed, D=all stopped,
    // P=part stopped, Q=part looping, U=unknown, X=down plus unknown.
    let matrix = [
        ['R', 'P', 'P', 'P', 'P', 'P', 'U'],
        ['P', 'L', 'Q', 'Q', 'Q', 'Q', 'X'],
        ['P', 'Q', 'F', 'P', 'P', 'P', 'X'],
        ['P', 'Q', 'P', 'D', 'D', 'D', 'X'],
        ['P', 'Q', 'P', 'D', 'D', 'D', 'X'],
        ['P', 'Q', 'P', 'D', 'D', 'D', 'X'],
        ['U', 'X', 'X', 'X', 'X', 'X', 'U'],
    ];
    for (server_index, server) in activities.iter().enumerate() {
        for (agent_index, agent) in activities.iter().enumerate() {
            let fixture = Fixture::new();
            fixture.write("var-lib/infraternal.sqlite", "");
            match server_index {
                3 => std::os::unix::fs::symlink(
                    "/dev/null",
                    fixture.root.join("etc/infraternal-server.service"),
                )
                .unwrap(),
                4 => {}
                _ => fixture.write(
                    "etc/infraternal-server.service",
                    "[Service]\nExecStart=/usr/bin/infraternal server\n",
                ),
            }
            // A standalone host has an installed unit even when the manager
            // reports missing/masked; without it no local host role is known.
            fixture.write(
                "user/infraternal-agent.service",
                "[Service]\nExecStart=/usr/bin/infraternal agent run\n",
            );
            if agent_index == 3 {
                fs::remove_file(fixture.root.join("user/infraternal-agent.service")).unwrap();
                std::os::unix::fs::symlink(
                    "/dev/null",
                    fixture.root.join("user/infraternal-agent.service"),
                )
                .unwrap();
            }
            let node = probe(&fixture.roots(), &IDS.map(str::to_owned), &|scope, _| {
                if scope == Scope::System {
                    *server
                } else if let Restarting { .. } = agent {
                    Restarting {
                        code: 2,
                        status: 11,
                    }
                } else {
                    *agent
                }
            });
            let label = matrix[server_index][agent_index];
            let expected = if agent_index == 3 {
                assert_eq!(node.role, Role::Server);
                match server_index {
                    0 => "The server is running on this machine.",
                    1 => "The server is restarting repeatedly on this machine.",
                    2 => "The server has failed on this machine.",
                    6 => "The status of part of this machine's setup is unknown.",
                    _ => "The server is not running on this machine.",
                }
            } else {
                match label {
                    'R' => "The server and the infraternal agent are running on this machine.",
                    'L' => {
                        "The server and the infraternal agent are restarting repeatedly on this machine."
                    }
                    'F' => "The server and the infraternal agent have failed on this machine.",
                    'D' => "The server and the infraternal agent are not running on this machine.",
                    'Q' => "Part of this machine's setup is restarting repeatedly.",
                    'U' => "The status of part of this machine's setup is unknown.",
                    'X' => {
                        "Part of this machine's setup is not running; another status is unknown."
                    }
                    _ => "Part of this machine's setup is not running.",
                }
            };
            assert_eq!(
                node.headline().1,
                expected,
                "server={server_index}, infraternal agent={agent_index}"
            );
            let exit = if node.confirmed_down_count() == 0 {
                0
            } else {
                5
            };
            let healthy = if agent_index == 3 {
                matches!(server_index, 0 | 6)
            } else {
                matches!(label, 'R' | 'U')
            };
            assert_eq!(exit, if healthy { 0 } else { 5 });
            if exit == 5 {
                assert_ne!(node.headline().0, Active);
            }
        }
    }
    for (kind, role) in [(Kind::Server, "server"), (Kind::Agent, "infraternal agent")] {
        for (index, activity) in activities.iter().enumerate() {
            let fixture = Fixture::new();
            fixture.write(
                "etc/infraternal.service",
                &format!(
                    "[Service]\nExecStart=/usr/bin/infraternal {}\n",
                    if kind == Kind::Server {
                        "server"
                    } else {
                        "agent run"
                    }
                ),
            );
            let node = probe(&fixture.roots(), &IDS.map(str::to_owned), &|_, _| *activity);
            let (phrase, exit) = match index {
                0 => ("is running", 0),
                1 => ("is restarting repeatedly", 5),
                2 => ("has failed", 5),
                6 => ("unknown", 0),
                _ => ("is not running", 5),
            };
            assert_eq!(
                node.headline().1,
                if index == 6 {
                    "The status of part of this machine's setup is unknown.".to_owned()
                } else {
                    format!("The {role} {phrase} on this machine.")
                }
            );
            assert_eq!(
                if node.confirmed_down_count() == 0 {
                    0
                } else {
                    5
                },
                exit
            );
        }
    }
}
