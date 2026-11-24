//! Unit tests for `SELinux` boot-pointer labeling (#211).
//!
//! Uses a mock [`Environment`] so detection, idempotent rule skipping,
//! missing-`semanage` refusal, `restorecon` execution and `--dry-run` command
//! formatting are verified in CI without a real `SELinux` host.

use super::*;
use std::collections::{HashMap, VecDeque};

/// Scripted [`Environment`] recording every command and directory creation.
struct MockEnv {
    /// Whether `/sys/fs/selinux/enforce` exists.
    enforce_exists: bool,
    /// Fixed tool lookup outcomes keyed by first candidate path.
    tools: HashMap<&'static str, Result<PathBuf, ToolError>>,
    /// Queued outputs for sequential [`Environment::run`] calls.
    responses: VecDeque<io::Result<CommandOutput>>,
    /// Recorded `(program, args)` invocations.
    calls: Vec<(PathBuf, Vec<String>)>,
    /// Recorded directories passed to [`Environment::ensure_updates_dir`].
    created_dirs: Vec<PathBuf>,
}

impl MockEnv {
    /// An empty non-SELinux host with no `SELinux` tools installed.
    fn non_selinux() -> Self {
        Self {
            enforce_exists: false,
            tools: HashMap::new(),
            responses: VecDeque::new(),
            calls: Vec::new(),
            created_dirs: Vec::new(),
        }
    }

    /// An enforcing `SELinux` host with trusted `semanage` and `restorecon`.
    fn enforcing_with_tools() -> Self {
        let mut env = Self::non_selinux();
        env.enforce_exists = true;
        env.tools.insert(
            "/usr/sbin/semanage",
            Ok(PathBuf::from("/usr/sbin/semanage")),
        );
        env.tools.insert(
            "/usr/sbin/restorecon",
            Ok(PathBuf::from("/usr/sbin/restorecon")),
        );
        env
    }

    /// Queue a successful command output.
    fn push_ok(&mut self, stdout: &str) {
        self.responses.push_back(Ok(CommandOutput {
            success: true,
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }));
    }

    /// Queue a failing command output.
    fn push_err(&mut self, stderr: &str) {
        self.responses.push_back(Ok(CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        }));
    }
}

impl Environment for MockEnv {
    fn enforce_file_exists(&self) -> bool {
        self.enforce_exists
    }

    fn find_tool(&self, candidates: &[&str]) -> Result<PathBuf, ToolError> {
        let key = candidates.first().copied().unwrap_or("");
        match self.tools.get(key) {
            Some(Ok(path)) => Ok(path.clone()),
            Some(Err(ToolError::Missing)) | None => Err(ToolError::Missing),
            Some(Err(ToolError::Untrusted)) => Err(ToolError::Untrusted),
        }
    }

    fn run(&mut self, program: &Path, args: &[&str]) -> io::Result<CommandOutput> {
        self.calls.push((
            program.to_owned(),
            args.iter().map(|arg| (*arg).to_owned()).collect(),
        ));
        self.responses
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected command: {} {args:?}", program.display()))
    }

    fn ensure_updates_dir(&mut self, path: &Path) -> io::Result<()> {
        self.created_dirs.push(path.to_owned());
        Ok(())
    }
}

/// `/sys/fs/selinux/enforce` alone marks the host as `SELinux`-active without running `getenforce`.
#[test]
fn detects_selinux_from_enforce_file_without_spawning_getenforce() {
    let mut env = MockEnv::non_selinux();
    env.enforce_exists = true;
    assert!(is_selinux_active(&mut env));
    assert_eq!(env.calls, Vec::new());
}

/// Without `/sys/fs/selinux/enforce`, `getenforce` distinguishes active modes from `Disabled`.
#[test]
fn detects_selinux_from_getenforce_output() {
    for (stdout, expected) in [
        ("Enforcing\n", true),
        ("Permissive\n", true),
        ("Disabled\n", false),
        ("disabled\n", false),
        ("\n", false),
    ] {
        let mut env = MockEnv::non_selinux();
        env.tools.insert(
            "/usr/sbin/getenforce",
            Ok(PathBuf::from("/usr/sbin/getenforce")),
        );
        env.push_ok(stdout);
        assert_eq!(is_selinux_active(&mut env), expected, "stdout={stdout:?}");
    }

    // Missing getenforce + missing enforce file => non-SELinux host.
    let mut missing = MockEnv::non_selinux();
    assert!(!is_selinux_active(&mut missing));
}

/// Non-SELinux hosts return no plan and execute no `SELinux` commands.
#[test]
fn non_selinux_host_is_unchanged() {
    let mut env = MockEnv::non_selinux();
    let plan = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut env, false).unwrap();
    assert!(plan.is_none());
    assert_eq!(env.calls, Vec::new());
}

/// When the persistent `bin_t` rule is missing, the plan adds it and runs `restorecon -R`.
#[test]
fn plans_and_applies_fcontext_rule_and_restorecon_when_absent() {
    let mut env = MockEnv::enforcing_with_tools();
    // semanage fcontext -l -C returns no matching local rules.
    env.push_ok(
        "SELinux fcontext                                   type               Context\n\n",
    );
    let plan = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut env, false)
        .unwrap()
        .expect("SELinux plan");
    assert_eq!(
        plan.dry_run_commands(),
        vec![
            "semanage fcontext -a -t bin_t \"/var/lib/infraternal/updates(/.*)?\"",
            "restorecon -R /var/lib/infraternal/updates",
        ]
    );

    // Apply: semanage fcontext -a, then create updates dir, then restorecon -R.
    env.push_ok("");
    env.push_ok("");
    plan.apply(&mut env).unwrap();

    assert_eq!(
        env.calls,
        vec![
            (
                PathBuf::from("/usr/sbin/semanage"),
                vec!["fcontext".into(), "-l".into(), "-C".into()]
            ),
            (
                PathBuf::from("/usr/sbin/semanage"),
                vec![
                    "fcontext".into(),
                    "-a".into(),
                    "-t".into(),
                    "bin_t".into(),
                    "/var/lib/infraternal/updates(/.*)?".into(),
                ]
            ),
            (
                PathBuf::from("/usr/sbin/restorecon"),
                vec!["-R".into(), "/var/lib/infraternal/updates".into()]
            ),
        ]
    );
    assert_eq!(
        env.created_dirs,
        vec![PathBuf::from("/var/lib/infraternal/updates")]
    );
}

/// When the exact `bin_t` rule already exists, `semanage fcontext -a` is skipped and only `restorecon -R` runs.
#[test]
fn skips_semanage_add_when_exact_rule_already_exists() {
    let mut env = MockEnv::enforcing_with_tools();
    env.push_ok(
        "SELinux fcontext                                   type               Context\n\n\
         /var/lib/infraternal/updates(/.*)?                 all files          system_u:object_r:bin_t:s0 \n",
    );
    let plan = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut env, false)
        .unwrap()
        .expect("SELinux plan");
    assert_eq!(
        plan.dry_run_commands(),
        vec!["restorecon -R /var/lib/infraternal/updates"]
    );

    env.push_ok("");
    plan.apply(&mut env).unwrap();
    assert_eq!(
        env.calls,
        vec![
            (
                PathBuf::from("/usr/sbin/semanage"),
                vec!["fcontext".into(), "-l".into(), "-C".into()]
            ),
            (
                PathBuf::from("/usr/sbin/restorecon"),
                vec!["-R".into(), "/var/lib/infraternal/updates".into()]
            ),
        ]
    );
}

/// Rules with another type, file class, or path prefix do not satisfy the exact-rule check.
#[test]
fn exact_fcontext_rule_matching_rejects_partial_or_wrong_type_matches() {
    let pattern = "/var/lib/infraternal/updates(/.*)?";
    assert!(has_exact_fcontext_rule(
        "/var/lib/infraternal/updates(/.*)?   all files   system_u:object_r:bin_t:s0\n",
        pattern,
        "bin_t"
    ));
    assert!(has_exact_fcontext_rule(
        "/var/lib/infraternal/updates(/.*)?   all files   system_u:object_r:bin_t:s0:c0.c1023\n",
        pattern,
        "bin_t"
    ));
    assert!(!has_exact_fcontext_rule(
        "/var/lib/infraternal/updates(/.*)?   all files   system_u:object_r:var_lib_t:s0\n",
        pattern,
        "bin_t"
    ));
    assert!(!has_exact_fcontext_rule(
        "/var/lib/infraternal/updates(/.*)?   regular file   system_u:object_r:bin_t:s0\n",
        pattern,
        "bin_t"
    ));
    assert!(!has_exact_fcontext_rule(
        "/var/lib/infraternal/updates(/.*)?extra   all files   system_u:object_r:bin_t:s0\n",
        pattern,
        "bin_t"
    ));
}

/// Missing `semanage` on an `SELinux` host refuses with a clear message naming `policycoreutils-python-utils`.
#[test]
fn missing_semanage_refuses_and_names_package() {
    for dry_run in [false, true] {
        let mut env = MockEnv::non_selinux();
        env.enforce_exists = true;
        env.tools.insert(
            "/usr/sbin/restorecon",
            Ok(PathBuf::from("/usr/sbin/restorecon")),
        );
        let error = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut env, dry_run)
            .expect_err("must refuse when semanage is missing");
        assert!(matches!(error, SelinuxError::MissingSemanage { .. }));
        assert!(
            error.to_string().contains("policycoreutils-python-utils"),
            "{error}"
        );
        assert!(
            error.next_step().contains("policycoreutils-python-utils"),
            "{}",
            error.next_step()
        );
    }
}

/// Untrusted `semanage` is refused rather than executed as root.
#[test]
fn untrusted_semanage_is_refused() {
    let mut env = MockEnv::non_selinux();
    env.enforce_exists = true;
    env.tools
        .insert("/usr/sbin/semanage", Err(ToolError::Untrusted));
    let error = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut env, false)
        .expect_err("must refuse untrusted semanage");
    assert_eq!(error, SelinuxError::UntrustedTool { tool: "semanage" });
}

/// Dry-run tolerates an unreadable `SELinux` store (non-root user) by still planning the add command;
/// real runs fail closed.
#[test]
fn dry_run_tolerates_unreadable_locallist_while_real_run_fails() {
    let mut dry_env = MockEnv::enforcing_with_tools();
    dry_env.push_err("Permission denied");
    let plan = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut dry_env, true)
        .unwrap()
        .expect("dry-run plan");
    assert_eq!(
        plan.dry_run_commands(),
        vec![
            "semanage fcontext -a -t bin_t \"/var/lib/infraternal/updates(/.*)?\"",
            "restorecon -R /var/lib/infraternal/updates",
        ]
    );

    let mut real_env = MockEnv::enforcing_with_tools();
    real_env.push_err("Permission denied");
    let error = plan_updates_exec(Path::new("/var/lib/infraternal"), &mut real_env, false)
        .expect_err("real run must fail");
    assert!(matches!(error, SelinuxError::CommandFailed { .. }));
}

/// Regex metacharacters in custom data paths are escaped cleanly.
#[test]
fn escapes_regex_metacharacters_in_custom_data_paths() {
    assert_eq!(
        updates_fcontext_pattern(Path::new("/var/lib/infraternal/updates")).unwrap(),
        "/var/lib/infraternal/updates(/.*)?"
    );
    assert_eq!(
        updates_fcontext_pattern(Path::new("/srv/prod.1+a/updates")).unwrap(),
        r"/srv/prod\.1\+a/updates(/.*)?"
    );
}
