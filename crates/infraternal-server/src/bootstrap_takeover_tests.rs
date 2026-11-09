//! Checks the server side of Take over (D359, #394). A root-mode add that finds a
//! finished install of another server offers Take over, naming the old install's
//! id, and sets the install aside only after the person confirms. When the new
//! install then fails, the server puts the old one back with the same token.
//! Everything else keeps J303's refusal: a rootless add, an install the host
//! found in use or could not prove ours, and an id this server still serves.
//! The host programs themselves run on real files in previous_attempt_shell.py;
//! here the host answers from a script.
use super::*;

/// The host as the server sees it over SSH: a fixed check answer, every script it
/// was sent, and a join that fails, so a confirmed Take over always ends in a
/// restore. `takeover_exit` makes the host's Take over refuse with that status.
struct TakeoverHost {
    check: Vec<u8>,
    scripts: Arc<Mutex<Vec<String>>>,
    /// The reviewed public record travels over stdin, including lists too large for argv (D368).
    record: Arc<Mutex<Option<Vec<u8>>>>,
    takeover_exit: Option<u8>,
}
impl SshTransport for TakeoverHost {
    fn open(
        &self,
        _: Destination,
        _: Credentials,
        _: MeshEvidence,
    ) -> Operation<'_, Arc<dyn SshSession>> {
        Box::pin(async move {
            Ok(Arc::new(Self {
                check: self.check.clone(),
                scripts: self.scripts.clone(),
                record: self.record.clone(),
                takeover_exit: self.takeover_exit,
            }) as Arc<dyn SshSession>)
        })
    }
}
impl SshSession for TakeoverHost {
    fn run<'a>(&'a self, script: &'a str, input: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async move {
            self.scripts.lock().unwrap().push(script.to_owned());
            let stdout = if script.starts_with(infraternal_plugin_ssh::probe::CHECK_SCRIPT) {
                self.check.clone()
            } else if script.contains("\ntake_over_finished_install ") {
                *self.record.lock().unwrap() = match input {
                    Input::Bytes(bytes) => Some(bytes.to_vec()),
                    _ => None,
                };
                if let Some(status) = self.takeover_exit {
                    let mut failure = Failure::install("the take over refused");
                    failure.exit_status = Some(status);
                    return Err(failure);
                }
                Vec::new()
            } else if script.contains("\nrestore_taken_over_install ") {
                b"restored\n".to_vec()
            } else if script.contains("prepare-join-key") {
                format!("KEY-DIGEST {}\n", hex(&[7; 32])).into_bytes()
            } else if script.contains("agent --data \"$stage/state\" join ") {
                return Err(Failure::install("stop after the invitation"));
            } else {
                Vec::new()
            };
            Ok(CommandOutput { stdout })
        })
    }
}

/// The check's answer for a finished install of `old` as `uid`, with the host's
/// Take over verdict `takeover` (ready, busy or unproven).
fn installed_check(uid: u32, old: Uuid, takeover: &str) -> Vec<u8> {
    format!(
        "INFRATERNAL_CHECK_V1\nLinux\nx86_64\nsystemd\n{uid}\nno\nyes\nyes\nno\nINFRATERNAL_SETUP_INSTALLED {} 64:1234 live {takeover}\n",
        old.simple()
    )
    .into_bytes()
}

/// One add of `user@fixture` in `mode` against [`TakeoverHost`].
struct Run {
    runner: Bootstrap,
    batch: Batch,
    scripts: Arc<Mutex<Vec<String>>>,
    /// Retain only takeover's public stdin so the assertion cannot mistake a script for its record.
    record: Arc<Mutex<Option<Vec<u8>>>>,
}
impl Run {
    /// Start the add of `root@fixture` in `mode`, with the host answering `check`.
    fn start(f: &Fixture, check: Vec<u8>, mode: InstallMode, takeover_exit: Option<u8>) -> Self {
        let scripts = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::new(Mutex::new(None));
        let binary = std::env::current_exe().unwrap();
        let runner = Bootstrap::new(
            Arc::new(TakeoverHost {
                check,
                scripts: scripts.clone(),
                record: record.clone(),
                takeover_exit,
            }),
            f.backend.clone(),
            BinaryPaths {
                x86_64: binary.clone(),
                aarch64: binary,
            },
        );
        let batch = runner
            .start_authenticated(
                "owner".into(),
                Secret::new(f.cookie.as_bytes().to_vec()),
                vec![Target {
                    id: "one".into(),
                    address: TargetAddress::Manual("root@fixture".into()),
                    credential: None,
                    mode,
                    root_consent: mode == InstallMode::Root,
                }],
                None,
            )
            .unwrap();
        Self {
            runner,
            batch,
            scripts,
            record,
        }
    }
    /// The first host script containing `needle`, if one was sent.
    fn script(&self, needle: &str) -> Option<String> {
        self.scripts
            .lock()
            .unwrap()
            .iter()
            .find(|script| script.contains(needle))
            .cloned()
    }
    /// Wait for the paused event that offers Take over.
    async fn offer(&self) -> Event {
        let mut changed = self.batch.subscribe();
        tokio::time::timeout(TEST_HANG_BOUND, async {
            loop {
                let events = self.batch.events(0).1;
                if let Some(event) = events.iter().find(|event| event.leftovers.is_some()) {
                    return event.clone();
                }
                assert!(
                    events.iter().all(|event| event.step != Step::Failed),
                    "Take over must be offered first: {events:?}"
                );
                changed.changed().await.unwrap();
            }
        })
        .await
        .unwrap()
    }
}

/// The owner's shape (#394): root SSH, a finished install of a server that is
/// gone. Take over is offered with the old install's id, nothing is changed
/// before the confirmation, and a failed new install gets the old one back
/// through the same token. D368 also binds its listed terminal to explicit close consent.
#[tokio::test]
async fn a_root_add_offers_take_over_and_a_failed_install_puts_the_old_one_back() {
    let f = fixture(true).await;
    let old = Uuid::new_v4();
    let terminal = format!(
        "{},726f6f74,62617368,1792195200,{}",
        "2".repeat(32),
        "a".repeat(64)
    );
    let check = String::from_utf8(installed_check(0, old, "ready")).unwrap();
    let run = Run::start(
        &f,
        format!("{} {terminal}\n", check.trim_end()).into_bytes(),
        InstallMode::Root,
        None,
    );
    let offer = run.offer().await;
    let failure = serde_json::to_value(offer.failure.as_ref().unwrap()).unwrap();
    assert_eq!(failure["kind"], "unrecognized_install");
    assert_eq!(
        failure["takeover"]["install"],
        old.simple().to_string(),
        "the confirmation names the old install"
    );
    assert_eq!(failure["takeover"]["live"], true);
    assert_eq!(failure["takeover"]["terminals"][0]["account"], "root");
    assert_eq!(failure["takeover"]["terminals"][0]["program"], "bash");
    assert_eq!(offer.leftovers.as_ref().unwrap().mode, InstallMode::Root);
    assert!(
        run.script("\ntake_over_finished_install ").is_none(),
        "nothing changes before the confirmation"
    );

    assert!(
        run.runner
            .start_fresh(
                &run.batch,
                "owner",
                "one",
                offer.leftovers.unwrap().challenge
            )
            .is_err(),
        "generic cleanup cannot close terminals"
    );
    let close = Uuid::parse_str(failure["takeover"]["close_challenge"].as_str().unwrap()).unwrap();
    run.runner
        .start_fresh(&run.batch, "owner", "one", close)
        .unwrap();
    let event = finished(&run.batch).await;
    assert_eq!(event.step, Step::Failed);

    let take_over = run
        .script("\ntake_over_finished_install ")
        .expect("set aside after the confirmation");
    let record = format!(
        "INFRATERNAL_SETUP_INSTALLED {} 64:1234 live ready {terminal}",
        old.simple()
    );
    assert!(
        !take_over.contains(&format!("'{record}'")),
        "long terminal records must not be constrained by argv"
    );
    assert_eq!(
        run.record.lock().unwrap().as_deref(),
        Some(format!("{record}\n").as_bytes()),
        "bound to the exact stdin record"
    );
    let token = take_over
        .rsplit("\ntake_over_finished_install ")
        .next()
        .and_then(|call| call.lines().next())
        .and_then(|call| call.rsplit(' ').next())
        .unwrap()
        .to_owned();
    assert_eq!(token.len(), 32);
    let restore = run
        .script("\nrestore_taken_over_install ")
        .expect("put back after the failure");
    assert!(
        restore.contains(&format!("\nrestore_taken_over_install {token} ")),
        "the same token"
    );
    assert!(
        run.batch
            .events(0)
            .1
            .iter()
            .any(|event| event.message.contains("put back as it was found")),
        "the person is told"
    );
}

/// D359: rootless adds of another account's install still refuse, even when
/// the host's verdict says ready; nothing is offered or changed.
#[tokio::test]
async fn a_rootless_add_is_never_offered_take_over() {
    let f = fixture(true).await;
    let run = Run::start(
        &f,
        installed_check(1002, Uuid::new_v4(), "ready"),
        InstallMode::Rootless,
        None,
    );
    let event = finished(&run.batch).await;
    assert_eq!(event.step, Step::Failed);
    assert_eq!(
        event.failure.as_ref().unwrap().message,
        infraternal_plugin_ssh::previous_attempt::INSTALLED_ELSEWHERE
    );
    assert!(
        run.batch
            .events(0)
            .1
            .iter()
            .all(|event| event.leftovers.is_none())
    );
    assert!(run.script("\ntake_over_finished_install ").is_none());
}

/// An install the host found in use, or could not prove ours, is never offered.
#[tokio::test]
async fn a_busy_or_unproven_install_is_never_offered() {
    for (takeover, message) in [
        (
            "busy",
            infraternal_plugin_ssh::previous_attempt::TAKEOVER_BUSY,
        ),
        (
            "unproven",
            infraternal_plugin_ssh::previous_attempt::INSTALLED_ELSEWHERE,
        ),
    ] {
        let f = fixture(true).await;
        let run = Run::start(
            &f,
            installed_check(0, Uuid::new_v4(), takeover),
            InstallMode::Root,
            None,
        );
        let event = finished(&run.batch).await;
        assert_eq!(event.step, Step::Failed, "{takeover}");
        assert_eq!(
            event.failure.as_ref().unwrap().message,
            message,
            "{takeover}"
        );
        assert!(
            run.batch
                .events(0)
                .1
                .iter()
                .all(|event| event.leftovers.is_none()),
            "{takeover}"
        );
        assert!(
            run.script("\ntake_over_finished_install ").is_none(),
            "{takeover}"
        );
    }
}

/// A host this server still serves is never taken over from under it.
#[tokio::test]
async fn an_install_of_a_host_this_server_serves_is_never_offered() {
    let f = fixture(true).await;
    let run = Run::start(
        &f,
        installed_check(0, f.prior, "ready"),
        InstallMode::Root,
        None,
    );
    let event = finished(&run.batch).await;
    assert_eq!(event.step, Step::Failed);
    assert_eq!(
        event.failure.as_ref().unwrap().message,
        infraternal_plugin_ssh::previous_attempt::INSTALLED_ELSEWHERE
    );
    assert!(run.script("\ntake_over_finished_install ").is_none());
}

/// A Take over the host refuses because something started using the install
/// says so; its own trap already put everything back, so the server sends no
/// restore of its own.
#[tokio::test]
async fn a_take_over_the_host_finds_busy_says_so_and_needs_no_restore() {
    let f = fixture(true).await;
    let run = Run::start(
        &f,
        installed_check(0, Uuid::new_v4(), "ready"),
        InstallMode::Root,
        Some(73),
    );
    let offer = run.offer().await;
    run.runner
        .start_fresh(
            &run.batch,
            "owner",
            "one",
            offer.leftovers.unwrap().challenge,
        )
        .unwrap();
    let event = finished(&run.batch).await;
    assert_eq!(event.step, Step::Failed);
    assert_eq!(
        event.failure.as_ref().unwrap().message,
        infraternal_plugin_ssh::previous_attempt::TAKEOVER_BUSY
    );
    assert!(run.script("\nrestore_taken_over_install ").is_none());
    assert!(
        run.script("prepare-join-key").is_none(),
        "nothing is installed beside it"
    );
}
