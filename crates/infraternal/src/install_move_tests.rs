//! Behaviour of the data-folder move: each test builds a real install in a
//! scratch folder (data files, a socket, a unit with drop-ins) and checks what
//! is on disk afterwards, including after a simulated crash at each step.

use super::*;
use std::{
    cell::{Cell, RefCell},
    env,
    os::unix::net::UnixListener,
};

thread_local! {
    /// Make the folder rename fail as if the target were on another filesystem.
    pub(super) static FORCE_COPY: Cell<bool> = const { Cell::new(false) };
}

/// A service manager that records calls and holds a running flag.
#[derive(Default)]
struct Fake {
    /// Whether the service runs now.
    running: Cell<bool>,
    /// What `enabled` answers.
    enabled: bool,
    /// Make `stop` fail.
    fail_stop: bool,
    /// Every call, in order.
    calls: RefCell<Vec<&'static str>>,
}

impl Fake {
    /// A service that is running and enabled, as a live install is.
    fn running() -> Self {
        Self {
            running: Cell::new(true),
            enabled: true,
            ..Self::default()
        }
    }

    /// The calls made so far.
    fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }
}

impl Service for Fake {
    fn active(&self) -> io::Result<bool> {
        self.calls.borrow_mut().push("active");
        Ok(self.running.get())
    }
    fn enabled(&self) -> io::Result<bool> {
        self.calls.borrow_mut().push("enabled");
        Ok(self.enabled)
    }
    fn stop(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("stop");
        if self.fail_stop {
            return Err(io::Error::other("stop refused"));
        }
        self.running.set(false);
        Ok(())
    }
    fn reload(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("reload");
        Ok(())
    }
    fn start(&self) -> io::Result<()> {
        self.calls.borrow_mut().push("start");
        self.running.set(true);
        Ok(())
    }
}

/// One scratch install: an old data folder, the standard target and a unit.
struct Install {
    /// The scratch root, removed on drop.
    root: PathBuf,
    /// The folder the unit records.
    old: PathBuf,
    /// The standard folder (its parent does not exist yet).
    new: PathBuf,
    /// The unit file.
    unit: PathBuf,
}

impl Drop for Install {
    fn drop(&mut self) {
        // Leftovers are read-only; make them writable so the scratch tree goes.
        let _ = Command::new("chmod")
            .arg("-R")
            .arg("u+w")
            .arg(&self.root)
            .status();
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The unit text `server init` writes for `data`.
fn unit_text(data: &Path) -> String {
    format!(
        "[Unit]\nDescription=infraternal server (x)\n\n[Service]\nType=simple\n\
         ExecStart=\"/opt/infraternal\" \"server\" \"--listen\" \"127.0.0.1:47361\" \"--data\" \"{0}\" \
         \"--public-origin\" \"https://localhost:47361\" \"--remote-ca-dir\" \"{0}/remote-ca\"\n\
         Restart=on-failure\n\n[Install]\nWantedBy=default.target\n",
        data.display()
    )
}

/// Build an install with a database, WAL, a nested key folder and a stale socket.
fn install() -> Install {
    let root = env::temp_dir().join(format!(
        "mv-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let old = root.join("cwd/data");
    let new = root.join("home/.local/state/infraternal");
    fs::create_dir_all(old.join("mesh")).unwrap();
    fs::create_dir_all(old.join("remote-ca")).unwrap();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o750)).unwrap();
    fs::write(old.join("infraternal.sqlite"), vec![7_u8; 200_000]).unwrap();
    fs::write(old.join("infraternal.sqlite-wal"), b"wal frames").unwrap();
    fs::write(old.join("infraternal.sqlite-shm"), b"shm").unwrap();
    fs::write(old.join("mesh/key"), b"mesh private key").unwrap();
    fs::set_permissions(old.join("mesh/key"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(old.join("remote-ca/ca.pem"), b"ca").unwrap();
    std::os::unix::fs::symlink("infraternal.sqlite", old.join("link")).unwrap();
    let listener = UnixListener::bind(old.join("s.sock")).unwrap();
    drop(listener);
    let units = root.join("units");
    fs::create_dir_all(&units).unwrap();
    let unit = units.join("x.service");
    fs::write(&unit, unit_text(&old)).unwrap();
    Install {
        root,
        old,
        new,
        unit,
    }
}

/// The data files a move must carry, as (relative path, bytes).
fn data_of(folder: &Path) -> Vec<(String, Vec<u8>)> {
    [
        "infraternal.sqlite",
        "infraternal.sqlite-wal",
        "infraternal.sqlite-shm",
        "mesh/key",
        "remote-ca/ca.pem",
    ]
    .iter()
    .map(|name| ((*name).to_owned(), fs::read(folder.join(name)).unwrap()))
    .collect()
}

/// Permission bits of a path.
fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

/// A move at a fixed time, so the leftover name is known.
fn when() -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(1_794_733_687)
}

/// Prod's case: the unit already records the standard folder, so nothing is planned.
#[test]
fn a_standard_folder_is_left_alone() {
    let setup = install();
    let unit = fs::read(&setup.unit).unwrap();
    assert!(plan(&setup.old, &setup.old, &setup.unit).unwrap().is_none());
    let slash = PathBuf::from(format!("{}/", setup.old.display()));
    assert!(plan(&slash, &setup.old, &setup.unit).unwrap().is_none());
    assert!(
        plan(
            Path::new("/var/lib/infraternal"),
            Path::new("/var/lib/infraternal"),
            &setup.unit
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(fs::read(&setup.unit).unwrap(), unit);
}

/// Same filesystem: one rename moves everything, the unit points at the new folder, a re-run is a no-op.
#[test]
fn a_rename_moves_the_whole_folder_and_switches_the_unit() {
    let setup = install();
    let before = data_of(&setup.old);
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    assert_eq!(relocation.stage, Stage::Move);
    assert!(relocation.same_filesystem);
    let service = Fake::running();
    let outcome = apply(&relocation, &service, when()).unwrap();
    assert_eq!(
        outcome,
        Outcome {
            leftover: None,
            copied: false,
            warning: None
        }
    );
    assert!(!setup.old.exists());
    assert_eq!(data_of(&setup.new), before);
    assert_eq!(mode(&setup.new), 0o700);
    assert!(!setup.new.join(MARKER).exists());
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.new)
    );
    assert_eq!(
        service.calls(),
        ["active", "enabled", "stop", "active", "reload", "start"]
    );
    assert!(service.running.get());
    assert!(plan(&setup.new, &setup.new, &setup.unit).unwrap().is_none());
}

/// Across filesystems: copy, compare, switch, and keep the old folder read-only with a dated name.
#[test]
fn a_copy_is_verified_and_the_old_folder_is_kept_read_only() {
    let setup = install();
    let before = data_of(&setup.old);
    FORCE_COPY.with(|force| force.set(true));
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    let outcome = apply(&relocation, &Fake::running(), when());
    FORCE_COPY.with(|force| force.set(false));
    let outcome = outcome.unwrap();
    let leftover = setup.root.join("cwd/data.moved-20261115-090807");
    assert_eq!(
        outcome,
        Outcome {
            leftover: Some(leftover.clone()),
            copied: true,
            warning: None
        }
    );
    assert_eq!(data_of(&setup.new), before);
    assert_eq!(data_of(&leftover), before);
    assert!(!setup.old.exists());
    assert_eq!(
        fs::read_link(setup.new.join("link")).unwrap(),
        Path::new("infraternal.sqlite")
    );
    assert!(
        !setup.new.join("s.sock").exists(),
        "a stale socket is not copied"
    );
    assert_eq!(mode(&setup.new), 0o700);
    assert_eq!(mode(&setup.new.join("mesh/key")), 0o600);
    assert_eq!(mode(&leftover) & 0o222, 0);
    assert_eq!(mode(&leftover.join("mesh/key")) & 0o222, 0);
    assert!(!setup.new.join(MARKER).exists());
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.new)
    );
    let text = outcome.describe(&relocation);
    assert!(
        text.contains(&format!(
            "chmod -R u+w '{0}' && rm -rf '{0}'",
            leftover.display()
        )),
        "{text}"
    );
    assert!(plan(&setup.new, &setup.new, &setup.unit).unwrap().is_none());
}

/// A non-empty target that is not our own move is refused, and nothing changes.
#[test]
fn a_non_empty_target_is_refused() {
    let setup = install();
    fs::create_dir_all(&setup.new).unwrap();
    fs::write(setup.new.join("theirs"), b"x").unwrap();
    let error = plan(&setup.old, &setup.new, &setup.unit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is not empty"), "{error}");
    assert!(
        error.contains(&format!("--data {}", setup.old.display())),
        "{error}"
    );
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.old)
    );
}

/// An empty target folder is fine: it is replaced by the moved folder.
#[test]
fn an_empty_target_folder_is_used() {
    let setup = install();
    fs::create_dir_all(&setup.new).unwrap();
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    apply(&relocation, &Fake::running(), when()).unwrap();
    assert!(setup.new.join("mesh/key").is_file());
}

/// A symlinked, nested, foreign-owned-looking or missing old folder is refused before anything changes.
#[test]
fn unsafe_sources_are_refused() {
    let setup = install();
    let link = setup.root.join("linked");
    std::os::unix::fs::symlink(&setup.old, &link).unwrap();
    fs::write(&setup.unit, unit_text(&link)).unwrap();
    let error = plan(&link, &setup.new, &setup.unit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("symbolic link"), "{error}");

    fs::write(&setup.unit, unit_text(&setup.old)).unwrap();
    let inside = setup.old.join("state");
    let error = plan(&setup.old, &inside, &setup.unit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("inside the other"), "{error}");

    let missing = setup.root.join("gone");
    fs::write(&setup.unit, unit_text(&missing)).unwrap();
    let error = plan(&missing, &setup.new, &setup.unit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not exist"), "{error}");
}

/// Drop-ins: every `ExecStart` naming the folder is rewritten, the unit itself last.
#[test]
fn drop_in_exec_lines_are_rewritten_and_the_unit_goes_last() {
    let setup = install();
    let dropins = setup.root.join("units/x.service.d");
    fs::create_dir_all(&dropins).unwrap();
    let line = |data: &Path| {
        format!(
            "[Service]\nExecStart=\nExecStart=-/opt/infraternal server --data={} --listen 127.0.0.1:2\n",
            data.display()
        )
    };
    fs::write(dropins.join("10-local.conf"), line(&setup.old)).unwrap();
    fs::write(
        dropins.join("20-env.conf"),
        "[Service]\nEnvironment=RUST_LOG=info\n",
    )
    .unwrap();
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    let files: Vec<&Path> = relocation.unit_files().collect();
    assert_eq!(
        files,
        [
            dropins.join("10-local.conf").as_path(),
            setup.unit.as_path()
        ]
    );
    apply(&relocation, &Fake::running(), when()).unwrap();
    assert_eq!(
        fs::read_to_string(dropins.join("10-local.conf")).unwrap(),
        format!(
            "[Service]\nExecStart=\nExecStart=-\"/opt/infraternal\" \"server\" \"--data={}\" \"--listen\" \"127.0.0.1:2\"\n",
            setup.new.display()
        )
    );
    let words = infraternal_status::exec_words(
        fs::read_to_string(dropins.join("10-local.conf"))
            .unwrap()
            .lines()
            .last()
            .unwrap()
            .strip_prefix("ExecStart=")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(words[0], "-/opt/infraternal");
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.new)
    );
}

/// A setting other than `ExecStart` naming the old folder is refused; a lookalike path is not.
#[test]
fn other_lines_naming_the_folder_are_refused() {
    let setup = install();
    let dropins = setup.root.join("units/x.service.d");
    fs::create_dir_all(&dropins).unwrap();
    fs::write(
        dropins.join("hardening.conf"),
        format!(
            "[Service]\n# old: {0}\nReadWritePaths={0}2\n",
            setup.old.display()
        ),
    )
    .unwrap();
    assert!(plan(&setup.old, &setup.new, &setup.unit).unwrap().is_some());
    fs::write(
        dropins.join("hardening.conf"),
        format!("[Service]\nReadWritePaths={}\n", setup.old.display()),
    )
    .unwrap();
    let error = plan(&setup.old, &setup.new, &setup.unit)
        .unwrap_err()
        .to_string();
    assert!(error.contains("hardening.conf:2"), "{error}");
    assert!(error.contains("outside ExecStart"), "{error}");
}

/// Crash after the rename, before the switch: the next run only switches the unit.
#[test]
fn a_crash_after_the_rename_is_finished_by_the_next_run() {
    let setup = install();
    let before = data_of(&setup.old);
    write_marker(&setup.old, &setup.old).unwrap();
    fs::create_dir_all(setup.new.parent().unwrap()).unwrap();
    fs::rename(&setup.old, &setup.new).unwrap();
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    assert_eq!(relocation.stage, Stage::Switch);
    apply(&relocation, &Fake::running(), when()).unwrap();
    assert_eq!(data_of(&setup.new), before);
    assert!(!setup.new.join(MARKER).exists());
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.new)
    );
}

/// Crash after a copy, before the switch: the old folder wins and is copied again.
#[test]
fn a_crash_after_a_copy_redoes_it_from_the_old_folder() {
    let setup = install();
    fs::create_dir_all(&setup.new).unwrap();
    fs::write(setup.new.join("infraternal.sqlite"), b"stale copy").unwrap();
    write_marker(&setup.new, &setup.old).unwrap();
    // The service ran on the old folder after the crash and changed it.
    fs::write(setup.old.join("infraternal.sqlite-wal"), b"newer frames").unwrap();
    let before = data_of(&setup.old);
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    assert_eq!(relocation.stage, Stage::Redo);
    apply(&relocation, &Fake::running(), when()).unwrap();
    assert_eq!(data_of(&setup.new), before);
    assert!(!setup.old.exists());
}

/// Crash after the switch: the next run sets the old folder aside and drops the marker, without touching the service.
#[test]
fn a_crash_after_the_switch_is_cleaned_up() {
    let setup = install();
    fs::create_dir_all(&setup.new).unwrap();
    for (name, bytes) in data_of(&setup.old) {
        let path = setup.new.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    write_marker(&setup.new, &setup.old).unwrap();
    fs::write(&setup.unit, unit_text(&setup.new)).unwrap();
    let relocation = plan(&setup.new, &setup.new, &setup.unit).unwrap().unwrap();
    assert_eq!(relocation.stage, Stage::Cleanup);
    let service = Fake::running();
    let outcome = apply(&relocation, &service, when()).unwrap();
    assert_eq!(
        outcome.leftover,
        Some(setup.root.join("cwd/data.moved-20261115-090807"))
    );
    assert!(!setup.old.exists());
    assert!(!setup.new.join(MARKER).exists());
    assert_eq!(service.calls(), Vec::<&str>::new());
    assert!(plan(&setup.new, &setup.new, &setup.unit).unwrap().is_none());
}

/// A service that will not stop means nothing moves and the unit is untouched.
#[test]
fn a_failed_stop_moves_nothing() {
    let setup = install();
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    let service = Fake {
        fail_stop: true,
        ..Fake::running()
    };
    let error = apply(&relocation, &service, when())
        .unwrap_err()
        .to_string();
    assert!(error.contains("nothing was moved"), "{error}");
    assert!(setup.old.join("mesh/key").is_file());
    assert!(!setup.new.exists());
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.old)
    );
}

/// A unit that cannot be rewritten undoes the rename and starts the old service again.
#[test]
fn a_failed_switch_puts_the_old_install_back() {
    if nix::unistd::Uid::effective().is_root() {
        return; // root ignores the read-only folder this test relies on
    }
    for copy in [false, true] {
        let setup = install();
        let before = data_of(&setup.old);
        let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
        let units = setup.unit.parent().unwrap().to_owned();
        fs::set_permissions(&units, fs::Permissions::from_mode(0o500)).unwrap();
        FORCE_COPY.with(|force| force.set(copy));
        let service = Fake::running();
        let result = apply(&relocation, &service, when());
        FORCE_COPY.with(|force| force.set(false));
        fs::set_permissions(&units, fs::Permissions::from_mode(0o700)).unwrap();
        let error = result.unwrap_err().to_string();
        assert!(error.contains("rewriting"), "{copy}: {error}");
        assert_eq!(data_of(&setup.old), before, "{copy}");
        assert!(!setup.old.join(MARKER).exists(), "{copy}");
        assert!(!setup.new.exists(), "{copy}");
        assert_eq!(
            fs::read_to_string(&setup.unit).unwrap(),
            unit_text(&setup.old)
        );
        assert!(service.running.get(), "{copy}: the old service runs again");
    }
}

/// The copy check catches a byte that differs and an extra file.
#[test]
fn verification_catches_a_changed_or_extra_file() {
    let setup = install();
    let copy = setup.root.join("copy");
    copy_tree(&setup.old, &copy).unwrap();
    verify_tree(&setup.old, &copy).unwrap();
    fs::write(copy.join("mesh/key"), b"mesh private kez").unwrap();
    assert!(verify_tree(&setup.old, &copy).is_err());
    fs::write(copy.join("mesh/key"), b"mesh private key").unwrap();
    fs::write(copy.join("extra"), b"").unwrap();
    assert!(verify_tree(&setup.old, &copy).is_err());
}

/// Words under the old folder are mapped; a lookalike prefix is not.
#[test]
fn only_whole_paths_are_mapped() {
    assert_eq!(map_word("/srv/data", "/srv/data", "/new"), "/new");
    assert_eq!(map_word("/srv/data/ca", "/srv/data", "/new"), "/new/ca");
    assert_eq!(
        map_word("--data=/srv/data", "/srv/data", "/new"),
        "--data=/new"
    );
    assert_eq!(map_word("/srv/data2", "/srv/data", "/new"), "/srv/data2");
    assert!(names_path("ReadWritePaths=/srv/data /tmp", "/srv/data"));
    assert!(!names_path("ReadWritePaths=/srv/data2", "/srv/data"));
}

/// Leftover names use UTC calendar time.
#[test]
fn stamps_are_utc_calendar_time() {
    assert_eq!(utc_stamp(0), "19700101-000000");
    assert_eq!(utc_stamp(951_868_799), "20000229-235959");
    assert_eq!(utc_stamp(1_794_733_687), "20261115-090807");
}

/// Real cross-filesystem proof: `INFRATERNAL_MOVE_PROOF_DIR` names a folder on
/// another filesystem than `TMPDIR` (a tmpfs, or an attached disk image on
/// macOS). Nothing is forced: the rename must really fail with EXDEV and the
/// copy path must carry everything. Ignored by default; run it explicitly.
#[test]
#[ignore = "needs INFRATERNAL_MOVE_PROOF_DIR on a second filesystem"]
fn a_real_second_filesystem_takes_the_copy_path() {
    let other = PathBuf::from(
        env::var_os("INFRATERNAL_MOVE_PROOF_DIR").expect("set INFRATERNAL_MOVE_PROOF_DIR"),
    );
    let mut setup = install();
    setup.new = other.join(format!(
        "mv-{}/state/infraternal",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ));
    let before = data_of(&setup.old);
    let relocation = plan(&setup.old, &setup.new, &setup.unit).unwrap().unwrap();
    assert!(
        !relocation.same_filesystem,
        "{} is on the same filesystem",
        other.display()
    );
    let outcome = apply(&relocation, &Fake::running(), when()).unwrap();
    assert!(outcome.copied);
    assert_eq!(data_of(&setup.new), before);
    assert_eq!(data_of(outcome.leftover.as_ref().unwrap()), before);
    assert_eq!(
        fs::read_to_string(&setup.unit).unwrap(),
        unit_text(&setup.new)
    );
    println!("{}", outcome.describe(&relocation));
    let _ = fs::remove_dir_all(setup.new.parent().unwrap().parent().unwrap());
}
