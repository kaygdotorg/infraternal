//! Unit tests for how Take over finds an install's terminals and what it may close (D368, #433).
//!
//! These cover the pure parts: where a shim's cgroup puts its close boundary, how logind's session
//! record is read, and how the processes inside a boundary are attributed to the terminals shown in the
//! confirmation. The real-root fixture (`takeover_terminals_root.py`) and the guest end-to-end run cover
//! the parts that need a live system manager.

use super::{Boundary, Process, attribute, boundary, login_leader, members_digest, pts};

/// The id the tests use for the authenticated shim's session.
const ID: &str = "d2f8649c0123456789abcdef01234567";

/// The (device, inode) the tests use for the system manager's executor, `systemd-executor`.
const EXECUTOR: (u64, u64) = (9, 9);

/// A process record with the fields attribution reads; `tty` is a raw `tty_nr`. Its executable is
/// a distinct file per process, never the executor.
fn member(pid: i32, parent: i32, tty: u32, foreground: bool, program: &str) -> Process {
    Process {
        pid,
        ppid: parent,
        birth: u64::try_from(pid).unwrap() * 10,
        uid: 0,
        program: program.into(),
        tty,
        foreground,
        exe: (1, u64::try_from(pid).unwrap()),
    }
}

/// The real PAM helper of a host login: the executor process systemd left in the session when it
/// started the worker, so it runs the executor binary, as the login's account, born with the login.
fn pam_helper(pid: i32, worker: i32) -> Process {
    Process {
        exe: EXECUTOR,
        ..member(pid, worker, 0, false, "(sd-pam)")
    }
}

/// The `tty_nr` the kernel reports for `/dev/pts/<index>`.
fn pty(index: u32) -> u32 {
    let major = 136 + index / 256;
    let minor = index % 256;
    (major << 8) | minor
}

/// The old layout (minipc01, before host login): one shim in its own
/// `infraternal-session-<id>.scope`, nested scopes included.
#[test]
fn an_old_layout_scope_is_its_own_close_boundary() {
    let (path, found) =
        boundary(&format!("/system.slice/infraternal-session-{ID}.scope"), ID).unwrap();
    assert_eq!(
        path,
        std::path::Path::new(&format!(
            "/sys/fs/cgroup/system.slice/infraternal-session-{ID}.scope"
        ))
    );
    assert_eq!(
        found,
        Boundary::Scope(format!("infraternal-session-{ID}.scope"))
    );
    let (_, nested) = boundary(
        &format!("/system.slice/infraternal-session-{ID}.scope/inner"),
        ID,
    )
    .unwrap();
    assert_eq!(
        nested,
        Boundary::Scope(format!("infraternal-session-{ID}.scope"))
    );
}

/// P1 (#433): since host login, a product terminal's shim runs in logind's
/// `session-N.scope`. That must be accepted as a login boundary, not refused.
#[test]
fn a_host_login_session_scope_is_a_login_boundary() {
    let (path, found) = boundary("/user.slice/user-0.slice/session-8.scope", ID).unwrap();
    assert_eq!(
        path,
        std::path::Path::new("/sys/fs/cgroup/user.slice/user-0.slice/session-8.scope")
    );
    assert_eq!(
        found,
        Boundary::Login {
            session: "8".into(),
            uid: 0
        }
    );
    let (_, other) = boundary("/user.slice/user-1000.slice/session-c4.scope", ID).unwrap();
    assert_eq!(
        other,
        Boundary::Login {
            session: "c4".into(),
            uid: 1000
        }
    );
}

/// Anything else stays fail-closed: another session's scope, a service, a
/// nested login cgroup, traversal, or a scope name with odd characters.
#[test]
fn every_other_cgroup_is_refused() {
    for path in [
        "/system.slice/infraternal-session-00000000000000000000000000000000.scope".to_owned(),
        "/system.slice/sshd.service".to_owned(),
        // #433 P3-4: the old layout's scope is a direct child of system.slice, the unit Take over stops.
        format!("/user.slice/user-0.slice/infraternal-session-{ID}.scope"),
        format!("/system.slice/other.slice/infraternal-session-{ID}.scope"),
        format!("/infraternal-session-{ID}.scope"),
        "/user.slice/user-0.slice/session-8.scope/inner".to_owned(),
        "/user.slice/user-0.slice/user@0.service/app.slice".to_owned(),
        "/user.slice/user-0.slice/session-.scope".to_owned(),
        "/user.slice/user-0.slice/session-8-x.scope".to_owned(),
        "/user.slice/user-x.slice/session-8.scope".to_owned(),
        "/user.slice/../user-0.slice/session-8.scope".to_owned(),
        format!("/user.slice/user-0.slice/session-8.scope/../infraternal-session-{ID}.scope"),
        String::new(),
    ] {
        assert_eq!(boundary(&path, ID), Err(73), "{path}");
    }
}

/// logind's own record names the session's leader; its scope and account must
/// be the ones the cgroup path says.
#[test]
fn the_logind_record_names_the_leader() {
    let record = "# This is private data. Do not parse.\nUID=0\nUSER=root\nACTIVE=1\nSTATE=active\nREMOTE=0\nTYPE=unspecified\nCLASS=user\nSCOPE=session-8.scope\nSERVICE=login\nLEADER=2669\n";
    assert_eq!(login_leader(record, "8", 0), Ok(2669));
    assert_eq!(
        login_leader(record, "9", 0),
        Err(73),
        "another session's record"
    );
    assert_eq!(login_leader(record, "8", 1000), Err(73), "another account");
    assert_eq!(
        login_leader(&record.replace("LEADER=2669\n", ""), "8", 0),
        Err(73)
    );
    assert_eq!(
        login_leader(&record.replace("LEADER=2669", "LEADER=0"), "8", 0),
        Err(73)
    );
    assert_eq!(
        login_leader(&format!("{record}LEADER=7\n"), "8", 0),
        Err(73),
        "two leaders"
    );
}

/// Only `/dev/pts/N` terminals are named; the name tells rows apart (P3-2).
#[test]
fn pts_names_come_from_the_kernel_device_number() {
    assert_eq!(pts(pty(3)), Some(3));
    assert_eq!(pts(pty(300)), Some(300));
    assert_eq!(pts(0), None);
    assert_eq!(
        pts((4 << 8) | 1),
        None,
        "a virtual console is not a product terminal"
    );
}

/// Old layout: everything in the scope is that terminal's; background jobs are counted (P3-1).
#[test]
fn an_old_scope_counts_its_background_programs() {
    let members = [
        member(10, 1, 0, false, "live"),
        member(11, 10, pty(3), true, "bash"),
        member(12, 11, pty(3), false, "sleep"),
        member(13, 1, 0, false, "orphan"),
    ];
    let found = attribute(&members, &[(10, None)], None, &[EXECUTOR]).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(members[found[0].foreground].program, "bash");
    assert_eq!(found[0].others, 2);
    assert_eq!(found[0].tty, Some(3));
}

/// Host login: one logind session holds the worker, each terminal's shim and
/// its shell. Each shell is attributed to its shim through the PTY index.
#[test]
fn a_login_session_attributes_each_shell_to_its_shim() {
    let members = [
        member(20, 1, 0, false, "infraternal"),
        member(21, 2, 0, false, "live"),
        member(22, 2, 0, false, "live"),
        member(23, 20, pty(3), false, "bash"),
        member(24, 23, pty(3), true, "vim"),
        member(25, 20, pty(4), true, "bash"),
        member(26, 23, 0, false, "daemonish"),
    ];
    let found = attribute(
        &members,
        &[(21, Some(3)), (22, Some(4))],
        Some(20),
        &[EXECUTOR],
    )
    .unwrap();
    assert_eq!(members[found[0].foreground].program, "vim");
    assert_eq!(
        found[0].others, 2,
        "its shell and the tty-less child of that shell"
    );
    assert_eq!(found[0].tty, Some(3));
    assert_eq!(members[found[1].foreground].program, "bash");
    assert_eq!(found[1].others, 0);
    assert_eq!(found[1].tty, Some(4));
}

/// A login boundary refuses whatever it cannot attribute to one of this
/// install's terminals: nothing is closed that the confirmation doesn't show.
#[test]
fn a_login_session_refuses_what_it_cannot_attribute() {
    let base = vec![
        member(20, 1, 0, false, "infraternal"),
        member(21, 2, 0, false, "live"),
        member(23, 20, pty(3), true, "bash"),
    ];
    assert!(attribute(&base, &[(21, Some(3))], Some(20), &[EXECUTOR]).is_ok());
    let with = |extra: Process| {
        let mut members = base.clone();
        members.push(extra);
        attribute(&members, &[(21, Some(3))], Some(20), &[EXECUTOR])
    };
    assert_eq!(
        with(member(30, 1, 0, false, "escaped")),
        Err(73),
        "not under the worker or a shim"
    );
    assert_eq!(
        with(member(31, 20, pty(5), true, "bash")),
        Err(73),
        "a terminal that is not this install's"
    );
    assert_eq!(
        with(member(32, 20, 0, false, "helper")),
        Err(73),
        "a tty-less child of the worker"
    );
    assert_eq!(
        attribute(&base, &[(21, None)], Some(20), &[EXECUTOR]),
        Err(73),
        "a shim without a PTY"
    );
    assert_eq!(
        attribute(&base, &[(21, Some(3))], Some(99), &[EXECUTOR]),
        Err(73),
        "the leader is not a member"
    );
    assert_eq!(
        attribute(
            &base,
            &[(21, Some(3)), (21, Some(3))],
            Some(20),
            &[EXECUTOR]
        ),
        Err(73),
        "a shim listed twice"
    );
}

/// Every terminal needs a foreground program to name in its row.
#[test]
fn a_terminal_without_a_foreground_program_is_refused() {
    let members = [
        member(10, 1, 0, false, "live"),
        member(11, 10, pty(3), false, "bash"),
    ];
    assert_eq!(
        attribute(&members, &[(10, None)], None, &[EXECUTOR]),
        Err(73)
    );
}

/// Seen on the real guest (#433 e2e L1): `PAMName=login` leaves systemd's `(sd-pam)` helper, a tty-less
/// child of the login worker, inside the session scope. It belongs to the login itself, like the
/// worker, and is neither refused nor counted as a program of a terminal.
#[test]
fn the_logins_own_pam_helper_belongs_to_the_login() {
    let members = [
        member(2632, 1, 0, false, "infraternal"),
        pam_helper(2634, 2632),
        member(2636, 2525, 0, false, "infraternal"),
        member(2637, 2632, pty(0), true, "bash"),
        member(2661, 2637, pty(0), false, "sleep"),
    ];
    let found = attribute(&members, &[(2636, Some(0))], Some(2632), &[EXECUTOR]).unwrap();
    assert_eq!(members[found[0].foreground].program, "bash");
    assert_eq!(
        found[0].others, 1,
        "the background sleep, not the PAM helper"
    );
    let mut renamed = members.clone();
    renamed[1].ppid = 2637;
    renamed[1].tty = pty(0);
    assert_eq!(
        attribute(&renamed, &[(2636, Some(0))], Some(2632), &[EXECUTOR]).unwrap()[0].others,
        2,
        "a program on the terminal that calls itself (sd-pam) is still that terminal's"
    );
}

/// #433 P2-1 (J462): a name is not an identity. The login worker is a child subreaper, so a terminal's
/// detached program is reparented to it with no tty, exactly where the helper sits. Named `(sd-pam)`
/// (a binary file called that is enough) it would have been closed unlisted. Each spoof must refuse
/// the whole offer (73): another executable, born after the login's terminals, another account, or
/// a second helper.
#[test]
fn a_spoofed_pam_helper_refuses_the_offer() {
    let members = vec![
        member(3482, 1, 0, false, "infraternal"),
        pam_helper(3484, 3482),
        member(3486, 2525, 0, false, "infraternal"),
        member(3490, 3482, pty(0), true, "bash"),
    ];
    let offer =
        |members: &[Process]| attribute(members, &[(3486, Some(0))], Some(3482), &[EXECUTOR]);
    assert!(offer(&members).is_ok());
    let with = |spoof: Process| {
        let mut all = members.clone();
        all.push(spoof);
        offer(&all)
    };
    assert_eq!(
        with(member(3883, 3482, 0, false, "(sd-pam)")),
        Err(73),
        "a detached /tmp/(sd-pam) under the worker"
    );
    assert_eq!(
        with(pam_helper(3883, 3482)),
        Err(73),
        "the executor binary, started after the login's terminals"
    );
    let mut account = pam_helper(3485, 3482);
    account.uid = 1000;
    assert_eq!(with(account), Err(73), "another account than the login's");
    assert_eq!(with(pam_helper(3485, 3482)), Err(73), "a second helper");
    let mut real = members.clone();
    real[1].exe = (1, 3484);
    assert_eq!(
        offer(&real),
        Err(73),
        "the helper's executable is not the executor"
    );
    assert_eq!(
        attribute(&members, &[(3486, Some(0))], Some(3482), &[]),
        Err(73),
        "no known executor: nothing passes as the helper"
    );
}

/// #433 P2-1 (J379d): a real executor inode cannot identify the helper when its birth tick ties
/// another non-worker. Coarse kernel ticks do not prove which process started first.
#[test]
fn a_pam_helper_tied_for_earliest_tick_refuses_the_offer() {
    let mut members = vec![
        member(20, 1, 0, false, "infraternal"),
        pam_helper(21, 20),
        member(22, 2, 0, false, "infraternal"),
        member(23, 20, pty(0), true, "bash"),
    ];
    let offer = |members: &[Process]| attribute(members, &[(22, Some(0))], Some(20), &[EXECUTOR]);
    assert!(
        offer(&members).is_ok(),
        "a strictly earlier helper is accepted"
    );
    // Either a shim or a shell can share the helper's tick; neither tie proves precedence.
    for other in [2, 3] {
        let birth = members[other].birth;
        members[other].birth = members[1].birth;
        assert_eq!(offer(&members), Err(73), "tied member {other}");
        members[other].birth = birth;
    }
    members[0].birth = members[1].birth;
    assert!(offer(&members).is_ok(), "the worker is the sole exception");
}

/// Seen on the real guest (#433 e2e L1, second run): a host-login shim's parent is the old agent, and
/// Take over stops that agent before it compares the records again, so the shim is reparented to
/// pid 1. That must not read as "changed since you reviewed"; any other process changing still does.
#[test]
fn a_shim_reparented_by_the_agent_stop_keeps_its_fingerprint() {
    let members = vec![
        member(2637, 1, 0, false, "infraternal"),
        member(2695, 2529, 0, false, "infraternal"),
        member(2696, 2637, pty(0), true, "bash"),
        member(2720, 2696, pty(0), false, "sleep"),
    ];
    let digest = |members: &[Process]| {
        members_digest(
            std::path::Path::new("/sys/fs/cgroup/s"),
            7,
            members,
            &[2695],
            Some(2637),
        )
        .as_ref()
        .to_vec()
    };
    let before = digest(&members);
    let mut reparented = members.clone();
    reparented[1].ppid = 1;
    assert_eq!(digest(&reparented), before);
    let mut moved = members.clone();
    moved[3].ppid = 1;
    assert_ne!(
        digest(&moved),
        before,
        "a terminal's program changing parent is a change"
    );
    let mut swapped = members.clone();
    swapped[3].exe = (1, 4242);
    assert_ne!(
        digest(&swapped),
        before,
        "#433 P3-3: the same pid and name running another binary is a change"
    );
    let mut started = members;
    started.push(member(2800, 2696, pty(0), false, "vim"));
    assert_ne!(digest(&started), before);
}
