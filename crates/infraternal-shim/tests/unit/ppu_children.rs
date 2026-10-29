//! Child status is reconciled on exit readiness, never on every output turn [D81/D270].
use super::*;

#[test]
fn ordinary_housekeeping_does_not_probe_child_status() {
    let state = crate::fixture_state::fixture_state();
    let mut config = Config::new([11; 16], Uid::effective().as_raw());
    config.state = Some(state.clone());
    config.readiness = true;
    let mut session = Session::new(config, 65536).unwrap();
    session.pty.child.kill().unwrap();
    let path = format!("/proc/{}/stat", session.pty.child.id());
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let stat = std::fs::read_to_string(&path).unwrap();
        if stat
            .rsplit(')')
            .next()
            .unwrap()
            .trim_start()
            .starts_with('Z')
        {
            break;
        }
        assert!(Instant::now() < deadline, "owned child did not exit");
        std::thread::yield_now();
    }
    session.housekeeping().unwrap();
    assert!(
        session.exit.is_none(),
        "ordinary output housekeeping reaped a child"
    );
    session.observe_exit().unwrap();
    assert!(session.exit.is_some());
    assert!(session.deadline.is_some());
    drop(session);
    std::fs::remove_dir_all(state).unwrap();
}

#[test]
fn threaded_startup_is_refused_before_creating_session_state() {
    let state = crate::fixture_state::fixture_state();
    assert!(!state.exists());
    let (ready, started) = std::sync::mpsc::channel();
    let (quit, stop) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        ready.send(()).unwrap();
        stop.recv().unwrap();
    });
    started.recv().unwrap();
    let mut config = Config::new([14; 16], Uid::effective().as_raw());
    config.state = Some(state.clone());
    config.readiness = true;
    let result = run_host(vec![config]);
    quit.send(()).unwrap();
    thread.join().unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
    assert!(!state.exists());
}
