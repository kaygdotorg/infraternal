//! A viewer that attaches at a different size than the output was written at
//! must still see the shim's screen (#521, D13).
//!
//! Raw PTY bytes only make sense at the width they were produced for. A shell
//! wraps a long line by printing past the margin and then returning with `\r`,
//! so the same bytes parsed at another width put the wrapped tail over the
//! start of the line. Each case below builds the screen a browser would show
//! from exactly what the shim sends it, and compares it with the shim's own
//! engine, which reflows correctly on resize.
//!
//! A live shell's engine never leaves the state libghostty-vt's C API starts
//! in (prompt redraw off), which the exact serializer refuses, so a real
//! session's repaint is the flagged approximate one: visible cells and cursor
//! are right, soft-wrap flags are not carried (D110). Those cases compare what
//! the viewer sees; raw-replay controls and the exact-export case compare the
//! full state, wrap flags included.
//!
//! Known gap, kept on purpose: a tab that reopens at the session's current
//! size still gets the raw replay, even when the ring begins with bytes from
//! before an earlier resize. Every session is spawned at 80x24 and resized by
//! its first viewer, so repainting there would make every reload approximate.
//! It becomes cheap once shell snapshots can be exact (owner question, #521).
//!
//! D74 as amended (owner, 2026-11-16): the tab that typed last keeps the
//! size only while it is attached. Once it has left, the next tab that
//! reports a size takes it, so a reopen narrower, shorter or taller than the
//! session ends on its own size with the repaint. While the typist is still
//! attached, a new tab's size is only staged: a smaller one keeps the raw
//! replay until it types, as D74 leaves smaller viewers to scaling (#521).
use super::*;

/// The prompt J745 saw, 36 columns wide; with `echo j` it fills 42 columns.
const PROMPT: &[u8] = b"qa-device@infraternal-dev-02-std:~$ ";

/// What bash's line editor writes for `echo j745-echo-ok` at 42 columns: at the
/// margin it prints a space to force the wrap, then `\r` to the new row's start.
fn typed_at_42() -> Vec<u8> {
    [PROMPT, b"echo j \r745-echo-ok\r\nj745-echo-ok\r\n", PROMPT].concat()
}

/// Kills the shell the PTY spawned when a case ends, even on failure.
struct ChildGuard(Pty);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.child.kill();
        let _ = self.0.child.wait();
    }
}

/// One shim session at a starting size: its PTY, engine, output ring and the
/// session-wide geometry and input state that `handle` updates.
struct Session {
    child: ChildGuard,
    terminal: Terminal,
    ring: Ring,
    config: Config,
    input: VecDeque<u8>,
    cursors: Inputs,
}
impl Session {
    /// A session that a viewer has already sized to `cols` x `rows`, as one is
    /// by the time anyone can reopen it: its first viewer reported that size.
    fn new(cols: u16, rows: u16) -> Self {
        let mut session = Self::spawned(cols, rows);
        let mut first = peer();
        session.resize(&mut first, cols, rows);
        session
    }
    /// A session just spawned at `cols` x `rows`, before any viewer's size.
    fn spawned(cols: u16, rows: u16) -> Self {
        let uid = Uid::effective().as_raw();
        let mut config = Config::new([0; 16], uid);
        config.cols = cols;
        config.rows = rows;
        Self {
            child: ChildGuard(Pty::spawn(uid, cols, rows).unwrap()),
            terminal: Terminal::new(cols, rows).unwrap(),
            ring: Ring::new(64 * 1024),
            config,
            input: VecDeque::new(),
            cursors: Inputs::with_geometry((cols, rows, 0, 0)),
        }
    }
    /// Output the program wrote: the engine parses it and the ring keeps it.
    fn output(&mut self, bytes: &[u8]) {
        self.terminal.process(bytes);
        self.ring.append(bytes).unwrap();
    }
    /// Peers left the session and `staying` are the ones still connected:
    /// runs the shim's own check that gives up the size of a typist who is
    /// gone (D74 as amended, #521), as its event loops do after a removal.
    fn leave(&mut self, staying: &[&Peer]) {
        release_size_of_departed_typist(staying.iter().copied(), &mut self.cursors);
    }
    /// Runs one frame from `peer` through the shim's real frame handler.
    fn handle(&mut self, peer: &mut Peer, frame: Frame) {
        handle(
            frame,
            peer,
            &mut self.child.0,
            &mut self.terminal,
            &self.ring,
            &mut self.config,
            &mut self.input,
            &mut self.cursors,
            false,
            false,
        )
        .unwrap();
    }
    /// Sends the viewer's `Resize` to `cols` x `rows` from `peer`.
    fn resize(&mut self, peer: &mut Peer, cols: u16, rows: u16) {
        self.handle(
            peer,
            Frame::Resize {
                cols,
                rows,
                px_w: 0,
                px_h: 0,
            },
        );
    }
    /// Sends `peer` everything the shim's loop would send it now, and applies
    /// it to the browser's `viewer` the way the client does: raw output is
    /// written as is, a Snapshot replaces the screen. Returns the repaint the
    /// viewer got, if any.
    fn deliver(&self, peer: &mut Peer, viewer: &mut Terminal) -> Option<Repaint> {
        let mut repaint = None;
        match peer.request.take() {
            Some(Request::Read(seq)) => peer.cursor = Some(seq),
            Some(Request::Snapshot) => {
                peer.snapshot(&self.terminal, self.ring.head()).unwrap();
                repaint = Some(self.repaint(peer, viewer));
            }
            Some(Request::SnapshotFirst(seq)) => {
                peer.snapshot_first(&self.terminal, self.ring.head(), seq)
                    .unwrap();
                // Without a repaint it falls back to the raw replay below.
                if !peer.pending.is_empty() {
                    repaint = Some(self.repaint(peer, viewer));
                }
            }
            None => {}
        }
        while let Some(seq) = peer.cursor.filter(|seq| *seq < self.ring.head()) {
            let bytes = self.ring.read(seq, CHUNK).unwrap();
            peer.cursor = Some(seq + bytes.len() as u64);
            viewer.process(&bytes);
        }
        repaint
    }
    /// Takes the one Snapshot queued for `peer` and paints it on a fresh
    /// `viewer` at the session's size, as the client replaces its screen.
    fn repaint(&self, peer: &mut Peer, viewer: &mut Terminal) -> Repaint {
        let frames = Decoder::default().feed(&peer.pending).unwrap();
        peer.pending.clear();
        let (repaint, bytes) = match frames.as_slice() {
            [Frame::Snapshot(_, bytes)] => (Repaint::Exact, bytes),
            [Frame::SnapshotWithFlags(_, 1, bytes)] => (Repaint::Approximate, bytes),
            other => panic!("expected one Snapshot, got {other:?}"),
        };
        let (cols, rows) = (self.config.cols, self.config.rows);
        *viewer = Terminal::new(cols, rows).unwrap();
        viewer.process(bytes);
        repaint
    }
}

/// Which kind of Snapshot replaced the viewer's screen.
#[derive(Debug, PartialEq)]
enum Repaint {
    /// Full state, soft-wrap flags included.
    Exact,
    /// Visible cells and cursor only, flagged so the client says so (D110).
    Approximate,
}

/// Asserts the viewer shows what the shim's engine holds: every visible cell,
/// its style and the cursor. Painting both screens cell by cell makes two
/// byte strings that are equal exactly when the visible screens are.
fn assert_same_visible_screen(viewer: &Terminal, shim: &Terminal) {
    assert_eq!(
        String::from_utf8_lossy(&viewer.approximate_snapshot()),
        String::from_utf8_lossy(&shim.approximate_snapshot()),
        "the viewer must show the shim's screen"
    );
}

/// A browser link as the agent opens it: the writer, no cursor yet.
fn peer() -> Peer {
    let (stream, _remote) = UnixStream::pair().unwrap();
    Peer {
        stream,
        decoder: Decoder::default(),
        trailing: Vec::new(),
        deferred: None,
        attached: true,
        caps: APPROXIMATE_SNAPSHOT,
        input_reply: None,
        writer: Some(0),
        shared_writer: false,
        ack_queued: 0,
        size: (0, 0, 0, 0),
        cursor: None,
        pending: Vec::new(),
        written: 0,
        exited_sent: false,
        stopping: false,
        request: None,
        replay_awaits_size: false,
        echo_hidden_told: false,
    }
}

/// A new tab at `cols` attaches to a session whose output (after `start`) was
/// written at 42 columns. The agent sends `ReadFrom` first and the browser's
/// `Resize` after it; the shim may already have streamed the replay by then.
fn reopen_at(cols: u16, start: &[u8]) -> (Session, Terminal, Option<Repaint>) {
    let mut session = Session::new(42, 24);
    session.output(&[start, typed_at_42().as_slice()].concat());
    let mut tab = peer();
    let mut viewer = Terminal::new(cols, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, cols, 24);
    let repaint = session.deliver(&mut tab, &mut viewer);
    (session, viewer, repaint)
}

/// J745's case: a tab reopened wider than the 42 columns its output was
/// written at shows the shim's reflowed screen, flagged approximate.
#[test]
fn reopening_wider_shows_the_shim_screen_not_the_old_width_bytes() {
    let (session, viewer, repaint) = reopen_at(45, b"");
    // Without the repaint, row 0 reads "745-echo-oknfraternal-dev-02-std:~$ echo j"
    // here, exactly as in J745's screenshot.
    assert_same_visible_screen(&viewer, &session.terminal);
    assert_eq!(repaint, Some(Repaint::Approximate));
}

/// A tab reopened narrower than the session, whose size applies, shows
/// the shim's reflowed screen.
#[test]
fn reopening_narrower_shows_the_shim_screen() {
    let (session, viewer, repaint) = reopen_at(38, b"");
    assert_same_visible_screen(&viewer, &session.terminal);
    assert_eq!(repaint, Some(Repaint::Approximate));
}

/// After RIS the engine can export itself exactly, so the reopened viewer
/// gets the full state, including the reflowed row's soft-wrap flag.
#[test]
fn reopening_wider_after_a_reset_restores_the_exact_state() {
    let (session, viewer, repaint) = reopen_at(45, b"\x1bc");
    assert_eq!(repaint, Some(Repaint::Exact));
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}

/// The common reconnect: nothing changed size, so the cheaper raw replay
/// stays exact and no repaint is added to the resume path.
#[test]
fn reopening_at_the_same_size_keeps_the_raw_replay() {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    let mut tab = peer();
    let mut viewer = Terminal::new(42, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert!(matches!(tab.request, Some(Request::Read(0))));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, 42, 24);
    assert!(tab.request.is_none(), "an unchanged size needs no repaint");
    session.deliver(&mut tab, &mut viewer);
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}

/// No reconnect: the viewer received every byte at 42 columns, then both
/// sides reflow the same engine state, so the screens still match.
#[test]
fn a_live_resize_reflows_without_a_repaint() {
    let mut session = Session::new(42, 24);
    let mut tab = peer();
    let mut viewer = Terminal::new(42, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.output(&typed_at_42());
    session.deliver(&mut tab, &mut viewer);
    viewer.resize(45, 24).unwrap();
    session.resize(&mut tab, 45, 24);
    assert!(
        tab.request.is_none(),
        "a live resize keeps streaming raw output"
    );
    session.deliver(&mut tab, &mut viewer);
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}

/// The session was resized while a tab was open (42 then 45 columns), and
/// a new tab opens at a third size. Its Resize repaints the reflowed engine.
#[test]
fn reopening_at_a_new_size_after_an_earlier_resize_shows_the_shim_screen() {
    let mut session = Session::new(42, 24);
    let mut live = peer();
    let mut live_view = Terminal::new(42, 24).unwrap();
    session.handle(&mut live, Frame::ReadFrom(0));
    session.output(&typed_at_42());
    session.deliver(&mut live, &mut live_view);
    session.resize(&mut live, 45, 24);
    session.output(&[b"echo second\r\nsecond\r\n".as_slice(), PROMPT].concat());
    drop(live);

    let mut tab = peer();
    let mut viewer = Terminal::new(50, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, 50, 24);
    assert!(session.deliver(&mut tab, &mut viewer).is_some());
    assert_same_visible_screen(&viewer, &session.terminal);
}

/// J745's shape, with the tab that typed last still attached: its writer
/// keeps the geometry (D74) and the new tab's Resize is only staged until it
/// types. The
/// session stays at 42 columns while the new tab is 45 wide, so the raw
/// replay must still be replaced, by the engine painted at its own size.
#[test]
fn reopening_wider_while_another_writer_owns_the_size_still_repaints() {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    session.cursors.active_writer = Some(0);
    session.cursors.select(1, (45, 24, 0, 0)).unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(45, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, 45, 24);
    assert_eq!(
        (session.config.cols, session.config.rows),
        (42, 24),
        "staged, not applied"
    );
    assert!(matches!(tab.request.take(), Some(Request::Snapshot)));
    tab.snapshot(&session.terminal, session.ring.head())
        .unwrap();
    let frames = Decoder::default().feed(&tab.pending).unwrap();
    let [Frame::Snapshot(_, bytes) | Frame::SnapshotWithFlags(_, 1, bytes)] = frames.as_slice()
    else {
        panic!("expected one Snapshot, got {frames:?}");
    };
    let mut repainted = Terminal::new(45, 24).unwrap();
    repainted.process(bytes);
    assert_same_visible_screen(&repainted, &session.terminal);
}

/// A session is spawned at the 80x24 placeholder and prints its first
/// prompt before its opener reports a size. Nobody saw that width, so the
/// opener keeps the cheap raw replay (and its shell redraws on SIGWINCH);
/// a repaint here would be approximate on every new terminal.
#[test]
fn opening_a_new_session_keeps_the_raw_replay() {
    let mut session = Session::spawned(80, 24);
    session.output(PROMPT);
    let mut tab = peer();
    let mut viewer = Terminal::new(44, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, 44, 24);
    assert!(
        tab.request.is_none(),
        "the opener's first size needs no repaint"
    );
}

/// The tab that typed last is still attached, so it keeps the session's 45
/// columns (D74, unchanged for attached devices) and the new 42-column tab's
/// Resize is only staged. The engine's repaint is laid out for 45 columns
/// with absolute positions, which pile up in the last column of a narrower
/// viewer. D74 leaves this to client-side scaling, which does not exist
/// yet, so the replay stays as on dev (#521).
#[test]
fn reopening_narrower_while_the_typist_is_still_attached_keeps_the_raw_replay() {
    let mut session = Session::new(45, 24);
    session.output(&typed_at_42());
    let typist = peer();
    // Another tab closing must not take the size from the attached typist.
    session.leave(&[&typist]);
    assert_eq!(session.cursors.active_writer, Some(0));
    session.cursors.select(1, (42, 24, 0, 0)).unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(42, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, 42, 24);
    assert_eq!((session.config.cols, session.config.rows), (45, 24));
    assert!(
        tab.request.is_none(),
        "a smaller staged viewer keeps the replay"
    );
}

/// A peer that types after attaching is past its attach: its later Resize
/// is a live resize (it reflows locally), not the attach-time size report,
/// so it gets no repaint even though its replay was written at another
/// size. Found by `real_shell_reconnect_resize_and_delivered_exit` (#521).
#[test]
fn a_peer_that_typed_before_resizing_gets_no_repaint() {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    let mut tab = peer();
    let mut viewer = Terminal::new(42, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.handle(&mut tab, Frame::Input(b"x".to_vec()));
    session.resize(&mut tab, 45, 24);
    assert!(
        tab.request.is_none(),
        "a live resize keeps streaming raw output"
    );
}

/// The attach-time size check runs once. A tab whose Resize at attach
/// matched the session's size (raw replay kept) is a live viewer from then
/// on: when it is resized later, it reflows its own screen, and a repaint
/// would only make that live resize lossy (#521).
#[test]
fn a_live_resize_after_a_same_size_reopen_gets_no_repaint() {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    let mut tab = peer();
    let mut viewer = Terminal::new(42, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, 42, 24);
    assert!(tab.request.is_none(), "an unchanged size needs no repaint");
    viewer.resize(45, 24).unwrap();
    session.resize(&mut tab, 45, 24);
    assert!(
        tab.request.is_none(),
        "a later live resize keeps streaming raw output"
    );
    session.deliver(&mut tab, &mut viewer);
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}

/// The tab that typed last is still attached and keeps 42x24 (D74), and the
/// new tab is wider but shorter (60x20, a phone turned to landscape). The
/// repaint keeps the session's 24 rows with absolute positions, so its
/// bottom rows, where the prompt and cursor usually are, would pile up on
/// the viewer's last row. Until D74's scaling exists, this viewer keeps the
/// raw replay, as a narrower one does. Once the typist has left, the same
/// reopen takes the size instead
/// (`reopening_wider_but_shorter_after_the_typist_left_takes_the_size_and_repaints`, #521).
#[test]
fn reopening_wider_but_shorter_while_the_typist_is_still_attached_keeps_the_raw_replay() {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    // The typist's tab reconnected: its new link is attached when the old
    // one is dropped, so the writer never left.
    let replacement = peer();
    session.leave(&[&replacement]);
    assert_eq!(session.cursors.active_writer, Some(0));
    session.cursors.select(1, (60, 20, 0, 0)).unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(60, 20).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, 60, 20);
    assert_eq!((session.config.cols, session.config.rows), (42, 24));
    assert!(
        tab.request.is_none(),
        "a staged viewer with fewer rows keeps the replay"
    );
}

/// A session sized and typed in at 42x24 by its writer 0, whose every tab
/// has now closed. Returns it with the typist's writer already gone.
fn session_whose_typist_left() -> Session {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    assert_eq!(
        session.cursors.active_writer,
        Some(0),
        "the first viewer's size made it the owner"
    );
    session.leave(&[]);
    session
}

/// A new tab (writer 1) reopens at `cols` x `rows` after the tab that typed
/// last at 42x24 closed. The agent sends `ReadFrom` first and the browser's
/// `Resize` after it, so the raw replay at 42x24 has already gone out.
fn reopen_after_the_typist_left(cols: u16, rows: u16) -> (Session, Terminal, Option<Repaint>) {
    let mut session = session_whose_typist_left();
    // A newly selected writer starts from the session's applied size; its
    // first Resize stages the tab's actual geometry before applying it.
    session
        .cursors
        .select(1, (session.config.cols, session.config.rows, 0, 0))
        .unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(cols, rows).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert_eq!(session.deliver(&mut tab, &mut viewer), None);
    session.resize(&mut tab, cols, rows);
    let repaint = session.deliver(&mut tab, &mut viewer);
    (session, viewer, repaint)
}

/// Asserts a reopen after the typist left took the size: the session is at
/// the tab's `cols` x `rows`, the tab owns it, and the tab shows the shim's
/// screen through the approximate repaint (D74 as amended, #521).
fn assert_took_the_size(cols: u16, rows: u16) {
    let (session, viewer, repaint) = reopen_after_the_typist_left(cols, rows);
    assert_eq!(
        (session.config.cols, session.config.rows),
        (cols, rows),
        "the reopened tab takes the size"
    );
    assert_eq!(session.cursors.active_writer, Some(1));
    let applied = session.cursors.get(Some(1)).unwrap();
    assert_eq!(applied.requested_size, (cols, rows, 0, 0));
    assert_eq!(applied.accepted_size, (cols, rows, 0, 0));
    assert_eq!(repaint, Some(Repaint::Approximate));
    assert_same_visible_screen(&viewer, &session.terminal);
}

/// The tab that typed last closed, then a narrower tab reopens: it takes
/// the size and gets the shim's reflowed screen, not the 42-column bytes.
#[test]
fn reopening_narrower_after_the_typist_left_takes_the_size_and_repaints() {
    assert_took_the_size(38, 24);
}

/// Same as narrower, for a tab with fewer rows than the session.
#[test]
fn reopening_shorter_after_the_typist_left_takes_the_size_and_repaints() {
    assert_took_the_size(42, 20);
}

/// J795's case: a phone tab turned to landscape (42x24 → 60x20). With the
/// typist gone, its size applies, so the repaint fits it in both dimensions.
#[test]
fn reopening_wider_but_shorter_after_the_typist_left_takes_the_size_and_repaints() {
    assert_took_the_size(60, 20);
}

/// J811's case: a taller reopen got a 24-row repaint and showed only the
/// top of its 30 rows until its first key. Now it takes the size at once.
#[test]
fn reopening_taller_after_the_typist_left_takes_the_size_and_repaints() {
    assert_took_the_size(42, 30);
}

/// A reopen at the size the departed typist left stays on the fast path:
/// it takes the (unchanged) size, keeps the exact raw replay and gets no
/// repaint, exactly like a reconnect while the typist is attached.
#[test]
fn reopening_at_the_same_size_after_the_typist_left_keeps_the_raw_replay() {
    let mut session = session_whose_typist_left();
    session.cursors.select(1, (42, 24, 0, 0)).unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(42, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    assert!(matches!(tab.request, Some(Request::Read(0))));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, 42, 24);
    assert!(tab.request.is_none(), "an unchanged size needs no repaint");
    assert_eq!(session.cursors.active_writer, Some(1));
    session.deliver(&mut tab, &mut viewer);
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}

/// A departed typist may reconnect after a new writer has taken the size, but
/// its stale resize stays staged while that newer writer remains attached.
#[test]
fn a_departed_typist_reconnecting_does_not_reclaim_an_attached_writers_size() {
    let mut session = session_whose_typist_left();
    session
        .cursors
        .select(1, (session.config.cols, session.config.rows, 0, 0))
        .unwrap();
    let mut current = peer();
    current.writer = Some(1);
    let mut current_view = Terminal::new(50, 30).unwrap();
    session.handle(&mut current, Frame::ReadFrom(0));
    session.deliver(&mut current, &mut current_view);
    session.resize(&mut current, 50, 30);
    assert_eq!(
        session.deliver(&mut current, &mut current_view),
        Some(Repaint::Approximate)
    );
    assert_eq!((session.config.cols, session.config.rows), (50, 30));
    assert_eq!(session.cursors.active_writer, Some(1));

    let mut returned = peer();
    let mut returned_view = Terminal::new(42, 24).unwrap();
    session.handle(&mut returned, Frame::ReadFrom(0));
    session.deliver(&mut returned, &mut returned_view);
    session.resize(&mut returned, 42, 24);

    assert_eq!((session.config.cols, session.config.rows), (50, 30));
    assert_eq!(session.cursors.active_writer, Some(1));
    assert_eq!(
        session.deliver(&mut returned, &mut returned_view),
        None,
        "the smaller reconnect stays on raw replay while its resize is staged"
    );
    let applied = session.cursors.get(Some(1)).unwrap();
    assert_eq!(applied.requested_size, (50, 30, 0, 0));
    assert_eq!(applied.accepted_size, (50, 30, 0, 0));
}

/// Only an attached link keeps the typist's size. A link of the same writer
/// that has connected but not attached yet is not a device on the session.
#[test]
fn a_link_that_has_not_attached_does_not_keep_the_size() {
    let mut session = Session::new(42, 24);
    let mut connecting = peer();
    connecting.attached = false;
    session.leave(&[&connecting]);
    assert_eq!(session.cursors.active_writer, None);
}

/// Two tabs reopen at once after the typist left, the narrower one's Resize
/// first. It takes the size (D74: the next device that reports a size); the
/// wider one's size is staged, and the repaint at the session's size fits
/// it. Both end on the shim's screen.
#[test]
fn two_tabs_reopening_after_the_typist_left_both_show_the_shim_screen_when_the_smaller_reports_first()
 {
    let mut session = session_whose_typist_left();
    let applied_before = (session.config.cols, session.config.rows, 0, 0);
    session.cursors.select(1, applied_before).unwrap();
    session.cursors.select(2, applied_before).unwrap();
    let (mut small, mut large) = (peer(), peer());
    small.writer = Some(1);
    large.writer = Some(2);
    let mut small_view = Terminal::new(38, 24).unwrap();
    let mut large_view = Terminal::new(50, 24).unwrap();
    session.handle(&mut small, Frame::ReadFrom(0));
    session.handle(&mut large, Frame::ReadFrom(0));
    session.deliver(&mut small, &mut small_view);
    session.deliver(&mut large, &mut large_view);
    session.resize(&mut small, 38, 24);
    session.resize(&mut large, 50, 24);
    assert_eq!((session.config.cols, session.config.rows), (38, 24));
    assert_eq!(session.cursors.active_writer, Some(1));
    assert_eq!(
        session.cursors.get(Some(1)).unwrap().accepted_size,
        (38, 24, 0, 0)
    );
    let staged_large = session.cursors.get(Some(2)).unwrap();
    assert_eq!(staged_large.requested_size, (50, 24, 0, 0));
    assert_eq!(staged_large.accepted_size, applied_before);
    assert_eq!(
        session.deliver(&mut small, &mut small_view),
        Some(Repaint::Approximate)
    );
    assert_same_visible_screen(&small_view, &session.terminal);
    assert!(session.deliver(&mut large, &mut large_view).is_some());
    assert_same_visible_screen(&large_view, &session.terminal);
}

/// The same two tabs, the wider one's Resize first. It takes the size and
/// is repainted. The narrower one then reports a size while the wider tab
/// holds it and is attached, which is plain D74 for attached devices: its
/// size is staged, a 50-column repaint would pile up in its last column,
/// so it keeps the raw replay until it types. Pinned so a change here is a
/// deliberate one (#521).
#[test]
fn two_tabs_reopening_after_the_typist_left_the_larger_reporting_first_takes_the_size() {
    let mut session = session_whose_typist_left();
    let applied_before = (session.config.cols, session.config.rows, 0, 0);
    session.cursors.select(1, applied_before).unwrap();
    session.cursors.select(2, applied_before).unwrap();
    let (mut small, mut large) = (peer(), peer());
    small.writer = Some(1);
    large.writer = Some(2);
    let mut small_view = Terminal::new(38, 24).unwrap();
    let mut large_view = Terminal::new(50, 24).unwrap();
    session.handle(&mut large, Frame::ReadFrom(0));
    session.handle(&mut small, Frame::ReadFrom(0));
    session.deliver(&mut large, &mut large_view);
    session.deliver(&mut small, &mut small_view);
    session.resize(&mut large, 50, 24);
    session.resize(&mut small, 38, 24);
    assert_eq!((session.config.cols, session.config.rows), (50, 24));
    assert_eq!(session.cursors.active_writer, Some(2));
    assert_eq!(
        session.cursors.get(Some(2)).unwrap().accepted_size,
        (50, 24, 0, 0)
    );
    let staged_small = session.cursors.get(Some(1)).unwrap();
    assert_eq!(staged_small.requested_size, (38, 24, 0, 0));
    assert_eq!(staged_small.accepted_size, applied_before);
    assert_eq!(
        session.deliver(&mut large, &mut large_view),
        Some(Repaint::Approximate)
    );
    assert_same_visible_screen(&large_view, &session.terminal);
    assert!(
        small.request.is_none(),
        "a smaller staged viewer keeps the replay"
    );
}

/// A command long enough to wrap after [`PROMPT`] at every width the sweep
/// writes at (the whole line is 100 columns), and whose output wraps too in
/// the narrowest viewers.
const LONG_COMMAND: &[u8] = b"echo j792-the-quick-brown-fox-jumps-over-the-lazy-dog-0123456789";

/// What bash's line editor writes for `line` echoed from column 0 of a
/// `cols`-wide terminal. Each time the cursor reaches the right margin with
/// more to come, it prints a space to force the wrap and `\r` to the new
/// row's start, then overwrites that space with the next character. Those
/// two bytes are what make the replay wrong at any other width: elsewhere
/// the space does not wrap, and `\r` returns to the start of the same row.
fn echoed_at(cols: u16, line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len() * 2);
    for (index, byte) in line.iter().enumerate() {
        out.push(*byte);
        let written = index + 1;
        if written % usize::from(cols) == 0 && written < line.len() {
            out.extend_from_slice(b" \r");
        }
    }
    out
}

/// The session's whole output when a long command was typed at `cols`: the
/// wrapped prompt and command, the command's output and the next prompt.
fn long_command_at(cols: u16) -> Vec<u8> {
    let echoed = echoed_at(cols, &[PROMPT, LONG_COMMAND].concat());
    let printed = &LONG_COMMAND[b"echo ".len()..];
    [echoed.as_slice(), b"\r\n", printed, b"\r\n", PROMPT].concat()
}

/// Widths the sweep writes at: the prompt itself wraps at 30, J745's 42
/// wraps only the command, and 80 is a desktop terminal.
const WRITTEN_AT: [u16; 3] = [30, 42, 80];

/// The reopen widths for output written at `cols`: narrower (20 wraps even
/// the prompt, `cols - 5` is a small shrink) and wider (`cols + 3` is
/// J745's small growth, `cols * 2` a phone tab reopened on a desktop).
fn reopened_at(cols: u16) -> [u16; 4] {
    [20, cols - 5, cols + 3, cols * 2]
}

/// Reopens a session whose long command was written at `written` columns in
/// a new tab `reopened` columns wide, the size applying because no other
/// writer owns the geometry. Returns a description of the mismatch if the
/// viewer does not end on the shim's screen, or if no repaint replaced the
/// replay.
fn applied_reopen_mismatch(written: u16, reopened: u16) -> Option<String> {
    let mut session = Session::new(written, 24);
    session.output(&long_command_at(written));
    let mut tab = peer();
    let mut viewer = Terminal::new(reopened, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, reopened, 24);
    let repaint = session.deliver(&mut tab, &mut viewer);
    screen_mismatch(&viewer, &session.terminal, repaint.is_some())
        .map(|why| format!("{written} -> {reopened} cols: {why}"))
}

/// Reopens a session whose long command was written at `written` columns in
/// a new, wider tab while the tab that typed last is still attached and
/// keeps the size (D74), so
/// the new tab's Resize is only staged. The repaint keeps the session's size;
/// the browser paints it into its own, wider grid.
fn staged_wider_reopen_mismatch(written: u16, reopened: u16) -> Option<String> {
    let mut session = Session::new(written, 24);
    session.output(&long_command_at(written));
    session.cursors.active_writer = Some(0);
    session.cursors.select(1, (reopened, 24, 0, 0)).unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(reopened, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, reopened, 24);
    let repainted = matches!(tab.request.take(), Some(Request::Snapshot));
    if repainted {
        tab.snapshot(&session.terminal, session.ring.head())
            .unwrap();
        let frames = Decoder::default().feed(&tab.pending).unwrap();
        let [Frame::Snapshot(_, bytes) | Frame::SnapshotWithFlags(_, 1, bytes)] = frames.as_slice()
        else {
            panic!("expected one Snapshot, got {frames:?}");
        };
        viewer = Terminal::new(reopened, 24).unwrap();
        viewer.process(bytes);
    }
    screen_mismatch(&viewer, &session.terminal, repainted)
        .map(|why| format!("{written} -> {reopened} cols (staged): {why}"))
}

/// Reopens a session whose long command was written at `written` x 24 in a
/// new tab (writer 1) of `cols` x `rows`, after the tab that typed it left.
/// The new tab's size applies (D74 as amended, #521). Returns a description
/// of the mismatch if the viewer does not end on the shim's screen at the
/// new size, or if no repaint replaced the replay.
fn departed_typist_reopen_mismatch(written: u16, cols: u16, rows: u16) -> Option<String> {
    let mut session = Session::new(written, 24);
    session.output(&long_command_at(written));
    session.leave(&[]);
    session.cursors.select(1, (cols, rows, 0, 0)).unwrap();
    let mut tab = peer();
    tab.writer = Some(1);
    let mut viewer = Terminal::new(cols, rows).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, cols, rows);
    let label = format!("{written}x24 -> {cols}x{rows} (typist left)");
    if (session.config.cols, session.config.rows) != (cols, rows) {
        return Some(format!(
            "{label}: session stayed at {}x{}",
            session.config.cols, session.config.rows
        ));
    }
    let repaint = session.deliver(&mut tab, &mut viewer);
    screen_mismatch(&viewer, &session.terminal, repaint.is_some())
        .map(|why| format!("{label}: {why}"))
}

/// Why `viewer` is not showing `shim`'s screen, or `None` when it is and a
/// repaint replaced the replay. Compares the two screens painted cell by
/// cell, as [`assert_same_visible_screen`] does, without panicking, so a
/// sweep can report every failing width at once.
fn screen_mismatch(viewer: &Terminal, shim: &Terminal, repainted: bool) -> Option<String> {
    let seen = String::from_utf8_lossy(&viewer.approximate_snapshot()).into_owned();
    let held = String::from_utf8_lossy(&shim.approximate_snapshot()).into_owned();
    if seen != held {
        return Some(format!("viewer shows {seen:?}, shim holds {held:?}"));
    }
    (!repainted).then(|| "screen matched by chance, but no repaint was sent".to_owned())
}

/// Sweep of #521 over widths: a wrapped prompt and command written at 30, 42
/// and 80 columns, reopened narrower and wider in a tab whose size applies.
/// Every reopen must end on the shim's reflowed screen. Each case is listed
/// when it fails, so a regression at one width cannot hide behind another.
#[test]
fn reopening_at_any_other_width_shows_the_shim_screen() {
    let failures: Vec<String> = WRITTEN_AT
        .iter()
        .flat_map(|&written| reopened_at(written).map(|reopened| (written, reopened)))
        .filter_map(|(written, reopened)| applied_reopen_mismatch(written, reopened))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The same sweep while the tab that typed last is still attached and keeps
/// the size (D74), so the new, wider tab's size is only staged. Narrower staged reopens
/// keep the raw replay until D74's scaling exists (see
/// `reopening_narrower_while_the_typist_is_still_attached_keeps_the_raw_replay`).
#[test]
fn reopening_wider_at_any_width_while_another_writer_owns_the_size_repaints() {
    let failures: Vec<String> = WRITTEN_AT
        .iter()
        .flat_map(|&written| reopened_at(written).map(|reopened| (written, reopened)))
        .filter(|(written, reopened)| reopened > written)
        .filter_map(|(written, reopened)| staged_wider_reopen_mismatch(written, reopened))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The input modes a program left on when a tab reopened at another width:
/// bracketed paste, cursor keys, keypad, focus events, SGR button mouse,
/// modifyOtherKeys and a bar cursor, written after a short prompt that fits
/// every width tried here, so no row soft-wraps and the whole oracle applies.
const MODES: &[u8] = b"\x1b[?2004h\x1b[?1h\x1b=\x1b[?1004h\x1b[?1002h\x1b[?1006h\x1b[>4;2m\x1b[6 q";

/// #521's reopen repaint must keep #524's input modes for a shell and a
/// full-screen program. Both the initial geometry owner and a new writer
/// after that owner disconnected take the narrower, wider, shorter or taller
/// size. The non-strict oracle checks modes, key flags, charsets and cells.
#[test]
fn reopening_at_another_width_keeps_the_programs_input_modes() {
    let mut failures = Vec::new();
    for (name, screen) in [
        ("shell", [PROMPT, MODES].concat()),
        (
            "full-screen program",
            [PROMPT, b"\x1b[?1049h\x1b[>1u", MODES, b"\x1b[Hvim"].concat(),
        ),
    ] {
        for (cols, rows, departed) in [
            (38, 24, false),
            (45, 24, false),
            (38, 24, true),
            (45, 24, true),
            (42, 20, true),
            (42, 30, true),
        ] {
            let mut session = Session::new(42, 24);
            session.output(&screen);
            let mut tab = peer();
            if departed {
                session.leave(&[]);
                session.cursors.select(1, (42, 24, 0, 0)).unwrap();
                tab.writer = Some(1);
            }
            let mut viewer = Terminal::new(cols, rows).unwrap();
            session.handle(&mut tab, Frame::ReadFrom(0));
            assert_eq!(session.deliver(&mut tab, &mut viewer), None);
            session.resize(&mut tab, cols, rows);
            let repaint = session.deliver(&mut tab, &mut viewer);
            let difference = viewer.screen_difference(&session.terminal);
            if repaint != Some(Repaint::Approximate) || difference != 0 {
                failures.push(format!(
                    "{name} at {cols}x{rows}, departed={departed}: repaint {repaint:?}, difference {difference}"
                ));
            }
            assert_eq!(session.cursors.active_writer, tab.writer);
            assert_eq!((session.config.cols, session.config.rows), (cols, rows));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Sweep of the amended D74 (#521): after the tab that typed last left, a
/// reopen at any other width, with fewer, the same or more rows, takes the
/// size and ends on the shim's screen. Each failing case is listed.
#[test]
fn reopening_at_any_other_size_after_the_typist_left_shows_the_shim_screen() {
    let failures: Vec<String> = WRITTEN_AT
        .iter()
        .flat_map(|&written| reopened_at(written).map(|cols| (written, cols)))
        .flat_map(|(written, cols)| [20, 24, 30].map(|rows| (written, cols, rows)))
        .filter_map(|(written, cols, rows)| departed_typist_reopen_mismatch(written, cols, rows))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `seq`-style lines, `first..` until `bytes` long: a build log or a flood
/// that scrolled while the tab was away.
fn backlog(first: u64, bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 32);
    let mut line = first;
    while out.len() < bytes {
        out.extend_from_slice(format!("{line}\r\n").as_bytes());
        line += 1;
    }
    out.truncate(bytes);
    out
}

/// A tab that saw `before` and comes back after `away` more bytes, at the
/// session's own size: the session, the tab's link and its screen after the
/// reattach, the repaint it got, and the screen a full raw replay would give.
fn reattach_after(
    before: &[u8],
    away: &[u8],
    caps: u64,
) -> (Session, Peer, Terminal, Option<Repaint>, Terminal) {
    let mut session = Session::new(80, 24);
    // A backlog that the shim's default ring still holds in full.
    session.ring = Ring::new(DEFAULT_CAPACITY);
    session.output(before);
    let mut viewer = Terminal::new(80, 24).unwrap();
    viewer.process(before);
    let mut raw = Terminal::new(80, 24).unwrap();
    raw.process(&[before, away].concat());
    session.output(away);
    let mut tab = peer();
    tab.caps = caps;
    session.handle(&mut tab, Frame::ReadFrom(before.len() as u64));
    let repaint = session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, 80, 24);
    assert_eq!(
        session.deliver(&mut tab, &mut viewer),
        None,
        "a same-size Resize adds no repaint"
    );
    (session, tab, viewer, repaint, raw)
}

/// #583: a tab that comes back further behind than `SNAPSHOT_FIRST_BACKLOG`
/// to a session whose engine exports exactly (here after RIS) gets the screen
/// first, not its backlog, and ends on exactly the shim's state, which is also
/// the screen a full raw replay gives.
#[test]
fn a_reattach_far_behind_gets_the_exact_screen_first() {
    let before = [b"\x1bc".as_slice(), &backlog(1, 4096)].concat();
    let away = backlog(
        100_000,
        usize::try_from(SNAPSHOT_FIRST_BACKLOG).unwrap() + 1,
    );
    let (session, tab, viewer, repaint, raw) = reattach_after(&before, &away, APPROXIMATE_SNAPSHOT);
    assert_eq!(repaint, Some(Repaint::Exact));
    assert_eq!(
        tab.cursor,
        Some(session.ring.head()),
        "nothing of the backlog is replayed raw"
    );
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
    assert_eq!(viewer.screen_difference(&raw), 0);
}

/// #583: a backlog of exactly `SNAPSHOT_FIRST_BACKLOG` bytes is still replayed raw.
#[test]
fn a_reattach_within_the_snapshot_first_backlog_keeps_the_raw_replay() {
    let before = [b"\x1bc".as_slice(), &backlog(1, 4096)].concat();
    let away = backlog(100_000, usize::try_from(SNAPSHOT_FIRST_BACKLOG).unwrap());
    let (session, tab, viewer, repaint, raw) = reattach_after(&before, &away, APPROXIMATE_SNAPSHOT);
    assert_eq!(repaint, None);
    assert_eq!(tab.cursor, Some(session.ring.head()));
    assert_eq!(viewer.screen_difference(&raw), 0);
}

/// #583: a live shell's engine cannot export exactly (prompt redraw off,
/// #521), so a reattach far behind keeps the exact raw replay: never the
/// approximate repaint, even on a link that negotiated it, and never an Error.
#[test]
fn a_reattach_far_behind_without_an_exact_export_keeps_the_raw_replay() {
    let before = backlog(1, 4096);
    let away = backlog(
        100_000,
        usize::try_from(SNAPSHOT_FIRST_BACKLOG).unwrap() + 1,
    );
    for caps in [APPROXIMATE_SNAPSHOT, 0] {
        let (session, tab, viewer, repaint, raw) = reattach_after(&before, &away, caps);
        assert_eq!(repaint, None, "caps {caps:#x}");
        assert_eq!(tab.cursor, Some(session.ring.head()));
        assert_eq!(viewer.screen_difference(&raw), 0);
        assert_eq!(viewer.screen_difference(&session.terminal), 0);
    }
}
