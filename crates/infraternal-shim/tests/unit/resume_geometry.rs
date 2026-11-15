//! A viewer that attaches at a different size than the output was written at
//! must still see the shim's screen (#521, D13).
//!
//! Raw PTY bytes only make sense at the width they were produced for. A shell
//! wraps a long line by printing past the margin and then returning with `\r`,
//! so the same bytes parsed at another width put the wrapped tail over the
//! start of the line. Each case below builds the screen a browser would show
//! from exactly what the shim sends it, and compares it cell for cell with the
//! shim's own engine, which reflows correctly on resize.
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
    fn new(cols: u16, rows: u16) -> Self {
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
    /// written as is, a Snapshot replaces the screen.
    fn deliver(&self, peer: &mut Peer, viewer: &mut Terminal) {
        match peer.request.take() {
            Some(Request::Read(seq)) => peer.cursor = Some(seq),
            Some(Request::Snapshot) => {
                peer.snapshot(&self.terminal, self.ring.head()).unwrap();
                let frames = Decoder::default().feed(&peer.pending).unwrap();
                peer.pending.clear();
                let [Frame::Snapshot(_, bytes)] = frames.as_slice() else {
                    panic!("expected one exact Snapshot, got {frames:?}");
                };
                let (cols, rows) = (self.config.cols, self.config.rows);
                *viewer = Terminal::new(cols, rows).unwrap();
                viewer.process(bytes);
            }
            None => {}
        }
        while let Some(seq) = peer.cursor.filter(|seq| *seq < self.ring.head()) {
            let bytes = self.ring.read(seq, CHUNK).unwrap();
            peer.cursor = Some(seq + bytes.len() as u64);
            viewer.process(&bytes);
        }
    }
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
    }
}

/// A new tab at `cols` attaches to a session whose output was written at 42
/// columns. The agent sends ReadFrom first and the browser's Resize after it;
/// the shim may already have streamed the replay when the Resize arrives.
fn reopen_at(cols: u16) -> (Session, Terminal) {
    let mut session = Session::new(42, 24);
    session.output(&typed_at_42());
    let mut tab = peer();
    let mut viewer = Terminal::new(cols, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, cols, 24);
    session.deliver(&mut tab, &mut viewer);
    (session, viewer)
}

#[test]
fn reopening_wider_shows_the_shim_screen_not_the_old_width_bytes() {
    let (session, viewer) = reopen_at(45);
    assert_eq!(
        viewer.screen_difference(&session.terminal),
        0,
        "the wrapped tail must not overwrite the prompt (J745's screenshot)"
    );
}

#[test]
fn reopening_narrower_shows_the_shim_screen() {
    let (session, viewer) = reopen_at(38);
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}

#[test]
fn reopening_at_the_same_size_keeps_the_raw_replay() {
    // The common reconnect: nothing changed size, so the cheaper raw replay
    // stays exact and no repaint is added to the resume path.
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

#[test]
fn a_live_resize_reflows_without_a_repaint() {
    // No reconnect: the viewer received every byte at 42 columns, then both
    // sides reflow the same engine state, so the screens still match.
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

#[test]
fn reopening_after_an_earlier_resize_shows_the_shim_screen() {
    // The session was resized while a tab was open, then a new tab opens at
    // the current size. The ring still starts with bytes for the old width.
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
    let mut viewer = Terminal::new(45, 24).unwrap();
    session.handle(&mut tab, Frame::ReadFrom(0));
    session.deliver(&mut tab, &mut viewer);
    session.resize(&mut tab, 45, 24);
    session.deliver(&mut tab, &mut viewer);
    assert_eq!(viewer.screen_difference(&session.terminal), 0);
}
