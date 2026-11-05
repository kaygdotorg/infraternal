//! Drives the shim bridge against a scripted shim peer on a real socket pair.
use super::*;
use tokio::net::UnixStream;

/// Session.
fn session(peer: UnixStream) -> Session {
    Session {
        id: [1; 16],
        path: PathBuf::from("/nonexistent"),
        peer,
        head: 0,
        size: (80, 24),
        pid: 1,
        caps: 0,
        supports_owner: false,
    }
}

/// Expect.
async fn expect(shim: &mut UnixStream, reader: &mut Reader) -> Frame {
    tokio::time::timeout(std::time::Duration::from_secs(5), reader.read(shim))
        .await
        .expect("frame in time")
        .expect("frame")
}

/// Shell output input resize and exit cross the bridge.
#[tokio::test]
async fn shell_output_input_resize_and_exit_cross_the_bridge() {
    let (bridge_end, mut shim) = UnixStream::pair().unwrap();
    let size = TerminalSize {
        columns: 120,
        rows: 40,
        width_pixels: 0,
        height_pixels: 0,
    };
    let attachment = bridge(session(bridge_end), size);
    let Attachment {
        mut input,
        mut output,
        control,
        exit,
        ..
    } = attachment;
    let mut reader = Reader::default();
    // A launched session is already attached; a second Attach would make the
    // real shim drop the link (measured on dev-02, #221).
    assert!(matches!(
        expect(&mut shim, &mut reader).await,
        Frame::Resize {
            cols: 120,
            rows: 40,
            ..
        }
    ));
    assert!(matches!(
        expect(&mut shim, &mut reader).await,
        Frame::ReadFrom(0)
    ));
    sessions::send(&mut shim, &Frame::Output(0, b"prompt$ ".to_vec()))
        .await
        .unwrap();
    let mut seen = [0; 8];
    output.read_exact(&mut seen).await.unwrap();
    assert_eq!(&seen, b"prompt$ ");
    input.write_all(b"ls\n").await.unwrap();
    let Frame::Input(bytes) = expect(&mut shim, &mut reader).await else {
        panic!("expected input");
    };
    assert_eq!(bytes, b"ls\n");
    control
        .send(Control::Resize(TerminalSize {
            columns: 100,
            rows: 30,
            width_pixels: 0,
            height_pixels: 0,
        }))
        .await
        .unwrap();
    assert!(matches!(
        expect(&mut shim, &mut reader).await,
        Frame::Resize {
            cols: 100,
            rows: 30,
            ..
        }
    ));
    control
        .send(Control::Signal(russh::Sig::INT))
        .await
        .unwrap();
    assert!(matches!(
        expect(&mut shim, &mut reader).await,
        Frame::Signal(2)
    ));
    sessions::send(&mut shim, &Frame::Exited(3, 8))
        .await
        .unwrap();
    assert!(matches!(
        expect(&mut shim, &mut reader).await,
        Frame::ExitAck
    ));
    assert!(matches!(exit.await.unwrap(), Exit::Status(3)));
}

/// Control flows while output is blocked.
#[tokio::test]
async fn control_flows_while_output_is_blocked() {
    let (bridge_end, mut shim) = UnixStream::pair().unwrap();
    let attachment = bridge(session(bridge_end), TerminalSize::default());
    let mut reader = Reader::default();
    for _ in 0..2 {
        expect(&mut shim, &mut reader).await;
    }
    // Nobody reads the SSH side: more output than the bridge buffer holds.
    for _ in 0..8 {
        sessions::send(&mut shim, &Frame::Output(0, vec![b'x'; PACKET_BYTES]))
            .await
            .unwrap();
    }
    attachment
        .control
        .send(Control::Signal(russh::Sig::TERM))
        .await
        .unwrap();
    // The signal still reaches the shim although output is backed up.
    let frame = expect(&mut shim, &mut reader).await;
    assert!(matches!(frame, Frame::Signal(15)), "unexpected {frame:?}");
    drop(attachment);
}

/// Signals map to linux numbers.
#[test]
fn signals_map_to_linux_numbers() {
    assert_eq!(signal_number(&russh::Sig::HUP), Some(1));
    assert_eq!(signal_number(&russh::Sig::KILL), Some(9));
    assert_eq!(signal_number(&russh::Sig::TERM), Some(15));
    assert_eq!(signal_number(&russh::Sig::Custom("WINCH".into())), None);
}
