//! Checks that renderer reply bursts preserve ordinary command capacity and FIFO order [307].
#![allow(clippy::unwrap_used)]
use super::*;

#[tokio::test]
async fn sixteen_replies_and_eight_typing_commands_retain_their_order() {
    let (mut sender, mut receiver) = channel();
    for value in 0..16 {
        sender.try_send(Command::Reply(vec![value])).unwrap();
    }
    for sequence in 0..8 {
        sender
            .try_send(Command::Input(sequence, vec![b'x']))
            .unwrap();
    }
    assert!(matches!(
        sender.try_send(Command::Input(8, vec![b'y'])),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    for value in 0..16 {
        assert!(matches!(receiver.next().await, Some(Command::Reply(bytes)) if bytes == [value]));
    }
    for sequence in 0..8 {
        assert!(
            matches!(receiver.next().await, Some(Command::Input(actual, _)) if actual == sequence)
        );
    }
}

#[tokio::test]
async fn full_reply_reservations_cannot_spend_keyboard_capacity() {
    let (mut sender, mut receiver) = channel();
    for _ in 0..64 {
        sender.try_send(Command::Reply(vec![b'r'; 1024])).unwrap();
    }
    // Best-effort overflow remains a harmless skip, without retiring the stream.
    sender.try_send(Command::Reply(vec![b's'])).unwrap();
    for sequence in 0..8 {
        sender
            .try_send(Command::Input(sequence, vec![b'x']))
            .unwrap();
    }
    for _ in 0..64 {
        assert!(
            matches!(receiver.next().await, Some(Command::Reply(bytes)) if bytes == [b'r'; 1024])
        );
    }
    for sequence in 0..8 {
        assert!(
            matches!(receiver.next().await, Some(Command::Input(actual, _)) if actual == sequence)
        );
    }
}
