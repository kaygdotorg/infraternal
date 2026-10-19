//! Exercises exact accumulated credit, cancellation and unchanged bounded Input/Resize admission, #78.
use super::*;

#[tokio::test]
async fn credit_bursts_do_not_consume_ordered_input_capacity() {
    let (mut sender, mut receiver) = channel();
    for _ in 0..32 {
        assert!(sender.try_send(Command::Credit(4096)).is_ok());
    }
    for seq in 0..8 {
        assert!(sender.try_send(Command::Input(seq, vec![b'x'])).is_ok());
    }
    assert!(matches!(
        sender.try_send(Command::Input(8, vec![b'x'])),
        Err(mpsc::error::TrySendError::Full(_))
    ));
    let mut inputs = Vec::new();
    let mut granted = 0;
    for _ in 0..9 {
        match receiver.next().await.unwrap() {
            Command::Input(seq, _) => inputs.push(seq),
            Command::Credit(bytes) => granted += bytes,
            Command::Reply(_) | Command::Resize(..) | Command::Ping(..) => {
                panic!("unexpected command")
            }
            #[cfg(feature = "remote")]
            Command::Cursor(_) => panic!("unexpected native cursor"),
        }
    }
    assert_eq!(inputs, (0..8).collect::<Vec<_>>());
    assert_eq!(granted, 32 * 4096);
}
#[tokio::test]
async fn credit_above_one_wire_word_is_exact_and_idle_after_drain() {
    let (mut sender, mut receiver) = channel();
    assert!(sender.try_send(Command::Credit(u32::MAX)).is_ok());
    assert!(sender.try_send(Command::Credit(u32::MAX)).is_ok());
    for _ in 0..2 {
        assert!(matches!(
            receiver.next().await,
            Some(Command::Credit(u32::MAX))
        ));
    }
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), receiver.next())
            .await
            .is_err()
    );
    assert!(sender.try_send(Command::Credit(7)).is_ok());
    assert!(matches!(receiver.next().await, Some(Command::Credit(7))));
}

#[tokio::test]
async fn zero_credit_is_idle_and_overflow_refuses_without_mutating_accounting() {
    let (mut sender, mut receiver) = channel();
    assert!(sender.try_send(Command::Credit(0)).is_ok());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), receiver.next())
            .await
            .is_err()
    );
    sender.credits.send_replace(u64::MAX);
    assert!(matches!(
        sender.try_send(Command::Credit(1)),
        Err(mpsc::error::TrySendError::Full(Command::Credit(1)))
    ));
    assert_eq!(*sender.credits.borrow(), u64::MAX);
    drop(receiver);
    assert!(matches!(
        sender.try_send(Command::Credit(1)),
        Err(mpsc::error::TrySendError::Closed(_))
    ));
}
#[tokio::test]
async fn input_and_resize_keep_their_shared_fifo_order_around_credit() {
    let (mut sender, mut receiver) = channel();
    assert!(sender.try_send(Command::Input(7, vec![1])).is_ok());
    assert!(sender.try_send(Command::Credit(5)).is_ok());
    assert!(sender.try_send(Command::Resize(80, 24, 0, 0)).is_ok());
    assert!(sender.try_send(Command::Input(8, vec![2])).is_ok());
    let mut ordered = Vec::new();
    let mut credit = 0;
    for _ in 0..4 {
        match receiver.next().await.unwrap() {
            Command::Input(seq, _) => ordered.push(seq),
            Command::Resize(80, 24, 0, 0) => ordered.push(100),
            Command::Credit(bytes) => credit += bytes,
            Command::Reply(_) | Command::Resize(..) | Command::Ping(..) => {
                panic!("unexpected command")
            }
            #[cfg(feature = "remote")]
            Command::Cursor(_) => panic!("unexpected native cursor"),
        }
    }
    assert_eq!(ordered, [7, 100, 8]);
    assert_eq!(credit, 5);
}

#[tokio::test]
async fn credit_allowance_does_not_cross_ordered_command_barriers() {
    let (mut sender, mut receiver) = channel();
    assert!(sender.try_send(Command::Credit(5)).is_ok());
    assert!(sender.try_send(Command::Input(7, vec![1])).is_ok());
    assert!(sender.try_send(Command::Credit(9)).is_ok());
    assert!(sender.try_send(Command::Resize(80, 24, 0, 0)).is_ok());
    assert!(matches!(receiver.next().await, Some(Command::Credit(5))));
    assert!(matches!(receiver.next().await, Some(Command::Input(7, _))));
    assert!(matches!(receiver.next().await, Some(Command::Credit(9))));
    assert!(matches!(
        receiver.next().await,
        Some(Command::Resize(80, 24, 0, 0))
    ));
}

#[tokio::test]
async fn probe_at_full_command_capacity_preserves_accepted_input() {
    let (mut sender, mut receiver) = channel();
    for seq in 0..8 {
        sender.try_send(Command::Input(seq, vec![b'x'])).unwrap();
    }
    assert!(
        sender.try_send(Command::Ping(41, 73)).is_ok(),
        "probe overload must not retire the terminal"
    );
    for seq in 0..8 {
        assert!(matches!(receiver.next().await, Some(Command::Input(actual, _)) if actual == seq));
    }
    sender.try_send(Command::Ping(42, 74)).unwrap();
    assert!(matches!(receiver.next().await, Some(Command::Ping(42, 74))));
    drop(receiver);
    assert!(matches!(
        sender.try_send(Command::Ping(43, 75)),
        Err(mpsc::error::TrySendError::Closed(_))
    ));
}
