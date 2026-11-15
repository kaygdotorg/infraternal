//! Which socket a new page takes over when its account is full, and what it may never take (#523, option B).
use super::*;

/// An account with `limit` slots, all taken: returns the account and the held slots in admission order.
fn full_account(limit: usize) -> (Arc<AccountSockets>, Vec<AccountSlot>) {
    let account = Arc::new(AccountSockets::new(limit));
    let slots = (0..limit)
        .map(|_| account.try_slot().expect("a free slot"))
        .collect();
    (account, slots)
}

/// Drives one taken-over socket the way its loop does: wait for the signal, then end (drop the slot).
fn end_when_taken_over(slot: AccountSlot) -> tokio::task::JoinHandle<()> {
    let viewer = slot.viewer();
    tokio::spawn(async move {
        viewer.taken_over().await;
        drop(slot);
    })
}

/// The longest-hidden socket is the one taken over, and its slot goes to the new page.
#[tokio::test(start_paused = true)]
async fn the_longest_hidden_socket_is_taken_over() {
    let (account, mut slots) = full_account(3);
    assert!(account.try_slot().is_none(), "the account is full");
    slots[2].viewer().set_hidden(true);
    tokio::time::advance(Duration::from_secs(1)).await;
    slots[1].viewer().set_hidden(true);
    // A repeated "hidden" keeps its first time and cannot move a socket up the queue.
    tokio::time::advance(Duration::from_secs(1)).await;
    slots[2].viewer().set_hidden(true);
    let newest_hidden = slots.remove(1);
    let oldest_hidden = slots.remove(1);
    let oldest_viewer = oldest_hidden.viewer();
    let ended = end_when_taken_over(oldest_hidden);
    let taken = account.take_over_hidden(TAKEOVER_WAIT).await;
    assert!(taken.is_some(), "the new page gets the freed slot");
    ended.await.unwrap();
    assert_eq!(Arc::strong_count(&oldest_viewer), 1, "the taken-over socket ended");
    assert!(!newest_hidden.viewer.claimed.load(Ordering::Acquire));
    assert!(!slots[0].viewer.claimed.load(Ordering::Acquire));
}

/// A socket whose page came back into view is no longer a candidate, and with nothing hidden the new page is refused.
#[tokio::test(start_paused = true)]
async fn visible_sockets_are_never_taken_over() {
    let (account, slots) = full_account(2);
    slots[0].viewer().set_hidden(true);
    slots[0].viewer().set_hidden(false);
    assert!(account.take_over_hidden(TAKEOVER_WAIT).await.is_none());
    assert!(
        slots
            .iter()
            .all(|slot| !slot.viewer.claimed.load(Ordering::Acquire)),
        "a refusal claims nothing"
    );
}

/// Two new pages arriving together take two different hidden sockets; a third, with none left, is refused.
#[tokio::test(start_paused = true)]
async fn concurrent_takers_pick_different_sockets() {
    let (account, mut slots) = full_account(3);
    for slot in &slots[1..] {
        slot.viewer().set_hidden(true);
        tokio::time::advance(Duration::from_millis(10)).await;
    }
    let first = end_when_taken_over(slots.remove(1));
    let second = end_when_taken_over(slots.remove(1));
    let (a, b) = tokio::join!(
        account.take_over_hidden(TAKEOVER_WAIT),
        account.take_over_hidden(TAKEOVER_WAIT)
    );
    assert!(a.is_some() && b.is_some());
    first.await.unwrap();
    second.await.unwrap();
    assert!(account.take_over_hidden(TAKEOVER_WAIT).await.is_none());
}

/// A taken-over socket that does not end in time leaves the new page refused, and is still asked only once.
#[tokio::test(start_paused = true)]
async fn a_slow_teardown_refuses_the_new_page_after_the_wait() {
    let (account, slots) = full_account(1);
    slots[0].viewer().set_hidden(true);
    let started = Instant::now();
    assert!(account.take_over_hidden(TAKEOVER_WAIT).await.is_none());
    assert_eq!(started.elapsed(), TAKEOVER_WAIT);
    assert!(
        account.take_over_hidden(TAKEOVER_WAIT).await.is_none(),
        "the claimed socket is not picked twice"
    );
    drop(slots);
    assert!(account.try_slot().is_some(), "its slot frees when it ends");
}

/// Ended sockets leave the viewer list at once, so it never grows past the live sockets.
#[test]
fn ended_sockets_leave_the_list() {
    let (account, slots) = full_account(4);
    drop(slots);
    assert!(account.viewers.lock().unwrap().is_empty());
}

/// Accounts are separate: a full account cannot take over another account's hidden socket.
#[tokio::test(start_paused = true)]
async fn another_accounts_hidden_socket_is_out_of_reach() {
    let (full, _held) = full_account(1);
    let (other, other_slots) = full_account(1);
    other_slots[0].viewer().set_hidden(true);
    assert!(full.take_over_hidden(TAKEOVER_WAIT).await.is_none());
    assert!(!other_slots[0].viewer.claimed.load(Ordering::Acquire));
    drop(other);
}
