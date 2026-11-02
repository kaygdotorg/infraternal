//! Account-scoped, coalescing authority notifications; no idle task or retained inactive account.
//!
//! A watch change means re-read this account's authority, even if intermediate session events
//! were overwritten. Never filter by the last session: an earlier coalesced logout may be ours.
//! Subscribers register before reading SQLite, and mutations publish only after commit.

use std::{
    cell::Cell,
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::watch;

/// The map key supplies the affected account; the value carries the session hash when known.
/// Hashes stay private, are never logged, and are hints only: every wake rechecks authority.
#[derive(Default)]
pub(crate) struct AccountEvents {
    accounts: std::sync::Mutex<Channels>,
    // Serializes teardown observation with recovery commit and publication.
    completion_commit: tokio::sync::Mutex<()>,
    #[cfg(test)]
    after_unsubscribe: std::sync::Mutex<Option<Arc<std::sync::Barrier>>>,
}

type Channels = HashMap<Arc<str>, Channel>;

struct Channel {
    sender: watch::Sender<Option<String>>,
    // Count subscription lifetimes under the registry lock. Receiver fields drop after
    // their wrapper's Drop returns, so receiver_count can overcount concurrent final drops.
    subscribers: Cell<usize>,
    // Completion survives coalesced logout hints, but not the last subscriber.
    completions: Arc<AtomicU64>,
}

/// A socket-local cursor sharing only its authenticated account's generation.
pub(crate) struct AccountSubscription {
    receiver: watch::Receiver<Option<String>>,
    account: Arc<str>,
    registry: Arc<AccountEvents>,
    completions: Arc<AtomicU64>,
    completion_seen: u64,
}

impl AccountEvents {
    /// Transfer the final commit and its account wakes together. Earlier validation
    /// and writes may still roll back on cancellation; an enqueued commit cannot
    /// outlive the code responsible for notifying its subscribers.
    pub(super) async fn commit(
        self: &Arc<Self>,
        transaction: sqlx::Transaction<'static, sqlx::Sqlite>,
        account: &str,
        revocations: Option<Arc<Self>>,
    ) -> super::Result<()> {
        let changes = self.clone();
        let account = account.to_owned();
        super::committed::run(Box::pin(async move {
            // A socket can see deletion as soon as SQLite commits, before this
            // task resumes. Hold the barrier until the completion marker is published.
            let _publication = if let Some(revocations) = revocations.as_ref() {
                Some(revocations.completion_commit.lock().await)
            } else {
                None
            };
            transaction.commit().await?;
            if let Some(revocations) = revocations.as_ref() {
                revocations.publish_recovery_complete(&account);
            }
            changes.publish(&account, None);
            Ok(())
        }))
        .await
    }

    fn accounts(&self) -> std::sync::MutexGuard<'_, Channels> {
        // No user code or await runs under this lock. Recovering bookkeeping after a panic
        // preserves existing generations; replacing them could hide a committed revocation.
        self.accounts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(super) fn subscribe(self: &Arc<Self>, account: &str) -> AccountSubscription {
        let mut accounts = self.accounts();
        // Operations on an already-connected account clone its key without allocating.
        let (account, receiver, completions, completion_seen) =
            if let Some((account, channel)) = accounts.get_key_value(account) {
                channel.subscribers.set(channel.subscribers.get() + 1);
                (
                    account.clone(),
                    channel.sender.subscribe(),
                    channel.completions.clone(),
                    channel.completions.load(Ordering::Acquire),
                )
            } else {
                let account: Arc<str> = Arc::from(account);
                let (sender, receiver) = watch::channel(None);
                let completions = Arc::new(AtomicU64::new(0));
                accounts.insert(
                    account.clone(),
                    Channel {
                        sender,
                        subscribers: Cell::new(1),
                        completions: completions.clone(),
                    },
                );
                (account, receiver, completions, 0)
            };
        AccountSubscription {
            receiver,
            account,
            registry: self.clone(),
            completions,
            completion_seen,
        }
    }

    pub(super) fn publish(&self, account: &str, session_hash: Option<String>) {
        // Snapshot the channel under the registration lock, then wake outside it. A custom
        // waker must never run while bookkeeping is locked. If the last receiver disappears
        // before delivery, its replacement reads SQL after this mutation's commit.
        let sender = self
            .accounts()
            .get(account)
            .map(|channel| channel.sender.clone());
        if let Some(sender) = sender {
            sender.send_replace(session_hash);
        }
    }

    // Mark before waking any socket. Teardown may win through recovery events or
    // another authority guard; it must still carry this committed completion.
    fn publish_recovery_complete(&self, account: &str) {
        let channel = self
            .accounts()
            .get(account)
            .map(|channel| (channel.sender.clone(), channel.completions.clone()));
        if let Some((sender, completions)) = channel {
            completions.fetch_add(1, Ordering::Release);
            sender.send_replace(None);
        }
    }

    /// Only tests model a database edit whose affected accounts are unknown. Current production
    /// mutations (logout and recovery) always know the account; none require a global event.
    #[cfg(test)]
    pub(super) fn publish_all(&self) {
        let senders: Vec<_> = self
            .accounts()
            .values()
            .map(|channel| channel.sender.clone())
            .collect();
        for sender in senders {
            sender.send_replace(None);
        }
    }
}

impl AccountSubscription {
    pub(crate) fn completion_generation(&self) -> u64 {
        self.completions.load(Ordering::Acquire)
    }

    pub(crate) fn acknowledge_completion(&mut self, generation: u64) {
        self.completion_seen = generation;
    }

    // A completion is account-scoped, content-free teardown information, not
    // renewed authority. New subscribers do not inherit an older completion.
    pub(crate) async fn committed_recovery_completed(&self) -> bool {
        let _publication = self.registry.completion_commit.lock().await;
        self.recovery_completed()
    }

    fn recovery_completed(&self) -> bool {
        self.completion_generation() != self.completion_seen
    }

    /// Model source loss without changing production channel ownership.
    #[cfg(test)]
    pub(crate) fn close_source_for_test(&self) {
        self.registry.accounts().remove(&self.account);
    }

    pub(crate) async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.receiver.changed().await
    }

    pub(crate) fn has_changed(&self) -> Result<bool, watch::error::RecvError> {
        self.receiver.has_changed()
    }

    pub(crate) fn borrow_and_update(&mut self) -> watch::Ref<'_, Option<String>> {
        self.receiver.borrow_and_update()
    }
}

impl Drop for AccountSubscription {
    fn drop(&mut self) {
        let mut accounts = self.registry.accounts();
        if let Some((account, channel)) = accounts.get_key_value(&self.account)
            && Arc::ptr_eq(account, &self.account)
        {
            // A closed test source may have a replacement under the same account ID.
            // Its key has a different identity; an old cursor cannot remove that channel.
            let remaining = channel.subscribers.get() - 1;
            channel.subscribers.set(remaining);
            if remaining == 0 {
                accounts.remove(&self.account);
            }
        }
        drop(accounts);
        // Hold receiver fields alive after bookkeeping to expose concurrent final drops.
        #[cfg(test)]
        {
            let barrier = self.registry.after_unsubscribe.lock().unwrap().clone();
            if let Some(barrier) = barrier {
                barrier.wait();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;

    #[tokio::test]
    async fn completion_teardown_waits_for_commit_publication() {
        let events = Arc::new(AccountEvents::default());
        let socket = events.subscribe("a");
        // A socket can observe the committed session deletion before the
        // committing task resumes to publish. Teardown must await that publication.
        let committing = events.completion_commit.lock().await;
        assert!(
            socket
                .committed_recovery_completed()
                .now_or_never()
                .is_none()
        );
        events.publish_recovery_complete("a");
        drop(committing);
        assert!(socket.committed_recovery_completed().await);
    }

    #[test]
    fn completion_notice_survives_coalesced_logout_without_reaching_new_subscribers() {
        let events = Arc::new(AccountEvents::default());
        let old = events.subscribe("a");
        let other = events.subscribe("b");
        events.publish_recovery_complete("a");
        events.publish("a", Some("synthetic-logout-hint".into()));
        assert!(old.recovery_completed());
        assert!(!other.recovery_completed());
        let mut replacement = events.subscribe("a");
        assert!(!replacement.recovery_completed());
        events.publish_recovery_complete("a");
        assert!(replacement.recovery_completed());
        let generation = replacement.completion_generation();
        replacement.acknowledge_completion(generation);
        events.publish("a", None);
        assert!(!replacement.recovery_completed());
    }

    #[tokio::test]
    async fn cancelled_commit_waiter_still_commits_and_wakes_both_account_sources() {
        let root = std::env::var_os("CARGO_TARGET_DIR")
            .map_or_else(
                || std::path::PathBuf::from("target"),
                std::path::PathBuf::from,
            )
            .join("account-event-commit");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("{}.sqlite", uuid::Uuid::new_v4()));
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE state(id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        let changes = Arc::new(AccountEvents::default());
        let revocations = Arc::new(AccountEvents::default());
        let mut events = changes.subscribe("a");
        let mut revoked = revocations.subscribe("a");
        let other_change = changes.subscribe("b");
        let other_revocation = revocations.subscribe("b");
        let observer = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        let mut reader = observer.begin().await.unwrap();
        // Rollback-journal readers permit the INSERT but block its final COMMIT,
        // making cancellation deterministic even when ordinary completion is inline.
        let _: i64 = sqlx::query_scalar("SELECT count(*) FROM state")
            .fetch_one(&mut *reader)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO state VALUES(1)")
            .execute(&mut *tx)
            .await
            .unwrap();
        let mut commit = Box::pin(changes.commit(tx, "a", Some(revocations.clone())));
        assert!(commit.as_mut().now_or_never().is_none());
        // Public auth futures may be dropped from a thread with no runtime entered.
        std::thread::scope(|scope| scope.spawn(move || drop(commit)).join().unwrap());
        reader.rollback().await.unwrap();
        // The pool has one connection, so this read waits behind the detached
        // commit itself. The generous bound catches a lost commit without making
        // ordinary scheduler delay part of the behavior under test.
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM state")
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(rows, 1);
            revoked.changed().await.unwrap();
            events.changed().await.unwrap();
        })
        .await
        .expect("cancelled waiter did not observe commit and account notifications");
        assert!(revoked.recovery_completed());
        assert!(!other_change.has_changed().unwrap());
        assert!(!other_revocation.has_changed().unwrap());
        pool.close().await;
        observer.close().await;
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn refused_transaction_commit_wakes_neither_account_source() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE state(id INTEGER PRIMARY KEY)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE dependent(id INTEGER REFERENCES state(id) DEFERRABLE INITIALLY DEFERRED)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let changes = Arc::new(AccountEvents::default());
        let revocations = Arc::new(AccountEvents::default());
        let events = changes.subscribe("a");
        let revoked = revocations.subscribe("a");
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO dependent VALUES(1)")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(changes.commit(tx, "a", Some(revocations)).await.is_err());
        assert!(!events.has_changed().unwrap());
        assert!(!revoked.has_changed().unwrap());
        assert!(!revoked.recovery_completed());
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM dependent")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0);
        pool.close().await;
    }

    #[test]
    fn coalesced_changes_remain_pending_for_each_affected_account() {
        let registry = Arc::new(AccountEvents::default());
        let mut a = registry.subscribe("a");
        let b = registry.subscribe("b");
        let c = registry.subscribe("c");
        registry.publish("a", Some("first-session-hash".into()));
        registry.publish("b", None);
        registry.publish("a", Some("second-session-hash".into()));
        assert!(a.has_changed().unwrap());
        assert!(b.has_changed().unwrap());
        assert!(!c.has_changed().unwrap());
        assert_eq!(
            a.borrow_and_update().as_deref(),
            Some("second-session-hash")
        );
        assert!(!a.has_changed().unwrap());
        // The session metadata cannot authorize skipping a recheck: the first event is gone.
        registry.publish("a", None);
        assert!(a.has_changed().unwrap());
    }

    #[test]
    fn last_subscriber_removes_only_its_account() {
        let registry = Arc::new(AccountEvents::default());
        let first = registry.subscribe("a");
        let second = registry.subscribe("a");
        let other = registry.subscribe("b");
        assert_eq!(registry.accounts().len(), 2);
        drop(first);
        assert_eq!(registry.accounts().len(), 2);
        registry.publish("a", None);
        assert!(second.has_changed().unwrap());
        drop(second);
        assert_eq!(registry.accounts().len(), 1);
        registry.publish("a", None);
        assert_eq!(registry.accounts().len(), 1);
        assert!(!other.has_changed().unwrap());
        drop(other);
        assert!(registry.accounts().is_empty());
        let replacement = registry.subscribe("a");
        assert!(!replacement.has_changed().unwrap());
        registry.publish("a", None);
        assert!(replacement.has_changed().unwrap());
    }

    #[tokio::test]
    async fn cancellation_preserves_an_unread_generation() {
        let registry = Arc::new(AccountEvents::default());
        let mut events = registry.subscribe("a");
        assert!(events.changed().now_or_never().is_none());
        registry.publish("a", None);
        events.changed().await.unwrap();
        assert!(!events.has_changed().unwrap());
    }

    #[test]
    fn many_accounts_do_not_share_generations_or_retain_inactive_entries() {
        let registry = Arc::new(AccountEvents::default());
        let subscribers: Vec<_> = (0..256)
            .map(|i| registry.subscribe(&i.to_string()))
            .collect();
        registry.publish("127", None);
        assert_eq!(
            subscribers
                .iter()
                .filter(|s| s.has_changed().unwrap())
                .count(),
            1
        );
        registry.publish_all();
        assert!(subscribers.iter().all(|s| s.has_changed().unwrap()));
        drop(subscribers);
        assert!(registry.accounts().is_empty());
    }

    #[tokio::test]
    async fn a_dropped_source_reports_unavailable_instead_of_consuming_a_change() {
        let registry = Arc::new(AccountEvents::default());
        let mut events = registry.subscribe("a");
        events.close_source_for_test();
        assert!(events.has_changed().is_err());
        assert!(events.changed().await.is_err());
    }

    #[test]
    fn concurrent_final_drops_remove_the_account_before_receiver_fields_drop() {
        let registry = Arc::new(AccountEvents::default());
        *registry.after_unsubscribe.lock().unwrap() = Some(Arc::new(std::sync::Barrier::new(2)));
        let first = registry.subscribe("a");
        let second = registry.subscribe("a");
        std::thread::scope(|scope| {
            scope.spawn(move || drop(first));
            scope.spawn(move || drop(second));
        });
        assert!(
            registry.accounts().is_empty(),
            "final concurrent drops retained an inactive account"
        );
    }

    #[test]
    fn a_closed_cursor_cannot_remove_its_replacement_channel() {
        let registry = Arc::new(AccountEvents::default());
        let old = registry.subscribe("a");
        old.close_source_for_test();
        let replacement = registry.subscribe("a");
        drop(old);
        assert_eq!(registry.accounts().len(), 1);
        registry.publish("a", None);
        assert!(replacement.has_changed().unwrap());
        drop(replacement);
        assert!(registry.accounts().is_empty());
    }

    #[test]
    fn publication_wakes_outside_the_registry_lock() {
        struct CheckUnlocked(Arc<AccountEvents>);
        impl std::task::Wake for CheckUnlocked {
            fn wake(self: Arc<Self>) {
                assert!(self.0.accounts.try_lock().is_ok());
            }
        }
        let registry = Arc::new(AccountEvents::default());
        let mut events = registry.subscribe("a");
        let mut changed = Box::pin(events.changed());
        let waker = std::task::Waker::from(Arc::new(CheckUnlocked(registry.clone())));
        let mut context = std::task::Context::from_waker(&waker);
        assert!(std::future::Future::poll(changed.as_mut(), &mut context).is_pending());
        registry.publish("a", None);
        assert!(std::future::Future::poll(changed.as_mut(), &mut context).is_ready());
    }

    #[test]
    fn concurrent_registration_and_cleanup_keep_the_existing_generation() {
        let registry = Arc::new(AccountEvents::default());
        let anchor = registry.subscribe("a");
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let registry = &registry;
                scope.spawn(move || {
                    for _ in 0..1000 {
                        let subscriber = registry.subscribe("a");
                        registry.publish("a", None);
                        drop(subscriber);
                    }
                });
            }
        });
        assert!(anchor.has_changed().unwrap());
        assert_eq!(registry.accounts().len(), 1);
        drop(anchor);
        assert!(registry.accounts().is_empty());
    }
}

#[cfg(test)]
#[path = "review_revocation_r2_tests.rs"]
mod review_revocation_r2;
