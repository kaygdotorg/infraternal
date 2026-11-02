//! A login cannot inherit another same-owner socket's live authority [D208].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_api::streams::Authority;
use infraternal_plugin_desktop::session::{AccessRules, Error, HostCommand, Session, Video};
use infraternal_protocol::desktop::Input;
use std::sync::Arc;
struct Owner;
impl AccessRules for Owner {
    fn may_view(&self, u: &str, _h: &str, o: &str) -> bool {
        u == o
    }
    fn may_control(&self, u: &str, _h: &str, o: &str) -> bool {
        u == o
    }
}
struct Login(tokio::sync::watch::Sender<bool>);
impl Authority for Login {
    fn permits(&self) -> bool {
        *self.0.borrow()
    }
    fn cancelled(&self) -> infraternal_plugin_api::Operation<'_, ()> {
        let mut live = self.0.subscribe();
        Box::pin(async move {
            let _ = live.wait_for(|value| !*value).await;
        })
    }
}
#[tokio::test]
async fn same_user_viewers_keep_independent_login_and_queued_input_authority() {
    let (session, mut commands) =
        Session::new([1; 16], "mac".into(), "owner".into(), Arc::new(Owner));
    let a = Arc::new(Login(tokio::sync::watch::channel(true).0));
    let b = Arc::new(Login(tokio::sync::watch::channel(true).0));
    let mut first = session
        .attach_authorized("owner".into(), a.clone())
        .unwrap();
    let second = session
        .attach_authorized("owner".into(), b.clone())
        .unwrap();
    commands.recv().await.unwrap();
    first.take_control().unwrap();
    commands.recv().await.unwrap();
    first
        .input(Input::Key {
            keycode: 1,
            down: true,
            modifiers: 0,
        })
        .unwrap();
    let queued = commands.recv().await.unwrap();
    assert!(session.command_allowed(queued).unwrap());
    session
        .publish(Video {
            sequence: 1,
            capture_ns: 1,
            keyframe: true,
            bytes: vec![7; 100].into(),
        })
        .unwrap();
    a.0.send_replace(false);
    assert!(
        !session.command_allowed(queued).unwrap(),
        "revoked login inherited another owner's live socket"
    );
    assert_eq!(first.take_control(), Err(Error::Forbidden));
    assert_eq!(first.input(Input::Release), Err(Error::Forbidden));
    assert!(matches!(first.next().await, Err(Error::Forbidden)));
    second.take_control().unwrap();
    assert!(matches!(
        commands.recv().await,
        Some(HostCommand::Control { .. })
    ));
    second
        .input(Input::Key {
            keycode: 2,
            down: true,
            modifiers: 0,
        })
        .unwrap();
    let queued = commands.recv().await.unwrap();
    assert!(session.command_allowed(queued).unwrap());
    b.0.send_replace(false);
    assert!(!session.command_allowed(queued).unwrap());
    assert!(matches!(
        session.attach_authorized("owner".into(), a),
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn pending_view_and_input_wake_on_their_own_login_loss_or_handover() {
    let (session, mut commands) =
        Session::new([2; 16], "mac".into(), "owner".into(), Arc::new(Owner));
    let login = Arc::new(Login(tokio::sync::watch::channel(true).0));
    let mut viewer = session
        .attach_authorized("owner".into(), login.clone())
        .unwrap();
    let next = viewer.next();
    tokio::pin!(next);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut next)
            .await
            .is_err()
    );
    login.0.send_replace(false);
    assert!(matches!(
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut next)
            .await
            .unwrap(),
        Err(Error::Forbidden)
    ));
    let login = Arc::new(Login(tokio::sync::watch::channel(true).0));
    let first = session
        .attach_authorized("owner".into(), login.clone())
        .unwrap();
    let second = session
        .attach_authorized(
            "owner".into(),
            Arc::new(Login(tokio::sync::watch::channel(true).0)),
        )
        .unwrap();
    commands.recv().await.unwrap();
    first.take_control().unwrap();
    commands.recv().await.unwrap();
    first.input(Input::Release).unwrap();
    let command = commands.recv().await.unwrap();
    let cancelled = session.command_cancelled(command);
    tokio::pin!(cancelled);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut cancelled)
            .await
            .is_err()
    );
    second.take_control().unwrap();
    first.take_control().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), &mut cancelled)
        .await
        .unwrap();
    // The old lease is permanently withdrawn. Test login cancellation with
    // new input admitted after reacquiring control, not the prior command.
    commands.recv().await.unwrap();
    commands.recv().await.unwrap();
    first.input(Input::Release).unwrap();
    let current = commands.recv().await.unwrap();
    let cancelled = session.command_cancelled(current);
    tokio::pin!(cancelled);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut cancelled)
            .await
            .is_err()
    );
    login.0.send_replace(false);
    tokio::time::timeout(std::time::Duration::from_secs(1), &mut cancelled)
        .await
        .unwrap();
}

/// Database-aware forwarding can refuse while the cheap socket projection is still live.
struct ForwardingDenied;
impl Authority for ForwardingDenied {
    fn permits(&self) -> bool {
        true
    }
    fn cancelled(&self) -> infraternal_plugin_api::Operation<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn authorized<'a>(
        &'a self,
        _operation: infraternal_plugin_api::Operation<'a, Result<(), ()>>,
    ) -> infraternal_plugin_api::Operation<'a, Result<(), ()>> {
        Box::pin(async { Err(()) })
    }
}
#[tokio::test]
async fn forwarding_rechecks_originating_login_even_when_its_projection_is_live() {
    let (session, mut commands) =
        Session::new([3; 16], "mac".into(), "owner".into(), Arc::new(Owner));
    let viewer = session
        .attach_authorized("owner".into(), Arc::new(ForwardingDenied))
        .unwrap();
    commands.recv().await.unwrap();
    viewer.take_control().unwrap();
    commands.recv().await.unwrap();
    viewer.input(Input::Release).unwrap();
    let command = commands.recv().await.unwrap();
    assert!(session.command_allowed(command).unwrap());
    let polled = std::sync::atomic::AtomicBool::new(false);
    assert_eq!(
        session
            .command_authorized(
                command,
                Box::pin(async {
                    polled.store(true, std::sync::atomic::Ordering::Relaxed);
                    Ok(())
                })
            )
            .await,
        Err(Error::Forbidden)
    );
    assert!(!polled.load(std::sync::atomic::Ordering::Relaxed));
}

#[tokio::test]
async fn dropping_a_noncontrolling_viewer_cancels_its_pending_packet_write() {
    let (session, mut commands) =
        Session::new([3; 16], "mac".into(), "owner".into(), Arc::new(Owner));
    let viewer = session.attach("owner".into()).unwrap();
    commands.recv().await.unwrap();
    let delivery = viewer.delivery_authority();
    let guard = delivery.clone();
    let (started, receiving) = tokio::sync::oneshot::channel();
    let sending = tokio::spawn(async move {
        guard
            .authorized(Box::pin(async move {
                let _ = started.send(());
                std::future::pending().await
            }))
            .await
    });
    receiving.await.unwrap();
    drop(viewer);
    assert!(!delivery.permits());
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), sending)
            .await
            .unwrap()
            .unwrap(),
        Err(())
    );
    assert!(session.attach("owner".into()).is_ok());
}

#[tokio::test]
async fn passive_viewer_retirement_does_not_cancel_another_controllers_pending_input() {
    let (session, mut commands) =
        Session::new([4; 16], "mac".into(), "owner".into(), Arc::new(Owner));
    let controller = session.attach("owner".into()).unwrap();
    commands.recv().await.unwrap();
    controller.take_control().unwrap();
    commands.recv().await.unwrap();
    controller.input(Input::Release).unwrap();
    let input = commands.recv().await.unwrap();
    let retained = session.clone();
    let (started, receiving) = tokio::sync::oneshot::channel();
    let mut sending = tokio::spawn(async move {
        retained
            .command_authorized(
                input,
                Box::pin(async move {
                    let _ = started.send(());
                    std::future::pending().await
                }),
            )
            .await
    });
    receiving.await.unwrap();
    let passive = session.attach("owner".into()).unwrap();
    drop(passive);
    let interrupted =
        tokio::time::timeout(std::time::Duration::from_millis(100), &mut sending).await;
    session.close();
    if interrupted.is_err() {
        let _ = sending.await;
    }
    assert!(
        interrupted.is_err(),
        "passive viewer retirement cancelled a current controller's input"
    );
}

#[tokio::test]
async fn queued_input_from_prior_controller_lease_is_not_readmitted_after_handover_back() {
    let (session, mut commands) =
        Session::new([91; 16], "mac".into(), "owner".into(), Arc::new(Owner));
    let first = session.attach("owner".into()).unwrap();
    let second = session.attach("owner".into()).unwrap();
    commands.recv().await.unwrap();
    first.take_control().unwrap();
    commands.recv().await.unwrap();
    first
        .input(Input::Key {
            keycode: 36,
            down: true,
            modifiers: 0,
        })
        .unwrap();
    let prior = commands.recv().await.unwrap();
    second.take_control().unwrap();
    assert!(!session.command_allowed(prior).unwrap());
    first.take_control().unwrap();
    // Reacquiring control creates a new lease. Input admitted by the earlier
    // lease must stay withdrawn, even if its viewer identity is current again.
    let readmitted = session.command_allowed(prior).unwrap();
    session.close();
    drop(first);
    drop(second);
    assert!(!readmitted, "queued input inherited a later control lease");
}
