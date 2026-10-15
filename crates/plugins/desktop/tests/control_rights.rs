//! Control refusal and queued revocation checks for all desktop input forms on the real server session [D208,D232].
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_desktop::session::{AccessRules, Error, HostCommand, Session};
use infraternal_protocol::desktop::Input;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct Rights(AtomicBool);
impl AccessRules for Rights {
    fn may_view(&self, user: &str, host: &str, owner: &str) -> bool {
        host == "mac" && owner == "owner" && matches!(user, "owner" | "reader")
    }
    fn may_control(&self, user: &str, host: &str, owner: &str) -> bool {
        self.may_view(user, host, owner) && user == "owner" && self.0.load(Ordering::Acquire)
    }
}

#[tokio::test]
async fn watching_does_not_confer_control_and_revocation_fences_queued_input() {
    let rights = Arc::new(Rights(AtomicBool::new(true)));
    let (session, mut commands) =
        Session::new([146; 16], "mac".into(), "owner".into(), rights.clone());
    assert!(matches!(
        session.attach("stranger".into()),
        Err(Error::Forbidden)
    ));
    let owner = session.attach("owner".into()).unwrap();
    let reader = session.attach("reader".into()).unwrap();
    assert!(matches!(commands.recv().await, Some(HostCommand::Keyframe)));
    assert!(matches!(reader.take_control(), Err(Error::Forbidden)));
    let inputs = [
        Input::Mouse {
            x: 500_000,
            y: 500_000,
            button: 0,
            state: 1,
            modifiers: 0,
        },
        Input::Scroll {
            x: 500_000,
            y: 500_000,
            dx: 0,
            dy: 10,
            modifiers: 0,
        },
        Input::Key {
            keycode: 0,
            down: true,
            modifiers: 8,
        },
        Input::Text {
            scalar: 0x0001_f600,
        },
    ];
    assert!(matches!(
        owner.input(Input::Control { active: true }),
        Err(Error::Forbidden)
    ));
    for input in inputs {
        assert!(matches!(reader.input(input), Err(Error::Forbidden)));
        assert!(
            matches!(owner.input(input), Err(Error::Forbidden)),
            "input requires taking control first"
        );
    }
    assert!(commands.try_recv().is_err());
    owner.take_control().unwrap();
    let visible = commands.recv().await.unwrap();
    assert!(matches!(visible, HostCommand::Control { .. }));
    assert_eq!(session.control_command().unwrap(), Some(visible));
    assert!(session.command_allowed(visible).unwrap());
    assert!(matches!(
        owner.input(Input::Control { active: false }),
        Err(Error::Forbidden)
    ));
    for input in inputs {
        owner.input(input).unwrap();
    }
    rights.0.store(false, Ordering::Release);
    assert!(!session.command_allowed(visible).unwrap());
    assert_eq!(session.control_command().unwrap(), None);
    for _ in inputs {
        assert!(
            !session
                .command_allowed(commands.recv().await.unwrap())
                .unwrap()
        );
    }
    assert!(matches!(owner.take_control(), Err(Error::Forbidden)));
    assert!(matches!(
        owner.input(Input::Text { scalar: 32 }),
        Err(Error::Forbidden)
    ));
    drop(owner);
    assert!(matches!(
        commands.recv().await,
        Some(HostCommand::ReleaseInput)
    ));
}
