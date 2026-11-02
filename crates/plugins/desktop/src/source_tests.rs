//! Controls cleanup scheduling to prove a retired source generation cannot remove a freshly prepared UUID [D198,D232], #146.
#![allow(clippy::unwrap_used)]
use super::*;
use crate::protocol::{Size, Target};
use std::{future::Future, task::Poll};

fn start() -> Start {
    Start {
        target: Target::Screen { display_id: 1 },
        size: Size {
            width: 960,
            height: 600,
            canvas_width: 960.0,
            canvas_height: 600.0,
            backing_scale: 1.0,
        },
    }
}

#[tokio::test]
async fn duplicate_stop_cannot_remove_a_new_uuid_generation() {
    let bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(1);
    bridge.prepare(id, start()).unwrap();
    let (released, cleanup) = oneshot::channel();
    let worker = Worker::new(
        watch::channel(false).0,
        None,
        None,
        tokio::spawn(async move {
            cleanup.await.unwrap();
            Outcome {
                output: Ok(Value::Null),
                cleanup: Ok(()),
            }
        }),
    );
    bridge
        .0
        .state
        .lock()
        .unwrap()
        .prepared
        .get_mut(&id)
        .unwrap()
        .worker = Some(worker);
    let mut first = Box::pin(bridge.stop(id));
    let mut duplicate = Box::pin(bridge.stop(id));
    // Poll both callers into the same cleanup before completing it. Keeping the
    // duplicate unpolled after the first completes makes UUID reuse deterministic.
    std::future::poll_fn(|context| {
        assert!(first.as_mut().poll(context).is_pending());
        assert!(duplicate.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    released.send(()).unwrap();
    first.await.unwrap();
    let mut replacement = start();
    replacement.target = Target::Screen { display_id: 2 };
    bridge.prepare(id, replacement.clone()).unwrap();
    duplicate.await.unwrap();
    assert!(bridge.status_value(Some(id)).is_ok());
    assert!(bridge.prepare(id, replacement).is_ok());
    assert_eq!(bridge.status_value(None).unwrap()["prepared_count"], 1);
}

#[tokio::test]
async fn replacement_leg_requires_successful_joined_previous_cleanup() {
    let bridge = SourceBridge::new("missing-runtime".into(), "missing-helper".into(), 2);
    bridge.set_enabled(true).await.unwrap();
    let id = Uuid::from_u128(1);
    bridge.prepare(id, start()).unwrap();
    let worker = Worker::new(
        watch::channel(false).0,
        None,
        None,
        tokio::spawn(async {
            Outcome {
                output: Err(PluginError::Rejected),
                cleanup: Err(PluginError::Rejected),
            }
        }),
    );
    assert!(worker.retire().await.is_err());
    assert!(worker.finished());
    bridge
        .0
        .state
        .lock()
        .unwrap()
        .prepared
        .get_mut(&id)
        .unwrap()
        .worker = Some(worker);
    assert!(bridge.retire_previous(id).await.is_err());
}
