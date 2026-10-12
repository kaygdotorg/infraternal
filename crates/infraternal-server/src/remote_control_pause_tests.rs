//! Verifies paused native control preserves a cancelled packet and resumes FIFO exactly once [128,215], #129.
use super::*;

#[tokio::test]
async fn cancelled_control_packet_survives_pause_and_resumes_before_queued_sibling() {
    let (link, control, _listener, _endpoint, _peer) = super::super::native_link_pair().await;
    let (ready, held) = tokio::sync::oneshot::channel();
    let (release, release_rx) = tokio::sync::oneshot::channel();
    let held_link = link.clone();
    let holder = tokio::spawn(async move {
        held_link.hold_writer_map(ready, release_rx).await;
    });
    held.await.unwrap();
    for call_id in [91, 92] {
        Transmit::default()
            .send(
                &control,
                0,
                &Frame::Result {
                    call_id,
                    ok: true,
                    json: b"{}",
                },
            )
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while !link.control_packet_ready().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let mut received = bytes::BytesMut::new();
    let mut scratch = [0; 4096];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err()
    );
    assert_eq!(link.native_delivery_counts().unwrap()[4], Some(1));
    link.control_read_ready(false);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err()
    );
    release.send(()).unwrap();
    holder.await.unwrap();
    // The map is now free: cancellation must still preserve the paused frame,
    // and neither it nor its queued sibling may escape control backpressure.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err()
    );
    assert!(received.is_empty());
    assert_eq!(link.native_delivery_counts().unwrap()[4], Some(1));
    link.control_read_ready(true);
    for expected in [91, 92] {
        tokio::time::timeout(
            Duration::from_millis(100),
            link.read(&mut received, &mut scratch),
        )
        .await
        .expect("resuming must deliver the held control frame before its queued sibling")
        .unwrap();
        let decoded = infraternal_protocol::decode_muxed_frame(&received).unwrap();
        assert!(matches!(decoded.frame, Frame::Result { call_id, .. } if call_id == expected));
        received.clear();
    }
    assert!(
        tokio::time::timeout(
            Duration::from_millis(25),
            link.read(&mut received, &mut scratch)
        )
        .await
        .is_err(),
        "held control frames must be delivered only once"
    );
}
