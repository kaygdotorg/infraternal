//! Exercises real duplex staging with remote consumption gated by virtual time.
use super::*;

/// The duplex uploader remains alive for a 240-second sequence of consumed bytes.
#[tokio::test]
async fn duplex_consumption_outlives_the_former_attempt_clock() {
    let f = Fixture::new();
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    let receipts = f.root.join("receipts");
    std::fs::create_dir(&receipts).unwrap();
    let remote = scripted_remote(
        "CAPS - - -\n",
        "dd",
        &format!(
            r"
import pathlib, time
root = pathlib.Path({receipts:?})
total = size('raw')
consumed = 0
out.write(b'STEP upload\nTRANSFER raw\n'); out.flush()
for index in range(24):
    count = total // 24 if index < 23 else total - consumed
    exact(count)
    consumed += count
    out.write(b'PROGRESS ' + str(consumed).encode() + b'\n'); out.flush()
    (root / str(index)).touch()
    while not (root / ('release' + str(index))).exists():
        # sleep: consume the next chunk only after the test advances virtual time.
        time.sleep(.001)
out.write(b'STEP start\nSESSION {id}\n')
",
            receipts = receipts.to_str().unwrap()
        ),
    );
    let session = Arc::new(remote);
    let (_, checked) = Installation::check_channel(session.as_ref(), "true")
        .await
        .unwrap();
    let transaction = Installation::new(session, &f.target, &f.join).unwrap();
    let binary = f.binary.clone();
    let running =
        tokio::spawn(async move { transaction.stage_session_on(&binary, Some(checked)).await });
    tokio::time::pause();
    let guard = std::time::Instant::now() + INSTALL_HANG;
    for index in 0..24 {
        while !receipts.join(index.to_string()).exists() {
            assert!(
                !running.is_finished(),
                "staging ended before consumption receipt {index}"
            );
            assert!(std::time::Instant::now() < guard, "duplex fixture wedged");
            tokio::task::yield_now().await;
        }
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        std::fs::write(receipts.join(format!("release{index}")), []).unwrap();
    }
    tokio::time::resume();
    let (actual, bridge) = running.await.unwrap().unwrap();
    assert_eq!(actual, id);
    bridge.write(b"same-channel\n").await.unwrap();
    assert_eq!(bridge.line(64).await.unwrap(), b"same-channel\n");
}
