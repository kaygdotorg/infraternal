//! Proves decoding and hashing make progress before the compressed image's final bytes arrive.
use super::*;

#[tokio::test]
async fn decoded_image_and_hash_advance_before_the_transfer_tail_is_released() {
    let f = Fixture::new();
    executable(
        &f.root.join("tools/sh"),
        &format!(
            "#!/usr/bin/python3\nimport os,sys\nargs=sys.argv[1:]\nif len(args)>1 and args[0]=='-c': args[1]=args[1].replace('$HOME', {root:?})\nos.execv('/bin/sh',['sh',*args])\n",
            root = f.root.to_str().unwrap()
        ),
    );
    // Keep the installed decoder, staging tee and digest implementation.
    let hashed = f.root.join("hash-received-byte");
    let released = f.root.join("transfer-tail-released");
    let input_progress = f.root.join("compressed-input-progress");
    executable(
        &f.root.join("tools/sha256sum"),
        &format!(
            r#"#!/usr/bin/python3
"""Mark real streaming hash input, preserving the canonical digest receipt."""
import os, subprocess, sys
from pathlib import Path
if len(sys.argv) > 1:
    os.execv('/usr/bin/sha256sum', ['sha256sum', *sys.argv[1:]])
first = os.read(0, 1)
child = subprocess.Popen(['/usr/bin/sha256sum'], stdin=subprocess.PIPE)
child.stdin.write(first)
child.stdin.flush()
if first:
    Path({hashed:?}).touch()
while True:
    chunk = os.read(0, 65536)
    if not chunk:
        break
    child.stdin.write(chunk)
child.stdin.close()
sys.exit(child.wait())
"#,
            hashed = hashed.to_str().unwrap()
        ),
    );
    executable(
        &f.root.join("tools/head"),
        &format!(
            r#"#!/usr/bin/python3
"""Hold a bounded compressed tail until both decode and hash advance."""
import os, sys, time
from pathlib import Path
remaining = int(sys.argv[sys.argv.index('-c') + 1])
total = remaining
tail = min(16384, max(1, total // 8))
prefix = total - tail
sent = 0
observed = False
payload = Path({payload:?})
hashed = Path({hashed:?})
released = Path({released:?})
input_progress = Path({input_progress:?})
while remaining:
    if not observed and sent == prefix:
        # The Rust timeout bounds this wait; keep the reserved tail unread.
        while not (hashed.exists() and payload.exists() and payload.stat().st_size > 0):
            time.sleep(0.01)
        observed = True
        released.write_text("%d:%d" % (remaining, payload.stat().st_size))
    limit = min(65536, remaining)
    if not observed:
        limit = min(limit, prefix - sent)
    chunk = os.read(0, limit)
    if not chunk:
        sys.exit(3)
    remaining -= len(chunk)
    sent += len(chunk)
    view = memoryview(chunk)
    while view:
        view = view[os.write(1, view):]
    input_progress.write_text("%d/%d" % (sent, total))
    # The decoder's block boundary varies with the encoded image. Check the
    # real consumers after each bounded write, while the encoded tail remains.
    if not observed and hashed.exists() and payload.exists() and payload.stat().st_size > 0:
        if remaining > tail:
            observed = True
            released.write_text("%d:%d" % (remaining, payload.stat().st_size))
"#,
            payload = f.base().join(".bootstrap-lock/payload").to_str().unwrap(),
            hashed = hashed.to_str().unwrap(),
            released = released.to_str().unwrap(),
            input_progress = input_progress.to_str().unwrap(),
        ),
    );
    let id = uuid::Uuid::new_v4();
    large_fixture_binary(&f, id);
    // A deterministic public sample keeps the compressed image larger than a
    // pipe buffer, so completing a tiny upload cannot accidentally pass.
    let mut binary = std::fs::read(&f.binary).unwrap();
    let mut sample = 1_u32;
    let mut suffix = String::from("\n#");
    for _ in 0..65_536 {
        sample ^= sample << 13;
        sample ^= sample >> 17;
        sample ^= sample << 5;
        write!(suffix, "{sample:08x}").unwrap();
    }
    binary.extend_from_slice(suffix.as_bytes());
    binary.push(b'\n');
    std::fs::write(&f.binary, &binary).unwrap();
    let session = Arc::new(SingleCheckChannel {
        local: Local {
            root: f.root.clone(),
        },
        streams: std::sync::atomic::AtomicUsize::new(0),
    });
    // The normal check chooses the installed codec. This verifies progress,
    // without assigning a build-host latency to either decoder.
    let check = "printf 'INFRATERNAL_CHECK_V1\\nLinux\\nx86_64\\nsystemd\\n1002\\nno\\nyes\\nyes\\nno\\nINFRATERNAL_SETUP_CLEAR\\n'";
    let (_, checked) = Installation::check_channel(session.as_ref(), check)
        .await
        .unwrap();
    let transaction = Installation::new(session, &f.target, &f.join).unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        transaction.stage_session_on(&f.binary, Some(checked)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "streaming fixture exceeded its bounded wait: hashed={} released={:?} input_progress={:?} staged_bytes={:?} expected_bytes={}",
            hashed.exists(),
            std::fs::read_to_string(&released),
            std::fs::read_to_string(&input_progress),
            std::fs::metadata(f.base().join(".bootstrap-lock/payload")).map(|m| m.len()),
            binary.len()
        )
    });
    assert!(
        result.is_ok(),
        "streaming transfer failed: error={:?} hashed={} released={:?} input_progress={:?} staged_bytes={:?} expected_bytes={}",
        result.as_ref().err(),
        hashed.exists(),
        std::fs::read_to_string(&released),
        std::fs::read_to_string(&input_progress),
        std::fs::metadata(f.base().join(".bootstrap-lock/payload")).map(|m| m.len()),
        binary.len()
    );
    let (actual, bridge) = result.unwrap();
    assert_eq!(actual, id);
    let released_state = std::fs::read_to_string(&released).unwrap_or_else(|_| {
        panic!(
            "the compressed tail completed before stage/hash progress: input_progress={:?} staged_bytes={:?}",
            std::fs::read_to_string(&input_progress),
            std::fs::metadata(f.base().join(".bootstrap-lock/payload")).map(|m| m.len())
        )
    });
    let (remaining, staged) = released_state.split_once(':').unwrap();
    assert!(
        remaining.parse::<u64>().unwrap() > 0,
        "the reader consumed the compressed tail before observing progress"
    );
    assert!(
        staged.parse::<u64>().unwrap() > 0,
        "the reader released the tail before staging a decoded prefix"
    );
    assert_eq!(
        std::fs::read(f.base().join(".bootstrap-lock/payload")).unwrap(),
        binary
    );
    bridge.write(b"same-channel\n").await.unwrap();
    assert_eq!(bridge.line(64).await.unwrap(), b"same-channel\n");
    drop(bridge);
    transaction.rollback().await.unwrap();
}
