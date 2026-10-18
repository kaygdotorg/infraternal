//! Proves decoding and hashing make progress before the compressed image's final bytes arrive.
use super::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "The real pipeline fixture keeps its two bounded observers together."
)]
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
"""Hold the compressed tail until both decode and hash have consumed the prefix."""
import os, sys, time
from pathlib import Path
remaining = int(sys.argv[sys.argv.index('-c') + 1])
sent = 0
observed = False
while remaining:
    chunk = os.read(0, min(65536, remaining))
    if not chunk:
        sys.exit(3)
    remaining -= len(chunk)
    sent += len(chunk)
    view = memoryview(chunk)
    while view:
        view = view[os.write(1, view):]
    # Hold past one full decoder input block (128 KiB plus a frame header):
    # stopping exactly at 128 KiB deadlocks the decoder whenever the payload
    # starts page-aligned in the pipe, whatever the setup script's length.
    if not observed and sent >= 196608 and remaining:
        observed = True
        deadline = time.monotonic() + 10
        payload = Path({payload:?})
        while not (Path({hashed:?}).exists() and payload.exists() and payload.stat().st_size > 0):
            if time.monotonic() >= deadline:
                sys.exit(88)
            time.sleep(0.01)
        Path({released:?}).touch()
"#,
            payload = f.base().join(".bootstrap-lock/payload").to_str().unwrap(),
            hashed = hashed.to_str().unwrap(),
            released = released.to_str().unwrap(),
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
    .unwrap_or_else(|_| panic!("streaming fixture exceeded its bounded wait"));
    assert!(
        result.is_ok(),
        "streaming transfer stalled or refused; hashed={} staged_bytes={:?}",
        hashed.exists(),
        std::fs::metadata(f.base().join(".bootstrap-lock/payload")).map(|m| m.len())
    );
    let (actual, bridge) = result.unwrap();
    assert_eq!(actual, id);
    assert!(released.exists(), "the reader never held a nonempty tail");
    assert_eq!(
        std::fs::read(f.base().join(".bootstrap-lock/payload")).unwrap(),
        binary
    );
    bridge.write(b"same-channel\n").await.unwrap();
    assert_eq!(bridge.line(64).await.unwrap(), b"same-channel\n");
    drop(bridge);
    transaction.rollback().await.unwrap();
}
