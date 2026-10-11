//! Exercises the real socketpair, OpenSSL validation and a deterministic malformed-frame property corpus [168][217], #154.

use super::*;
use crate::ca_memory::AdministratorCaUnlock;

struct Unlocked(CaMaterial);
impl AdministratorCaUnlock for Unlocked {
    fn unlock(&self) -> Result<CaMaterial, CaError> {
        Ok(self.0.clone())
    }
}
fn source() -> MemoryCaSource {
    let material = crate::ca::tests::test_material();
    let source = MemoryCaSource::cold_start(material.issuer().clone());
    source.unlock_from(&Unlocked(material)).unwrap();
    source
}

#[test]
fn socketpair_preserves_unlock_and_cold_start_still_locks() {
    let source = source();
    let socket = prepare(&source).unwrap();
    let material = receive(&socket).unwrap();
    let successor = MemoryCaSource::cold_start(source.issuer().unwrap());
    successor.install(material).unwrap();
    assert!(crate::ca::CertificateAuthority::from_source(&successor).is_ok());
    assert!(!*successor.subscribe_locked().borrow());
    assert!(
        MemoryCaSource::cold_start(source.issuer().unwrap())
            .load()
            .is_err()
    );
}

#[test]
fn truncated_wrong_generation_and_wrong_version_leave_successor_locked() {
    let source = source();
    let frame = encode(&source.load().unwrap()).unwrap();
    let cold = MemoryCaSource::cold_start(source.issuer().unwrap());
    for end in 0..frame.len() {
        assert!(parse(&frame[..end]).is_err());
    }
    let mut wrong = Zeroizing::new(frame.to_vec());
    wrong[4] = 2;
    assert!(parse(&wrong).is_err());
    let different = crate::ca::tests::test_material();
    assert!(cold.install(different).is_err());
    assert!(cold.load().is_err());
    let (writer, reader) = UnixStream::pair().unwrap();
    drop(writer);
    assert!(receive(&reader).is_err());
}

#[test]
fn parser_property_corpus_is_bounded_and_never_accepts_trailing_bytes() {
    let source = source();
    let frame = encode(&source.load().unwrap()).unwrap();
    for length in 0..=4096 {
        let mut data = Zeroizing::new(vec![0; length]);
        for (offset, byte) in data.iter_mut().enumerate() {
            *byte = u8::try_from((offset * 31 + length * 17) % 256).unwrap();
        }
        assert!(parse(&data).is_err());
    }
    for offset in 0..frame.len() {
        let mut data = Zeroizing::new(frame.to_vec());
        data[offset] ^= 0xff;
        if let Ok(material) = parse(&data) {
            // Some certificate fields may vary while retaining a valid signature;
            // the install boundary must still require exact retained trust.
            assert!(
                MemoryCaSource::cold_start(source.issuer().unwrap())
                    .install(material)
                    .is_err()
            );
        }
    }
    let mut trailing = Zeroizing::new(frame.to_vec());
    trailing.push(0);
    assert!(parse(&trailing).is_err());
}

#[test]
fn exec_child() {
    use std::os::unix::process::CommandExt;
    let Ok(stage) = std::env::var("INFRATERNAL_HANDOFF_TEST_STAGE") else {
        return;
    };
    if let Some(next) = stage.strip_prefix("send-") {
        let source = source();
        let socket = if matches!(next, "truncated" | "wrong-version") {
            let mut frame = encode(&source.load().unwrap()).unwrap();
            if next == "truncated" {
                frame.truncate(HEADER - 1);
            } else {
                frame[4] = 2;
            }
            let (mut writer, reader) = UnixStream::pair().unwrap();
            writer.write_all(&frame).unwrap();
            drop(writer);
            reader
        } else {
            prepare(&source).unwrap()
        };
        let issuer = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            source.issuer().unwrap().to_der().unwrap(),
        );
        let error = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ca_handoff::tests::exec_child", "--nocapture"])
            .env("INFRATERNAL_HANDOFF_TEST_STAGE", next)
            // The certificate is public; private material exists only on stdin.
            .env("INFRATERNAL_HANDOFF_TEST_PUBLIC_ISSUER", issuer)
            .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
                socket,
            )))
            .exec();
        panic!("exec failed: {}", error.kind());
    }
    if stage == "foreign" {
        let input = std::io::stdin();
        assert!(receive(&input).is_err());
        return;
    }
    let public = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        std::env::var("INFRATERNAL_HANDOFF_TEST_PUBLIC_ISSUER").unwrap(),
    )
    .unwrap();
    let cold = MemoryCaSource::cold_start(X509::from_der(&public).unwrap());
    if stage == "killed" {
        let input = std::io::stdin();
        let peer = getsockopt(&input, sockopt::PeerCredentials).unwrap();
        assert_eq!(peer.pid(), nix::unistd::Pid::this().as_raw());
        let mut partial = Zeroizing::new([0u8; 26]);
        assert_eq!(nix::unistd::read(&input, &mut *partial).unwrap(), 26);
        nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGKILL)
            .unwrap();
        unreachable!();
    }
    if matches!(stage.as_str(), "truncated" | "wrong-version" | "cold") {
        assert!(accept_stdin(&cold).is_err());
        assert!(cold.load().is_err());
        assert!(*cold.subscribe_locked().borrow());
        return;
    }
    accept_stdin(&cold).unwrap();
    assert!(crate::ca::CertificateAuthority::from_source(&cold).is_ok());
    assert!(!*cold.subscribe_locked().borrow());
}

#[test]
fn real_exec_retains_unlock_but_another_process_cannot_import_the_channel() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ca_handoff::tests::exec_child", "--nocapture"])
        .env("INFRATERNAL_HANDOFF_TEST_STAGE", "send-receive")
        .output()
        .unwrap();
    assert!(output.status.success(), "real exec child failed");
    let socket = prepare(&source()).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ca_handoff::tests::exec_child", "--nocapture"])
        .env("INFRATERNAL_HANDOFF_TEST_STAGE", "foreign")
        .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
            socket,
        )))
        .output()
        .unwrap();
    assert!(output.status.success(), "foreign process refusal failed");
}

#[test]
fn real_exec_failures_and_killed_receiver_never_unlock_a_cold_successor() {
    use std::os::unix::process::ExitStatusExt;
    for stage in ["send-truncated", "send-wrong-version", "send-killed"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ca_handoff::tests::exec_child", "--nocapture"])
            .env("INFRATERNAL_HANDOFF_TEST_STAGE", stage)
            .output()
            .unwrap();
        if stage == "send-killed" {
            assert_eq!(output.status.signal(), Some(9));
        } else {
            assert!(
                output.status.success(),
                "invalid frame imported during exec"
            );
        }
    }
    let issuer = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        source().issuer().unwrap().to_der().unwrap(),
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "ca_handoff::tests::exec_child", "--nocapture"])
        .env("INFRATERNAL_HANDOFF_TEST_STAGE", "cold")
        .env("INFRATERNAL_HANDOFF_TEST_PUBLIC_ISSUER", issuer)
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cold successor unexpectedly unlocked"
    );
}

#[test]
fn failed_null_open_or_duplication_closes_private_stdin() {
    const NAME: &str = "ca_handoff::tests::failed_null_open_or_duplication_closes_private_stdin";
    if let Ok(stage) = std::env::var("INFRATERNAL_NULL_FAILURE_TEST") {
        let (sender, receiver) = UnixStream::pair().unwrap();
        nix::unistd::dup2_stdin(&receiver).unwrap();
        drop(sender);
        drop(receiver);
        let result = if stage == "open" {
            clear_stdin(
                || Err(std::io::ErrorKind::PermissionDenied.into()),
                nix::unistd::dup2_stdin,
            )
        } else {
            clear_stdin(
                || std::fs::File::open("/dev/null"),
                |_| Err(nix::errno::Errno::EBADF),
            )
        };
        assert!(result.is_err());
        assert_eq!(
            nix::fcntl::fcntl(std::io::stdin(), nix::fcntl::FcntlArg::F_GETFD),
            Err(nix::errno::Errno::EBADF),
            "cleanup failure must close private fd0"
        );
        return;
    }
    for stage in ["open", "dup"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"])
            .env("INFRATERNAL_NULL_FAILURE_TEST", stage)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn serialized_seed_frame_is_locked_and_excluded_from_core_dumps() {
    let frame = encode(&source().load().unwrap()).unwrap();
    let pointer = frame.as_ptr() as usize;
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut selected = false;
    for line in maps.lines() {
        if let Some((start, end)) = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .split_once('-')
            && let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            )
        {
            selected = start <= pointer && pointer < end;
        }
        if selected && line.starts_with("VmFlags:") {
            assert!(
                line.split_whitespace().any(|flag| flag == "lo"),
                "seed frame must be mlocked"
            );
            assert!(
                line.split_whitespace().any(|flag| flag == "dd"),
                "seed frame must be MADV_DONTDUMP"
            );
            return;
        }
    }
    panic!("frame mapping missing from smaps");
}
