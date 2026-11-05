//! Proves real same-PID sealed exec and late-refusal recovery with a live listener and memory-only CA handoff [217,224], #157.
use super::*;
use crate::restart_binary::fixture::RESTART_TEST_HANG_BOUND;
use infraternal_server::{
    ca::{CaKeySource, CaMaterial},
    ca_memory::MemoryCaSource,
};
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    pkey::PKey,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage},
    },
};
use std::sync::Arc;

/// Restart fixtures must work from an oversized debug image without raising production's limit.
/// Pad past the current running-image bound so both refusal and fixture recovery
/// stay covered when development binaries require a different bound.
/// Pad a staging inode and publish a separate executable: sibling tests may fork
/// while the staging writer is open, so closing our descriptor alone cannot make it executable.
#[cfg(target_os = "linux")]
#[test]
fn oversized_debug_image_does_not_limit_restart_fixtures() {
    use crate::restart_binary::fixture::{Directory, Signed};
    use std::os::unix::process::CommandExt;
    const NAME: &str =
        "restart::recovery_tests::oversized_debug_image_does_not_limit_restart_fixtures";
    if std::env::var_os("INFRATERNAL_OVERSIZED_RESTART_BOUND").is_some() {
        assert!(crate::restart_binary::Opened::running().is_err());
        println!("production oversized running-image refusal: preserved");
        return;
    }
    let directory = Directory::new();
    let image = Signed::image(directory.0.join("oversized-debug-staging"));
    std::fs::OpenOptions::new()
        .write(true)
        .open(&image.path)
        .unwrap()
        .set_len(crate::restart_binary::RUNNING_IMAGE_LIMIT + 1)
        .unwrap();
    let executable = directory.0.join("oversized-debug-image");
    crate::test_executable::copy(&image.path, &executable, 0o700);
    // ELF ignores trailing padding; strip removes it along with debug sections.
    // A sparse extension crosses the real bound without manufacturing debug symbols.
    for check_bound in [true, false] {
        let mut command = std::process::Command::new(&executable);
        if check_bound {
            command
                .args(["--exact", NAME, "--nocapture"])
                .env("INFRATERNAL_OVERSIZED_RESTART_BOUND", "1");
        } else {
            command.args([
                "restart::",
                "--skip",
                NAME,
                "--test-threads=2",
                "--nocapture",
            ]);
        }
        // A failing nested suite can exceed a pipe buffer; collect its logs in private files.
        let stdout = directory.0.join(format!("{check_bound}.stdout"));
        let stderr = directory.0.join(format!("{check_bound}.stderr"));
        let child = command
            .stdin(std::process::Stdio::null())
            .stdout(std::fs::File::create(&stdout).unwrap())
            .stderr(std::fs::File::create(&stderr).unwrap())
            .process_group(0)
            .spawn()
            .unwrap();
        let output = super::tests::bounded_output(child, Duration::from_secs(300), NAME);
        let stdout = std::fs::read_to_string(stdout).unwrap();
        let stderr = std::fs::read_to_string(stderr).unwrap();
        assert!(
            output.status.success(),
            "check_bound={check_bound}\n{stdout}\n{stderr}"
        );
        println!("{stdout}");
    }
}

fn material() -> (CaMaterial, X509) {
    let key = PKey::generate_ed25519().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "replacement fixture CA")
        .unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    certificate
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::from_unix(2_000_000_000).unwrap())
        .unwrap();
    certificate
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .unwrap(),
        )
        .unwrap();
    certificate
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    certificate.sign(&key, MessageDigest::null()).unwrap();
    let issuer = certificate.build();
    (CaMaterial::new(key, issuer.clone()), issuer)
}

#[cfg(target_os = "linux")]
#[test]
/// Verify real execution and late recovery using compact images, private state, and owned children.
fn verified_exec_and_late_refusal_preserve_listener_and_ca() {
    use std::os::unix::{ffi::OsStrExt, process::CommandExt};
    const NAME: &str =
        "restart::recovery_tests::verified_exec_and_late_refusal_preserve_listener_and_ca";
    if let Some(directory) = std::env::var_os("INFRATERNAL_RECOVERY_FIXTURE") {
        let directory = PathBuf::from(directory);
        let address = std::env::var("INFRATERNAL_RECOVERY_ADDRESS").unwrap();
        let successor = std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_bytes()
            .starts_with(b"/memfd:");
        if successor {
            let previous: u32 = std::fs::read_to_string(directory.join("ready"))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                previous,
                std::process::id(),
                "replacement and recovery must retain the original PID"
            );
            let issuer =
                X509::from_der(&std::fs::read(directory.join("issuer.der")).unwrap()).unwrap();
            let source = MemoryCaSource::cold_start_with_system_https(issuer);
            let received = infraternal_server::ca_handoff::receive_stdin();
            if nix::unistd::Uid::effective().is_root() {
                received.unwrap().install(&source).unwrap();
                assert!(
                    source.load().is_ok(),
                    "CA must remain unlocked after replacement or recovery"
                );
            } else {
                assert!(
                    received.is_err(),
                    "rootless execution must retain cold compatibility"
                );
                assert!(source.load().is_err());
            }
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let listener = tokio::net::TcpListener::bind(&address).await.unwrap();
                std::fs::write(directory.join("recovered"), b"ready").unwrap();
                let (mut stream, _) = listener.accept().await.unwrap();
                stream.write_all(b"alive\n").await.unwrap();
            });
            println!(
                "RECOVERY same_pid=true ca_unlocked={} serving=true",
                nix::unistd::Uid::effective().is_root()
            );
            return;
        }
        let (material, issuer) = material();
        std::fs::write(directory.join("issuer.der"), issuer.to_der().unwrap()).unwrap();
        let source = Arc::new(MemoryCaSource::cold_start_with_system_https(issuer));
        infraternal_server::ca_bootstrap::install(&source, material).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind(&address).await.unwrap();
            runtime.spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    stream.write_all(b"alive\n").await.unwrap();
                }
            });
        });
        let signed = crate::restart_binary::fixture::Signed::image(directory.join("candidate"));
        let admitted = signed.open().unwrap();
        let mut replacement = Replacement::new(admitted, Some(source.as_ref())).unwrap();
        // Mutation after admission must not change the successful execution image.
        std::fs::write(&signed.path, b"changed after verification").unwrap();
        if std::env::var("INFRATERNAL_RECOVERY_CASE").unwrap() == "late" {
            // Simulate a late kernel refusal after the authentic image passed its
            // real probe. The retained recovery image and second CA frame stay intact.
            replacement.binary.image.file = std::fs::File::open("/dev/null").unwrap();
        }
        // The admission/fixture phase may hash a large unoptimized debug image.
        // Start the bounded recovery observation only after that work, while the
        // old listener is still live; the production shutdown bound is unchanged.
        std::fs::write(directory.join("ready"), std::process::id().to_string()).unwrap();
        let outcome = replace(runtime, replacement, true);
        panic!("verified replacement or recovery returned: {outcome:?}");
    }
    for case in ["replacement", "late"] {
        let fixture = crate::restart_binary::fixture::Directory::new();
        let directory = fixture.0.clone();
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut child = crate::restart_binary::fixture::ChildGuard::new(
            std::process::Command::new(crate::restart_binary::fixture::stripped_test_image(
                &std::env::current_exe().unwrap(),
            ))
            .args(["--exact", NAME, "--nocapture"])
            .env("INFRATERNAL_RECOVERY_FIXTURE", &directory)
            .env("INFRATERNAL_RECOVERY_ADDRESS", address.to_string())
            .env("INFRATERNAL_RECOVERY_CASE", case)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .process_group(0)
            .spawn()
            .unwrap(),
        );
        let preparation_deadline = std::time::Instant::now() + Duration::from_secs(300);
        let mut recovery_deadline = None;
        while !directory.join("ready").exists() || !directory.join("recovered").exists() {
            if directory.join("ready").exists() {
                recovery_deadline
                    .get_or_insert_with(|| std::time::Instant::now() + RESTART_TEST_HANG_BOUND);
            }
            if child.process().try_wait().unwrap().is_some()
                || std::time::Instant::now() >= recovery_deadline.unwrap_or(preparation_deadline)
            {
                let _ = child.process().kill();
                let output = child.output();
                let _ = std::fs::remove_dir_all(&directory);
                panic!(
                    "{case} did not recover: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(RESTART_TEST_HANG_BOUND))
            .unwrap();
        let mut alive = [0; 6];
        std::io::Read::read_exact(&mut stream, &mut alive).unwrap();
        assert_eq!(&alive, b"alive\n");
        let output_deadline = std::time::Instant::now() + RESTART_TEST_HANG_BOUND;
        loop {
            if child.process().try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= output_deadline {
                let _ = child.process().kill();
                let output = child.output();
                panic!(
                    "{case} child did not exit within its hang bound:\n{}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.output();
        std::fs::remove_dir_all(&directory).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        println!(
            "VERIFIED_EXEC case={case} {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
