//! Real pipe-to-mTLS replacement retains SSH until the original writer acknowledges reattachment (D255).

use super::*;
use crate::embedded::TerminalOutput;
use infraternal_plugin_ssh::{
    duplex::Duplex,
    model::Failure,
    transport::{CommandOutput, Input, Operation, SshSession},
};
use std::{fmt::Write, path::PathBuf};

struct Master(Arc<std::sync::atomic::AtomicBool>);
impl Drop for Master {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl SshSession for Master {
    fn run<'a>(&'a self, _: &'a str, _: Input<'a>) -> Operation<'a, CommandOutput> {
        Box::pin(async {
            Err(Failure::unsupported(
                "The fixture master never starts another command.",
            ))
        })
    }
}
fn hex(bytes: &[u8]) -> String {
    let mut output = String::new();
    for byte in bytes {
        write!(output, "{byte:02x}").unwrap();
    }
    output
}
fn alive(pid: u32) -> bool {
    std::fs::read(format!("/proc/{pid}/stat"))
        .is_ok_and(|record| infraternal_agent::sessions::process_birth_ticks(&record).is_some())
}
fn pipe_peer(pidfile: &std::path::Path) -> Duplex {
    pipe_peer_greeting(pidfile, 0, &[])
}
fn pipe_peer_greeting(pidfile: &std::path::Path, caps: u64, suffix: &[u8]) -> Duplex {
    let mut hello = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps,
            client_info: "pipe fixture",
        },
        &mut hello,
    )
    .unwrap();
    hello.extend_from_slice(suffix);
    pipe_peer_bytes(pidfile, &hello)
}
fn pipe_peer_bytes(pidfile: &std::path::Path, hello: &[u8]) -> Duplex {
    let mut ack = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(2, &Frame::Ack { in_seq_acked: 0 }, &mut ack)
        .unwrap();
    // The scripted peer tests transport lifetime, while the separate real-binary
    // oracle proves actual shim ownership and byte replay through this actor.
    let script = r"import os,pathlib,sys
pathlib.Path(sys.argv[1]).write_text(str(os.getpid()))
sys.stdout.buffer.write(bytes.fromhex(sys.argv[2])); sys.stdout.buffer.flush()
def integer():
 v=0; shift=0
 while True:
  b=sys.stdin.buffer.read(1)
  if not b: raise EOFError()
  v|=(b[0]&127)<<shift
  if b[0]<128: return v
  shift+=7
try:
 while True:
  stream=integer(); body=sys.stdin.buffer.read(integer())
  if body and body[0]==0x16:
   sys.stdout.buffer.write(bytes.fromhex(sys.argv[3])); sys.stdout.buffer.flush()
except EOFError: pass
";
    let mut command = tokio::process::Command::new("python3");
    command
        .arg("-c")
        .arg(script)
        .arg(pidfile)
        .arg(hex(hello))
        .arg(hex(&ack));
    Duplex::spawn(&mut command).unwrap()
}

/// Reuse the real pipe transport for bootstrap admission-order regressions.
pub(crate) async fn pipe_link(pidfile: &std::path::Path) -> RemoteLink {
    RemoteLink::ssh(pipe_peer(pidfile), Arc::new(Master(Arc::default())))
        .await
        .unwrap()
}

#[tokio::test]
async fn ssh_bridge_does_not_invent_node_path_capabilities() {
    let scratch = std::env::var_os("INFRATERNAL_TEST_STATE_ROOT").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").unwrap())
                .join(".cache/codex-scratch/addhost-instant")
        },
        PathBuf::from,
    );
    let root = scratch.join(format!("ssh-caps-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let link = pipe_link(&root.join("pid")).await;
    let advertised = link.supports_server_paths();
    let mut prefix = bytes::BytesMut::new();
    let mut scratch = [0; 1024];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(decoded) = infraternal_protocol::decode_muxed_frame(&prefix) {
                assert!(matches!(
                    decoded.frame,
                    Frame::Hello {
                        version: 1,
                        caps: 0,
                        ..
                    }
                ));
                break;
            }
            assert!(link.read(&mut prefix, &mut scratch).await.unwrap() != 0);
        }
    })
    .await
    .unwrap();
    drop(link);
    std::fs::remove_dir_all(root).unwrap();
    assert!(
        !advertised,
        "A session-only SSH greeting cannot advertise node path actions"
    );
}

#[tokio::test]
async fn ssh_greeting_keeps_full_capabilities_and_coalesced_frames() {
    let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
        ".cache/codex-scratch/addhost-instant/ssh-prefix-{}",
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let mut suffix = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(
        0,
        &Frame::Ping {
            nonce: 99,
            sent_us: 7,
        },
        &mut suffix,
    )
    .unwrap();
    let link = RemoteLink::ssh(
        pipe_peer_greeting(
            &root.join("pid"),
            infraternal_plugin_api::channel::SERVER_PATH_PROPOSALS,
            &suffix,
        ),
        Arc::new(Master(Arc::default())),
    )
    .await
    .unwrap();
    assert!(link.supports_server_paths());
    let mut received = bytes::BytesMut::new();
    let mut scratch = [0; 1024];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(first) = infraternal_protocol::decode_muxed_frame(&received)
                && let Ok(second) =
                    infraternal_protocol::decode_muxed_frame(&received[first.wire_len..])
            {
                assert!(matches!(first.frame, Frame::Hello { version: 1, .. }));
                assert!(matches!(
                    second.frame,
                    Frame::Ping {
                        nonce: 99,
                        sent_us: 7
                    }
                ));
                break;
            }
            assert!(link.read(&mut received, &mut scratch).await.unwrap() != 0);
        }
    })
    .await
    .unwrap();
    drop(link);
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn ssh_greeting_refuses_invalid_first_frames_and_releases_its_master() {
    let root = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
        ".cache/codex-scratch/addhost-instant/ssh-invalid-{}",
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let frames = [
        (
            2,
            Frame::Hello {
                version: 1,
                caps: 0,
                client_info: "wrong stream",
            },
        ),
        (
            0,
            Frame::Hello {
                version: 2,
                caps: 0,
                client_info: "wrong version",
            },
        ),
        (
            0,
            Frame::Ping {
                nonce: 0,
                sent_us: 0,
            },
        ),
    ];
    for (index, (stream, frame)) in frames.into_iter().enumerate() {
        let mut bytes = Vec::new();
        infraternal_protocol::encode_muxed_frame_into(stream, &frame, &mut bytes).unwrap();
        let retired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let result = RemoteLink::ssh(
            pipe_peer_bytes(&root.join(index.to_string()), &bytes),
            Arc::new(Master(retired.clone())),
        )
        .await;
        assert!(matches!(result, Err(error) if error.kind() == std::io::ErrorKind::InvalidData));
        assert!(retired.load(std::sync::atomic::Ordering::SeqCst));
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn ssh_bridge_retires_only_after_installed_writer_acknowledges() {
    replacement(false, false).await;
}

#[tokio::test]
async fn refused_installed_reattachment_restores_the_ssh_writer() {
    replacement(true, false).await;
}

#[tokio::test]
async fn component_off_retires_ssh_fallback_after_installed_admission() {
    replacement(false, true).await;
}

/// Rebinding emits control/status notices before its authoritative writer Ack.
/// Keep one deadline across those notices; data and final Close still fail the oracle.
async fn writer_frame(output: &mut tokio::sync::mpsc::Receiver<TerminalOutput>) -> TerminalOutput {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match output.recv().await.unwrap() {
                TerminalOutput::Reconnecting => {}
                frame => return frame,
            }
        }
    })
    .await
    .unwrap()
}

async fn replacement(refuse: bool, component_off: bool) {
    let root_dir = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
        ".cache/codex-scratch/addhost-instant/pipe-{}",
        Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root_dir).unwrap();
    let pidfile = root_dir.join("pid");
    let channel = pipe_peer(&pidfile);
    let (server, identity, issuer, _) = identities();
    let (store, _pool, host, _) = revocation::admitted_store(&identity, &issuer).await;
    sqlx::query("INSERT INTO remote_bootstrap_retirement_intents(host_id) VALUES(?)")
        .bind(host.as_bytes().as_slice())
        .execute(&store.0)
        .await
        .unwrap();
    let guard =
        crate::remote_guard::AuthorityGuard::provisioning(store.clone(), "owner", host, 1002)
            .await
            .unwrap();
    let hosts = RemoteHosts::default();
    let retired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    hosts
        .admit_observed(
            guard,
            RemoteLink::ssh(channel, Arc::new(Master(retired.clone())))
                .await
                .unwrap(),
            None,
        )
        .await
        .unwrap();
    let actor = hosts.actor(host).await.unwrap();
    let (_handle, mut output) = actor
        .attach(*Uuid::from_u128(7).as_bytes(), 0, 0, 2)
        .await
        .unwrap()
        .split();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), output.recv())
            .await
            .unwrap()
            .unwrap(),
        TerminalOutput::Ack { in_seq_acked: 0 }
    ));
    assert!(!actor.installed_route().await.unwrap());
    let pid: u32 = std::fs::read_to_string(&pidfile).unwrap().parse().unwrap();
    assert!(alive(pid));
    let listeners = RemoteListeners::start(
        "127.0.0.1:0".parse().unwrap(),
        &server,
        std::slice::from_ref(&issuer),
        store,
        hosts.clone(),
    )
    .await
    .unwrap();
    let client = remote_tls::client_config(&identity, &[issuer]).unwrap();
    let (attached, seen) = tokio::sync::oneshot::channel();
    let (release, approved) = tokio::sync::oneshot::channel();
    let address = listeners.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let connection = remote_tls::dial(address, "localhost", &client)
            .await
            .unwrap();
        let mut receive = Receive::default();
        Transmit::default()
            .send(
                &connection.channel,
                0,
                &Frame::Hello {
                    version: 1,
                    caps: 0,
                    client_info: "installed fixture",
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            receive.next(&connection.channel).await.unwrap().frame,
            Frame::Hello { .. }
        ));
        let attach = receive.next(&connection.channel).await.unwrap();
        assert!(matches!(attach.frame, Frame::AttachTerm { .. }));
        let writer = attach.stream_id;
        attached.send(()).unwrap();
        approved.await.unwrap();
        if refuse {
            return;
        }
        Transmit::default()
            .send(&connection.channel, writer, &Frame::Ack { in_seq_acked: 0 })
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    tokio::time::timeout(Duration::from_secs(5), seen)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !retired.load(std::sync::atomic::Ordering::SeqCst),
        "SSH was retired before installed replay acknowledgment"
    );
    if component_off {
        hosts.stop_provisioning().await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while alive(pid) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("component-off retained the old SSH bridge after installed admission");
        assert!(
            hosts.installed(host).await,
            "SSH off cannot stop the installed component"
        );
    }
    release.send(()).unwrap();
    let frame = writer_frame(&mut output).await;
    assert!(
        matches!(&frame, TerminalOutput::Ack { in_seq_acked: 0 }),
        "unexpected frame before SSH Ack: {frame:?}"
    );
    if refuse {
        assert!(!actor.installed_route().await.unwrap());
        assert!(
            alive(pid),
            "failed replacement must retain the working SSH bridge"
        );
        assert!(!retired.load(std::sync::atomic::Ordering::SeqCst));
        peer.await.unwrap();
        drop(actor);
        drop(listeners);
    } else {
        assert!(actor.installed_route().await.unwrap());
        peer.abort();
        drop(actor);
        drop(listeners);
    }
    drop(hosts);
    tokio::time::timeout(Duration::from_secs(5), async {
        while alive(pid) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    std::fs::remove_dir_all(root_dir).unwrap();
}
