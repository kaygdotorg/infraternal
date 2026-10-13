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
    let mut hello = Vec::new();
    infraternal_protocol::encode_muxed_frame_into(
        0,
        &Frame::Hello {
            version: 1,
            caps: 0,
            client_info: "pipe fixture",
        },
        &mut hello,
    )
    .unwrap();
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
        .arg(hex(&hello))
        .arg(hex(&ack));
    Duplex::spawn(&mut command).unwrap()
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

#[allow(
    clippy::too_many_lines,
    reason = "Keep admission, reattachment and retirement ordered in the real peer lifecycle."
)]
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
        .admit(
            guard,
            RemoteLink::ssh(channel, Arc::new(Master(retired.clone()))),
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
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), output.recv())
            .await
            .unwrap()
            .unwrap(),
        TerminalOutput::Ack { in_seq_acked: 0 }
    ));
    if refuse {
        assert!(
            alive(pid),
            "failed replacement must retain the working SSH bridge"
        );
        assert!(!retired.load(std::sync::atomic::Ordering::SeqCst));
        peer.await.unwrap();
        drop(actor);
        drop(listeners);
    } else {
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
