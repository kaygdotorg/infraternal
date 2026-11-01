//! Opt-in D170 real-host proof: pinned `NetBird` SSH, private-stdin enrollment, real PTY and installation-specific cleanup (#78).

use super::*;
use futures_util::FutureExt;

/// Fixed test peer only; the caller must provision the explicitly authorised pin.
fn ssh(pin: &Path, command: &str) -> Command {
    let mut ssh = ssh_options(pin);
    ssh.args(["kayg@10.69.69.51", command]);
    ssh
}

fn ssh_options(pin: &Path) -> Command {
    let mut ssh = Command::new("netbird");
    ssh.args([
        "ssh",
        "--no-browser",
        "--strict-host-key-checking",
        "--known-hosts",
    ])
    .arg(pin);
    ssh
}

struct Installation {
    pin: PathBuf,
    data: String,
    state: String,
    cleaned: bool,
}

fn runtime_state(root: &str, id: uuid::Uuid) -> String {
    // Leave room for /sessions/<32 hex>.sock and its NUL in Linux sun_path;
    // keep the full UUID so simultaneous jobs never intentionally share state.
    format!("{root}/i78-{}", id.simple())
}

#[test]
fn o1_runtime_path_admits_real_unix_socket_address() {
    let state = runtime_state("/run/user/1002", uuid::Uuid::from_u128(42));
    let socket = PathBuf::from(state)
        .join("sessions")
        .join(format!("{}.sock", uuid::Uuid::nil().simple()));
    assert!(
        nix::sys::socket::UnixAddr::new(&socket).is_ok(),
        "o1 shim rendezvous exceeds the platform Unix-socket address bound"
    );
}

impl Installation {
    fn cleanup(&mut self) -> bool {
        // Authenticate shim PIDs using our own private rendezvous. The daemon PID
        // is checked against this exact binary path before signalling; no process
        // names, broad pkill or unrelated user directories are involved.
        let script = r"import os,pathlib,signal,socket,struct,shutil,time
data=pathlib.Path(DATA)
state=pathlib.Path(STATE)
def exact(s,n):
 b=b''
 while len(b)<n:
  c=s.recv(n-len(b))
  if not c: raise EOFError()
  b+=c
 return b
for name in ('pid','forward-pid-4701','forward-pid-7443'):
 pidfile=data/name
 if pidfile.exists():
  pid=int(pidfile.read_text())
  try:
   args=pathlib.Path('/proc/%d/cmdline'%pid).read_bytes().split(b'\0')
   owned=os.fsencode(str(data/'infraternal')) in args if name=='pid' else os.fsencode(str(state)) in args
   if owned: os.kill(pid,signal.SIGKILL)
  except ProcessLookupError: pass
  except FileNotFoundError: pass
for p in (state/'sessions').glob('*.sock'):
 try:
  with socket.socket(socket.AF_UNIX) as s:
   s.settimeout(2);s.connect(str(p))
   hello=exact(s,struct.unpack('<I',exact(s,4))[0])
   if hello[0]!=1: raise ValueError('bad shim greeting')
   os.kill(struct.unpack('<I',hello[27:31])[0],signal.SIGKILL)
 except (FileNotFoundError,ProcessLookupError): pass
time.sleep(.2)
remaining=0
for p in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
 try:
  args=p.read_bytes().split(b'\0')
  if os.fsencode(str(data/'infraternal')) in args or os.fsencode(str(state)) in args: remaining+=1
 except (FileNotFoundError,PermissionError): pass
if remaining: raise RuntimeError('installation processes remain')
shutil.rmtree(state,ignore_errors=True)
shutil.rmtree(data,ignore_errors=True)
assert not state.exists() and not data.exists()
print('remote_host_cleanup processes=0 data_absent=true state_absent=true')";
        let script = script
            .replace("DATA", &format!("{:?}", self.data))
            .replace("STATE", &format!("{:?}", self.state));
        let result = ssh(&self.pin, "python3 -")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                child.stdin.take().unwrap().write_all(script.as_bytes())?;
                child.wait_with_output()
            });
        self.cleaned = result.as_ref().is_ok_and(|out| out.status.success());
        if self.cleaned {
            print!("{}", String::from_utf8_lossy(&result.unwrap().stdout));
        }
        self.cleaned
    }
}

impl Drop for Installation {
    fn drop(&mut self) {
        if !self.cleaned && !self.cleanup() {
            eprintln!(
                "o1 test installation cleanup failed: data={} state={}",
                self.data, self.state
            );
        }
    }
}

/// Distinct single-byte keys cannot match a previous line redraw. Fence each
/// observation with the real shim Ack; report network echo, not rendered glyph time.
async fn keystroke_echo(browser: &mut Browser, entered: &mut u64, cursor: &mut u64) {
    let mut samples = Vec::new();
    for glyph in b"BDFGHJKNQRTUVWXYZbcgjkquvwxyz".iter().take(25) {
        let started = Instant::now();
        send(
            browser,
            1,
            &Frame::Input {
                in_seq: *entered,
                bytes: std::slice::from_ref(glyph),
            },
        )
        .await;
        *entered += 1;
        let mut echoed = None;
        let mut acked = false;
        while echoed.is_none() || !acked {
            let wire = next(browser).await;
            match infraternal_protocol::decode_muxed_frame(&wire)
                .unwrap()
                .frame
            {
                Frame::Output { out_seq, bytes } => {
                    assert_eq!(out_seq, *cursor, "lost or duplicated keystroke output");
                    *cursor += bytes.len() as u64;
                    if bytes.contains(glyph) && echoed.is_none() {
                        echoed = Some(started.elapsed().as_micros());
                    }
                }
                Frame::Ack { in_seq_acked } => {
                    assert!(in_seq_acked <= *entered);
                    acked = in_seq_acked == *entered;
                }
                _ => {}
            }
        }
        samples.push(echoed.unwrap());
    }
    samples.sort_unstable();
    println!(
        "remote_host_keystroke_echo n=25 p50_us={} p99_us={} authoritative_acks=true contiguous_output_bytes={} lost=0 duplicated=0",
        samples[12], samples[24], cursor
    );
    // Leave the shared shell at a clean prompt for subsequent device writers.
    send(
        browser,
        1,
        &Frame::Input {
            in_seq: *entered,
            bytes: b"\x15\n",
        },
    )
    .await;
    *entered += 2;
    let mut prompt = Vec::new();
    until(browser, &mut prompt, cursor, b"shim-test").await;
}

/// Reuse the existing passive scheduler observer over private SSH stdin. It
/// installs no helper and verifies the PID against this installation before use.
async fn host_idle_canary(installation: &Installation) {
    if std::env::var_os("INFRATERNAL_O1_IDLE_CANARY").is_none() {
        return;
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    let script = format!(
        "import pathlib,os;d=pathlib.Path('{}');pid=int((d/'pid').read_text());assert os.fsencode(str(d/'infraternal')) in pathlib.Path('/proc/%d/cmdline'%pid).read_bytes().split(b'\\0');print(pid)",
        installation.data
    );
    let public = ssh(&installation.pin, &format!("python3 -c \"{script}\""))
        .output()
        .unwrap();
    assert!(public.status.success());
    let pid: u32 = String::from_utf8(public.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let script = include_bytes!("../../../scripts/idle_canary.py");
    let result = ssh(
        &installation.pin,
        &format!("python3 - --pid {pid} --label 'o1 infraternal agent' --seconds 10 --events"),
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .and_then(|mut child| {
        child.stdin.take().unwrap().write_all(script)?;
        child.wait_with_output()
    })
    .unwrap();
    print!("{}", String::from_utf8_lossy(&result.stdout));
    if !result.status.success() {
        eprint!("{}", String::from_utf8_lossy(&result.stderr));
    }
    assert!(
        result.status.success(),
        "o1 infraternal agent idle canary failed"
    );
}

// Keep setup, round trips and cleanup in one sequential opt-in host transaction.
#[allow(clippy::too_many_lines)]
#[tokio::test]
#[ignore = "authorised o1 proof requires pinned INFRATERNAL_O1_KNOWN_HOSTS and aarch64 INFRATERNAL_REMOTE_TEST_BINARY; exclusive 4701/7443"]
async fn o1_rootless_join_terminal_and_cleanup() {
    let relay = std::env::var_os("INFRATERNAL_O1_TCP_RELAY").is_some();
    let pin = PathBuf::from(std::env::var_os("INFRATERNAL_O1_KNOWN_HOSTS").unwrap());
    let binary = PathBuf::from(std::env::var_os("INFRATERNAL_REMOTE_TEST_BINARY").unwrap());
    assert!(pin.is_file() && binary.is_file());
    let probe = ssh(
        &pin,
        "id -u; uname -m; printf '%s\\n' \"$HOME\" \"$XDG_RUNTIME_DIR\"; cat /proc/loadavg",
    )
    .output()
    .unwrap();
    assert!(probe.status.success(), "pinned o1 probe failed");
    let probe = String::from_utf8(probe.stdout).unwrap();
    let lines: Vec<_> = probe.lines().collect();
    assert_eq!(lines[1], "aarch64");
    let uid: u32 = lines[0].parse().unwrap();
    assert_ne!(uid, 0);
    assert_eq!(lines[2], "/home/kayg");
    assert_eq!(lines[3], format!("/run/user/{uid}"));
    let id = uuid::Uuid::new_v4();
    let mut installation = Installation {
        pin,
        data: format!("{}/.local/share/infraternal-78-{id}", lines[2]),
        state: runtime_state(lines[3], id),
        cleaned: false,
    };
    let digest = openssl::sha::sha256(&std::fs::read(&binary).unwrap());
    let digest = digest
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            use std::fmt::Write as _;
            write!(hex, "{byte:02x}").unwrap();
            hex
        });
    let upload = format!(
        "umask 077; mkdir '{}' && cat > '{}/infraternal' && chmod 700 '{}/infraternal' && printf '%s  %s\\n' '{}' '{}/infraternal' | sha256sum -c - && printf \"PS1='shim-test%% '\\n\" > '{}/.zshrc'",
        installation.data,
        installation.data,
        installation.data,
        digest,
        installation.data,
        installation.data
    );
    let result = ssh(&installation.pin, &upload)
        .stdin(std::fs::File::open(&binary).unwrap())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(result.success(), "rootless upload/hash check failed");
    println!(
        "remote_host_artifact target=aarch64-unknown-linux-musl sha256={digest} uid={uid} host_load={}",
        lines[4]
    );
    let directory = Directory::new();
    let mut fixture = fixture_at(
        &directory,
        "10.69.69.125:4701".parse().unwrap(),
        "10.69.69.125:7443".parse().unwrap(),
    )
    .await;
    // This NetBird CLI routes multiple -R requests on one connection to its
    // first backend. Own separate pinned connections so HTTPS and mTLS stay distinct.
    let forward: Vec<_> = if relay {
        [4701, 7443].into_iter().map(|port| {
            let script = format!("import os,pathlib,sys;pathlib.Path('{}/forward-pid-{port}').write_text(str(os.getpid()));sys.stdin.buffer.read()", installation.data);
            Process(ssh_options(&installation.pin)
                .arg("-R").arg(format!("{port}:10.69.69.125:{port}"))
                .arg("kayg@10.69.69.51")
                .arg(format!("python3 -c \"{script}\" '{}'", installation.state))
                .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().unwrap())
        }).collect()
    } else {
        Vec::new()
    };
    let contact = if relay { "127.0.0.1" } else { "10.69.69.125" };
    let preflight = format!(
        "import socket,time\nfor p in (4701,7443):\n for attempt in range(20):\n  try: socket.create_connection(('{contact}',p),1).close();break\n  except OSError:\n   if attempt==19: raise\n   time.sleep(.1)\nprint('remote_host_preflight tcp4701=true tcp7443=true relay={relay}')"
    );
    let preflight = ssh(&installation.pin, "python3 -")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut process| {
            process
                .stdin
                .take()
                .unwrap()
                .write_all(preflight.as_bytes())?;
            process.wait_with_output()
        })
        .unwrap();
    assert!(
        preflight.status.success(),
        "o1 cannot reach dev TCP4701/7443; fix test-network reachability before enrollment"
    );
    let host = uuid::Uuid::new_v4();
    let invitation = invitation_for_uid(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
        host,
        uid,
    )
    .await;
    let invitation = if relay {
        // The trusted server/operator fixture chooses the loopback relay's
        // address through private stdin. Keep issuer and SAN pins unchanged;
        // this diagnoses real TCP/mTLS execution, never direct QUIC reachability.
        let mut private: crate::remote_http::JoinInvitation =
            serde_json::from_slice(&invitation).unwrap();
        private.endpoint = Some("127.0.0.1:7443".parse().unwrap());
        serde_json::to_vec(&private).unwrap()
    } else {
        invitation
    };
    let join_url = if relay {
        "https://localhost:4701/remote/join"
    } else {
        "https://10.69.69.125:4701/remote/join"
    };
    // The wrapper records only the public PID; capability/key material is never
    // written by the harness. join receives the invitation through inherited stdin.
    let wrapper = format!(
        "import subprocess,pathlib,sys; p=subprocess.Popen(['{0}/infraternal','agent','--data','{0}/identity','--state','{1}','join','{2}'],env=dict(__import__('os').environ,ZDOTDIR='{0}')); pathlib.Path('{0}/pid').write_text(str(p.pid));sys.exit(p.wait())",
        installation.data, installation.state, join_url
    );
    let command = format!("python3 -c \"{wrapper}\"");
    let started = Instant::now();
    let mut child = Process(
        ssh(&installation.pin, &command)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(&invitation)
        .unwrap();
    drop(invitation);
    let mut browser = browser(
        fixture.address,
        &fixture.root,
        "https://localhost:4701",
        &fixture.cookie,
    )
    .await;
    let issued: i64 =
        sqlx::query_scalar("SELECT count(*) FROM remote_certificates WHERE host_id=?")
            .bind(host.as_bytes().as_slice())
            .fetch_one(&fixture.pool)
            .await
            .unwrap();
    let admitted = fixture
        .listeners
        .as_ref()
        .unwrap()
        .diagnostic_hosts
        .actor(host)
        .await
        .is_some();
    println!(
        "remote_host_before_open certificate_count={issued} previously_tls_admitted={admitted}"
    );
    let opened = std::panic::AssertUnwindSafe(open_remote(&mut browser, host, started))
        .catch_unwind()
        .await;
    let session = match opened {
        Ok(session) => session,
        Err(failure) => {
            let issued: i64 =
                sqlx::query_scalar("SELECT count(*) FROM remote_certificates WHERE host_id=?")
                    .bind(host.as_bytes().as_slice())
                    .fetch_one(&fixture.pool)
                    .await
                    .unwrap();
            let admitted = fixture
                .listeners
                .as_ref()
                .unwrap()
                .diagnostic_hosts
                .actor(host)
                .await
                .is_some();
            println!(
                "remote_host_failed_open certificate_count={issued} previously_tls_admitted={admitted} ssh_wrapper_exited={}",
                child.0.try_wait().unwrap().is_some()
            );
            let diagnostic = format!(
                "import pathlib,os;d=pathlib.Path('{}');s=pathlib.Path('{}');pid=int((d/'pid').read_text());print('remote_host_state identity_exists=%s pid_alive=%s session_sockets=%d'%( (d/'identity'/'identity.json').exists(),pathlib.Path('/proc/%d'%pid).exists(),len(list((s/'sessions').glob('*.sock')))))",
                installation.data, installation.state
            );
            let diagnostic = ssh(&installation.pin, &format!("python3 -c \"{diagnostic}\""))
                .output()
                .unwrap();
            print!("{}", String::from_utf8_lossy(&diagnostic.stdout));
            std::panic::resume_unwind(failure);
        }
    };
    let join_us = started.elapsed().as_micros();
    send(
        &mut browser,
        1,
        &Frame::AttachTerm {
            session_id: session.as_bytes(),
            last_out_seq: 0,
            last_in_seq: 0,
        },
    )
    .await;
    send(&mut browser, 1, &Frame::Credit { bytes: 1024 * 1024 }).await;
    let mut output = Vec::new();
    let mut cursor = 0;
    until(&mut browser, &mut output, &mut cursor, b"shim-test").await;
    let mut entered = 0;
    let mut samples = Vec::new();
    for sample in 0..25 {
        let command = format!("printf 'O1_%s\\n' SAMPLE_{sample:02}\n");
        let marker = format!("O1_SAMPLE_{sample:02}");
        let started = Instant::now();
        send(
            &mut browser,
            1,
            &Frame::Input {
                in_seq: entered,
                bytes: command.as_bytes(),
            },
        )
        .await;
        entered += command.len() as u64;
        until(&mut browser, &mut output, &mut cursor, marker.as_bytes()).await;
        samples.push(started.elapsed().as_micros());
    }
    samples.sort_unstable();
    println!(
        "remote_host_demo host=o1 rootless=true tcp_ssh_relay={relay} join_to_terminal_us={join_us} command_roundtrip_n=25 p50_us={} p99_us={} contiguous_output_bytes={cursor} lost=0 duplicated=0 dev_load={}",
        samples[12],
        samples[24],
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    keystroke_echo(&mut browser, &mut entered, &mut cursor).await;
    host_idle_canary(&installation).await;
    browser_proof(&fixture, host, session).await;
    drop(browser);
    drop(child);
    drop(forward);
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    fixture.listeners.take();
    fixture.pool.close().await;
    assert!(installation.cleanup(), "o1 cleanup failed");
}
