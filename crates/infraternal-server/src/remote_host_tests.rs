//! Opt-in D170 real-host proof: pinned `NetBird` SSH, private-stdin enrollment, real PTY and installation-specific cleanup (#78).

use super::*;

/// Fixed test peer only; the caller must provision the explicitly authorised pin.
fn ssh(pin: &Path, command: &str) -> Command {
    let mut ssh = Command::new("netbird");
    ssh.args(["ssh", "--no-browser", "--known-hosts"])
        .arg(pin)
        .args(["kayg@10.69.69.51", command]);
    ssh
}

struct Installation {
    pin: PathBuf,
    data: String,
    state: String,
    cleaned: bool,
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
pidfile=data/'pid'
if pidfile.exists():
 pid=int(pidfile.read_text())
 try:
  args=pathlib.Path('/proc/%d/cmdline'%pid).read_bytes().split(b'\0')
  if os.fsencode(str(data/'infraternal')) in args: os.kill(pid,signal.SIGKILL)
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

// Keep setup, round trips and cleanup in one sequential opt-in host transaction.
#[allow(clippy::too_many_lines)]
#[tokio::test]
#[ignore = "authorised o1 proof requires pinned INFRATERNAL_O1_KNOWN_HOSTS and aarch64 INFRATERNAL_REMOTE_TEST_BINARY; exclusive 4701/7443"]
async fn o1_rootless_join_terminal_and_cleanup() {
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
        state: format!("{}/infraternal-78-{id}", lines[3]),
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
    let preflight = ssh(&installation.pin, "python3 -c \"import socket; [socket.create_connection(('10.69.69.125',p),3).close() for p in (4701,7443)]; print('remote_host_preflight tcp4701=true tcp7443=true')\"").output().unwrap();
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
    // The wrapper records only the public PID; capability/key material is never
    // written by the harness. join receives the invitation through inherited stdin.
    let wrapper = format!(
        "import subprocess,pathlib,sys; p=subprocess.Popen(['{0}/infraternal','agent','--data','{0}/identity','--state','{1}','join','https://10.69.69.125:4701/remote/join'],env=dict(__import__('os').environ,ZDOTDIR='{0}')); pathlib.Path('{0}/pid').write_text(str(p.pid));sys.exit(p.wait())",
        installation.data, installation.state
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
    let session = open_remote(&mut browser, host, started).await;
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
        "remote_host_demo host=o1 rootless=true join_to_terminal_us={join_us} command_roundtrip_n=25 p50_us={} p99_us={} contiguous_output_bytes={cursor} lost=0 duplicated=0 dev_load={}",
        samples[12],
        samples[24],
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
    browser_proof(&fixture, host, session).await;
    drop(browser);
    drop(child);
    fixture.server.abort();
    let _ = (&mut fixture.server).await;
    fixture.listeners.take();
    fixture.pool.close().await;
    assert!(installation.cleanup(), "o1 cleanup failed");
}
