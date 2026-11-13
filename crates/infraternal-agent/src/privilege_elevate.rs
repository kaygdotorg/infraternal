//! Becomes root once with the person's password, to start the relay of a root upgrade (D274, D376, #399).
//!
//! A rootless infraternal agent can be upgraded to the root one. The person
//! proves they may become root on this host. The way in is detected and has
//! no menu (D274): sudo without a password (consent only), then sudo or doas
//! with their own password, then su with the root password. This module runs
//! that one command under a fresh pseudo-terminal, because doas and su only
//! read a password from a terminal. That terminal is private
//! (`infraternal_shim::private_pty`): no other process of this account can
//! open it, so none can read the line before the command does (J569 P1-2). It types the password once when asked,
//! and reports exactly one of: the relay started, the password was wrong, the
//! person may not become root this way, or nothing answered in time.
//!
//! What runs as root is only [`snippet`]: a few lines of `/bin/sh` that copy
//! this infraternal agent's binary into a fresh root-owned directory, check
//! its SHA-256 against the digest the server vouches for, and only then run
//! the copy as the relay. An attacker who controls this account can replace
//! the binary on disk, but can't make root run their bytes.
//!
//! Each try costs the host exactly one failed login: on a second prompt the
//! whole process group is killed at once, instead of letting sudo ask three
//! times. The password itself is never in argv, the environment, a file or a
//! log; it lives in a wiping buffer and is written once to the terminal.
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    path::Path,
    process::Stdio,
    time::Duration,
};

/// How this person becomes root here, in the order D274 tries them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    /// sudo allows this account without a password. Consent only, no field.
    SudoNoPassword,
    /// sudo with the person's own password.
    Sudo,
    /// doas with the person's own password.
    Doas,
    /// su with the root password.
    Su,
}

impl Way {
    /// The word the server, the browser and the messages use.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::SudoNoPassword | Self::Sudo => "sudo",
            Self::Doas => "doas",
            Self::Su => "su",
        }
    }
}

/// The result of one try.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The command became root and the snippet ran (the relay is starting).
    Started,
    /// su can't run a command here: root's login shell isn't a POSIX shell
    /// (often `nologin`). Nothing was typed (J415 B11).
    RootShell,
    /// The password was refused. Counts toward D376's two tries.
    Wrong,
    /// This account may not become root this way (not in sudoers, no doas rule).
    Denied,
    /// The binary on disk didn't match the server's digest; nothing ran as root.
    Mismatch,
    /// No prompt, or no answer, within the bound.
    Timeout,
    /// The command ended for some other reason.
    Failed,
}

/// What the driver should do after reading more of the terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Keep reading.
    Wait,
    /// The prompt is showing: type the password now (once).
    Type,
    /// The answer is known; stop the command.
    Done(Outcome),
}

/// The exit code and line the snippet uses when the digest doesn't match.
pub const MISMATCH_CODE: i32 = 70;
/// The line the snippet prints just before it starts the relay.
pub const STARTED_LINE: &str = "INFRATERNAL_PRIVILEGE_STARTED";
/// Bytes of terminal output kept to recognise prompts and refusals.
const TAIL: usize = 1024;

/// Reads the elevation command's terminal and decides each step.
///
/// It keeps only the last [`TAIL`] bytes, and looks only for fixed prompts
/// and refusal phrases with the locale forced to `C`. The sudo prompt is a
/// random marker set with `-p`, so nothing a host prints can fake it.
pub struct Transcript {
    way: Way,
    marker: Vec<u8>,
    typed: bool,
    /// Wiped when dropped: should a terminal ever echo, the password could
    /// pass through here (J415 B3).
    tail: zeroize::Zeroizing<Vec<u8>>,
}

impl Transcript {
    /// Start reading for `way`; `marker` is the sudo prompt set with `-p`.
    #[must_use]
    pub fn new(way: Way, marker: &str) -> Self {
        Self {
            way,
            marker: marker.as_bytes().to_vec(),
            typed: false,
            tail: zeroize::Zeroizing::new(Vec::new()),
        }
    }

    /// Note that the password has been typed. Any prompt after this means it
    /// was wrong.
    pub fn typed(&mut self) {
        self.typed = true;
        self.tail.clear();
    }

    /// Whether the password has been typed (so PAM may have counted it).
    #[must_use]
    pub const fn was_typed(&self) -> bool {
        self.typed
    }

    /// Read more terminal output and decide what to do.
    pub fn feed(&mut self, bytes: &[u8]) -> Step {
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > TAIL {
            let excess = self.tail.len() - TAIL;
            self.tail.drain(..excess);
        }
        if contains(&self.tail, STARTED_LINE.as_bytes()) {
            return Step::Done(Outcome::Started);
        }
        if contains(&self.tail, b"INFRATERNAL_DIGEST_MISMATCH") {
            return Step::Done(Outcome::Mismatch);
        }
        if self.denied() {
            return Step::Done(Outcome::Denied);
        }
        if self.typed && self.refused() {
            return Step::Done(Outcome::Wrong);
        }
        if self.prompting() {
            return if self.typed || self.way == Way::SudoNoPassword {
                // A second prompt, or a prompt where none should come.
                Step::Done(if self.typed {
                    Outcome::Wrong
                } else {
                    Outcome::Failed
                })
            } else {
                Step::Type
            };
        }
        Step::Wait
    }

    /// The answer when the command exits before the snippet reported.
    #[must_use]
    pub fn exited(&self, code: Option<i32>) -> Outcome {
        if code == Some(MISMATCH_CODE) && contains(&self.tail, b"INFRATERNAL_DIGEST_MISMATCH") {
            Outcome::Mismatch
        } else if self.denied() {
            Outcome::Denied
        } else if self.typed {
            // sudo, doas and su all exit non-zero after a refused password;
            // the phrase may be missing when the terminal closed first.
            Outcome::Wrong
        } else {
            Outcome::Failed
        }
    }

    /// The tail ends with this way's password prompt.
    fn prompting(&self) -> bool {
        let text = trim_end(&self.tail);
        match self.way {
            Way::SudoNoPassword | Way::Sudo => text.ends_with(trim_end(&self.marker)),
            // doas: "doas (kayg@host) password:", su: "Password:".
            Way::Doas | Way::Su => text.ends_with(b"assword:"),
        }
    }

    /// A refused-password phrase is in the tail (locale `C`).
    fn refused(&self) -> bool {
        [
            &b"Sorry, try again"[..],
            b"Authentication failure",
            b"Authentication failed",
            b"incorrect password",
        ]
        .iter()
        .any(|phrase| contains(&self.tail, phrase))
    }

    /// A phrase saying this account may not use this way at all.
    fn denied(&self) -> bool {
        [
            &b"is not in the sudoers file"[..],
            b"is not allowed to execute",
            b"may not run sudo",
            b"Operation not permitted",
            // P3-5: pam_wheel and similar account checks refuse after the
            // password ("su: Permission denied"); an expired password needs
            // a change this flow can't make. Neither is a wrong password.
            b"Permission denied",
            b"Authentication token expired",
            b"password has expired",
            b"change your password immediately",
        ]
        .iter()
        .any(|phrase| contains(&self.tail, phrase))
    }
}

/// `haystack` contains `needle`.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// `bytes` without trailing spaces, tabs, carriage returns and newlines.
fn trim_end(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .map_or(0, |i| i + 1);
    &bytes[..end]
}

/// The `/bin/sh` program root runs: verify the binary, then start the relay.
///
/// Arguments (all public): `$1` this infraternal agent's binary, `$2` the
/// SHA-256 the server vouches for, `$3` the relay socket, `$4` the account's
/// uid. It copies the binary into a fresh 0700 directory under `/run` that
/// only root can write, hashes *the copy*, and runs it only on a match, so a
/// file swapped after the check is never run. The relay removes that
/// directory when it exits. The relay's stdin stays the terminal: it reads
/// its one-time token from there (see [`elevate`]).
///
/// Root first leaves the account's working directory (`cd /`, J465 P2-4),
/// sweeps relay copies older than any live relay's lifetime that killed
/// tries left in `/run`, and copies only a regular file that isn't a link,
/// so a FIFO or a link to an endless device can't hang root or fill `/run`
/// (P3-1); either refusal reads as a digest mismatch.
#[must_use]
pub fn snippet() -> String {
    format!(
        r#"set -eu
cd /
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LANG=C LC_ALL=C
for old in /run/infraternal-privilege.*; do
    [ -d "$old" ] && [ ! -L "$old" ] && [ -n "$(find "$old" -maxdepth 0 -mmin +20)" ] && rm -rf -- "$old"
done
[ -f "$1" ] && [ ! -L "$1" ] || {{ echo INFRATERNAL_DIGEST_MISMATCH; exit {MISMATCH_CODE}; }}
dir=$(mktemp -d /run/infraternal-privilege.XXXXXXXX)
cp -- "$1" "$dir/relay"
if [ "$(sha256sum "$dir/relay" | cut -c1-64)" != "$2" ]; then
    rm -rf -- "$dir"
    echo INFRATERNAL_DIGEST_MISMATCH
    exit {MISMATCH_CODE}
fi
chmod 0700 "$dir/relay"
[ ! -e /sys/fs/selinux/enforce ] || chcon -t bin_t "$dir/relay" 2>/dev/null || :
echo {STARTED_LINE}
exec "$dir/relay" __privilege-relay --socket "$3" --uid "$4" --dir "$dir" >/dev/null 2>&1
"#
    )
}

/// The command for `way`, by absolute path, ready to run `snippet` with its
/// four public arguments. `None` when the tool isn't installed.
#[must_use]
pub fn command(way: Way, marker: &str, words: [&str; 4]) -> Option<(String, Vec<String>)> {
    let first = |paths: &[&str]| {
        paths
            .iter()
            .find(|path| Path::new(path).exists())
            .map(|path| (*path).to_owned())
    };
    let script = snippet();
    let mut tail = vec![
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        script.clone(),
        "infraternal-privilege".to_owned(),
    ];
    tail.extend(words.iter().map(|word| (*word).to_owned()));
    match way {
        Way::SudoNoPassword => {
            let sudo = first(&["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"])?;
            let mut argv = vec!["-n".to_owned(), "--".to_owned()];
            argv.extend(tail);
            Some((sudo, argv))
        }
        Way::Sudo => {
            let sudo = first(&["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"])?;
            // -k: always check the password, never a cached timestamp, so each
            // try is a real check. -p: our own prompt, which nothing can fake.
            let mut argv = vec![
                "-k".to_owned(),
                "-p".to_owned(),
                marker.to_owned(),
                "--".to_owned(),
            ];
            argv.extend(tail);
            Some((sudo, argv))
        }
        Way::Doas => {
            let doas = first(&["/usr/bin/doas", "/bin/doas", "/usr/local/bin/doas"])?;
            let mut argv = vec!["--".to_owned()];
            argv.extend(tail);
            Some((doas, argv))
        }
        Way::Su => {
            let su = first(&["/bin/su", "/usr/bin/su"])?;
            // su passes one string to root's shell, so quote each word.
            let line = tail
                .iter()
                .map(|word| quote(word))
                .collect::<Vec<_>>()
                .join(" ");
            Some((su, vec!["root".to_owned(), "-c".to_owned(), line]))
        }
    }
}

/// How long to wait for a prompt's terminal to turn echo off (B3).
const ECHO_WAIT: Duration = Duration::from_secs(3);

/// Wait up to `wait` for the terminal behind `master` to have echo off.
async fn echo_off(master: &OwnedFd, wait: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match nix::sys::termios::tcgetattr(master) {
            Ok(modes)
                if !modes
                    .local_flags
                    .contains(nix::sys::termios::LocalFlags::ECHO) =>
            {
                return true;
            }
            Ok(_) if tokio::time::Instant::now() < deadline => {
                // sleep: polling the terminal's modes; there is no event for a mode change.
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            _ => return false,
        }
    }
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// Whether root's login shell (from `passwd`, the text of `/etc/passwd`) is
/// one `su root -c` can run a command with. `nologin`, `false` and other
/// non-POSIX shells can't (J415 B11).
#[must_use]
pub fn root_shell_is_posix(passwd: &str) -> bool {
    passwd
        .lines()
        .find(|line| line.starts_with("root:"))
        .and_then(|line| line.rsplit(':').next())
        .and_then(|shell| shell.rsplit('/').next())
        .is_some_and(|name| {
            ["sh", "bash", "dash", "ash", "ksh", "mksh", "zsh", "busybox"].contains(&name)
        })
}

/// Single-quote `word` for `/bin/sh`.
fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', r"'\''"))
}

/// What one try came to.
pub struct Try {
    /// The answer.
    pub outcome: Outcome,
    /// Whether the password reached the prompt, so PAM may have counted the
    /// try even when the outcome isn't [`Outcome::Wrong`] (J415 B2).
    pub typed: bool,
    /// The running relay, on [`Outcome::Started`].
    pub elevated: Option<Elevated>,
}

/// A command that became root and is now the relay. Keep it alive for as
/// long as the relay should run: dropping it closes the terminal, which hangs
/// up the session, and kills the command.
pub struct Elevated {
    /// The elevation command (sudo, doas or su, then the relay).
    pub child: tokio::process::Child,
    /// The terminal's master side; the session ends when it closes.
    pub terminal: infraternal_shim::readiness::Registration<OwnedFd>,
}

/// Run `way` under a fresh pseudo-terminal and type `secret` at its prompt.
///
/// The command starts in its own session with the terminal as its
/// controlling terminal (util-linux `setsid --ctty`), with an empty
/// environment apart from `PATH` and the `C` locale. The whole session is
/// killed on any answer but [`Outcome::Started`], and in every case after
/// `bound`. On `Started` the command keeps running: it *is* the relay now,
/// and `token` has been typed to it (64 hex digits, echo off), which the
/// relay then requires as the first frame on its socket (J415 B5).
///
/// # Errors
/// Only when the terminal or the command can't be set up at all.
pub async fn elevate(
    way: Way,
    secret: Option<&[u8]>,
    token: &[u8; 32],
    words: [&str; 4],
    bound: Duration,
) -> io::Result<Try> {
    // P3-5: the terminal reads a line, and its line editing acts on control
    // bytes (a newline ends the line early, ^U erases it, ^C interrupts). A
    // password with such a byte can't arrive intact, so it is refused before
    // anything runs, instead of being sent mangled and spending a try.
    if secret.is_some_and(|secret| secret.iter().any(|byte| *byte < 0x20 || *byte == 0x7f)) {
        return Ok(Try {
            outcome: Outcome::Failed,
            typed: false,
            elevated: None,
        });
    }
    if way == Way::Su
        && !root_shell_is_posix(&std::fs::read_to_string("/etc/passwd").unwrap_or_default())
    {
        return Ok(Try {
            outcome: Outcome::RootShell,
            typed: false,
            elevated: None,
        });
    }
    let marker = format!("[infraternal-{:032x}] ", uuid::Uuid::new_v4().as_u128());
    let (program, argv) =
        command(way, &marker, words).ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    // J569 P1-2: a terminal that no other process of this account can open,
    // so nothing but the elevation command can read the line typed to it.
    // A terminal someone tried to get into is refused before anything runs,
    // and nothing is typed: no try is spent.
    let pty = match infraternal_shim::private_pty::open() {
        Ok(pty) => pty,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(Try {
                outcome: Outcome::Failed,
                typed: false,
                elevated: None,
            });
        }
        Err(error) => return Err(error),
    };
    let flags =
        nix::fcntl::fcntl(&pty.master, nix::fcntl::FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let flags = nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(&pty.master, nix::fcntl::FcntlArg::F_SETFL(flags))
        .map_err(io::Error::from)?;
    let slave = |fd: &OwnedFd| fd.try_clone().map(Stdio::from);
    let mut child = tokio::process::Command::new("/usr/bin/setsid")
        .arg("--ctty")
        .arg("--")
        .arg(&program)
        .args(&argv)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(slave(&pty.slave)?)
        .stdout(slave(&pty.slave)?)
        .stderr(slave(&pty.slave)?)
        .kill_on_drop(true)
        .spawn()?;
    drop(pty.slave);
    let session = child
        .id()
        .and_then(|pid| i32::try_from(pid).ok())
        .map(nix::unistd::Pid::from_raw);
    // The shim's audited readiness wrapper owns the descriptor for the
    // reactor (tokio's own safe constructors are deprecated as unsound).
    let master = infraternal_shim::readiness::Registration::new(pty.master)?;
    let mut transcript = Transcript::new(way, &marker);
    let outcome = tokio::time::timeout(bound, async {
        let mut buffer = [0u8; 512];
        loop {
            let mut ready = tokio::select! {
                ready = master.readable() => ready?,
                status = child.wait() => {
                    return Ok::<_, io::Error>(transcript.exited(status?.code()));
                }
            };
            let read = match ready
                .try_io(|fd| nix::unistd::read(fd.as_fd(), &mut buffer).map_err(io::Error::from))
            {
                Ok(Ok(0) | Err(_)) => {
                    // EIO: the last holder of the terminal closed it.
                    let status = child.wait().await?;
                    return Ok(transcript.exited(status.code()));
                }
                Ok(Ok(read)) => read,
                Err(_would_block) => continue,
            };
            match transcript.feed(&buffer[..read]) {
                Step::Wait => {}
                Step::Done(outcome) => return Ok(outcome),
                Step::Type => {
                    let Some(secret) = secret else {
                        return Ok(Outcome::Failed);
                    };
                    // B3: su (Linux-PAM's conversation) prints its prompt
                    // before it turns echo off. Typing before that would echo
                    // the password back, or lose it. Wait for echo to be off;
                    // a terminal that never turns it off gets no password.
                    if !echo_off(master.get_ref(), ECHO_WAIT).await {
                        return Ok(Outcome::Failed);
                    }
                    let mut line = zeroize::Zeroizing::new(Vec::with_capacity(secret.len() + 1));
                    line.extend_from_slice(secret);
                    line.push(b'\n');
                    nix::unistd::write(master.get_ref(), &line).map_err(io::Error::from)?;
                    transcript.typed();
                }
            }
        }
    })
    .await
    .unwrap_or(Ok(Outcome::Timeout))?;
    let typed = transcript.was_typed();
    if outcome == Outcome::Started {
        // B5: type the relay's one-time token to its terminal, with echo off
        // on our side. The relay reads it, then requires it as the first
        // frame on the socket, which proves the listener is this process.
        if let Ok(mut modes) = nix::sys::termios::tcgetattr(master.get_ref()) {
            modes
                .local_flags
                .remove(nix::sys::termios::LocalFlags::ECHO);
            let _ = nix::sys::termios::tcsetattr(
                master.get_ref(),
                nix::sys::termios::SetArg::TCSANOW,
                &modes,
            );
        }
        let mut line = zeroize::Zeroizing::new(hex(token).into_bytes());
        line.push(b'\n');
        nix::unistd::write(master.get_ref(), &line).map_err(io::Error::from)?;
        return Ok(Try {
            outcome,
            typed,
            elevated: Some(Elevated {
                child,
                terminal: master,
            }),
        });
    }
    if let Some(session) = session {
        let _ = nix::sys::signal::killpg(session, nix::sys::signal::Signal::SIGKILL);
    }
    let _ = child.wait().await;
    Ok(Try {
        outcome,
        typed,
        elevated: None,
    })
}

#[cfg(test)]
mod tests {
    //! Prompts, refusals and the one-try rule, from real transcripts (locale C).
    use super::*;
    use std::os::unix::process::CommandExt as _;

    /// A stand-in for the random sudo prompt marker.
    const MARK: &str = "[infraternal-0123] ";

    /// Feed `chunks` in order and collect each step.
    fn steps(way: Way, chunks: &[&str], type_after_first: bool) -> Vec<Step> {
        let mut transcript = Transcript::new(way, MARK);
        let mut out = Vec::new();
        for chunk in chunks {
            let step = transcript.feed(chunk.as_bytes());
            if step == Step::Type && type_after_first {
                transcript.typed();
            }
            out.push(step);
        }
        out
    }

    /// B11: su needs root's login shell to run a command; nologin can't.
    #[test]
    fn su_needs_a_posix_root_shell() {
        assert!(root_shell_is_posix("root:x:0:0:root:/root:/bin/bash\n"));
        assert!(root_shell_is_posix(
            "daemon:x:1:1::/:/usr/sbin/nologin\nroot:x:0:0::/root:/bin/sh\n"
        ));
        assert!(!root_shell_is_posix(
            "root:x:0:0::/root:/usr/sbin/nologin\n"
        ));
        assert!(!root_shell_is_posix("root:x:0:0::/root:/usr/bin/fish\n"));
        assert!(!root_shell_is_posix(""));
    }

    /// The token is typed as 64 lowercase hex digits.
    #[test]
    fn tokens_are_typed_as_hex() {
        assert_eq!(hex(&[0, 0xab, 0x10]), "00ab10");
    }

    /// sudo: our marker asks once; a second marker or "Sorry, try again" after
    /// typing is a wrong password, never a second chance.
    #[test]
    fn sudo_types_once_and_a_second_prompt_is_wrong() {
        assert_eq!(steps(Way::Sudo, &[MARK], true), [Step::Type]);
        assert_eq!(
            steps(Way::Sudo, &[MARK, "\r\n", MARK], true),
            [Step::Type, Step::Wait, Step::Done(Outcome::Wrong)]
        );
        assert_eq!(
            steps(Way::Sudo, &[MARK, "\r\nSorry, try again.\r\n"], true),
            [Step::Type, Step::Done(Outcome::Wrong)]
        );
        assert_eq!(
            steps(
                Way::Sudo,
                &[MARK, "\r\nINFRATERNAL_PRIVILEGE_STARTED\r\n"],
                true
            ),
            [Step::Type, Step::Done(Outcome::Started)]
        );
    }

    /// P3-5: an account check that refuses after the password (`pam_wheel`'s
    /// "Permission denied") or an expired password is not a wrong password.
    #[test]
    fn account_refusals_after_the_password_are_denials() {
        for refusal in [
            "\r\nsu: Permission denied\r\n",
            "\r\nsu: Authentication token expired\r\n",
            "\r\nYou are required to change your password immediately (administrator enforced)\r\n",
        ] {
            assert_eq!(
                steps(Way::Su, &["Password: ", refusal], true),
                [Step::Type, Step::Done(Outcome::Denied)],
                "{refusal}"
            );
        }
    }

    /// P3-5: a password the terminal's line editing would split or erase is
    /// refused before anything runs, so no try is spent.
    #[tokio::test]
    async fn a_password_with_control_bytes_spends_no_try() {
        for secret in [&b"pass\nword"[..], b"pass\x15word", b"pass\x03", b"\x7f"] {
            let tried = elevate(
                Way::Sudo,
                Some(secret),
                &[0; 32],
                [
                    "/nonexistent",
                    &"0".repeat(64),
                    "/nonexistent.sock",
                    "65534",
                ],
                Duration::from_secs(5),
            )
            .await
            .unwrap();
            assert_eq!(tried.outcome, Outcome::Failed);
            assert!(!tried.typed);
        }
    }

    /// A host can't fake our sudo prompt: "Password:" alone is not it.
    #[test]
    fn only_the_marker_is_a_sudo_prompt() {
        assert_eq!(
            steps(Way::Sudo, &["[sudo] password for kayg: "], true),
            [Step::Wait]
        );
    }

    /// doas and su prompts, their refusals, and denial phrases.
    #[test]
    fn doas_and_su_prompts_and_refusals() {
        assert_eq!(
            steps(
                Way::Doas,
                &[
                    "doas (kayg@build-01) password: ",
                    "\r\ndoas: Authentication failed\r\n"
                ],
                true
            ),
            [Step::Type, Step::Done(Outcome::Wrong)]
        );
        assert_eq!(
            steps(
                Way::Su,
                &["Password: ", "\r\nsu: Authentication failure\r\n"],
                true
            ),
            [Step::Type, Step::Done(Outcome::Wrong)]
        );
        assert_eq!(
            steps(Way::Doas, &["doas: Operation not permitted\r\n"], true),
            [Step::Done(Outcome::Denied)]
        );
        assert_eq!(
            steps(
                Way::Sudo,
                &[MARK, "\r\nkayg is not in the sudoers file.\r\n"],
                true
            ),
            [Step::Type, Step::Done(Outcome::Denied)]
        );
    }

    /// Passwordless sudo must never prompt; a prompt there is a failure, and
    /// nothing is typed.
    #[test]
    fn passwordless_sudo_never_types() {
        assert_eq!(
            steps(Way::SudoNoPassword, &[MARK], true),
            [Step::Done(Outcome::Failed)]
        );
        assert_eq!(
            steps(
                Way::SudoNoPassword,
                &["INFRATERNAL_PRIVILEGE_STARTED\r\n"],
                true
            ),
            [Step::Done(Outcome::Started)]
        );
    }

    /// The exit code decides when the terminal closed before any phrase.
    #[test]
    fn exits_without_a_phrase() {
        let mut transcript = Transcript::new(Way::Su, MARK);
        assert_eq!(transcript.exited(Some(1)), Outcome::Failed);
        transcript.typed();
        assert_eq!(transcript.exited(Some(1)), Outcome::Wrong);
        let mut mismatch = Transcript::new(Way::Sudo, MARK);
        mismatch.feed(b"INFRATERNAL_DIGEST_MISMATCH\r\n");
        assert_eq!(mismatch.exited(Some(MISMATCH_CODE)), Outcome::Mismatch);
    }

    /// The sudo command checks the password every time and runs the snippet
    /// with its four public arguments; no secret is ever in argv.
    #[test]
    fn commands_carry_only_public_arguments() {
        if let Some((program, argv)) =
            command(Way::Sudo, MARK, ["/bin/true", "ab", "/tmp/s", "1000"])
        {
            assert!(program.ends_with("/sudo"));
            assert_eq!(&argv[..4], ["-k", "-p", MARK, "--"]);
            assert_eq!(
                &argv[argv.len() - 4..],
                ["/bin/true", "ab", "/tmp/s", "1000"]
            );
        }
        if let Some((_, argv)) = command(Way::Su, MARK, ["/bin/true", "ab", "/tmp/s'x", "1000"]) {
            assert_eq!(&argv[..2], ["root", "-c"]);
            assert!(argv[2].ends_with(r"'/tmp/s'\''x' '1000'"), "{}", argv[2]);
        }
    }

    /// The snippet refuses a binary whose copy doesn't hash to the digest,
    /// and removes its directory. Runs the real program, as this account, with
    /// `/run` swapped for a scratch directory.
    #[test]
    fn the_snippet_runs_nothing_on_a_digest_mismatch() {
        the_snippet_mismatch_case();
    }

    /// The snippet as the tests run it: its root-only directory moved under
    /// `scratch`, and the relay's `exec` replaced by printing the working
    /// directory, so a matching digest shows where root would run.
    fn test_snippet(scratch: &Path) -> String {
        snippet()
            .replace(
                "/run/infraternal-privilege",
                &format!("{}/p", scratch.display()),
            )
            .replace("exec \"$dir/relay\"", "pwd; : \"$dir/relay\"")
    }

    /// Hex SHA-256 of a file, as the server vouches for it.
    fn digest_of(path: &str) -> String {
        use sha2::Digest as _;
        hex(&sha2::Sha256::digest(std::fs::read(path).unwrap()))
    }

    /// J465 P2-4: the snippet leaves the account's working directory before
    /// root does anything.
    #[test]
    fn the_snippet_runs_from_the_root_directory() {
        let scratch = std::env::temp_dir().join(format!("j416-cwd-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &test_snippet(&scratch), "sh", "/bin/true"])
            .arg(digest_of("/bin/true"))
            .args(["/nonexistent", "1"])
            .current_dir(&scratch)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(text.lines().any(|line| line == "/"), "{text}");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// J465 P3-1: root copies only a regular file. A FIFO (or a link to an
    /// endless device) in the account's home is refused at once, instead of
    /// hanging root or filling `/run`; nothing is left behind.
    #[test]
    fn the_snippet_refuses_a_binary_that_is_not_a_regular_file() {
        let scratch = std::env::temp_dir().join(format!("j416-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let fifo = scratch.join("relay-fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let link = scratch.join("relay-link");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        for binary in [&fifo, &link] {
            let mut child = std::process::Command::new("/bin/sh")
                .args(["-c", &test_snippet(&scratch), "sh"])
                .arg(binary)
                .args([&"0".repeat(64), "/nonexistent", "1"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap();
            let group = nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap());
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break Some(status);
                }
                if std::time::Instant::now() > deadline {
                    // The whole group: a hung `cp` must not outlive the test.
                    let _ = nix::sys::signal::killpg(group, nix::sys::signal::Signal::SIGKILL);
                    let _ = child.wait();
                    break None;
                }
                // sleep: poll the child under a 5 s bound.
                std::thread::sleep(Duration::from_millis(20));
            };
            assert!(
                status.is_some_and(|status| !status.success()),
                "{}",
                binary.display()
            );
        }
        let left: Vec<_> = std::fs::read_dir(&scratch)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("p."))
            .collect();
        assert!(left.is_empty(), "{left:?}");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// J465 P3-1: a copy left by an earlier killed try (older than any live
    /// relay) is swept when the snippet next runs.
    #[test]
    fn the_snippet_sweeps_stale_copies() {
        let scratch = std::env::temp_dir().join(format!("j416-sweep-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let stale = scratch.join("p.STALE001");
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("relay"), b"old").unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let fresh = scratch.join("p.FRESH001");
        std::fs::create_dir(&fresh).unwrap();
        let _ = std::process::Command::new("/bin/sh")
            .args(["-c", &test_snippet(&scratch), "sh", "/bin/true"])
            .args([&"0".repeat(64), "/nonexistent", "1"])
            .output()
            .unwrap();
        assert!(!stale.exists());
        assert!(fresh.exists());
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// The digest-mismatch case, shared with the original test name.
    fn the_snippet_mismatch_case() {
        let scratch = std::env::temp_dir().join(format!("j410-snippet-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        let program = snippet().replace(
            "/run/infraternal-privilege",
            &format!("{}/p", scratch.display()),
        );
        let output = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                &program,
                "sh",
                "/bin/true",
                &"0".repeat(64),
                "/nonexistent",
                "1",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(MISMATCH_CODE));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "INFRATERNAL_DIGEST_MISMATCH"
        );
        assert_eq!(std::fs::read_dir(&scratch).unwrap().count(), 0);
        std::fs::remove_dir_all(&scratch).unwrap();
    }

    /// J569 P1 (#399, D274, D376): the terminal the password is typed to must
    /// be private to the infraternal agent.
    ///
    /// `elevate` types the opened password to an `openpty` terminal. Its
    /// `/dev/pts/N` belongs to the account (mode 0620), so any other process
    /// of that account can open it by path and `read` the line before su,
    /// sudo or doas does: no ptrace needed, so the agent being non-dumpable
    /// doesn't help. On the su path the line is the *root* password, and
    /// `choose` takes that path exactly when the account is not an admin. A
    /// local race on hd01 won 19 of 20 times against a reader already blocked
    /// with echo off (`/tmp/j569/ptyrace.py`, J569 evidence).
    ///
    /// This drives the real su path with no secret, so nothing ever reaches
    /// PAM: `elevate` stops at the prompt. Meanwhile a thread of this account
    /// opens every terminal device of ours that appears. It must not get one.
    /// (Run it alone: another test's terminal could also be seen.)
    #[tokio::test]
    async fn another_process_of_the_account_cannot_open_the_password_terminal() {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        let posix =
            root_shell_is_posix(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());
        if !posix || command(Way::Su, MARK, ["", "", "", ""]).is_none() {
            eprintln!("no su with a POSIX root shell here; nothing to check");
            return;
        }
        let uid = nix::unistd::getuid().as_raw();
        let names = || -> std::collections::HashSet<std::ffi::OsString> {
            std::fs::read_dir("/dev/pts")
                .map(|entries| {
                    entries
                        .filter_map(|entry| entry.ok().map(|e| e.file_name()))
                        .collect()
                })
                .unwrap_or_default()
        };
        let before = names();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let watching = stop.clone();
        let scanner = std::thread::spawn(move || {
            while !watching.load(Ordering::Acquire) {
                for name in names() {
                    if before.contains(&name) || name == "ptmx" {
                        continue;
                    }
                    let path = std::path::Path::new("/dev/pts").join(&name);
                    if std::fs::metadata(&path).is_ok_and(|m| m.uid() == uid)
                        && std::fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
                            .open(&path)
                            .is_ok()
                    {
                        return Some(path);
                    }
                }
                std::thread::yield_now();
            }
            None
        });
        for _ in 0..3 {
            let attempt = elevate(
                Way::Su,
                None,
                &[0; 32],
                [
                    "/nonexistent/j569",
                    &"0".repeat(64),
                    "/nonexistent/j569.sock",
                    "65534",
                ],
                Duration::from_secs(5),
            )
            .await;
            assert!(attempt.is_ok_and(|done| done.elevated.is_none()));
            if scanner.is_finished() {
                break;
            }
        }
        stop.store(true, Ordering::Release);
        let opened = scanner.join().unwrap();
        assert!(
            opened.is_none(),
            "another process of this account opened the password terminal {opened:?}"
        );
    }
}
