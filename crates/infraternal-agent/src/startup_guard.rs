//! Read-only multiplexer discovery and explicitly confirmed, reversible startup edits [D315].
//!
//! The private helper runs as the shell user. It never executes startup text;
//! only an isolated invocation can be rewritten. Unknown syntax stays manual.
use nix::{
    fcntl::{Flock, FlockArg, OFlag, open, openat, renameat},
    sys::stat::{Mode, fchmod},
    unistd::{UnlinkatFlags, unlinkat},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

const FILE_LIMIT: u64 = 256 * 1024;
mod helper;
pub use helper::run_if_requested;

/// Execute a private helper off terminal dispatch, using the authenticated shim and host UID.
/// # Errors
/// Refuses malformed requests, other users, absent shims and helper failures.
pub async fn execute(
    exe: &Path,
    state: &Path,
    input: &[u8],
    allowed_uid: Option<u32>,
) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncWriteExt as _;
    let request: helper::Request = serde_json::from_slice(input).map_err(|_| refused())?;
    if input.len() > 8192
        || allowed_uid.is_some_and(|uid| uid != request.uid)
        || (!nix::unistd::Uid::effective().is_root()
            && request.uid != nix::unistd::Uid::effective().as_raw())
    {
        return Err(refused());
    }
    let session = crate::sessions::observe(
        crate::sessions::rendezvous(state, *request.session.as_bytes()),
        *request.session.as_bytes(),
    )
    .await?;
    let mut command = tokio::process::Command::new(exe);
    command
        .arg("__startup-guard")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    infraternal_shim::prepare_child_without_control(command.as_std_mut());
    let mut child = command.spawn()?;
    let mut body: serde_json::Value = serde_json::from_slice(input).map_err(|_| refused())?;
    body["pid"] = session.pid.into();
    let bytes = serde_json::to_vec(&body).map_err(|_| refused())?;
    let mut stdin = child.stdin.take().ok_or_else(refused)?;
    stdin.write_all(&bytes).await?;
    drop(stdin);
    helper_output(child).await
}

async fn helper_output(mut child: tokio::process::Child) -> io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt as _;
    let stdout = child.stdout.take().ok_or_else(refused)?;
    // Drain before waiting so a full pipe cannot stall a valid response. The
    // helper has no useful stderr; one bounded reader replaces collection of
    // both streams. Dropping the timed-out future still kills the child.
    tokio::time::timeout(std::time::Duration::from_secs(4), async move {
        let mut bytes = Vec::new();
        stdout.take(8193).read_to_end(&mut bytes).await?;
        if bytes.len() > 8192 || !child.wait().await?.success() {
            return Err(refused());
        }
        Ok(bytes)
    })
    .await
    .map_err(|_| refused())?
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub file: String,
    pub line: usize,
    pub original: String,
    pub guard: String,
    pub fingerprint: String,
    pub multiplexer: String,
}

fn invocation(line: &str) -> Option<(&str, String)> {
    let command = line.trim();
    // Shell syntax is deliberately not interpreted. In particular, putting an
    // OR guard in front of an AND list changes precedence and can still exec.
    if command.is_empty()
        || line.len() > 1024
        || !command
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" \t_-./:=@".contains(&b))
    {
        return None;
    }
    let mut words = command.split_ascii_whitespace();
    let first = words.next()?;
    let executable = if first == "exec" {
        words.next()?
    } else {
        first
    };
    let name = Path::new(executable).file_name()?.to_str()?;
    if !matches!(name, "tmux" | "zellij") {
        return None;
    }
    Some((
        name,
        format!("[ -n \"$INFRATERNAL_SESSION\" ] || {command}"),
    ))
}

fn refused() -> io::Error {
    io::ErrorKind::InvalidInput.into()
}

/// Walk directory descriptors, never a symlink (including intermediate components).
fn parent(home: &Path, file: &str) -> io::Result<(File, std::ffi::OsString)> {
    let mut parts = Path::new(file).components().peekable();
    let mut directory = File::from(open(
        home,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(refused());
        };
        if parts.peek().is_none() {
            return Ok((directory, name.to_owned()));
        }
        directory = File::from(openat(
            &directory,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
    }
    Err(refused())
}

fn read_file(directory: &File, name: &std::ffi::OsStr) -> io::Result<File> {
    let file = File::from(openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > FILE_LIMIT
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || infraternal_shim::startup_file_has_attributes(&file)?
    {
        return Err(refused());
    }
    Ok(file)
}

fn contents(file: &File) -> io::Result<String> {
    let mut text = String::new();
    file.take(FILE_LIMIT + 1).read_to_string(&mut text)?;
    if text.len() as u64 > FILE_LIMIT {
        return Err(refused());
    }
    Ok(text)
}

fn fingerprint(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn propose(home: &Path, path: &str, multiplexer: &str) -> io::Result<Option<Proposal>> {
    let (directory, name) = parent(home, path)?;
    let text = contents(&read_file(&directory, &name)?)?;
    let mut proposal = None;
    for (line, original) in text.lines().enumerate() {
        if let Some((name, guard)) = invocation(original)
            && name == multiplexer
        {
            if proposal.is_some() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            proposal = Some(Proposal {
                file: path.to_owned(),
                line,
                original: original.to_owned(),
                guard,
                fingerprint: fingerprint(&text),
                multiplexer: name.to_owned(),
            });
        }
    }
    Ok(proposal)
}

fn change(home: &Path, proposal: &Proposal, undo: bool) -> io::Result<()> {
    let Some((name, guard)) = invocation(&proposal.original) else {
        return Err(refused());
    };
    if guard != proposal.guard || name != proposal.multiplexer {
        return Err(refused());
    }
    let (directory, filename) = parent(home, &proposal.file)?;
    // Serialise our writers without waiting on a lock held by a shell editor.
    let locked = Flock::lock(
        read_file(&directory, &filename)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, e)| io::Error::from(e))?;
    let text = contents(&locked)?;
    let indent =
        &proposal.original[..proposal.original.len() - proposal.original.trim_start().len()];
    let guarded = format!("{indent}{}", proposal.guard);
    let (from, to) = if undo {
        (&guarded, &proposal.original)
    } else {
        (&proposal.original, &guarded)
    };
    let indices: Vec<_> = text
        .lines()
        .enumerate()
        .filter_map(|(i, line)| (line == from).then_some(i))
        .collect();
    let index = if undo {
        if indices.len() != 1 {
            return Err(refused());
        }
        indices[0]
    } else {
        if fingerprint(&text) != proposal.fingerprint || !indices.contains(&proposal.line) {
            return Err(refused());
        }
        proposal.line
    };
    let mut replacement = String::with_capacity(text.len() + guard.len());
    for (i, line) in text.split_inclusive('\n').enumerate() {
        if i == index {
            replacement.push_str(to);
            if line.ends_with("\r\n") {
                replacement.push_str("\r\n");
            } else if line.ends_with('\n') {
                replacement.push('\n');
            }
        } else {
            replacement.push_str(line);
        }
    }
    let temporary = format!(".infraternal-{}", uuid::Uuid::new_v4());
    let mut output = File::from(openat(
        &directory,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )?);
    let result = (|| {
        output.write_all(replacement.as_bytes())?;
        nix::unistd::fchown(
            &output,
            None,
            Some(nix::unistd::Gid::from_raw(locked.metadata()?.gid())),
        )?;
        fchmod(
            &output,
            Mode::from_bits_truncate(locked.metadata()?.mode() & 0o777),
        )?;
        output.sync_all()?;
        let current = read_file(&directory, &filename)?;
        if current.metadata()?.ino() != locked.metadata()?.ino() || contents(&current)? != text {
            return Err(refused());
        }
        renameat(
            &directory,
            temporary.as_str(),
            &directory,
            filename.as_os_str(),
        )?;
        directory.sync_all()
    })();
    if result.is_err() {
        let _ = unlinkat(&directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    result
}

#[cfg(test)]
mod tests {
    //! Real files catch accidental discovery writes, stale overwrites and unsafe path traversal.
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    struct Home(std::path::PathBuf);
    impl Home {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("d315-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, file: &str, content: &str) {
            let path = self.0.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
    }
    impl Drop for Home {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[tokio::test]
    async fn helper_output_keeps_response_and_exit_status_bounds() {
        for (script, accepted) in [
            ("printf %8192s x", true),
            ("printf %8193s x", false),
            ("printf ok; exit 1", false),
        ] {
            let child = tokio::process::Command::new("sh")
                .args(["-c", script])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let output = helper_output(child).await;
            assert_eq!(output.is_ok(), accepted, "{script}");
            if accepted {
                assert_eq!(output.unwrap().len(), 8192);
            }
        }
    }

    #[test]
    fn discovery_never_edits_and_exec_is_guarded_in_place() {
        let home = Home::new();
        let original = "set -e\n  exec tmux new-session -A -s main\nprintf ready\\n\n";
        home.write(".bashrc", original);
        fs::set_permissions(home.0.join(".bashrc"), fs::Permissions::from_mode(0o640)).unwrap();
        let proposal = propose(&home.0, ".bashrc", "tmux").unwrap().unwrap();
        assert_eq!(
            fs::read_to_string(home.0.join(".bashrc")).unwrap(),
            original
        );
        assert_eq!(
            proposal.guard,
            "[ -n \"$INFRATERNAL_SESSION\" ] || exec tmux new-session -A -s main"
        );
        change(&home.0, &proposal, false).unwrap();
        assert_eq!(
            fs::read_to_string(home.0.join(".bashrc")).unwrap(),
            "set -e\n  [ -n \"$INFRATERNAL_SESSION\" ] || exec tmux new-session -A -s main\nprintf ready\\n\n"
        );
        assert_eq!(
            fs::metadata(home.0.join(".bashrc"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        change(&home.0, &proposal, true).unwrap();
        assert_eq!(
            fs::read_to_string(home.0.join(".bashrc")).unwrap(),
            original
        );
        let crlf = "# startup\r\n\texec tmux\r\n";
        home.write(".bashrc", crlf);
        let proposal = propose(&home.0, ".bashrc", "tmux").unwrap().unwrap();
        change(&home.0, &proposal, false).unwrap();
        assert_eq!(
            fs::read_to_string(home.0.join(".bashrc")).unwrap(),
            "# startup\r\n\t[ -n \"$INFRATERNAL_SESSION\" ] || exec tmux\r\n"
        );
        change(&home.0, &proposal, true).unwrap();
        assert_eq!(fs::read_to_string(home.0.join(".bashrc")).unwrap(), crlf);
    }

    #[test]
    fn guard_works_for_shell_variants_and_does_not_rewrite_compound_text() {
        for (file, mux, line) in [
            (".bash_profile", "tmux", "exec tmux"),
            (".zshrc", "zellij", "zellij attach main"),
            (".config/fish/config.fish", "tmux", "exec tmux new -A"),
        ] {
            let home = Home::new();
            home.write(file, &format!("if true\n  {line}\nend\n"));
            let proposal = propose(&home.0, file, mux).unwrap().unwrap();
            change(&home.0, &proposal, false).unwrap();
            assert!(
                fs::read_to_string(home.0.join(file))
                    .unwrap()
                    .contains("  [ -n \"$INFRATERNAL_SESSION\" ] || ")
            );
        }
        let home = Home::new();
        home.write(".zshrc", "exec tmux\ntmux attach\n");
        assert!(propose(&home.0, ".zshrc", "tmux").is_err());
        for line in [
            "echo tmux",
            "# exec tmux",
            "exec tmux; exit",
            "[ -z \"$TMUX\" ] && exec tmux",
            "tmux $(touch unexpected)",
            "tmux &",
            "tmux > output",
            "tmux \\",
        ] {
            assert!(invocation(line).is_none(), "unsafe rewrite: {line}");
        }
    }

    #[test]
    fn stale_apply_and_ambiguous_undo_leave_files_untouched() {
        let home = Home::new();
        home.write(".zshrc", "exec tmux\n");
        let proposal = propose(&home.0, ".zshrc", "tmux").unwrap().unwrap();
        home.write(".zshrc", "exec tmux\n# newer edit\n");
        assert!(change(&home.0, &proposal, false).is_err());
        let proposal = propose(&home.0, ".zshrc", "tmux").unwrap().unwrap();
        change(&home.0, &proposal, false).unwrap();
        let guarded = fs::read_to_string(home.0.join(".zshrc")).unwrap();
        home.write(".zshrc", &format!("# edit after apply\n{guarded}"));
        change(&home.0, &proposal, true).unwrap();
        assert_eq!(
            fs::read_to_string(home.0.join(".zshrc")).unwrap(),
            "# edit after apply\nexec tmux\n# newer edit\n"
        );
        home.write(
            ".zshrc",
            &format!("{}\n{}\n", proposal.guard, proposal.guard),
        );
        assert!(change(&home.0, &proposal, true).is_err());
    }

    #[test]
    fn refuses_symlinks_parent_traversal_and_forged_proposals() {
        let home = Home::new();
        home.write("actual", "exec tmux\n");
        symlink("actual", home.0.join(".bashrc")).unwrap();
        assert!(propose(&home.0, ".bashrc", "tmux").is_err());
        assert!(propose(&home.0, "../actual", "tmux").is_err());
        symlink(".", home.0.join("alias")).unwrap();
        assert!(propose(&home.0, "alias/actual", "tmux").is_err());
        let mut proposal = propose(&home.0, "actual", "tmux").unwrap().unwrap();
        proposal.guard = "touch unexpected".to_owned();
        assert!(change(&home.0, &proposal, false).is_err());
        assert_eq!(
            fs::read_to_string(home.0.join("actual")).unwrap(),
            "exec tmux\n"
        );
    }

    #[test]
    #[ignore = "requires Nix bash, zsh, fish, tmux and zellij; run the D315 shell matrix explicitly"]
    fn real_shell_guards_keep_strict_startup_alive_and_manual_invocation_available() {
        use std::process::Command;
        for shell in ["bash", "zsh", "fish"] {
            for (mux, version) in [("tmux", "-V"), ("zellij", "--version")] {
                let home = Home::new();
                let original = if shell == "fish" {
                    format!("if true\n  exec {mux} {version}\nend\nprintf 'rc-ready\\n'\n")
                } else {
                    format!(
                        "set -e\nif true; then\n  exec {mux} {version}\nfi\nprintf 'rc-ready\\n'\n"
                    )
                };
                home.write("startup", &original);
                let proposal = propose(&home.0, "startup", mux).unwrap().unwrap();
                change(&home.0, &proposal, false).unwrap();
                let script = format!(
                    "source {}; source {}; {mux} {version}; printf 'manual-ready\\n'",
                    home.0.join("startup").display(),
                    home.0.join("startup").display()
                );
                let inside = Command::new(shell)
                    .args(["-c", &script])
                    .env("INFRATERNAL_SESSION", "1")
                    .output()
                    .unwrap();
                assert!(
                    inside.status.success(),
                    "{shell}/{mux}: {}",
                    String::from_utf8_lossy(&inside.stderr)
                );
                let stdout = String::from_utf8_lossy(&inside.stdout);
                assert_eq!(
                    stdout.matches("rc-ready").count(),
                    2,
                    "{shell}/{mux}: {stdout}"
                );
                assert!(
                    stdout.contains(mux) && stdout.contains("manual-ready"),
                    "{shell}/{mux}: {stdout}"
                );
                let outside = Command::new(shell)
                    .args(["-c", &script])
                    .env_remove("INFRATERNAL_SESSION")
                    .output()
                    .unwrap();
                assert!(
                    outside.status.success(),
                    "{shell}/{mux}: {}",
                    String::from_utf8_lossy(&outside.stderr)
                );
                let stdout = String::from_utf8_lossy(&outside.stdout);
                assert!(
                    stdout.contains(mux)
                        && !stdout.contains("rc-ready")
                        && !stdout.contains("manual-ready"),
                    "{shell}/{mux}: {stdout}"
                );
                change(&home.0, &proposal, true).unwrap();
                assert_eq!(
                    fs::read_to_string(home.0.join("startup")).unwrap(),
                    original
                );
            }
        }
    }
}
