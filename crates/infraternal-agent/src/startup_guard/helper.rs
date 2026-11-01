//! Single-use shell-user helper; bounded process discovery never alters login behavior [D315].
use super::{Proposal, change, propose, refused};
use nix::unistd::{Uid, User};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub uid: u32,
    pub session: uuid::Uuid,
    #[serde(default)]
    pid: u32,
    op: String,
    proposal: Option<Proposal>,
    #[serde(default)]
    confirmed: bool,
}

/// This route is private, accepts no argv data and drops authority before reading startup files.
#[must_use]
pub fn run_if_requested() -> Option<std::process::ExitCode> {
    if std::env::args_os()
        .nth(1)
        .is_none_or(|arg| arg != "__startup-guard")
    {
        return None;
    }
    let result = (|| {
        if std::env::args_os().len() != 2 {
            return Err(refused());
        }
        let mut bytes = Vec::new();
        io::stdin().take(8193).read_to_end(&mut bytes)?;
        if bytes.len() > 8192 {
            return Err(refused());
        }
        let request: Request = serde_json::from_slice(&bytes).map_err(|_| refused())?;
        let user = User::from_uid(Uid::from_raw(request.uid))?.ok_or_else(refused)?;
        if Uid::effective().is_root() {
            let name = std::ffi::CString::new(user.name.as_str()).map_err(|_| refused())?;
            let groups = nix::unistd::getgrouplist(&name, user.gid)?;
            nix::unistd::setgroups(&groups)?;
            nix::unistd::setgid(user.gid)?;
            nix::unistd::setuid(user.uid)?;
        } else if user.uid != Uid::effective() {
            return Err(refused());
        }
        let result = run(&user.dir, &user.shell, &request)?;
        let bytes = serde_json::to_vec(&result).map_err(|_| refused())?;
        io::stdout().write_all(&bytes)
    })();
    Some(if result.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    })
}

fn environment(pid: u32) -> Vec<(String, String)> {
    let Ok(file) = fs::File::open(format!("/proc/{pid}/environ")) else {
        return Vec::new();
    };
    let mut bytes = Vec::new();
    if file.take(64 * 1024).read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    bytes
        .split(|b| *b == 0)
        .filter_map(|entry| {
            let text = std::str::from_utf8(entry).ok()?;
            let (key, value) = text.split_once('=')?;
            matches!(key, "INFRATERNAL_SESSION" | "ZDOTDIR" | "XDG_CONFIG_HOME")
                .then(|| (key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn same_invocation(pid: u32, original: &str) -> Option<bool> {
    let Ok(file) = fs::File::open(format!("/proc/{pid}/cmdline")) else {
        return Some(false);
    };
    let mut bytes = Vec::new();
    if file.take(8192).read_to_end(&mut bytes).is_err() {
        return Some(false);
    }
    let actual: Vec<_> = bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(std::str::from_utf8)
        .collect::<Result<_, _>>()
        .unwrap_or_default();
    let mut expected: Vec<_> = original.split_ascii_whitespace().collect();
    if expected.first() == Some(&"exec") {
        expected.remove(0);
    }
    let (actual_name, expected_name) = actual.first().zip(expected.first())?;
    let name = Path::new(expected_name).file_name()?.to_str()?;
    // Some multiplexers overwrite argv with a client title after exec. With
    // no original argv left, only one candidate across all files is editable.
    if actual_name.starts_with(&format!("{name}: ")) {
        return None;
    }
    Some(
        Path::new(actual_name).file_name() == Path::new(expected_name).file_name()
            && actual.get(1..) == expected.get(1..),
    )
}

fn processes(root: u32) -> Vec<u32> {
    let mut pids = vec![root];
    let mut at = 0;
    while at < pids.len() && pids.len() < 64 {
        if let Ok(file) = fs::File::open(format!("/proc/{}/task/{}/children", pids[at], pids[at])) {
            let mut text = String::new();
            let _ = file.take(4096).read_to_string(&mut text);
            for child in text
                .split_ascii_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
            {
                if pids.len() < 64 && !pids.contains(&child) {
                    pids.push(child);
                }
            }
        }
        at += 1;
    }
    pids.into_iter().skip(1).collect()
}

fn files(home: &Path, shell: &Path, environment: &[(String, String)]) -> Vec<String> {
    let env = |name: &str| {
        environment
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| PathBuf::from(value))
    };
    let relative = |path: PathBuf| {
        path.strip_prefix(home)
            .ok()
            .and_then(Path::to_str)
            .map(str::to_owned)
    };
    match shell.file_name().and_then(|s| s.to_str()).unwrap_or("") {
        "bash" | "sh" | "dash" => [".bash_profile", ".bash_login", ".profile", ".bashrc"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        "zsh" => {
            let directory = env("ZDOTDIR").map_or_else(
                || home.to_owned(),
                |path| {
                    if path.is_absolute() {
                        path
                    } else {
                        home.join(path)
                    }
                },
            );
            [".zshenv", ".zprofile", ".zshrc", ".zlogin"]
                .into_iter()
                .filter_map(|name| relative(directory.join(name)))
                .collect()
        }
        "fish" => {
            let directory = env("XDG_CONFIG_HOME")
                .unwrap_or_else(|| home.join(".config"))
                .join("fish");
            let mut paths = vec![directory.join("config.fish")];
            if let Ok(entries) = fs::read_dir(directory.join("conf.d")) {
                paths.extend(
                    entries
                        .take(32)
                        .filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| p.extension().is_some_and(|e| e == "fish")),
                );
            }
            paths.sort();
            paths.into_iter().filter_map(relative).collect()
        }
        _ => Vec::new(),
    }
}

fn run(home: &Path, shell: &Path, request: &Request) -> io::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let pids = processes(request.pid);
        // The marker belongs to the real shell environment; no TMUX/ZELLIJ
        // values, hooks, PATH shims, rc arguments or shell options are injected.
        let environments: Vec<_> = pids
            .iter()
            .map(|pid| (*pid, environment(*pid)))
            .filter(|(_, env)| {
                env.iter()
                    .any(|(k, v)| k == "INFRATERNAL_SESSION" && !v.is_empty())
            })
            .collect();
        if request.op != "inspect" {
            if !request.confirmed || !matches!(request.op.as_str(), "apply" | "undo") {
                return Err(refused());
            }
            let proposal = request.proposal.as_ref().ok_or_else(refused)?;
            if !environments
                .iter()
                .any(|(_, env)| files(home, shell, env).contains(&proposal.file))
            {
                return Err(refused());
            }
            change(home, proposal, request.op == "undo")?;
            return Ok(json!({"saved":true}));
        }
        for (pid, env) in &environments {
            let Ok(exe) = fs::read_link(format!("/proc/{pid}/exe")) else {
                continue;
            };
            let Some(mux @ ("tmux" | "zellij")) = exe.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let mut proposals = Vec::new();
            let mut ambiguous = false;
            for path in files(home, shell, env) {
                match propose(home, &path, mux) {
                    Ok(Some(proposal))
                        if same_invocation(*pid, &proposal.original) != Some(false) =>
                    {
                        proposals.push(proposal);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => ambiguous = true,
                    _ => {}
                }
            }
            if !ambiguous && proposals.len() == 1 {
                return Ok(json!({"multiplexer":mux,"proposal":proposals[0]}));
            }
            return Ok(json!({"multiplexer":mux}));
        }
        if Instant::now() >= deadline {
            return Ok(json!({}));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
