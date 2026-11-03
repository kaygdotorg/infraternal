//! Owns the single Traefik child, drains it after the final exposure, and redacts its log stream [#281].

use crate::{
    config::{ListenerPorts, PublishedService, StaticConfig},
    identity,
};
use nix::fcntl::{Flock, FlockArg};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, mpsc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

/// Time allowed for existing connections to drain after the final exposure is removed.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Initial delay after an unexpected child exit.
pub const INITIAL_RESTART_BACKOFF: Duration = Duration::from_millis(200);
/// Maximum delay between unexpected child exit and restart.
pub const MAX_RESTART_BACKOFF: Duration = Duration::from_secs(30);
const MAX_LOG_LINE_BYTES: usize = 8 * 1024;
const LOG_QUEUE_CAPACITY: usize = 128;
const MAX_PROVIDER_SECRET_BYTES: usize = 64 * 1024;
const PRIVATE_FILE_MODE: u32 = 0o600;
const PROXY_CONFIG_MODE: u32 = 0o640;
const ROOTFUL_EXECUTABLE_MODE: u32 = 0o550;
const ROOTLESS_EXECUTABLE_MODE: u32 = 0o500;
const FIRST_PROXY_CHILD_FD: i32 = 64;
const CONFIG_APPLY_TIMEOUT: Duration = Duration::from_secs(5);
const CONFIG_APPLY_POLL_INTERVAL: Duration = Duration::from_millis(50);
#[cfg(target_os = "linux")]
const PROC_FD_ROOT: &str = "/proc/self/fd";
#[cfg(not(target_os = "linux"))]
const PROC_FD_ROOT: &str = "/dev/fd";

/// The lifecycle states of the one process owned by an infraternal agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecyclePhase {
    /// No exposures exist and no process is running.
    Stopped,
    /// The process is being started and has not answered its private health ping.
    Starting,
    /// At least one exposure is active.
    Running,
    /// The final exposure was removed; existing connections have a bounded drain window.
    Draining { deadline: Instant },
    /// An unexpected exit is waiting for the next bounded restart attempt.
    Backoff { retry_at: Instant, delay: Duration },
}

/// Work requested from the process owner by one lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAction {
    /// No external process operation is needed.
    Keep,
    /// Start Traefik after acquisition and config rendering.
    Start,
    /// Atomically replace the dynamic exposure snapshot.
    Apply,
    /// Replace the routes with an empty snapshot and begin draining.
    BeginDrain,
    /// Stop the owned child after the drain deadline.
    Stop,
    /// Wait this long before an unexpected-exit restart.
    RetryAfter(Duration),
}

/// Deterministic state machine separated from process I/O for lifecycle tests.
pub struct Lifecycle {
    phase: LifecyclePhase,
    next_backoff: Duration,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            phase: LifecyclePhase::Stopped,
            next_backoff: INITIAL_RESTART_BACKOFF,
        }
    }
}

impl Lifecycle {
    /// Return the current lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    /// Reconcile the owned child with the desired exposure count.
    pub fn update(&mut self, exposure_count: usize, now: Instant) -> LifecycleAction {
        match self.phase {
            LifecyclePhase::Stopped if exposure_count > 0 => {
                self.phase = LifecyclePhase::Starting;
                LifecycleAction::Start
            }
            LifecyclePhase::Running if exposure_count == 0 => {
                self.phase = LifecyclePhase::Draining {
                    deadline: now + DRAIN_TIMEOUT,
                };
                LifecycleAction::BeginDrain
            }
            LifecyclePhase::Draining { .. } if exposure_count > 0 => {
                self.phase = LifecyclePhase::Running;
                LifecycleAction::Apply
            }
            LifecyclePhase::Backoff { .. } if exposure_count == 0 => {
                self.phase = LifecyclePhase::Stopped;
                self.next_backoff = INITIAL_RESTART_BACKOFF;
                LifecycleAction::Keep
            }
            LifecyclePhase::Running if exposure_count > 0 => LifecycleAction::Apply,
            _ => LifecycleAction::Keep,
        }
    }

    /// Record that the child has passed its private health check.
    pub fn child_started(&mut self, exposure_count: usize, now: Instant) -> LifecycleAction {
        match self.phase {
            LifecyclePhase::Starting if exposure_count > 0 => {
                self.phase = LifecyclePhase::Running;
                LifecycleAction::Keep
            }
            LifecyclePhase::Starting => {
                self.phase = LifecyclePhase::Draining {
                    deadline: now + DRAIN_TIMEOUT,
                };
                LifecycleAction::BeginDrain
            }
            _ => LifecycleAction::Keep,
        }
    }

    /// Schedule an unexpected-exit restart when desired exposures remain.
    pub fn child_exited(&mut self, exposure_count: usize, now: Instant) -> LifecycleAction {
        if exposure_count == 0 {
            self.phase = LifecyclePhase::Stopped;
            self.next_backoff = INITIAL_RESTART_BACKOFF;
            return LifecycleAction::Keep;
        }
        let delay = self.next_backoff;
        self.next_backoff = delay.saturating_mul(2).min(MAX_RESTART_BACKOFF);
        self.phase = LifecyclePhase::Backoff {
            retry_at: now + delay,
            delay,
        };
        LifecycleAction::RetryAfter(delay)
    }

    /// Fire a drain deadline or a pending restart when its time arrives.
    pub fn tick(&mut self, exposure_count: usize, now: Instant) -> LifecycleAction {
        match self.phase {
            LifecyclePhase::Draining { .. } if exposure_count > 0 => {
                self.phase = LifecyclePhase::Running;
                LifecycleAction::Apply
            }
            LifecyclePhase::Draining { deadline } if now >= deadline => {
                self.phase = LifecyclePhase::Stopped;
                self.next_backoff = INITIAL_RESTART_BACKOFF;
                LifecycleAction::Stop
            }
            LifecyclePhase::Backoff { .. } if exposure_count == 0 => {
                self.phase = LifecyclePhase::Stopped;
                self.next_backoff = INITIAL_RESTART_BACKOFF;
                LifecycleAction::Keep
            }
            LifecyclePhase::Backoff { retry_at, .. } if now >= retry_at => {
                self.phase = LifecyclePhase::Starting;
                LifecycleAction::Start
            }
            _ => LifecycleAction::Keep,
        }
    }
}

/// Replace each provider credential value before a Traefik line enters tracing.
#[must_use]
pub fn redact_log_line(line: &str, secrets: &[&str]) -> String {
    let mut secrets: Vec<_> = secrets
        .iter()
        .flat_map(|secret| [*secret, secret.trim_end_matches(['\r', '\n'])])
        .filter(|secret| !secret.is_empty())
        .collect();
    secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
    let line = secrets.into_iter().fold(line.to_owned(), |line, secret| {
        line.replace(secret, "[REDACTED]")
    });
    redact_named_credentials(&line)
}

#[derive(Clone, Copy)]
enum CredentialKind {
    Authorization,
    Header,
    Query,
}

const CREDENTIAL_KEYS: &[(&str, CredentialKind)] = &[
    ("proxy-authorization", CredentialKind::Authorization),
    ("authorization", CredentialKind::Authorization),
    ("set-cookie", CredentialKind::Header),
    ("cookie", CredentialKind::Header),
    ("client_secret", CredentialKind::Query),
    ("refresh_token", CredentialKind::Query),
    ("access_token", CredentialKind::Query),
    ("dns_api_token", CredentialKind::Query),
    ("api_key", CredentialKind::Query),
    ("apikey", CredentialKind::Query),
    ("credential", CredentialKind::Query),
    ("password", CredentialKind::Query),
    ("secret", CredentialKind::Query),
    ("token", CredentialKind::Query),
];

fn redact_named_credentials(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut output = String::with_capacity(line.len());
    let mut copied_until = 0;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some((kind, value_start)) = CREDENTIAL_KEYS.iter().find_map(|(key, kind)| {
            let end = cursor.checked_add(key.len())?;
            bytes
                .get(cursor..end)?
                .eq_ignore_ascii_case(key.as_bytes())
                .then(|| credential_value_start(bytes, end).map(|value_start| (*kind, value_start)))
                .flatten()
        }) else {
            cursor += 1;
            continue;
        };

        let (prefix_end, value_end) = credential_span(bytes, value_start, kind);
        if value_end <= value_start {
            cursor += 1;
            continue;
        }
        output.push_str(&line[copied_until..prefix_end]);
        output.push_str("[REDACTED]");
        copied_until = value_end;
        cursor = value_end;
    }
    output.push_str(&line[copied_until..]);
    output
}

fn credential_value_start(bytes: &[u8], key_end: usize) -> Option<usize> {
    let mut separator = key_end;
    while bytes
        .get(separator)
        .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"'))
    {
        separator += 1;
    }
    if !matches!(bytes.get(separator), Some(b':' | b'=')) {
        return None;
    }
    let mut value_start = separator + 1;
    while bytes.get(value_start).is_some_and(u8::is_ascii_whitespace) {
        value_start += 1;
    }
    Some(value_start)
}

fn credential_span(bytes: &[u8], value_start: usize, kind: CredentialKind) -> (usize, usize) {
    let quote = match bytes.get(value_start) {
        Some(b'\'' | b'"') => bytes.get(value_start).copied(),
        _ => None,
    };
    let mut content_start = value_start + usize::from(quote.is_some());
    let prefix_end;
    if matches!(kind, CredentialKind::Authorization) {
        let scheme_end = token_end(bytes, content_start, false);
        let scheme = bytes.get(content_start..scheme_end).unwrap_or_default();
        if (scheme.eq_ignore_ascii_case(b"bearer") || scheme.eq_ignore_ascii_case(b"basic"))
            && bytes.get(scheme_end).is_some_and(u8::is_ascii_whitespace)
        {
            content_start = scheme_end + 1;
            while bytes
                .get(content_start)
                .is_some_and(u8::is_ascii_whitespace)
            {
                content_start += 1;
            }
            prefix_end = content_start;
        } else {
            prefix_end = value_start + usize::from(quote.is_some());
        }
    } else {
        prefix_end = value_start + usize::from(quote.is_some());
    }
    let end = token_end(bytes, content_start, matches!(kind, CredentialKind::Query));
    (prefix_end, end)
}

fn token_end(bytes: &[u8], start: usize, query: bool) -> usize {
    let mut end = start;
    while let Some(byte) = bytes.get(end) {
        let delimiter = byte.is_ascii_whitespace()
            || matches!(byte, b',' | b'"' | b'\'')
            || (query && matches!(byte, b'&' | b'#'));
        if delimiter {
            break;
        }
        end += 1;
    }
    end
}

/// Check Traefik's private `/ping` endpoint without allowing a probe to leave loopback.
///
/// # Errors
/// Returns an error if the address is not loopback, the endpoint times out, or it is unhealthy.
pub fn check_private_ping(address: SocketAddr, timeout: Duration) -> io::Result<()> {
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy health checks must use loopback",
        ));
    }
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut status = String::new();
    BufReader::new(stream).take(1024).read_line(&mut status)?;
    let mut fields = status.split_ascii_whitespace();
    if matches!(
        (fields.next(), fields.next()),
        (Some("HTTP/1.1" | "HTTP/1.0"), Some("200"))
    ) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "proxy private health ping did not return HTTP 200",
        ))
    }
}

/// Check the exact dynamic snapshot through its nonce-gated loopback-only rawdata route.
///
/// # Errors
/// Returns an error when the endpoint is not loopback, the request times out, or the generation is not active.
fn check_private_config_generation(
    address: SocketAddr,
    generation: &str,
    timeout: Duration,
) -> io::Result<()> {
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy config checks must use loopback",
        ));
    }
    if uuid::Uuid::parse_str(generation).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy config generation is invalid",
        ));
    }
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET /api/rawdata HTTP/1.1\r\nHost: localhost\r\nX-Infraternal-Config-Generation: {generation}\r\nConnection: close\r\n\r\n"
    )?;
    let mut status = String::new();
    BufReader::new(stream).take(1024).read_line(&mut status)?;
    let mut fields = status.split_ascii_whitespace();
    if matches!(
        (fields.next(), fields.next()),
        (Some("HTTP/1.1" | "HTTP/1.0"), Some("200"))
    ) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "proxy private config generation probe did not return HTTP 200",
        ))
    }
}

fn wait_for_config_generation(
    address: SocketAddr,
    generation: &str,
    timeout: Duration,
) -> io::Result<()> {
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy config checks must use loopback",
        ));
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy did not apply the dynamic config generation before the deadline",
            ));
        }
        if check_private_config_generation(
            address,
            generation,
            remaining.min(Duration::from_millis(250)),
        )
        .is_ok()
        {
            return Ok(());
        }
        thread::sleep(remaining.min(CONFIG_APPLY_POLL_INTERVAL));
    }
}

/// Bounded log output accepted from one managed Traefik child.
pub type ProxyLog = dyn Fn(String) + Send + Sync + 'static;

/// Owns one Traefik child and its bounded, credential-sanitized output readers.
pub struct TraefikChild {
    child: Child,
    readers: Vec<JoinHandle<()>>,
    logger: Option<JoinHandle<()>>,
}

impl TraefikChild {
    /// Start an installed executable with private config and provider credential file paths.
    ///
    /// Provider variable names are converted to `_FILE` forms. Credential bytes are read only
    /// into zeroizing memory for log redaction; the cleared child environment receives paths.
    ///
    /// # Errors
    /// Returns an error for unsafe files, invalid provider variable names, or a failed spawn.
    pub fn spawn(
        executable: &Path,
        config: &Path,
        provider_files: &[(&str, &Path)],
        log: Arc<ProxyLog>,
    ) -> io::Result<Self> {
        let rootful = identity::rootful();
        let prepared = prepare_child_files(executable, config, provider_files, rootful)?;
        let (mut child, secrets) = spawn_proxy_command(prepared, rootful)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("proxy stdout pipe was not created"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("proxy stderr pipe was not created"))?;

        let (sender, receiver) = mpsc::sync_channel(LOG_QUEUE_CAPACITY);
        let logger = thread::spawn(move || {
            for line in receiver {
                log(line);
            }
        });
        let readers = vec![
            spawn_log_reader(stdout, sender.clone(), Arc::clone(&secrets)),
            spawn_log_reader(stderr, sender, secrets),
        ];
        Ok(Self {
            child,
            readers,
            logger: Some(logger),
        })
    }

    /// Observe an unexpected child exit without blocking.
    ///
    /// # Errors
    /// Returns operating-system errors from `try_wait`.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Stop and reap the owned child, then finish its bounded log readers.
    ///
    /// # Errors
    /// Returns operating-system errors while stopping or reaping the child.
    pub fn stop(&mut self) -> io::Result<()> {
        if !self.child.try_wait().is_ok_and(|status| status.is_some()) {
            // The child can exit between try_wait and kill; wait below is the authoritative reap.
            let _ = self.child.kill();
        }
        let _ = self.child.wait()?;
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
        if let Some(logger) = self.logger.take() {
            let _ = logger.join();
        }
        Ok(())
    }
}

impl Drop for TraefikChild {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct PreparedChildFiles {
    executable_fd: i32,
    config_name: std::ffi::OsString,
    variables: Vec<(String, PathBuf)>,
    secrets: Arc<Vec<Zeroizing<String>>>,
    working_directory: File,
    inherited_files: Vec<File>,
    inherited_descriptors: Vec<(i32, i32)>,
}

struct PreparedProviderFiles {
    variables: Vec<(String, PathBuf)>,
    redaction_secrets: Arc<Vec<Zeroizing<String>>>,
}

struct ProxyChildFilePolicy {
    host_user: u32,
    child_user: u32,
    child_group: u32,
    executable_group: u32,
    executable_mode: u32,
    config_group: u32,
    config_mode: u32,
    directory_mode: u32,
}

fn proxy_child_file_policy(rootful: bool) -> ProxyChildFilePolicy {
    let (child_user, child_group) = identity::child_ids();
    let host_group = nix::unistd::Gid::effective().as_raw();
    ProxyChildFilePolicy {
        host_user: nix::unistd::Uid::effective().as_raw(),
        child_user,
        child_group,
        executable_group: if rootful {
            identity::TRAEFIK_GID
        } else {
            host_group
        },
        executable_mode: if rootful {
            ROOTFUL_EXECUTABLE_MODE
        } else {
            ROOTLESS_EXECUTABLE_MODE
        },
        config_group: if rootful {
            identity::TRAEFIK_GID
        } else {
            host_group
        },
        config_mode: if rootful {
            PROXY_CONFIG_MODE
        } else {
            PRIVATE_FILE_MODE
        },
        directory_mode: if rootful { 0o750 } else { 0o700 },
    }
}

fn validate_proxy_paths(
    executable: &Path,
    config: &Path,
    policy: &ProxyChildFilePolicy,
) -> io::Result<(PathBuf, std::ffi::OsString)> {
    validate_proxy_file(
        executable,
        policy.host_user,
        policy.executable_group,
        policy.executable_mode,
    )?;
    validate_proxy_file(
        config,
        policy.host_user,
        policy.config_group,
        policy.config_mode,
    )?;
    let working_directory_path = config.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy config path has no parent",
        )
    })?;
    validate_proxy_directory(
        working_directory_path,
        policy.host_user,
        policy.config_group,
        policy.directory_mode,
    )?;
    let config_name = config.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy config path has no file name",
        )
    })?;
    Ok((working_directory_path.to_owned(), config_name.to_owned()))
}

fn prepare_child_files(
    executable: &Path,
    config: &Path,
    provider_files: &[(&str, &Path)],
    rootful: bool,
) -> io::Result<PreparedChildFiles> {
    let policy = proxy_child_file_policy(rootful);
    let (working_directory_path, config_name) = validate_proxy_paths(executable, config, &policy)?;
    if provider_files.len() > 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS provider file count exceeds its limit",
        ));
    }

    let mut inherited_files = Vec::with_capacity(provider_files.len() + 2);
    let mut inherited_descriptors = Vec::with_capacity(provider_files.len() + 1);
    let mut next_child_fd = FIRST_PROXY_CHILD_FD;
    let executable_file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(executable)?;
    validate_proxy_file_metadata(
        &executable_file.metadata()?,
        policy.host_user,
        policy.executable_group,
        policy.executable_mode,
    )?;
    let executable_fd = add_inherited_file(
        executable_file,
        &mut inherited_files,
        &mut inherited_descriptors,
        &mut next_child_fd,
    )?;
    let working_directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(working_directory_path)?;
    let provider_files = prepare_provider_files(
        provider_files,
        policy.child_user,
        policy.child_group,
        &mut inherited_files,
        &mut inherited_descriptors,
        &mut next_child_fd,
    )?;
    Ok(PreparedChildFiles {
        executable_fd,
        config_name,
        variables: provider_files.variables,
        secrets: provider_files.redaction_secrets,
        working_directory,
        inherited_files,
        inherited_descriptors,
    })
}

fn prepare_provider_files(
    provider_files: &[(&str, &Path)],
    child_user: u32,
    child_group: u32,
    inherited_files: &mut Vec<File>,
    inherited_descriptors: &mut Vec<(i32, i32)>,
    next_child_fd: &mut i32,
) -> io::Result<PreparedProviderFiles> {
    let mut variables = Vec::with_capacity(provider_files.len());
    let mut secrets = Vec::with_capacity(provider_files.len());
    let mut seen_variables = std::collections::BTreeSet::new();
    for (name, path) in provider_files {
        if !valid_provider_variable(name) || !seen_variables.insert(*name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS provider file variable is invalid or duplicated",
            ));
        }
        validate_proxy_file(path, child_user, child_group, PRIVATE_FILE_MODE)?;
        let mut secret = Zeroizing::new(String::new());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(path)?;
        validate_proxy_file_metadata(
            &file.metadata()?,
            child_user,
            child_group,
            PRIVATE_FILE_MODE,
        )?;
        file.take((MAX_PROVIDER_SECRET_BYTES + 1) as u64)
            .read_to_string(&mut secret)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS provider credential file is not valid UTF-8",
                )
            })?;
        if secret.len() > MAX_PROVIDER_SECRET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS provider credential file exceeds its byte limit",
            ));
        }
        if !secret.is_empty() {
            secrets.push(secret);
        }
        let directory_path = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS provider file has no parent",
            )
        })?;
        validate_proxy_directory(directory_path, child_user, child_group, 0o700)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(directory_path)?;
        let directory_fd = add_inherited_file(
            directory,
            inherited_files,
            inherited_descriptors,
            next_child_fd,
        )?;
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "DNS provider file name is invalid",
                )
            })?;
        variables.push((
            format!("{name}_FILE"),
            PathBuf::from(format!("{PROC_FD_ROOT}/{directory_fd}/{filename}")),
        ));
    }
    Ok(PreparedProviderFiles {
        variables,
        redaction_secrets: Arc::new(secrets),
    })
}

fn spawn_proxy_command(
    prepared: PreparedChildFiles,
    rootful: bool,
) -> io::Result<(Child, Arc<Vec<Zeroizing<String>>>)> {
    let PreparedChildFiles {
        executable_fd,
        config_name,
        variables,
        secrets,
        working_directory,
        inherited_files,
        inherited_descriptors,
    } = prepared;
    let mut command = Command::new(format!("{PROC_FD_ROOT}/{executable_fd}"));
    command
        .arg("--configFile")
        .arg(config_name)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, path) in variables {
        command.env(name, path);
    }
    #[cfg(unix)]
    {
        // Keep shutdown scoped to this child's process group. The process owner also holds
        // an exclusive file lock; no inherited numeric PID is used to identify an owner.
        command.process_group(0);
    }
    let child_identity = rootful.then_some((identity::TRAEFIK_UID, identity::TRAEFIK_GID));
    infraternal_shim::prepare_child_without_control(&mut command);
    #[cfg(target_os = "linux")]
    infraternal_shim::prepare_parent_bound_child(&mut command);
    infraternal_shim::prepare_proxy_child(
        &mut command,
        &working_directory,
        &inherited_descriptors,
        child_identity,
    )?;
    let child = command.spawn()?;
    drop(inherited_files);
    Ok((child, secrets))
}

fn spawn_log_reader<R>(
    reader: R,
    sender: mpsc::SyncSender<String>,
    secrets: Arc<Vec<Zeroizing<String>>>,
) -> JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        loop {
            let line = match read_bounded_line(&mut reader) {
                Ok(Some(BoundedLogLine::Complete(line))) => line,
                Ok(Some(BoundedLogLine::Oversized)) => continue,
                Ok(None) | Err(_) => return,
            };
            let line = String::from_utf8_lossy(&line);
            let known_secrets: Vec<_> = secrets.iter().map(|secret| secret.as_str()).collect();
            let line = redact_log_line(line.trim_end_matches(['\r', '\n']), &known_secrets);
            // A slow or failed log sink must not backpressure Traefik's pipes.
            let _ = sender.try_send(line);
        }
    })
}

enum BoundedLogLine {
    Complete(Vec<u8>),
    Oversized,
}

fn read_bounded_line<R: BufRead>(reader: &mut R) -> io::Result<Option<BoundedLogLine>> {
    let mut line = Vec::with_capacity(MAX_LOG_LINE_BYTES);
    let mut oversized = false;
    loop {
        let (consumed, newline, eof) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                (0, false, true)
            } else {
                let newline_at = available.iter().position(|byte| *byte == b'\n');
                let consumed = newline_at.map_or(available.len(), |index| index + 1);
                let remaining = MAX_LOG_LINE_BYTES.saturating_sub(line.len());
                let copied = consumed.min(remaining);
                line.extend_from_slice(&available[..copied]);
                oversized |= consumed > remaining;
                (consumed, newline_at.is_some(), false)
            }
        };
        if eof {
            return if line.is_empty() {
                Ok(None)
            } else if oversized {
                Ok(Some(BoundedLogLine::Oversized))
            } else {
                Ok(Some(BoundedLogLine::Complete(line)))
            };
        }
        reader.consume(consumed);
        if newline {
            return Ok(Some(if oversized {
                BoundedLogLine::Oversized
            } else {
                BoundedLogLine::Complete(line)
            }));
        }
        // Continue draining an oversized record so neither stream can block the child.
    }
}

fn validate_proxy_file(
    path: &Path,
    owner_user: u32,
    owner_group: u32,
    required_mode: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_proxy_file_metadata(&metadata, owner_user, owner_group, required_mode)
}

fn validate_proxy_file_metadata(
    metadata: &fs::Metadata,
    owner_user: u32,
    owner_group: u32,
    required_mode: u32,
) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != owner_user
        || metadata.gid() != owner_group
        || metadata.mode() & 0o7777 != required_mode
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy executable, config, or credential file has unsafe ownership or mode",
        ));
    }
    Ok(())
}

fn validate_proxy_directory(
    path: &Path,
    owner_user: u32,
    owner_group: u32,
    required_mode: u32,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != owner_user
        || metadata.gid() != owner_group
        || metadata.mode() & 0o7777 != required_mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy child directory has unsafe ownership or mode",
        ));
    }
    Ok(())
}

fn add_inherited_file(
    file: std::fs::File,
    files: &mut Vec<std::fs::File>,
    descriptors: &mut Vec<(i32, i32)>,
    next_child_fd: &mut i32,
) -> io::Result<i32> {
    if *next_child_fd >= FIRST_PROXY_CHILD_FD + 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy child descriptor count exceeds its limit",
        ));
    }
    let target = *next_child_fd;
    descriptors.push((file.as_raw_fd(), target));
    files.push(file);
    *next_child_fd += 1;
    Ok(target)
}

fn valid_provider_variable(name: &str) -> bool {
    !name.is_empty()
        && !name.ends_with("_FILE")
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_uppercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Paths and health settings needed by the one node-local Traefik owner.
pub struct SupervisorSettings {
    /// Verified executable installed beneath the component digest.
    pub executable: PathBuf,
    /// Private rendered static configuration destination.
    pub static_config_path: PathBuf,
    /// Private watched dynamic configuration destination.
    pub dynamic_config_path: PathBuf,
    /// Current static listeners, DNS resolver and private ping configuration.
    pub static_config: StaticConfig,
    /// Provider variable names and owner-only token paths, never token values.
    pub provider_files: Vec<(String, PathBuf)>,
    /// Loopback-only Traefik health endpoint matching `static_config.private_ping_port`.
    pub private_ping_address: SocketAddr,
    /// Bounded time allowed for the first private health response after start.
    pub startup_timeout: Duration,
}

enum SupervisorCommand {
    Replace(
        Vec<PublishedService>,
        mpsc::Sender<io::Result<Option<ListenerPorts>>>,
    ),
    IsRunning(mpsc::Sender<bool>),
    Shutdown(mpsc::Sender<()>),
}

/// Owns the process lifecycle and applies complete exposure snapshots atomically.
pub struct TraefikSupervisor {
    sender: mpsc::SyncSender<SupervisorCommand>,
    worker: Option<JoinHandle<()>>,
    _lock: Flock<File>,
}

impl TraefikSupervisor {
    /// Start an idle owner; it starts Traefik only after a non-empty snapshot arrives.
    ///
    /// # Errors
    /// Returns an error when the health endpoint is not the private configured loopback endpoint or the owner thread cannot start.
    pub fn start(settings: SupervisorSettings, log: Arc<ProxyLog>) -> io::Result<Self> {
        if !settings.private_ping_address.ip().is_loopback()
            || settings.private_ping_address.port() != settings.static_config.private_ping_port
            || settings.startup_timeout.is_zero()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy supervisor health endpoint is outside policy",
            ));
        }
        let lock = acquire_supervisor_lock(&settings.static_config_path)?;
        let (sender, receiver) = mpsc::sync_channel(4);
        let worker = thread::Builder::new()
            .name("proxy-supervisor".to_owned())
            .spawn(move || run_supervisor(&settings, &log, &receiver))?;
        Ok(Self {
            sender,
            worker: Some(worker),
            _lock: lock,
        })
    }

    /// Replace every active route from one complete authorized exposure snapshot.
    ///
    /// # Errors
    /// Returns an error when config rendering/writing, process startup, or health readiness fails.
    pub fn replace(&self, services: Vec<PublishedService>) -> io::Result<Option<ListenerPorts>> {
        let (reply, received) = mpsc::channel();
        self.sender
            .send(SupervisorCommand::Replace(services, reply))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "proxy supervisor stopped"))?;
        received
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "proxy supervisor stopped"))?
    }

    /// Observe whether its Traefik child is live and passes the private health ping.
    ///
    /// # Errors
    /// Returns an error when the owner thread has stopped.
    pub fn is_running(&self) -> io::Result<bool> {
        let (reply, received) = mpsc::channel();
        self.sender
            .send(SupervisorCommand::IsRunning(reply))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "proxy supervisor stopped"))?;
        received
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "proxy supervisor stopped"))
    }

    fn shutdown(&mut self) {
        let Some(worker) = self.worker.take() else {
            return;
        };
        let (reply, received) = mpsc::channel();
        let _ = self.sender.send(SupervisorCommand::Shutdown(reply));
        let _ = received.recv_timeout(Duration::from_secs(5));
        let _ = worker.join();
    }
}

impl Drop for TraefikSupervisor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

enum Inbox {
    Command(SupervisorCommand),
    Timeout,
    Disconnected,
}

#[derive(Default)]
struct SupervisorRuntime {
    lifecycle: Lifecycle,
    services: Vec<PublishedService>,
    child: Option<TraefikChild>,
    listener_ports: Option<ListenerPorts>,
}

fn run_supervisor(
    settings: &SupervisorSettings,
    log: &Arc<ProxyLog>,
    receiver: &mpsc::Receiver<SupervisorCommand>,
) {
    let mut runtime = SupervisorRuntime::default();
    loop {
        match receive_command(receiver, runtime.lifecycle.phase()) {
            Inbox::Command(SupervisorCommand::Replace(next, reply)) => {
                let result = replace_services(settings, log, &mut runtime, next);
                let _ = reply.send(result);
            }
            Inbox::Command(SupervisorCommand::IsRunning(reply)) => {
                let running = match runtime.child.as_mut() {
                    Some(owned) => {
                        owned.try_wait().is_ok_and(|status| status.is_none())
                            && check_private_ping(
                                settings.private_ping_address,
                                Duration::from_millis(250),
                            )
                            .is_ok()
                    }
                    None => false,
                };
                let _ = reply.send(running);
            }
            Inbox::Command(SupervisorCommand::Shutdown(reply)) => {
                let _ = stop_child(&mut runtime.child);
                let _ = reply.send(());
                break;
            }
            Inbox::Timeout => handle_supervisor_timeout(settings, log, &mut runtime),
            Inbox::Disconnected => {
                let _ = stop_child(&mut runtime.child);
                break;
            }
        }
    }
}

fn replace_services(
    settings: &SupervisorSettings,
    log: &Arc<ProxyLog>,
    runtime: &mut SupervisorRuntime,
    services: Vec<PublishedService>,
) -> io::Result<Option<ListenerPorts>> {
    let previous_services = std::mem::replace(&mut runtime.services, services);
    let active_count = runtime.services.len();
    let revoked_routes = revoked_mesh_route_ids(&previous_services, &runtime.services);
    let action = runtime.lifecycle.update(active_count, Instant::now());
    let result = match action {
        LifecycleAction::Start => start_runtime_child(settings, log, runtime).map(Some),
        LifecycleAction::BeginDrain => match apply_dynamic_snapshot(settings, &[]) {
            Ok(()) => Ok(runtime.listener_ports),
            Err(error) => {
                let stop_result = stop_child(&mut runtime.child);
                runtime.listener_ports = None;
                let _ = runtime.lifecycle.child_exited(0, Instant::now());
                match stop_result {
                    Ok(()) => Err(error),
                    Err(stop_error) => Err(stop_error),
                }
            }
        },
        LifecycleAction::Apply | LifecycleAction::Keep => {
            if runtime.services.is_empty() {
                Ok(runtime.listener_ports)
            } else if revoked_routes.is_empty() {
                apply_dynamic_snapshot(settings, &runtime.services).map(|()| runtime.listener_ports)
            } else {
                let route_removal_snapshot: Vec<_> = runtime
                    .services
                    .iter()
                    .filter(|service| !revoked_routes.contains(&service.id))
                    .cloned()
                    .collect();
                apply_dynamic_snapshot(settings, &route_removal_snapshot)
                    .and_then(|()| apply_dynamic_snapshot(settings, &runtime.services))
                    .map(|()| runtime.listener_ports)
            }
        }
        LifecycleAction::Stop => {
            runtime.listener_ports = None;
            Ok(None)
        }
        LifecycleAction::RetryAfter(_) => Ok(runtime.listener_ports),
    };
    if result.is_err() && matches!(runtime.lifecycle.phase(), LifecyclePhase::Starting) {
        let _ = runtime
            .lifecycle
            .child_exited(runtime.services.len(), Instant::now());
    }
    if result.is_err() && runtime.child.is_some() {
        let _ = stop_child(&mut runtime.child);
        let _ = runtime
            .lifecycle
            .child_exited(runtime.services.len(), Instant::now());
    }
    result
}

fn start_runtime_child(
    settings: &SupervisorSettings,
    log: &Arc<ProxyLog>,
    runtime: &mut SupervisorRuntime,
) -> io::Result<ListenerPorts> {
    let (started, ports) = start_managed_child(settings, &mut runtime.services, Arc::clone(log))?;
    runtime.child = Some(started);
    runtime.listener_ports = Some(ports);
    let _ = runtime
        .lifecycle
        .child_started(runtime.services.len(), Instant::now());
    Ok(ports)
}

fn handle_supervisor_timeout(
    settings: &SupervisorSettings,
    log: &Arc<ProxyLog>,
    runtime: &mut SupervisorRuntime,
) {
    let child_exited = match runtime.child.as_mut() {
        Some(owned) => !owned.try_wait().is_ok_and(|status| status.is_none()),
        None => false,
    };
    if child_exited {
        let _ = stop_child(&mut runtime.child);
        let _ = runtime
            .lifecycle
            .child_exited(runtime.services.len(), Instant::now());
    }
    match runtime
        .lifecycle
        .tick(runtime.services.len(), Instant::now())
    {
        LifecycleAction::Stop => {
            let _ = stop_child(&mut runtime.child);
            runtime.listener_ports = None;
        }
        LifecycleAction::Start if start_runtime_child(settings, log, runtime).is_err() => {
            let _ = runtime
                .lifecycle
                .child_exited(runtime.services.len(), Instant::now());
        }
        _ => {}
    }
}

fn receive_command(receiver: &mpsc::Receiver<SupervisorCommand>, phase: LifecyclePhase) -> Inbox {
    let outcome = match phase {
        LifecyclePhase::Stopped => {
            return receiver.recv().map_or(Inbox::Disconnected, Inbox::Command);
        }
        LifecyclePhase::Draining { deadline } => receiver.recv_timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250)),
        ),
        LifecyclePhase::Backoff { retry_at, .. } => {
            receiver.recv_timeout(retry_at.saturating_duration_since(Instant::now()))
        }
        LifecyclePhase::Starting | LifecyclePhase::Running => {
            receiver.recv_timeout(Duration::from_millis(250))
        }
    };
    match outcome {
        Ok(command) => Inbox::Command(command),
        Err(mpsc::RecvTimeoutError::Timeout) => Inbox::Timeout,
        Err(mpsc::RecvTimeoutError::Disconnected) => Inbox::Disconnected,
    }
}

fn start_managed_child(
    settings: &SupervisorSettings,
    services: &mut [PublishedService],
    log: Arc<ProxyLog>,
) -> io::Result<(TraefikChild, ListenerPorts)> {
    let mut config = settings.static_config.clone();
    if config.ports.mesh_http.is_none() && config.ports.mesh_https.is_none() {
        config.ports = crate::config::detect_mixed_listener_ports(
            nix::unistd::Uid::effective().is_root(),
            config.mesh_address,
        )?;
    }
    for service in services.iter_mut() {
        service.https_port = config.ports.https_for_publication(service.public);
    }
    let static_config = crate::config::render_static_config(&config)?;
    crate::config::write_proxy_config_atomic(
        &settings.static_config_path,
        static_config.as_bytes(),
    )?;
    let generation = write_dynamic_snapshot(settings, services)?;
    let mut child = TraefikChild::spawn(
        &settings.executable,
        &settings.static_config_path,
        &settings
            .provider_files
            .iter()
            .map(|(name, path)| (name.as_str(), path.as_path()))
            .collect::<Vec<_>>(),
        log,
    )?;
    let deadline = Instant::now() + settings.startup_timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "proxy exited before its private health ping was ready",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy did not pass its private health ping before the deadline",
            ));
        }
        if check_private_ping(
            settings.private_ping_address,
            remaining.min(Duration::from_millis(250)),
        )
        .is_ok()
        {
            wait_for_config_generation(
                settings.private_ping_address,
                &generation,
                CONFIG_APPLY_TIMEOUT,
            )?;
            return Ok((child, config.ports));
        }
        thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

fn write_dynamic_snapshot(
    settings: &SupervisorSettings,
    services: &[PublishedService],
) -> io::Result<String> {
    let generation = uuid::Uuid::new_v4().to_string();
    let rendered = crate::config::render_dynamic_config_with_generation(services, &generation)?;
    crate::config::write_proxy_config_atomic(&settings.dynamic_config_path, &rendered)?;
    Ok(generation)
}

fn apply_dynamic_snapshot(
    settings: &SupervisorSettings,
    services: &[PublishedService],
) -> io::Result<()> {
    let generation = write_dynamic_snapshot(settings, services)?;
    wait_for_config_generation(
        settings.private_ping_address,
        &generation,
        CONFIG_APPLY_TIMEOUT,
    )
}

fn revoked_mesh_route_ids(
    previous: &[PublishedService],
    next: &[PublishedService],
) -> std::collections::BTreeSet<String> {
    previous
        .iter()
        .filter_map(|old| {
            if old.public {
                return None;
            }
            let new = next.iter().find(|candidate| candidate.id == old.id)?;
            (!new.public
                && old
                    .allowed_sources
                    .iter()
                    .any(|source| !new.allowed_sources.contains(source)))
            .then(|| old.id.clone())
        })
        .collect()
}

fn stop_child(child: &mut Option<TraefikChild>) -> io::Result<()> {
    if let Some(mut owned) = child.take() {
        owned.stop()?;
    }
    Ok(())
}

fn acquire_supervisor_lock(static_config_path: &Path) -> io::Result<Flock<File>> {
    let directory = static_config_path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "missing proxy state directory")
    })?;
    let directory_metadata = fs::symlink_metadata(directory)?;
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || directory_metadata.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy state directory has unsafe ownership or mode",
        ));
    }
    let path = directory.join(".traefik-supervisor.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(PRIVATE_FILE_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o7777 != PRIVATE_FILE_MODE
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy supervisor lock has unsafe ownership or mode",
        ));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        if error == nix::errno::Errno::EWOULDBLOCK || error == nix::errno::Errno::EAGAIN {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "another infraternal agent owns the proxy process lock",
            )
        } else {
            io::Error::from(error)
        }
    })
}

#[cfg(test)]
#[path = "supervisor_regressions.rs"]
mod reviewer_regressions;
