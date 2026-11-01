//! Owns the single Traefik child, drains it after the final exposure, and redacts its log stream [#281].

use std::time::{Duration, Instant};

/// Time allowed for existing connections to drain after the final exposure is removed.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Initial delay after an unexpected child exit.
pub const INITIAL_RESTART_BACKOFF: Duration = Duration::from_millis(200);
/// Maximum delay between unexpected child exit and restart.
pub const MAX_RESTART_BACKOFF: Duration = Duration::from_secs(30);

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
        .copied()
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
    while bytes.get(separator).is_some_and(|byte| {
        byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"')
    }) {
        separator += 1;
    }
    if !matches!(bytes.get(separator), Some(b':' | b'=')) {
        return None;
    }
    let mut value_start = separator + 1;
    while bytes
        .get(value_start)
        .is_some_and(u8::is_ascii_whitespace)
    {
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
            && bytes
                .get(scheme_end)
                .is_some_and(u8::is_ascii_whitespace)
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
