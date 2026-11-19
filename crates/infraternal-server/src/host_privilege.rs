//! The server's side of upgrading a host to the root infraternal agent (D274, D376, #399).
//!
//! This module talks to the host's rootless infraternal agent through its
//! `privilege.*` control actions (see `infraternal_agent::privilege_agent`):
//!
//! - [`probe`] asks how this person becomes root there (D274's order).
//! - [`seal_key`] gets a one-use key that the browser seals the password to.
//! - [`elevate`] forwards the sealed bytes, which the server can't read, and
//!   says what came of them.
//! - [`AgentPump`] then carries the relay's bytes, so a
//!   [`infraternal_plugin_ssh::relay_session::RelaySession`] can run the
//!   unchanged root install over it.
//!
//! [`Promotions`] drives one upgrade end to end, writing every step to the
//! promotion's row (`crate::enrollment::promotion`), in this order:
//! begin (bound to the live rootless link, R7) → the try, reserved in one
//! write (B2) → the relay → the root install's stage, join and start → the
//! successor's proof over its private lane (R2) → the install's commit and
//! the relay's `Commit` → the handover transaction (R3). Anything else ends
//! the row as abandoned or rolled back; the relay puts the host back by
//! itself when it never saw `Commit` (R4), and an abandoned successor
//! uninstalls itself from the durable outbox (R5).
//!
//! The server never sees the password. It only ever holds the sealed bytes,
//! for the length of one request, and never logs or stores them.
use crate::embedded::EmbeddedAgent;
use base64::Engine as _;
use infraternal_plugin_ssh::{model::Failure, relay_session::Pump, transport::Operation};
use std::time::Duration;

/// How long one pump call may take: the infraternal agent waits up to a
/// second for news, plus the link.
const PUMP_BOUND: Duration = Duration::from_secs(15);
/// How long an elevation may take: the host bounds it at 60 s for the
/// prompt and answer and 20 s for the relay to connect.
const ELEVATE_BOUND: Duration = Duration::from_secs(90);
/// How long the probe and key calls may take.
const SHORT_BOUND: Duration = Duration::from_secs(15);
/// Raw relay bytes per pump call; base64 and JSON keep it under the agent's
/// 2 MiB bound for these actions.
const SEND_CHUNK: usize = 1 << 20;

/// How this person becomes root on the host (D274's order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Way {
    /// sudo without a password: consent only, no field.
    SudoNoPassword,
    /// sudo with the person's own password.
    Sudo,
    /// doas with the person's own password.
    Doas,
    /// su with the root password.
    Su,
}

impl Way {
    /// The word on the wire and in the browser.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::SudoNoPassword => "sudo-nopasswd",
            Self::Sudo => "sudo",
            Self::Doas => "doas",
            Self::Su => "su",
        }
    }

    /// The method named in messages, the activity log and the wait rule.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::SudoNoPassword | Self::Sudo => "sudo",
            Self::Doas => "doas",
            Self::Su => "su",
        }
    }

    /// The way for a wire word.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        [Self::SudoNoPassword, Self::Sudo, Self::Doas, Self::Su]
            .into_iter()
            .find(|way| way.word() == word)
    }
}

/// What the host said about becoming root there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// The infraternal agent there already runs as root.
    Full,
    /// This way, and whether sudo exists but refuses this account.
    Way { way: Way, denied: bool },
    /// No way in at all (no sudo, doas or su).
    None,
}

/// The result of one elevation, as the host reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Elevation {
    /// Root reached and the relay connected.
    Started,
    /// The password was refused (counts toward the two tries).
    Wrong,
    /// This account may not become root this way.
    Denied,
    /// The host's binary didn't match this server's payload; nothing ran as root.
    Mismatch,
    /// No answer in time.
    Timeout,
    /// Another upgrade is running on that host.
    Busy,
    /// su can't run a command: root's login shell isn't a POSIX shell (B11).
    RootShell,
    /// Anything else.
    Failed,
}

/// A failure that never names host output.
/// (The shared step functions below return it; [`Promotions`] maps it to a
/// fixed reason word.)
fn failed() -> Failure {
    Failure::install("The host didn't answer the upgrade request.")
}

/// Call one `privilege.*` action with a bound, returning its JSON reply.
async fn call(
    agent: &EmbeddedAgent,
    action: &'static str,
    input: serde_json::Value,
    bound: Duration,
) -> Result<serde_json::Value, Failure> {
    let input = serde_json::to_vec(&input).map_err(|_| failed())?;
    let reply = tokio::time::timeout(bound, agent.privilege_call(action, input))
        .await
        .map_err(|_| failed())?
        .map_err(|_| failed())?;
    serde_json::from_slice(&reply).map_err(|_| failed())
}

/// Ask the host how this person becomes root there.
///
/// # Errors
/// The host didn't answer or answered something malformed.
pub async fn probe(agent: &EmbeddedAgent) -> Result<Probe, Failure> {
    let reply = call(agent, "privilege.probe", serde_json::json!({}), SHORT_BOUND).await?;
    if reply["full"] == true {
        return Ok(Probe::Full);
    }
    let denied = reply["denied"].as_bool().ok_or_else(failed)?;
    match reply["way"].as_str() {
        Some("none") => Ok(Probe::None),
        Some(word) => Way::from_word(word)
            .map(|way| Probe::Way { way, denied })
            .ok_or_else(failed),
        None => Err(failed()),
    }
}

/// Get the one-use seal key of `attempt` (32 bytes, X25519).
///
/// # Errors
/// The host refused (for example two keys already wait) or didn't answer.
pub async fn seal_key(agent: &EmbeddedAgent, attempt: uuid::Uuid) -> Result<[u8; 32], Failure> {
    let reply = call(
        agent,
        "privilege.key",
        serde_json::json!({"attempt": attempt.simple().to_string()}),
        SHORT_BOUND,
    )
    .await?;
    let key = reply["key"].as_str().ok_or_else(failed)?;
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| failed())?
        .try_into()
        .map_err(|_| failed())
}

/// Forward the sealed password (or none, for passwordless sudo) and become
/// root once. `digest` is this server's payload SHA-256 for the host's
/// architecture: the host only runs a relay binary that matches it.
/// Returns the outcome and whether the password reached PAM (B2).
///
/// # Errors
/// The host didn't answer or answered something malformed.
pub async fn elevate(
    agent: &EmbeddedAgent,
    host: uuid::Uuid,
    attempt: uuid::Uuid,
    way: Way,
    sealed: Option<&str>,
    digest: &str,
) -> Result<(Elevation, bool), Failure> {
    let input = serde_json::json!({
        "attempt": attempt.simple().to_string(),
        "host": host.simple().to_string(),
        "way": way.word(),
        "sealed": sealed,
        "digest": digest,
    });
    let reply = call(agent, "privilege.elevate", input, ELEVATE_BOUND).await?;
    let outcome = match reply["outcome"].as_str() {
        Some("started") => Elevation::Started,
        Some("wrong") => Elevation::Wrong,
        Some("denied") => Elevation::Denied,
        Some("mismatch") => Elevation::Mismatch,
        Some("timeout") => Elevation::Timeout,
        Some("busy") => Elevation::Busy,
        Some("rootshell") => Elevation::RootShell,
        _ => Elevation::Failed,
    };
    // A host that doesn't say counts the try (B2: the safe side).
    let typed = reply["typed"].as_bool().unwrap_or(true);
    Ok((outcome, typed))
}

/// End the relay of `attempt` (best effort; the relay also ends by itself).
pub async fn end(agent: &EmbeddedAgent, attempt: uuid::Uuid) {
    let _ = call(
        agent,
        "privilege.end",
        serde_json::json!({"attempt": attempt.simple().to_string()}),
        SHORT_BOUND,
    )
    .await;
}

/// The [`Pump`] of one upgrade, over the rootless infraternal agent's
/// `privilege.pump`.
pub struct AgentPump {
    /// The rootless infraternal agent's link.
    pub agent: EmbeddedAgent,
    /// The upgrade attempt.
    pub attempt: uuid::Uuid,
}

impl Pump for AgentPump {
    fn pump(&self, bytes: Vec<u8>) -> Operation<'_, (Vec<u8>, bool)> {
        Box::pin(async move {
            let mut received = Vec::new();
            let mut closed = false;
            // A large send goes in several calls; each returns what the relay said.
            let chunks: Vec<&[u8]> = if bytes.is_empty() {
                vec![&[][..]]
            } else {
                bytes.chunks(SEND_CHUNK).collect()
            };
            for chunk in chunks {
                let input = serde_json::json!({
                    "attempt": self.attempt.simple().to_string(),
                    "send": base64::engine::general_purpose::STANDARD.encode(chunk),
                });
                let reply = call(&self.agent, "privilege.pump", input, PUMP_BOUND).await?;
                let recv = reply["recv"].as_str().ok_or_else(failed)?;
                received.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(recv)
                        .map_err(|_| failed())?,
                );
                closed |= reply["closed"] == true;
                if closed {
                    break;
                }
            }
            Ok((received, closed))
        })
    }
}

#[cfg(test)]
mod tests {
    //! Wire words map both ways.
    use super::*;

    /// Every way round-trips, and the method folds passwordless sudo into sudo.
    #[test]
    fn ways_round_trip() {
        for way in [Way::SudoNoPassword, Way::Sudo, Way::Doas, Way::Su] {
            assert_eq!(Way::from_word(way.word()), Some(way));
        }
        assert_eq!(Way::SudoNoPassword.method(), "sudo");
        assert_eq!(Way::from_word("pkexec"), None);
    }
}
