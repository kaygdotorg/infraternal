//! Proves plugin-proposed server paths before replacement, retaining one live authenticated transport during probes [128,198,215].
use super::{
    Connected, RemoteIdentity, dial_preferred, dial_runtime::DialRuntime, quic_session_on,
};
use crate::{channel::Channel, daemon, remote_quic, remote_tls};
use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};
use std::{io, net::SocketAddr, path::PathBuf, time::Duration};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

enum Proof {
    Quic(
        crate::remote_native::NativeChannel,
        crate::transport::Receive,
    ),
    Tcp(crate::transport::Receive),
}

/// The dial drivers belong to a single transport, including losing probes.
struct Link {
    connected: Connected,
    endpoint: Option<quinn::Endpoint>,
    driver: Option<DialRuntime>,
    address: SocketAddr,
    kind: ServerLinkKind,
    proof: tokio::sync::Mutex<Option<Proof>>,
}
impl Drop for Link {
    fn drop(&mut self) {
        match &self.connected {
            Connected::Quic(connection) => connection.close(0u32.into(), b""),
            Connected::Tcp(connection) => connection.channel.retire(),
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(0u32.into(), b"");
        }
        self.driver.take();
    }
}

fn current(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    address: SocketAddr,
) -> io::Result<RemoteIdentity> {
    let credentials = match renewal {
        Some(renewal) => renewal.current()?,
        None => remote_tls::Identity {
            certificate: identity.identity.certificate.clone(),
            key: identity.identity.key.clone(),
        },
    };
    crate::remote_renewal::require_current(&credentials)?;
    Ok(RemoteIdentity {
        identity: credentials,
        roots: identity.roots.clone(),
        endpoint: address,
        server_name: identity.server_name.clone(),
        execution_uid: identity.execution_uid,
    })
}

async fn connect(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    address: SocketAddr,
    kind: ServerLinkKind,
    prove: bool,
    rtt: Duration,
) -> io::Result<Link> {
    let identity = current(identity, renewal, address)?;
    let driver = DialRuntime::new();
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std::net::UdpSocket::bind(if address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })?,
        driver.runtime(),
    )?;
    let config = if kind == ServerLinkKind::Mesh {
        remote_quic::client_config_with_liveness(
            &identity.identity,
            &identity.roots,
            (rtt / 2).max(Duration::from_millis(100)),
            Duration::from_secs(60),
        )?
    } else {
        remote_quic::client_config(&identity.identity, &identity.roots)?
    };
    endpoint.set_default_client_config(config);
    let connected = if kind == ServerLinkKind::Mesh {
        // Mutual TLS keeps the enrolled SAN and identity unchanged. Application
        // proof below completes before any Hello can replace the server actor.
        Connected::Quic(
            tokio::time::timeout(PROBE_TIMEOUT, super::quic_connect(&endpoint, &identity))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??,
        )
    } else {
        let tls = remote_tls::client_config(&identity.identity, &identity.roots)?;
        dial_preferred(&endpoint, &identity, &tls).await?
    };
    let (endpoint, driver) = if matches!(&connected, Connected::Tcp(_)) {
        drop(endpoint);
        drop(driver);
        (None, None)
    } else {
        (Some(endpoint), Some(driver))
    };
    let link = Link {
        connected,
        endpoint,
        driver,
        address,
        kind,
        proof: tokio::sync::Mutex::new(None),
    };
    if prove {
        let proof = tokio::time::timeout(PROBE_TIMEOUT, async {
            match &link.connected {
                Connected::Quic(connection) => {
                    let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
                    let control = crate::remote_native::NativeChannel::control(send, receive)?;
                    let mut receive = crate::transport::Receive::default();
                    prove_channel(&control, &mut receive).await?;
                    Ok::<_, io::Error>(Proof::Quic(control, receive))
                }
                Connected::Tcp(connection) => {
                    let mut receive = crate::transport::Receive::default();
                    prove_channel(&connection.channel, &mut receive).await?;
                    Ok(Proof::Tcp(receive))
                }
            }
        })
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        *link.proof.lock().await = Some(proof);
    }
    Ok(link)
}

async fn prove_channel<C: Channel>(
    channel: &C,
    receive: &mut crate::transport::Receive,
) -> io::Result<()> {
    let nonce = u64::from_le_bytes(
        uuid::Uuid::new_v4().as_bytes()[..8]
            .try_into()
            .map_err(io::Error::other)?,
    );
    crate::transport::Transmit::default()
        .send(
            channel,
            0,
            &infraternal_protocol::Frame::Ping { nonce, sent_us: 0 },
        )
        .await?;
    let response = receive.next(channel).await?;
    if response.stream_id != 0
        || response.frame != (infraternal_protocol::Frame::Pong { nonce, sent_us: 0 })
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

fn report(
    registry: &crate::plugin_control::Registry,
    link: Option<&Link>,
    reason: ServerLinkReason,
) {
    registry.set_server_link(ServerLink {
        kind: link.map_or(ServerLinkKind::Disconnected, |link| link.kind),
        endpoint: link.map(|link| link.address),
        reason,
    });
}

async fn session(
    link: &Link,
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
) -> io::Result<()> {
    match &link.connected {
        Connected::Quic(connection) => {
            let proof = match link.proof.lock().await.take() {
                Some(Proof::Quic(control, receive)) => Some((control, receive)),
                _ => None,
            };
            let session = quic_session_on(
                connection.clone(),
                identity,
                state,
                renewal,
                registry,
                proof,
            );
            if link.kind == ServerLinkKind::Mesh {
                // The 1,000-connection measurement observed 1.18 seconds of
                // authenticated silence under host load. Avoid false fallback
                // while bounding a failed path independently of QUIC's idle PTO.
                let deadline = Duration::from_secs(2)
                    + connection
                        .rtt()
                        .min(Duration::from_secs(5))
                        .saturating_mul(3);
                let mut freshness = remote_quic::PeerFreshness::new(connection);
                tokio::select! {
                    result = session => result,
                    result = freshness.interrupted(connection, deadline) => result,
                }
            } else {
                session.await
            }
        }
        Connected::Tcp(connection) => {
            if let Some(Proof::Tcp(receive)) = link.proof.lock().await.take() {
                let channel = super::PrefixedControl {
                    channel: super::ControlChannel::Tcp(&connection.channel),
                    prefix: tokio::sync::Mutex::new(Vec::new()),
                    sent_greeting: tokio::sync::Mutex::new(None),
                    receive: tokio::sync::Mutex::new(receive),
                };
                daemon::run_authenticated_with_plugins(
                    &channel,
                    state,
                    identity.execution_uid,
                    renewal,
                    registry,
                )
                .await
            } else {
                daemon::run_authenticated_with_plugins(
                    &connection.channel,
                    state,
                    identity.execution_uid,
                    renewal,
                    registry,
                )
                .await
            }
        }
    }
}

/// A failed candidate leaves the established session and all its dispatchers live.
/// Retrying is bounded and sleeps only while a proposed destination is unavailable.
async fn replacement(
    live: &Link,
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: &crate::plugin_control::Registry,
    cooling: bool,
) -> io::Result<(Link, ServerLinkReason)> {
    let mut paths = registry.server_paths();
    let mut retry = Duration::from_secs(1);
    if cooling {
        tokio::time::sleep(retry).await;
    }
    loop {
        let proposed = *paths.borrow_and_update();
        let (destination, kind, reason) = proposed.map_or(
            (
                identity.endpoint,
                ServerLinkKind::Fallback,
                ServerLinkReason::MeshDisabled,
            ),
            |ip| {
                (
                    SocketAddr::new(ip, identity.endpoint.port()),
                    ServerLinkKind::Mesh,
                    ServerLinkReason::MeshProven,
                )
            },
        );
        if destination == live.address && kind == live.kind {
            paths
                .changed()
                .await
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            retry = Duration::from_secs(1);
            continue;
        }
        // A changed preference cancels only this candidate's owned socket. In
        // particular, an explicit component down cannot leave a probe running.
        tokio::select! {
            result = connect(identity, renewal, destination, kind, true, match &live.connected {
                Connected::Quic(connection) => connection.rtt().min(Duration::from_secs(5)),
                Connected::Tcp(_) => Duration::from_millis(100),
            }) => {
                if let Ok(link) = result { return Ok((link, reason)); }
                if live.kind == ServerLinkKind::Fallback {
                    report(registry, Some(live), ServerLinkReason::MeshRefused);
                }
            }
            changed = paths.changed() => {
                changed.map_err(|_| io::ErrorKind::BrokenPipe)?;
                continue;
            }
        }
        tokio::select! {
            () = tokio::time::sleep(retry) => {},
            changed = paths.changed() => { changed.map_err(|_| io::ErrorKind::BrokenPipe)?; },
        }
        retry = (retry * 2).min(Duration::from_secs(30));
    }
}

/// Keeps enrolled fallback available, moving only after authenticated path proof.
/// Existing durable shim offsets make transport replacement independent of leg A.
/// Retained applied intent can reconnect even when the enrollment port is unavailable.
/// Fresh nodes have no proposal and use the unchanged enrollment dial race.
async fn available(
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: &crate::plugin_control::Registry,
    force_fallback: bool,
) -> io::Result<Link> {
    let mut paths = registry.server_paths();
    let proposed = *paths.borrow_and_update();
    let Some(ip) = proposed.filter(|_| !force_fallback) else {
        return connect(
            identity,
            renewal,
            identity.endpoint,
            ServerLinkKind::Fallback,
            false,
            Duration::ZERO,
        )
        .await;
    };
    let mesh = connect(
        identity,
        renewal,
        SocketAddr::new(ip, identity.endpoint.port()),
        ServerLinkKind::Mesh,
        true,
        Duration::from_millis(100),
    );
    let fallback = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        connect(
            identity,
            renewal,
            identity.endpoint,
            ServerLinkKind::Fallback,
            false,
            Duration::ZERO,
        )
        .await
    };
    tokio::pin!(mesh, fallback);
    tokio::select! {
        result = &mut mesh => match result { Ok(link) => Ok(link), Err(_) => fallback.await },
        result = &mut fallback => match result { Ok(link) => Ok(link), Err(_) => mesh.await },
        _ = paths.changed() => Err(io::ErrorKind::Interrupted.into()),
    }
}

pub(super) async fn run(
    identity: &RemoteIdentity,
    state: PathBuf,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    registry: crate::plugin_control::Registry,
) -> io::Result<()> {
    registry
        .initialize_paths()
        .await
        .map_err(|_| io::ErrorKind::Other)?;
    let mut live = None;
    let mut force_fallback = false;
    let mut reason = ServerLinkReason::MeshUnavailable;
    let mut backoff = Duration::from_millis(200);
    let mut cooling = false;
    loop {
        // Reconnection itself never waits for a failed mesh probe. Once the
        // fallback is healthy, probes run alongside it and cannot lose bytes.
        let link = if let Some(link) = live.take() {
            link
        } else {
            match available(identity, renewal, &registry, force_fallback).await {
                Ok(link) => {
                    force_fallback = false;
                    if link.kind == ServerLinkKind::Mesh {
                        reason = ServerLinkReason::MeshProven;
                    }
                    link
                }
                Err(error) => {
                    force_fallback = false;
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    current(identity, renewal, identity.endpoint)?;
                    report(&registry, None, reason);
                    let jitter =
                        Duration::from_millis(u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 100);
                    tokio::time::sleep(backoff + jitter).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            }
        };
        let started = tokio::time::Instant::now();
        report(&registry, Some(&link), reason);
        // Both futures leave scope before retiring the old transport. Aborting
        // a partial write is safe only because Link closes that entire channel.
        let moved = tokio::select! {
            result = replacement(&link, identity, renewal, &registry, cooling) => result.ok(),
            _ = session(&link, identity, state.clone(), renewal, registry.clone()) => None,
        };
        if let Some((next, why)) = moved {
            live = Some(next);
            reason = why;
            cooling = false;
        } else {
            reason = if link.kind == ServerLinkKind::Mesh {
                ServerLinkReason::MeshInterrupted
            } else {
                ServerLinkReason::Connecting
            };
            cooling = link.kind == ServerLinkKind::Mesh;
            force_fallback = cooling;
            report(&registry, None, reason);
            if link.kind == ServerLinkKind::Fallback {
                if started.elapsed() > Duration::from_secs(10) {
                    backoff = Duration::from_millis(200);
                }
                let jitter =
                    Duration::from_millis(u64::from(uuid::Uuid::new_v4().as_bytes()[0]) % 100);
                tokio::time::sleep(backoff + jitter).await;
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        }
        drop(link);
    }
}

#[cfg(test)]
#[path = "remote_server_path_tests.rs"]
mod tests;
