//! Proves plugin-proposed server paths before replacement, retaining one live authenticated transport during probes [128,198,215].
use super::{
    Connected, RemoteIdentity, dial_preferred, dial_runtime::DialRuntime, quic_session_on,
};
use crate::{channel::Channel, daemon, remote_quic, remote_tls};
use infraternal_plugin_api::server_path::{ServerLink, ServerLinkKind, ServerLinkReason};
use std::{io, net::SocketAddr, path::PathBuf, time::Duration};

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

enum Proof {
    Quic(super::ProvedControl),
    Tcp {
        receive: crate::transport::Receive,
        greeting: Option<Vec<u8>>,
    },
}

/// The dial drivers belong to a single transport, including losing probes.
struct Link {
    connected: Connected,
    endpoint: Option<quinn::Endpoint>,
    driver: Option<DialRuntime>,
    address: SocketAddr,
    kind: ServerLinkKind,
    proof: tokio::sync::Mutex<Option<Proof>>,
    standby: tokio::sync::watch::Sender<u64>,
    native: Option<super::primed_native::Service>,
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
            // A probe belongs to the new mesh path. Inheriting the old path
            // RTT can delay its first keepalive beyond the freshness budget.
            Duration::from_millis(100),
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
        standby: tokio::sync::watch::channel(0).0,
        native: None,
    };
    if prove {
        let proof = tokio::time::timeout(PROBE_TIMEOUT, async {
            match &link.connected {
                Connected::Quic(connection) => {
                    let (send, receive) = connection.open_bi().await.map_err(io::Error::other)?;
                    let control = crate::remote_native::NativeChannel::control(send, receive)?;
                    let mut receive = crate::transport::Receive::default();
                    prove_channel(&control, &mut receive).await?;
                    Ok::<_, io::Error>(Proof::Quic(super::ProvedControl {
                        control,
                        receive,
                        greeting: None,
                        primed: false,
                    }))
                }
                Connected::Tcp(connection) => {
                    let mut receive = crate::transport::Receive::default();
                    prove_channel(&connection.channel, &mut receive).await?;
                    Ok(Proof::Tcp {
                        receive,
                        greeting: None,
                    })
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
                Some(Proof::Quic(proof)) => Some(proof),
                _ => None,
            };
            let session = quic_session_on(
                connection.clone(),
                identity,
                state,
                renewal,
                registry,
                proof,
                &link.standby,
                link.native.is_some(),
            );
            if link.kind == ServerLinkKind::Mesh {
                // Existing authenticated transport traffic supplies liveness;
                // current RTT adjusts the guard through changing network delay.
                let mut freshness = remote_quic::PeerFreshness::new(connection);
                tokio::select! {
                    result = session => result,
                    result = freshness.interrupted_adaptive(connection) => result,
                }
            } else {
                session.await
            }
        }
        Connected::Tcp(connection) => {
            if let Some(Proof::Tcp { receive, greeting }) = link.proof.lock().await.take() {
                let channel = super::PrefixedControl {
                    channel: super::ControlChannel::Tcp(&connection.channel),
                    prefix: tokio::sync::Mutex::new(greeting.unwrap_or_default()),
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

/// Parking never replaces the active session. Legacy server greetings leave
/// this future asleep; failed warm probes retry without retiring the live mesh.
async fn warming(
    live: &Link,
    identity: &RemoteIdentity,
    renewal: Option<&crate::remote_renewal::RenewalIdentity>,
    state: &std::path::Path,
) -> io::Result<Link> {
    let mut support = live.standby.subscribe();
    while *support.borrow_and_update() & infraternal_plugin_api::channel::REMOTE_STANDBY == 0 {
        support
            .changed()
            .await
            .map_err(|_| io::ErrorKind::BrokenPipe)?;
    }
    let mut retry = Duration::from_secs(1);
    loop {
        if let Ok(mut link) = connect(
            identity,
            renewal,
            identity.endpoint,
            ServerLinkKind::Fallback,
            true,
        )
        .await
        {
            let prime = matches!(link.connected, Connected::Quic(_))
                && *support.borrow() & infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS != 0;
            let result = tokio::time::timeout(PROBE_TIMEOUT, async {
                let mut proof = link.proof.lock().await;
                match proof.as_mut().ok_or(io::ErrorKind::InvalidData)? {
                    Proof::Quic(proof) => {
                        proof.greeting = Some(park_channel(&proof.control, &mut proof.receive, prime).await?);
                        if prime {
                            if identity.execution_uid != nix::unistd::Uid::effective().as_raw() {
                                return Err(io::ErrorKind::PermissionDenied.into());
                            }
                            let Connected::Quic(connection) = &link.connected else {
                                return Err(io::ErrorKind::InvalidData.into());
                            };
                            let hello = infraternal_protocol::decode_frame(proof.greeting.as_ref().ok_or(io::ErrorKind::InvalidData)?)
                                .map_err(io::Error::other)?;
                            if !matches!(hello.frame, infraternal_protocol::Frame::Hello { caps, .. }
                                if caps & infraternal_plugin_api::channel::REMOTE_PRIMED_WRITERS != 0) {
                                return Err(io::ErrorKind::InvalidData.into());
                            }
                            let binding = remote_quic::negotiate_binding(connection, &hello.frame)?;
                            crate::transport::Transmit::default().send(&proof.control, 0, &super::client_greeting(renewal.is_some())).await?;
                            proof.primed = true;
                            link.native = Some(super::primed_native::Service::start(connection.clone(), binding, state.to_path_buf()));
                        }
                    }
                    Proof::Tcp { receive, greeting } => {
                        let Connected::Tcp(connection) = &link.connected else {
                            return Err(io::ErrorKind::InvalidData.into());
                        };
                        *greeting = Some(park_channel(&connection.channel, receive, false).await?);
                    }
                }
                Ok::<(), io::Error>(())
            })
            .await;
            if matches!(result, Ok(Ok(()))) {
                return Ok(link);
            }
        }
        current(identity, renewal, identity.endpoint)?;
        tokio::time::sleep(retry).await;
        retry = (retry * 2).min(Duration::from_secs(30));
    }
}

async fn park_channel<C: Channel>(
    channel: &C,
    receive: &mut crate::transport::Receive,
    prime: bool,
) -> io::Result<Vec<u8>> {
    crate::transport::Transmit::default()
        .send(
            channel,
            0,
            &infraternal_protocol::Frame::Call {
                call_id: 0,
                action_id: "transport.standby",
                input_json: if prime { b"{\"prime\":true}" } else { b"{}" },
            },
        )
        .await?;
    let result = receive.next(channel).await?;
    if result.stream_id != 0
        || !matches!(
            result.frame,
            infraternal_protocol::Frame::Result {
                call_id: 0,
                ok: true,
                ..
            }
        )
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let hello = receive.next(channel).await?;
    if hello.stream_id != 0
        || !matches!(hello.frame, infraternal_protocol::Frame::Hello { version: 1, caps, .. } if caps & infraternal_plugin_api::channel::REMOTE_STANDBY != 0)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut prefix = Vec::new();
    if channel.native_stream_id().is_some() {
        infraternal_protocol::encode_frame_into(&hello.frame, &mut prefix)
            .map_err(io::Error::other)?;
    } else {
        infraternal_protocol::encode_muxed_frame_into(0, &hello.frame, &mut prefix)
            .map_err(io::Error::other)?;
    }
    Ok(prefix)
}

async fn warm_closed(warm: Option<&Link>) {
    match warm.map(|link| &link.connected) {
        Some(Connected::Quic(connection)) => {
            connection.closed().await;
        }
        Some(Connected::Tcp(connection)) => {
            let _ = connection.channel.read(&mut [0; 1]).await;
        }
        None => std::future::pending().await,
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
            result = connect(identity, renewal, destination, kind, true) => {
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

/// A component down retains its meaning when transport closure wins its race.
fn interruption_reason(registry: &crate::plugin_control::Registry) -> ServerLinkReason {
    if registry.server_paths().borrow().is_none() {
        ServerLinkReason::MeshDisabled
    } else {
        ServerLinkReason::MeshInterrupted
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
        )
        .await;
    };
    let mesh = connect(
        identity,
        renewal,
        SocketAddr::new(ip, identity.endpoint.port()),
        ServerLinkKind::Mesh,
        true,
    );
    let fallback = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        connect(
            identity,
            renewal,
            identity.endpoint,
            ServerLinkKind::Fallback,
            false,
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
    let mut warm = None;
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
        let moved = {
            let active = session(&link, identity, state.clone(), renewal, registry.clone());
            let replacing = replacement(&link, identity, renewal, &registry, cooling);
            let mut preparing = (link.kind == ServerLinkKind::Mesh)
                .then(|| Box::pin(warming(&link, identity, renewal, &state)));
            tokio::pin!(active, replacing);
            loop {
                tokio::select! {
                    result = &mut replacing => break result.ok(),
                    _ = &mut active => break None,
                    result = async { preparing.as_mut().ok_or(io::ErrorKind::BrokenPipe)?.await },
                        if preparing.is_some() && warm.is_none() => {
                        warm = result.ok();
                        if warm.is_none() { preparing = Some(Box::pin(warming(&link, identity, renewal, &state))); }
                    }
                    () = warm_closed(warm.as_ref()), if warm.is_some() => {
                        warm = None;
                        preparing = Some(Box::pin(warming(&link, identity, renewal, &state)));
                    }
                }
            }
        };
        // A transport close can win the replacement race after component down.
        // The current applied preference owns the reason, rather than whichever
        // future happened to finish first.
        let interrupted_reason = interruption_reason(&registry);
        let moved = match moved {
            Some((next, why)) if next.kind == ServerLinkKind::Fallback && warm.is_some() => {
                Some((warm.take().ok_or(io::ErrorKind::BrokenPipe)?, why))
            }
            None if link.kind == ServerLinkKind::Mesh && warm.is_some() => Some((
                warm.take().ok_or(io::ErrorKind::BrokenPipe)?,
                interrupted_reason,
            )),
            other => other,
        };
        if let Some((next, why)) = moved {
            live = Some(next);
            reason = why;
            cooling = why == ServerLinkReason::MeshInterrupted;
        } else {
            reason = if link.kind == ServerLinkKind::Mesh {
                interrupted_reason
            } else {
                ServerLinkReason::Connecting
            };
            cooling = reason == ServerLinkReason::MeshInterrupted;
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
