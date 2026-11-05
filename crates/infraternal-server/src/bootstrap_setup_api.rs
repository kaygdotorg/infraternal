//! Streams retained host setup events under current owner/host authority, independently of wizard lifetime (D255).

use super::{Api, SocketFailure, authenticate_headers, authorized, send_live};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use infraternal_plugin_ssh::{model::identifier, transport::Secret};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case", deny_unknown_fields)]
enum Request {
    Subscribe {
        host_id: Uuid,
        window_id: String,
        #[serde(default)]
        after: u64,
    },
    Replay {
        after: u64,
    },
    Retry {
        host_id: Uuid,
    },
}

pub(super) async fn upgrade(
    State(api): State<Arc<Api>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let (owner, token) = match authenticate_headers(&api, &headers).await {
        Ok(identity) => identity,
        Err(status) => return status.into_response(),
    };
    let Ok(activity) = api.runner.activity() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(permit) = api.setup_sockets.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let token = Secret::new(token.as_bytes().to_vec());
    super::upgrade_admitted(
        ws.max_message_size(4096).max_frame_size(4096),
        api,
        owner,
        token,
        activity,
        permit,
        super::UpgradeContext {
            mode: super::SocketMode::Setup,
            #[cfg(feature = "remote")]
            api_key: None,
        },
    )
}

async fn host_owned(api: &Api, owner: &str, token: &str, host: Uuid) -> bool {
    authorized(api, token, owner).await && api.auth.bootstrap_host(owner, host).await
}

/// Bound initial subscription admission while retaining revocation and component shutdown.
async fn first_request(
    socket: &mut WebSocket,
    api: &Api,
    owner: &str,
    token: &str,
    enabled: &mut tokio::sync::watch::Receiver<bool>,
    revocation: &mut crate::auth::AccountSubscription,
) -> Result<Message, SocketFailure> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            tokio::select! {
                biased;
                _ = enabled.changed() => return Err(SocketFailure::Closed),
                change = revocation.changed() => {
                    change.map_err(|_| SocketFailure::AuthorityUnavailable)?;
                    if !authorized(api, token, owner).await {
                        return Err(SocketFailure::Closed);
                    }
                }
                incoming = socket.recv() => {
                    return incoming.ok_or(())?.map_err(|_| SocketFailure::Closed);
                }
            }
        }
    })
    .await
    .map_err(|_| SocketFailure::Closed)?
}

pub(super) async fn run(
    socket: &mut WebSocket,
    api: Arc<Api>,
    owner: String,
    token: Secret,
) -> Result<(), SocketFailure> {
    let token = std::str::from_utf8(token.expose()).map_err(|_| ())?;
    let mut enabled = api.runner.enabled_changes();
    let mut revocation = api.auth.revocation_events(&owner);
    // Admission preceded this subscription; recheck so an intervening logout cannot be missed.
    if !authorized(&api, token, &owner).await {
        return Err(SocketFailure::Closed);
    }
    let first = first_request(socket, &api, &owner, token, &mut enabled, &mut revocation).await?;
    let Message::Text(first) = first else {
        return Err(SocketFailure::Closed);
    };
    let Request::Subscribe {
        host_id,
        window_id,
        mut after,
    } = serde_json::from_str(&first).map_err(|_| ())?
    else {
        return Err(SocketFailure::Closed);
    };
    if !identifier(&window_id) || !host_owned(&api, &owner, token, host_id).await {
        return Err(SocketFailure::Closed);
    }
    let status = api.runner.setup_status();
    // Watch before replay closes the gap between snapshot and live delivery.
    let mut changed = status.subscribe(&owner, host_id).map_err(|_| ())?;
    let retired = api.runner.setup_cancelled(host_id);
    tokio::pin!(retired);
    let expiry = tokio::time::sleep(Duration::from_hours(30 * 24));
    tokio::pin!(expiry);
    loop {
        if !*enabled.borrow() || !host_owned(&api, &owner, token, host_id).await {
            return Err(SocketFailure::Closed);
        }
        let (resync, events) = status.events(&owner, host_id, after).map_err(|_| ())?;
        if resync {
            send_live(
                socket,
                &api,
                &owner,
                token,
                &mut revocation,
                serde_json::to_string(
                    &serde_json::json!({"resync":true,"host_id":host_id,"window_id":window_id}),
                )
                .ok(),
                None,
            )
            .await?;
        }
        for event in events {
            if !host_owned(&api, &owner, token, host_id).await {
                return Err(SocketFailure::Closed);
            }
            let sequence = event.sequence;
            let mut event = serde_json::to_value(event).map_err(|_| ())?;
            event["window_id"] = window_id.clone().into();
            send_live(
                socket,
                &api,
                &owner,
                token,
                &mut revocation,
                serde_json::to_string(&serde_json::json!({"setup":event})).ok(),
                None,
            )
            .await?;
            after = sequence;
        }
        tokio::select! {
            biased;
            _ = enabled.changed() => return Err(SocketFailure::Closed),
            _ = &mut retired => return Err(SocketFailure::Closed),
            () = &mut expiry => return Err(SocketFailure::Closed),
            change = revocation.changed() => {
                change.map_err(|_| SocketFailure::AuthorityUnavailable)?;
            },
            _ = changed.changed() => {},
            incoming = socket.recv() => {
                let Some(Ok(Message::Text(text))) = incoming else { return Ok(()); };
                if !host_owned(&api, &owner, token, host_id).await { return Err(SocketFailure::Closed); }
                match serde_json::from_str::<Request>(&text).map_err(|_| ())? {
                    Request::Replay {after: cursor} => after = cursor,
                    Request::Retry {host_id: requested} if requested == host_id => {
                        let result = api.runner.retry_setup(owner.clone(), Secret::new(token.as_bytes().to_vec()), host_id);
                        let reply = match result { Ok(()) => serde_json::json!({"retry":host_id}), Err(failure) => serde_json::json!({"error":failure.message}) };
                        send_live(socket, &api, &owner, token, &mut revocation, serde_json::to_string(&reply).ok(), None).await?;
                    },
                    _ => return Err(SocketFailure::Closed),
                }
            },
        }
    }
}
