//! `UniFFI` surface for sign-in and approval calls made by the iOS app (#580).
//!
//! Swift owns HTTPS through `URLSession` and opens the server's approval page.
//! This crate builds the exact device-start request, checks each response, and
//! keeps the short-lived poll capability out of Swift's general UI state.

use std::sync::{Arc, Mutex};

use infraternal_protocol::{Frame, decode_frame, encode_frame_into};
use infraternal_sign_in::{
    CheckFailure, device_machine_start_body, join_approval_link, parse_start_response, server_url,
};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// An error reported by the iOS sign-in surface without echoing response data.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ClientError {
    /// The configured server or device join facts are invalid.
    #[error("the server or device join request is invalid")]
    InvalidInput,
    /// The server returned an unexpected reply or status.
    #[error("the server returned an unusable reply (status {status})")]
    ServerReply {
        /// HTTP status code from the response.
        status: u16,
    },
    /// The approval start reply was malformed.
    #[error("the server's approval reply is invalid")]
    ApprovalReply,
    /// Starting has not completed, so there is no poll request to send.
    #[error("the approval has not started")]
    NotStarted,
}

/// A malformed mesh action or protocol frame.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ProtocolError {
    /// The frame or mesh action is unknown, malformed, oversized, or has trailing bytes.
    #[error("the mesh action or protocol frame is invalid")]
    InvalidFrame,
    /// The decoded frame is not a node action result.
    #[error("the extension returned a different protocol message")]
    WrongFrame,
}

/// A validated public HTTPS origin, with no path, credentials, query or fragment.
#[derive(Clone, Debug, uniffi::Record)]
pub struct ServerOrigin {
    /// Canonical origin used to build every device approval request.
    pub value: String,
}

/// The URL, method, headers and body that Swift sends through `URLSession`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct HttpRequest {
    /// Absolute HTTPS request URL.
    pub url: String,
    /// HTTP method, currently `POST`.
    pub method: String,
    /// Headers required for the server's JSON endpoint.
    pub headers: std::collections::HashMap<String, String>,
    /// JSON bytes to send; redeem bodies contain the private poll capability.
    pub body: Vec<u8>,
}

/// One response returned by Swift's `URLSession`.
#[derive(Clone, Debug, uniffi::Record)]
pub struct HttpResponse {
    /// HTTP status code from the response.
    pub status: u16,
    /// Bounded response body bytes.
    pub body: Vec<u8>,
    /// Parsed `Retry-After` seconds, when present.
    pub retry_after_seconds: Option<u64>,
}

/// The approval page and expiration shown after device-start succeeds.
#[derive(Clone, Debug, uniffi::Record)]
pub struct Approval {
    /// The server's own page for the owner to approve this device.
    pub approval_url: String,
    /// How long the app may poll before the approval expires.
    pub expires_in_seconds: u64,
}

/// A successful device redemption, pending poll, or retry instruction.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum Redeemed {
    /// The owner has not approved the join yet.
    Pending,
    /// The server asked the client to wait before polling again.
    RetryAfter {
        /// Retry delay parsed from `Retry-After`, if the server sent one.
        seconds: Option<u64>,
    },
    /// A verified-shape invitation document for the Packet Tunnel extension.
    Invitation {
        /// Join invitation JSON to pass to the Packet Tunnel extension.
        json: String,
    },
}

/// Facts the extension returns before the owner approves the device join.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EnrolmentRequest {
    host_id: Uuid,
    hostname: String,
    key_fingerprint: String,
}

/// The exact JSON body of the one-time approval poll.
#[derive(Serialize)]
struct RedeemBody<'a> {
    token: &'a str,
}

/// Parses a server address, accepting only a bare HTTPS origin.
///
/// # Errors
/// Returns `InvalidInput` when the input is not a bare HTTPS origin.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI exports owned Swift values at this boundary.
pub fn server_origin(input: String) -> Result<ServerOrigin, ClientError> {
    let url = server_url(&input).map_err(|_| ClientError::InvalidInput)?;
    Ok(ServerOrigin {
        value: url.origin().ascii_serialization(),
    })
}

/// Encode one mesh action for `NETunnelProviderSession.sendProviderMessage`.
///
/// # Errors
/// Returns `InvalidFrame` if the shared mesh-node action parser rejects the
/// action or input, or the protocol encoder refuses the bounded frame.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI exports owned Swift values at this boundary.
pub fn mesh_call(action: String, input_json: String) -> Result<Vec<u8>, ProtocolError> {
    infraternal_mesh_node::node_actions::parse_action(&action, input_json.as_bytes())
        .map_err(|_| ProtocolError::InvalidFrame)?;
    let call_id = NEXT_CALL_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut frame = Vec::new();
    encode_frame_into(
        &Frame::Call {
            call_id,
            action_id: &action,
            input_json: input_json.as_bytes(),
        },
        &mut frame,
    )
    .map_err(|_| ProtocolError::InvalidFrame)?;
    Ok(frame)
}

/// Decode one extension reply and return the action's JSON response.
///
/// # Errors
/// Returns `InvalidFrame` for malformed wire bytes and `WrongFrame` unless the
/// complete byte vector contains exactly one `Frame::Result`.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI exports owned Swift values at this boundary.
pub fn mesh_reply(frame: Vec<u8>) -> Result<String, ProtocolError> {
    let decoded = decode_frame(&frame).map_err(|_| ProtocolError::InvalidFrame)?;
    if decoded.wire_len != frame.len() {
        return Err(ProtocolError::InvalidFrame);
    }
    match decoded.frame {
        Frame::Result { json, .. } => {
            String::from_utf8(json.to_vec()).map_err(|_| ProtocolError::InvalidFrame)
        }
        _ => Err(ProtocolError::WrongFrame),
    }
}

/// Monotonically identifies app-to-extension calls within this process.
static NEXT_CALL_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// One passkey-approved device join, with HTTP performed by Swift.
///
/// The join object stores the opaque polling capability after checking the
/// start reply. Callers never need to print or persist that bearer value.
#[derive(uniffi::Object)]
pub struct MachineJoin {
    server: Url,
    device_name: String,
    start_body: Vec<u8>,
    poll_token: Mutex<Option<Zeroizing<String>>>,
}

#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI records cross the generated interface by value.
impl MachineJoin {
    /// Create a device-join approval from the extension's enrollment request.
    ///
    /// # Errors
    /// Returns `InvalidInput` for an invalid origin, device name, request JSON,
    /// or key fingerprint.
    #[uniffi::constructor]
    pub fn new(
        server: ServerOrigin,
        device_name: String,
        request: Vec<u8>,
    ) -> Result<Arc<Self>, ClientError> {
        let server = server_url(&server.value).map_err(|_| ClientError::InvalidInput)?;
        if request.len() > 8192
            || device_name.is_empty()
            || device_name.len() > 128
            || device_name.chars().any(char::is_control)
        {
            return Err(ClientError::InvalidInput);
        }
        let facts: EnrolmentRequest =
            serde_json::from_slice(&request).map_err(|_| ClientError::InvalidInput)?;
        if facts.hostname != device_name {
            return Err(ClientError::InvalidInput);
        }
        let start_body =
            device_machine_start_body(facts.host_id, &facts.hostname, &facts.key_fingerprint)
                .map_err(map_check)?;
        Ok(Arc::new(Self {
            server,
            device_name,
            start_body,
            poll_token: Mutex::new(None),
        }))
    }

    /// Build the `/auth/device-start` request for `URLSession`.
    pub fn start_request(&self) -> HttpRequest {
        HttpRequest {
            url: format!(
                "{}/auth/device-start",
                self.server.origin().ascii_serialization()
            ),
            method: "POST".to_owned(),
            headers: json_headers(),
            body: self.start_body.clone(),
        }
    }

    /// Check the start reply and return the owner approval page.
    ///
    /// # Errors
    /// Returns `ApprovalReply` for an unexpected status or malformed body.
    pub fn on_start(&self, reply: HttpResponse) -> Result<Approval, ClientError> {
        if reply.status != 200 || reply.body.len() > 8192 {
            return Err(ClientError::ServerReply {
                status: reply.status,
            });
        }
        let approval = parse_start_response(&reply.body).map_err(|_| ClientError::ApprovalReply)?;
        let url = join_approval_link(&self.server, &approval.user_code);
        let result = Approval {
            approval_url: url,
            expires_in_seconds: approval.lifetime.as_secs(),
        };
        let mut poll_token = self
            .poll_token
            .lock()
            .map_err(|_| ClientError::NotStarted)?;
        *poll_token = Some(approval.poll_token);
        Ok(result)
    }

    /// Build one `/auth/device-redeem` poll with the server's wait preference.
    ///
    /// # Errors
    /// Returns `NotStarted` before a successful start reply.
    pub fn redeem_request(&self) -> Result<HttpRequest, ClientError> {
        let token = self
            .poll_token
            .lock()
            .map_err(|_| ClientError::NotStarted)?;
        let token = token.as_deref().ok_or(ClientError::NotStarted)?;
        let body =
            serde_json::to_vec(&RedeemBody { token }).map_err(|_| ClientError::NotStarted)?;
        let mut headers = json_headers();
        headers.insert("prefer".to_owned(), "wait=10".to_owned());
        Ok(HttpRequest {
            url: format!(
                "{}/auth/device-redeem",
                self.server.origin().ascii_serialization()
            ),
            method: "POST".to_owned(),
            headers,
            body,
        })
    }

    /// Check a redeem response and return pending, retry, or the join invitation.
    ///
    /// # Errors
    /// Returns `NotStarted` before a successful start, or `ServerReply` for an
    /// unexpected response. Invitation bytes are bounded before returning them.
    pub fn on_redeem(&self, reply: HttpResponse) -> Result<Redeemed, ClientError> {
        let token = self
            .poll_token
            .lock()
            .map_err(|_| ClientError::NotStarted)?;
        if token.is_none() {
            return Err(ClientError::NotStarted);
        }
        drop(token);
        if reply.body.len() > 8192 {
            return Err(ClientError::ApprovalReply);
        }
        match reply.status {
            401 => Ok(Redeemed::Pending),
            429 => Ok(Redeemed::RetryAfter {
                seconds: reply.retry_after_seconds,
            }),
            200 if reply.body.len() <= 8192 => {
                let value: serde_json::Value =
                    serde_json::from_slice(&reply.body).map_err(|_| ClientError::ApprovalReply)?;
                let object = value.as_object().ok_or(ClientError::ApprovalReply)?;
                let mode = object.get("mode").and_then(serde_json::Value::as_str);
                let token = object.get("token").and_then(serde_json::Value::as_str);
                if mode != Some("device") || token.is_none_or(str::is_empty) {
                    return Err(ClientError::ApprovalReply);
                }
                let poll_token = self
                    .poll_token
                    .lock()
                    .map_err(|_| ClientError::NotStarted)?
                    .take();
                drop(poll_token);
                Ok(Redeemed::Invitation {
                    json: String::from_utf8(reply.body).map_err(|_| ClientError::ApprovalReply)?,
                })
            }
            _ => Err(ClientError::ServerReply {
                status: reply.status,
            }),
        }
    }

    /// The label shown to the owner on the approval page.
    pub fn device_name(&self) -> String {
        self.device_name.clone()
    }
}

/// Build standard JSON headers for the server's auth endpoints.
fn json_headers() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("content-type".to_owned(), "application/json".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
    ])
}

/// Map the shared sign-in validator's refusal to the FFI-safe error type.
fn map_check(_error: CheckFailure) -> ClientError {
    ClientError::InvalidInput
}

#[cfg(test)]
mod tests {
    //! Client boundary tests that exercise request and response handling offline.

    #![allow(clippy::unwrap_used)] // Fixed protocol fixtures fail the test immediately if invalid.

    use super::*;

    /// Build one fixed device enrollment request for the approval-flow tests.
    fn test_join() -> Arc<MachineJoin> {
        MachineJoin::new(
            ServerOrigin {
                value: "https://mesh.example".to_owned(),
            },
            "simulator".to_owned(),
            br#"{"host_id":"00000000-0000-0000-0000-000000000002","hostname":"simulator","key_fingerprint":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#.to_vec(),
        )
        .unwrap()
    }

    /// Accept only a bare HTTPS origin before building requests.
    #[test]
    fn server_origin_rejects_paths_and_http() {
        assert!(server_origin("http://mesh.example".to_owned()).is_err());
        assert!(server_origin("https://mesh.example/inside".to_owned()).is_err());
        assert_eq!(
            server_origin("https://mesh.example".to_owned())
                .unwrap()
                .value,
            "https://mesh.example"
        );
    }

    /// Device start has no host execution uid and sends JSON to the public HTTPS origin.
    #[test]
    fn start_request_omits_execution_uid() {
        let join = test_join();
        let request = join.start_request();
        assert_eq!(request.url, "https://mesh.example/auth/device-start");
        assert_eq!(request.method, "POST");
        let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(value["request"]["mode"], "device");
        assert!(value["request"].get("execution_uid").is_none());
    }

    /// A pending redeem keeps polling; a successful one returns and consumes the invitation.
    #[test]
    fn redeem_tracks_pending_and_consumes_approved_join() {
        let join = test_join();
        let poll_token = "A".repeat(43);
        let started = HttpResponse {
            status: 200,
            body: format!(
                "{{\"poll_token\":\"{poll_token}\",\"user_code\":\"AAAAAAAAAAAAAAAA\",\"expires_in\":600}}"
            )
            .into_bytes(),
            retry_after_seconds: None,
        };
        join.on_start(started).unwrap();
        let poll = join.redeem_request().unwrap();
        assert_eq!(poll.url, "https://mesh.example/auth/device-redeem");
        assert_eq!(
            poll.headers.get("prefer").map(String::as_str),
            Some("wait=10")
        );
        assert!(matches!(
            join.on_redeem(HttpResponse {
                status: 401,
                body: Vec::new(),
                retry_after_seconds: None,
            })
            .unwrap(),
            Redeemed::Pending
        ));
        let invitation = br#"{"host_id":"00000000-0000-0000-0000-000000000002","mode":"device","execution_uid":0,"public_origin":"https://mesh.example","token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","ca_der":"AA","https_system_roots":true,"server_name":"mesh.example"}"#.to_vec();
        assert!(matches!(
            join.on_redeem(HttpResponse {
                status: 200,
                body: invitation,
                retry_after_seconds: None,
            })
            .unwrap(),
            Redeemed::Invitation { .. }
        ));
        assert!(matches!(
            join.redeem_request(),
            Err(ClientError::NotStarted)
        ));
    }

    /// The exported mesh helpers encode calls and accept one complete result frame.
    #[test]
    fn mesh_helpers_round_trip_one_action_result() {
        let call = mesh_call("mesh.status".to_owned(), "{}".to_owned()).unwrap();
        match decode_frame(&call).unwrap().frame {
            Frame::Call {
                action_id,
                input_json,
                ..
            } => {
                assert_eq!(action_id, "mesh.status");
                assert_eq!(input_json, b"{}");
            }
            _ => panic!("mesh_call must encode an action call"),
        }

        let mut reply = Vec::new();
        encode_frame_into(
            &Frame::Result {
                call_id: 1,
                ok: true,
                json: br#"{"connected":true}"#,
            },
            &mut reply,
        )
        .unwrap();
        assert_eq!(mesh_reply(reply.clone()).unwrap(), r#"{"connected":true}"#);
        reply.push(0);
        assert!(matches!(
            mesh_reply(reply),
            Err(ProtocolError::InvalidFrame)
        ));
    }

    /// The shared node-action parser refuses unknown actions and malformed input before framing.
    #[test]
    fn mesh_helpers_reject_requests_outside_the_shared_node_contract() {
        assert!(matches!(
            mesh_call("mesh.unknown".to_owned(), "{}".to_owned()),
            Err(ProtocolError::InvalidFrame)
        ));
        assert!(matches!(
            mesh_call(
                "mesh.status".to_owned(),
                r#"{"unexpected":true}"#.to_owned()
            ),
            Err(ProtocolError::InvalidFrame)
        ));
    }
}
