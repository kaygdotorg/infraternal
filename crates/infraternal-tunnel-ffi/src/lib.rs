//! `UniFFI` boundary for the iOS Packet Tunnel extension's device join (#580).
//!
//! Swift owns the P-256 key and supplies its public key and signing operation
//! through [`DeviceSigner`]. The same boundary uses a software `CryptoKit` key
//! in the Simulator and the Secure Enclave on a device; Rust builds the CSR,
//! verifies the returned certificate, and holds the QUIC device link.

use std::{
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use infraternal_link::{
    device::DeviceLink,
    enrollment::{JoinInvitation, Mode},
    identity::{IdentitySigner, KeyAlgorithm, SignError},
    join::{HttpsTrust, PreparedJoin},
    quic::{self, client_config_with_liveness},
    server_leaf_floor::ServerLeafFloor,
};
use serde::Serialize;
use tokio::runtime::Runtime;
use uuid::Uuid;

uniffi::setup_scaffolding!();

/// Shared Apple mesh engine and node state machine available to the Packet Tunnel adapter.
///
/// This keeps the Packet Tunnel integration tied to `infraternal-mesh-node`
/// instead of creating a second node state machine or packet runtime here.
#[cfg(unix)]
pub use infraternal_mesh_node::engine as mesh_engine;

/// A P-256 key operation owned by Swift, usually `CryptoKit` or the Secure Enclave.
#[uniffi::export(with_foreign)]
pub trait DeviceSigner: Send + Sync {
    /// Return the key's complete P-256 `SubjectPublicKeyInfo` DER.
    fn public_key_spki(&self) -> Vec<u8>;
    /// Sign `message` with ECDSA P-256 and SHA-256, returning DER signature bytes.
    ///
    /// # Errors
    /// The key is unavailable or refused to sign.
    fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, TunnelError>;
}

/// Adapts Swift's signer callback to the link crate's platform-neutral identity trait.
///
/// The adapter keeps the key handle behind the same `IdentitySigner` interface
/// used by the host's existing CSR and TLS code.
struct ForeignSigner(Arc<dyn DeviceSigner>);

impl fmt::Debug for ForeignSigner {
    /// Does not print the Swift key handle or any signing data.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForeignSigner(P-256)")
    }
}

impl IdentitySigner for ForeignSigner {
    /// iPhones use ECDSA on P-256 for the device identity.
    fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::EcdsaP256Sha256
    }

    /// Return the SPKI supplied by `CryptoKit`, which the CSR and fingerprint use.
    fn public_key_spki(&self) -> Vec<u8> {
        self.0.public_key_spki()
    }

    /// Ask Swift's key handle for a DER ECDSA signature.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        self.0.sign(message.to_vec()).map_err(|_| SignError)
    }
}

/// A coarse link state safe to show in the extension's status view.
#[derive(Clone, Copy, Debug, uniffi::Enum)]
pub enum LinkStatus {
    /// No join invitation has been prepared.
    NotJoined,
    /// The certificate is verified and ready to dial QUIC.
    Joined,
    /// The QUIC device link completed its Hello exchange.
    Connected,
}

/// A JSON POST prepared by Rust for Swift's public-root `URLSession` request.
#[derive(Clone, Debug, uniffi::Record)]
pub struct JoinHttpRequest {
    /// The invitation's HTTPS origin followed by `/remote/join`.
    pub url: String,
    /// JSON content type for the request.
    pub content_type: String,
    /// Bounded join body containing the one-time invitation token.
    pub body: Vec<u8>,
}

/// An error reported to Swift without returning server text or credentials.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum TunnelError {
    /// The invitation, server response, or required state was invalid.
    #[error("the device join could not be verified")]
    Join,
    /// The system HTTPS trust mode or network request was unavailable.
    #[error("the device join network request failed")]
    Network,
    /// The key callback, runtime, or its state could not be used.
    #[error("the packet tunnel runtime is unavailable")]
    Runtime,
}

/// FFI version for smoke-checking that the extension linked its Rust archive.
#[uniffi::export]
#[must_use]
pub fn tunnel_ffi_version() -> String {
    "1".to_owned()
}

/// Facts the app asks the owner to approve for this device.
#[derive(Serialize)]
struct EnrolmentRequest {
    /// Fresh server-side host id bound by the owner approval.
    host_id: Uuid,
    /// The readable device label shown to the owner.
    hostname: String,
    /// SHA-256 of the raw P-256 point in the key's SPKI.
    key_fingerprint: String,
}

/// Mutable join state held inside one Packet Tunnel extension process.
#[derive(Default)]
struct JoinState {
    /// Invitation and zeroized request body while its HTTPS reply is pending.
    prepared: Option<PreparedJoin>,
    /// Certificate-checked device identity used for the QUIC link.
    joined: Option<infraternal_link::join::Joined>,
    /// Quinn endpoint kept alive with its active device connection.
    endpoint: Option<quinn::Endpoint>,
    /// Open control stream for the device Hello and liveness ping.
    link: Option<DeviceLink>,
}

/// A Packet Tunnel extension's enrollment, certificate join and QUIC device link.
///
/// The foreign P-256 signer stays owned by Swift. This object keeps the same
/// signer for the CSR, returned-certificate check and mutual-TLS link.
#[derive(uniffi::Object)]
pub struct DeviceJoin {
    /// Platform-owned P-256 signing callback, wrapped for the link crate.
    signer: Arc<dyn IdentitySigner>,
    /// One current-thread runtime for DNS, QUIC and the held control stream.
    runtime: Runtime,
    /// Enrollment and connection state, serialized across FFI calls.
    state: Mutex<JoinState>,
}

#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI exports owned Swift values at this boundary.
impl DeviceJoin {
    /// Create the device join around a Swift P-256 key handle.
    ///
    /// # Errors
    /// Returns `Runtime` when the signer or current-thread runtime is unavailable.
    #[uniffi::constructor]
    pub fn new(signer: Arc<dyn DeviceSigner>) -> Result<Arc<Self>, TunnelError> {
        let signer: Arc<dyn IdentitySigner> = Arc::new(ForeignSigner(signer));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| TunnelError::Runtime)?;
        Ok(Arc::new(Self {
            signer,
            runtime,
            state: Mutex::new(JoinState::default()),
        }))
    }

    /// Return the host id and exact P-256 fingerprint the owner approves.
    ///
    /// # Errors
    /// Returns `Join` for an invalid label or malformed public key.
    pub fn enrolment_request(&self, hostname: String) -> Result<Vec<u8>, TunnelError> {
        if hostname.is_empty()
            || hostname.len() > 128
            || hostname
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
        {
            return Err(TunnelError::Join);
        }
        let digest = infraternal_link::csr::key_digest(self.signer.as_ref())
            .map_err(|_| TunnelError::Join)?;
        let request = EnrolmentRequest {
            host_id: Uuid::new_v4(),
            hostname,
            key_fingerprint: format!("SHA256:{}", STANDARD_NO_PAD.encode(digest)),
        };
        serde_json::to_vec(&request).map_err(|_| TunnelError::Join)
    }

    /// Validate an invitation and prepare its HTTPS join request for `URLSession`.
    ///
    /// # Errors
    /// Returns `Join` for a malformed invitation and `Network` unless the
    /// invitation delegates public-root HTTPS verification to the platform.
    pub fn prepare_join(&self, invitation_json: String) -> Result<JoinHttpRequest, TunnelError> {
        if invitation_json.len() > 8192 {
            return Err(TunnelError::Join);
        }
        let invitation: JoinInvitation =
            serde_json::from_str(&invitation_json).map_err(|_| TunnelError::Join)?;
        if invitation.mode != Mode::Device {
            return Err(TunnelError::Join);
        }
        let prepared = PreparedJoin::new(invitation, Arc::clone(&self.signer))
            .map_err(|_| TunnelError::Join)?;
        if !matches!(prepared.trust(), HttpsTrust::SystemRoots) {
            return Err(TunnelError::Network);
        }
        let request = JoinHttpRequest {
            url: prepared.url().to_owned(),
            content_type: "application/json".to_owned(),
            body: prepared.body().to_vec(),
        };
        let mut state = self.state.lock().map_err(|_| TunnelError::Runtime)?;
        state.prepared = Some(prepared);
        state.joined = None;
        state.endpoint = None;
        state.link = None;
        Ok(request)
    }

    /// Verify the join reply's CA chain and that its leaf names this P-256 key.
    ///
    /// # Errors
    /// Returns `Join` when there is no prepared request or its response fails
    /// the certificate and key checks.
    pub fn finish_join(&self, response: Vec<u8>) -> Result<(), TunnelError> {
        if response.len() > 8192 {
            return Err(TunnelError::Join);
        }
        let mut state = self.state.lock().map_err(|_| TunnelError::Runtime)?;
        let prepared = state.prepared.take().ok_or(TunnelError::Join)?;
        let joined = prepared.finish(&response).map_err(|_| TunnelError::Join)?;
        state.joined = Some(joined);
        Ok(())
    }

    /// Dial the enrolled server over QUIC and complete the device Hello exchange.
    ///
    /// # Errors
    /// Returns `Join` when enrollment is incomplete and `Network` when DNS,
    /// TLS, QUIC, or the device Hello fails.
    pub fn connect(&self) -> Result<LinkStatus, TunnelError> {
        let mut state = self.state.lock().map_err(|_| TunnelError::Runtime)?;
        if state.joined.is_none() {
            return Err(TunnelError::Join);
        }
        if state.link.is_some() {
            return Ok(LinkStatus::Connected);
        }
        let joined = state.joined.as_ref().ok_or(TunnelError::Join)?;
        let config = client_config_with_liveness(
            &joined.identity,
            std::slice::from_ref(&joined.ca),
            std::time::Duration::from_secs(15),
            std::time::Duration::from_secs(60),
        )
        .map_err(|_| TunnelError::Network)?;
        let address = self
            .runtime
            .block_on(joined.quic_address())
            .map_err(|_| TunnelError::Network)?;
        let bind_address = "0.0.0.0:0"
            .parse::<SocketAddr>()
            .map_err(|_| TunnelError::Runtime)?;
        let mut endpoint = self
            .runtime
            .block_on(async { quinn::Endpoint::client(bind_address) })
            .map_err(|_| TunnelError::Network)?;
        endpoint.set_default_client_config(config);
        let floor = ServerLeafFloor::default();
        let connection = self
            .runtime
            .block_on(quic::connect(
                &endpoint,
                address,
                &joined.server_name,
                &floor,
            ))
            .map_err(|_| TunnelError::Network)?;
        let link = self
            .runtime
            .block_on(DeviceLink::open(connection, "infraternal-ios/1"))
            .map_err(|_| TunnelError::Network)?;
        state.endpoint = Some(endpoint);
        state.link = Some(link);
        Ok(LinkStatus::Connected)
    }

    /// Return the current coarse device link state.
    pub fn status(&self) -> LinkStatus {
        match self.state.lock() {
            Ok(state) if state.link.is_some() => LinkStatus::Connected,
            Ok(state) if state.joined.is_some() => LinkStatus::Joined,
            _ => LinkStatus::NotJoined,
        }
    }

    /// Ping the held device link and return its round-trip time in milliseconds.
    ///
    /// # Errors
    /// Returns `Network` when the link is not connected or the ping fails.
    pub fn ping_millis(&self) -> Result<u64, TunnelError> {
        let mut state = self.state.lock().map_err(|_| TunnelError::Runtime)?;
        let link = state.link.as_mut().ok_or(TunnelError::Network)?;
        let duration = self
            .runtime
            .block_on(link.ping())
            .map_err(|_| TunnelError::Network)?;
        u64::try_from(duration.as_millis()).map_err(|_| TunnelError::Runtime)
    }
}

impl Drop for DeviceJoin {
    /// Close the active link and UDP endpoint before the owned Tokio runtime drops.
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            state.link.take();
            state.endpoint.take();
        }
    }
}

#[cfg(test)]
mod tests {
    //! Device join boundary tests with a shape-only P-256 signer fixture.

    #![allow(clippy::unwrap_used, clippy::expect_used)] // Fixed fixtures fail the test immediately if invalid.

    use super::*;

    /// A correctly shaped P-256 SPKI fixture for fingerprint-only operations.
    struct TestSigner {
        spki: Vec<u8>,
    }

    impl DeviceSigner for TestSigner {
        /// Return the fixed DER key fixture.
        fn public_key_spki(&self) -> Vec<u8> {
            self.spki.clone()
        }

        /// This fixture never needs to sign a CSR or TLS handshake.
        fn sign(&self, _message: Vec<u8>) -> Result<Vec<u8>, TunnelError> {
            Err(TunnelError::Runtime)
        }
    }

    /// Create a join fixture whose public-key shape matches the Rust CSR builder.
    fn test_join() -> Arc<DeviceJoin> {
        let mut spki = infraternal_link::csr::P256_SPKI_PREFIX.to_vec();
        spki.push(0x04);
        spki.extend([1; 64]);
        DeviceJoin::new(Arc::new(TestSigner { spki }))
            .expect("the current-thread runtime should start")
    }

    /// Enrollment exposes only a fresh host id, label and raw-key fingerprint.
    #[test]
    fn enrollment_request_contains_device_facts() {
        let join = test_join();
        let request = join.enrolment_request("simulator".to_owned()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(value["hostname"], "simulator");
        assert_eq!(value["key_fingerprint"].as_str().unwrap().len(), 50);
        assert!(value["host_id"].as_str().is_some());
    }

    /// Host invitations are rejected before `URLSession` receives their token.
    #[test]
    fn prepare_join_rejects_host_mode() {
        let join = test_join();
        let invitation = serde_json::json!({
            "host_id": "00000000-0000-0000-0000-000000000002",
            "mode": "rootless",
            "execution_uid": 1000,
            "token": "opaque",
            "ca_der": "AA",
            "server_name": "mesh.example"
        })
        .to_string();
        assert!(matches!(
            join.prepare_join(invitation),
            Err(TunnelError::Join)
        ));
    }
}
