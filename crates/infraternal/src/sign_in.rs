//! Runs passkey-approved CLI device sign-in and stores each API credential privately [D303, D311].

/// Shared invalid/expired API-key remedy. Takes no secret, so callers cannot echo one.
// Remote CLI actions do not consume stored sign-in keys yet (#303).
#[allow(dead_code)]
pub(crate) fn invalid_api_key_diagnostic() -> (&'static str, crate::cli::output::Exit) {
    (
        "Signed out: your key expired or was revoked. Run `infraternal sign-in <server>`.",
        crate::cli::output::Exit::NotAllowed,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        ApiCredentialError, Failure, SCOPES, StoredCredential, approval_link,
        read_api_credential_from, server_url, store_credential,
    };
    use serde_json::Value;
    use std::{
        fs,
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
    };
    use zeroize::Zeroizing;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn default_sign_in_scopes_are_read_only() {
        assert_eq!(SCOPES, ["hosts:read", "sessions:read", "status:read"]);
    }

    /// J137 P3-6: a scope no action declares is not grantable; a later action that declared
    /// it would otherwise become callable by keys already issued, without a new approval.
    #[test]
    fn scopes_without_an_action_are_refused() {
        assert!(matches!(
            super::requested_scopes(&["sessions:write"]),
            Err(Failure::InvalidScope)
        ));
        assert!(super::requested_scopes(&["hosts:write"]).is_ok());
    }

    #[test]
    fn stored_key_selection_requires_one_server_or_an_explicit_origin() {
        let directory = TemporaryDirectory::new();
        store_credential(
            &directory.0,
            StoredCredential {
                server: "https://one.example.test".to_owned(),
                device: "one".to_owned(),
                scopes: vec!["hosts:read".to_owned()],
                api_key: Zeroizing::new("first-key-never-report".to_owned()),
            },
        )
        .expect("store first test credential");
        store_credential(
            &directory.0,
            StoredCredential {
                server: "https://two.example.test".to_owned(),
                device: "two".to_owned(),
                scopes: vec!["hosts:write".to_owned()],
                api_key: Zeroizing::new("second-key-never-report".to_owned()),
            },
        )
        .expect("store second test credential");

        assert!(matches!(
            read_api_credential_from(&directory.0, None),
            Err(ApiCredentialError::Ambiguous)
        ));
        let selected = read_api_credential_from(&directory.0, Some("https://one.example.test/"))
            .expect("select explicit server credential");
        assert_eq!(selected.server, "https://one.example.test");
        assert_eq!(selected.scopes, ["hosts:read"]);
        assert_eq!(selected.api_key.as_str(), "first-key-never-report");
    }

    #[test]
    fn missing_and_ambiguous_credential_errors_contain_no_key_material() {
        let directory = TemporaryDirectory::new();
        assert!(matches!(
            read_api_credential_from(&directory.0, None),
            Err(ApiCredentialError::Missing)
        ));
        let error = ApiCredentialError::Missing;
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("key"));
    }

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "infraternal-sign-in-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create temporary test directory");
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn credential(server: &str) -> StoredCredential {
        StoredCredential {
            server: server.to_owned(),
            device: "test-device".to_owned(),
            scopes: vec!["hosts:read".to_owned()],
            api_key: Zeroizing::new("fixture-value-not-a-bearer-token".to_owned()),
        }
    }

    #[cfg(unix)]
    #[test]
    fn credential_store_and_file_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = TemporaryDirectory::new();
        let directory = temporary.0.join("config").join("infraternal");
        let path = store_credential(&directory, credential("https://mesh.example.org"))
            .expect("store credential");

        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let stored: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        assert_eq!(stored["version"], 1);
        assert_eq!(
            stored["credentials"][0]["server"],
            "https://mesh.example.org"
        );
        assert_eq!(
            stored["credentials"][0]["api_key"],
            "fixture-value-not-a-bearer-token"
        );
        assert!(stored.get("poll_token").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn credential_store_refuses_a_symlink_destination() {
        use std::os::unix::fs::symlink;

        let temporary = TemporaryDirectory::new();
        let directory = temporary.0.join("infraternal");
        fs::create_dir(&directory).unwrap();
        let target = temporary.0.join("outside.json");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, directory.join("credentials.json")).unwrap();

        assert!(store_credential(&directory, credential("https://mesh.example.org")).is_err());
        assert_eq!(fs::read(target).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn credential_read_refuses_a_private_directory_replaced_after_locking() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = TemporaryDirectory::new();
        let directory = temporary.0.join("infraternal");
        fs::create_dir(&directory).unwrap();
        let locked_directory = super::lock_private_directory(&directory).unwrap();

        let replacement = temporary.0.join("replacement");
        fs::create_dir(&replacement).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_contents = br#"{"version":1,"credentials":[]}"#;
        let replacement_file = replacement.join("credentials.json");
        fs::write(&replacement_file, replacement_contents).unwrap();
        let original = temporary.0.join("original");
        fs::rename(&directory, original).unwrap();
        symlink(&replacement, &directory).unwrap();

        assert!(
            super::read_credential_file(&locked_directory).is_err(),
            "credential reads must stay bound to the directory inode that was locked"
        );
        assert!(
            super::replace_file_atomically(&locked_directory, b"redirected").is_err(),
            "credential replacement must stay bound to the directory inode that was locked"
        );
        assert_eq!(
            fs::read(&replacement_file).unwrap().as_slice(),
            replacement_contents,
            "credential writes must not be redirected into a replacement directory"
        );
    }

    #[test]
    fn credential_store_keeps_credentials_for_other_servers() {
        let temporary = TemporaryDirectory::new();
        let directory = temporary.0.join("infraternal");
        store_credential(&directory, credential("https://one.example.org")).unwrap();
        let path = store_credential(&directory, credential("https://two.example.org")).unwrap();

        let stored: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let servers = stored["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(|credential| credential["server"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            servers,
            ["https://one.example.org", "https://two.example.org"]
        );
    }

    #[test]
    fn simultaneous_credential_stores_preserve_each_server() {
        let temporary = TemporaryDirectory::new();
        let directory = temporary.0.join("infraternal");
        let writers = 16;
        let barrier = Arc::new(Barrier::new(writers));
        let tasks = (0..writers)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                let directory = directory.clone();
                thread::spawn(move || {
                    barrier.wait();
                    let server = format!("https://mesh-{index}.example.org");
                    store_credential(&directory, credential(&server)).expect("store credential");
                    server
                })
            })
            .collect::<Vec<_>>();
        let expected = tasks
            .into_iter()
            .map(|task| task.join().expect("credential writer thread"))
            .collect::<std::collections::BTreeSet<_>>();

        let path = directory.join("credentials.json");
        let stored: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let actual = stored["credentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(|credential| credential["server"].as_str().unwrap().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn server_input_accepts_only_a_bare_https_origin() {
        let parsed = server_url("https://Mesh.Example.org:8443/").unwrap();
        assert_eq!(
            parsed.origin().ascii_serialization(),
            "https://mesh.example.org:8443"
        );
        for invalid in [
            "http://mesh.example.org",
            "https://mesh.example.org/prefix",
            "https://mesh.example.org/?debug=1",
            "https://person:password@mesh.example.org",
            "https://mesh.example.org/#fragment",
        ] {
            assert!(
                matches!(server_url(invalid), Err(Failure::InvalidServer)),
                "{invalid}"
            );
        }
    }

    #[test]
    fn approval_link_carries_only_the_browser_user_code() {
        let server = server_url("https://mesh.example.org").unwrap();
        let link = approval_link(&server, "A_b-c123");

        assert_eq!(link, "https://mesh.example.org/?device_code=A_b-c123");
        assert!(!link.contains("poll_token"));
    }

    #[test]
    fn invalid_api_key_diagnostic_names_fix_and_exits_not_allowed() {
        let (message, exit) = super::invalid_api_key_diagnostic();
        assert_eq!(
            message,
            "Signed out: your key expired or was revoked. Run `infraternal sign-in <server>`."
        );
        assert_eq!(message.lines().count(), 1);
        assert_eq!(exit.code(), 3);
    }

    #[test]
    fn failure_exit_codes_follow_d303() {
        assert_eq!(super::exit_for_failure(Failure::InvalidServer).code(), 2);
        assert_eq!(super::exit_for_failure(Failure::Refused).code(), 3);
        assert_eq!(super::exit_for_failure(Failure::MissingEndpoint).code(), 4);
        assert_eq!(super::exit_for_failure(Failure::Expired).code(), 4);
        for failure in [
            Failure::Dns,
            Failure::Connect,
            Failure::Tls,
            Failure::ServerUnavailable,
        ] {
            assert_eq!(super::exit_for_failure(failure).code(), 5, "{failure:?}");
        }
        for failure in [
            Failure::Throttled,
            Failure::BadResponse,
            Failure::Runtime,
            Failure::InsecureStorage,
            Failure::LocalStorage,
        ] {
            assert_eq!(super::exit_for_failure(failure).code(), 1, "{failure:?}");
        }
        for failure in [
            Failure::InsecureStorageAfterApproval,
            Failure::StorageAfterApproval,
        ] {
            assert_eq!(super::exit_for_failure(failure).code(), 6, "{failure:?}");
        }
    }

    #[test]
    fn uncertain_device_redemption_uses_the_partial_exit_code() {
        assert_eq!(
            super::exit_for_failure(Failure::RedemptionUncertain).code(),
            6
        );
    }

    #[test]
    fn unusable_successful_redemption_bodies_are_partial() {
        for response in [
            b"not json".as_slice(),
            br#"{"unexpected":"field"}"#.as_slice(),
            br#"{"api_key":"not-a-capability"}"#.as_slice(),
        ] {
            assert!(matches!(
                super::parse_redemption_response(response),
                Err(Failure::RedemptionUncertain)
            ));
        }
    }

    #[test]
    fn redemption_timeout_exit_depends_on_whether_request_started() {
        for (request_started, expected_code) in [(false, 5), (true, 6)] {
            assert_eq!(
                super::exit_for_failure(super::map_redemption_network_failure(
                    super::NetworkFailure::Timeout { request_started }
                ))
                .code(),
                expected_code
            );
        }
    }

    #[test]
    fn ambiguous_redemption_transport_and_server_failures_are_partial() {
        for failure in [
            super::NetworkFailure::Dns,
            super::NetworkFailure::Connect,
            super::NetworkFailure::Tls,
        ] {
            assert_eq!(
                super::exit_for_failure(super::map_redemption_network_failure(failure)).code(),
                5
            );
        }
        for failure in [
            super::NetworkFailure::Request,
            super::NetworkFailure::ResponseBody,
        ] {
            assert_eq!(
                super::exit_for_failure(super::map_redemption_network_failure(failure)).code(),
                6
            );
        }
        for status in [
            super::StatusCode::OK,
            super::StatusCode::CREATED,
            super::StatusCode::INTERNAL_SERVER_ERROR,
            super::StatusCode::BAD_GATEWAY,
            super::StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert_eq!(
                super::exit_for_failure(super::map_redemption_http_failure(status)).code(),
                6
            );
        }
        assert_eq!(
            super::exit_for_failure(super::map_redemption_http_failure(
                super::StatusCode::BAD_REQUEST
            ))
            .code(),
            1
        );
    }

    #[test]
    fn server_generated_capabilities_have_exact_base64url_shapes() {
        assert!(super::server_capability_has_shape(&"A".repeat(43), 43));
        assert!(super::server_capability_has_shape(&"_".repeat(16), 16));
        assert!(!super::server_capability_has_shape(&"A".repeat(42), 43));
        assert!(!super::server_capability_has_shape(&"A".repeat(44), 43));
        assert!(!super::server_capability_has_shape(
            &("A".repeat(42) + "+"),
            43
        ));
        assert!(!super::server_capability_has_shape(
            &("A".repeat(42) + "="),
            43
        ));
    }
}

use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::Instant;
use url::Url;
use zeroize::Zeroizing;

use crate::cli::output::{CommandResult, CommandState, Exit, emit, print_progress};

const SCOPES: [&str; 3] = ["hosts:read", "sessions:read", "status:read"];
const ADDITIONAL_SCOPES: [&str; 3] = ["hosts:write", "terminal:connect", "actions:dry-run"];
const MAX_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_CREDENTIAL_FILE_BYTES: usize = 64 * 1024;
const MAX_DEVICE_LIFETIME_SECONDS: u64 = 10 * 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_secs(10);
const CREDENTIAL_FILE_NAME: &str = "credentials.json";
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCredential {
    server: String,
    device: String,
    scopes: Vec<String>,
    api_key: Zeroizing<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialFile {
    version: u32,
    credentials: Vec<StoredCredential>,
}

/// Error classes for choosing one already-approved server credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ApiCredentialError {
    Missing,
    Ambiguous,
    InvalidServer,
    UnsafeStorage,
}

/// Selected private credential; its key is zeroized and deliberately has no `Debug` output.
pub(crate) struct ApiCredential {
    pub(crate) server: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) api_key: Zeroizing<String>,
}

/// Read one server key through the same locked, private file boundary used by sign-in.
pub(crate) fn load_api_credential(
    server: Option<&str>,
) -> Result<ApiCredential, ApiCredentialError> {
    let directory = credential_directory().map_err(|_| ApiCredentialError::UnsafeStorage)?;
    read_api_credential_from(&directory, server)
}

/// Whether status should prefer the one configured server key to local node status.
pub(crate) fn has_stored_api_credentials() -> bool {
    match load_api_credential(None) {
        Ok(_) | Err(ApiCredentialError::Ambiguous) => true,
        Err(
            ApiCredentialError::Missing
            | ApiCredentialError::InvalidServer
            | ApiCredentialError::UnsafeStorage,
        ) => false,
    }
}

fn read_api_credential_from(
    directory: &Path,
    server: Option<&str>,
) -> Result<ApiCredential, ApiCredentialError> {
    let locked =
        lock_private_directory(directory).map_err(|_| ApiCredentialError::UnsafeStorage)?;
    let file = read_credential_file(&locked).map_err(|_| ApiCredentialError::UnsafeStorage)?;
    let selected = if let Some(server) = server {
        let expected = server_url(server).map_err(|_| ApiCredentialError::InvalidServer)?;
        let expected_origin = expected.origin().ascii_serialization();
        file.credentials
            .iter()
            .rev()
            .find(|credential| {
                server_url(&credential.server).is_ok_and(|candidate| {
                    candidate.origin().ascii_serialization() == expected_origin
                })
            })
            .ok_or(ApiCredentialError::Missing)?
    } else {
        let mut origins = file
            .credentials
            .iter()
            .filter_map(|credential| server_url(&credential.server).ok())
            .map(|credential| credential.origin().ascii_serialization())
            .collect::<Vec<_>>();
        origins.sort_unstable();
        origins.dedup();
        match origins.as_slice() {
            [] => return Err(ApiCredentialError::Missing),
            [_] => file
                .credentials
                .iter()
                .rev()
                .find(|credential| {
                    server_url(&credential.server).is_ok_and(|candidate| {
                        candidate.origin().ascii_serialization() == origins[0]
                    })
                })
                .ok_or(ApiCredentialError::Missing)?,
            _ => return Err(ApiCredentialError::Ambiguous),
        }
    };
    let parsed = server_url(&selected.server).map_err(|_| ApiCredentialError::UnsafeStorage)?;
    Ok(ApiCredential {
        server: parsed.origin().ascii_serialization(),
        scopes: selected.scopes.clone(),
        api_key: Zeroizing::new(selected.api_key.as_str().to_owned()),
    })
}

#[derive(Serialize)]
struct DeviceStartRequest<'a> {
    device: &'a str,
    scopes: &'a [String],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceStartResponse {
    poll_token: Zeroizing<String>,
    user_code: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct DeviceRedeemRequest<'a> {
    token: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceRedeemResponse {
    api_key: Zeroizing<String>,
}

struct DeviceApproval {
    poll_token: Zeroizing<String>,
    user_code: String,
    lifetime: Duration,
}

#[derive(Clone, Copy)]
enum NetworkFailure {
    Dns,
    Connect,
    Tls,
    Response,
    Request,
    ResponseBody,
    Timeout { request_started: bool },
}

impl From<crate::remote::ClientFailure> for NetworkFailure {
    fn from(failure: crate::remote::ClientFailure) -> Self {
        match failure {
            crate::remote::ClientFailure::Dns(..) => Self::Dns,
            crate::remote::ClientFailure::Connect(..)
            | crate::remote::ClientFailure::SocketOption(..) => Self::Connect,
            crate::remote::ClientFailure::TlsConfiguration
            | crate::remote::ClientFailure::TlsHandshake => Self::Tls,
            crate::remote::ClientFailure::HttpHandshake => Self::Response,
            crate::remote::ClientFailure::Request => Self::Request,
            crate::remote::ClientFailure::ResponseBody => Self::ResponseBody,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    InvalidServer,
    InvalidScope,
    Dns,
    Connect,
    Tls,
    Throttled,
    Expired,
    Refused,
    MissingEndpoint,
    ServerUnavailable,
    BadResponse,
    Runtime,
    InsecureStorage,
    LocalStorage,
    InsecureStorageAfterApproval,
    StorageAfterApproval,
    RedemptionUncertain,
}

enum Redemption {
    Pending,
    RetryAfter(Duration),
    Credential(Zeroizing<String>),
}

/// Starts one CLI device approval and saves the redeemed key only after private storage is ready.
pub(crate) fn run(server_input: &str, requested: &[&str], json_output: bool) -> ExitCode {
    let scopes = match requested_scopes(requested) {
        Ok(scopes) => scopes,
        Err(failure) => return fail(json_output, failure),
    };
    let server = match server_url(server_input) {
        Ok(server) => server,
        Err(failure) => return fail(json_output, failure),
    };
    let Ok(directory) = credential_directory() else {
        return fail(json_output, Failure::InsecureStorage);
    };
    if let Err(error) = prepare_store(&directory) {
        return fail(json_output, storage_failure(error.kind(), false));
    }
    let device = local_device_name();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return fail(json_output, Failure::Runtime);
    };
    let origin = server.origin().ascii_serialization();
    match crate::block_on(
        &runtime,
        run_flow(&server, &directory, &origin, &device, &scopes, json_output),
    ) {
        Ok(()) => emit(
            CommandResult::new(
                "sign-in",
                CommandState::Ready,
                "This device is signed in; its credential was saved privately.",
                json!({
                    "server": origin,
                    "device": device,
                    "scopes": scopes,
                    "stored": true,
                }),
            ),
            json_output,
            Exit::Ok,
        ),
        Err(failure) => fail(json_output, failure),
    }
}

async fn run_flow(
    server: &Url,
    directory: &Path,
    origin: &str,
    device: &str,
    scopes: &[String],
    json_output: bool,
) -> Result<(), Failure> {
    let approval = start_approval(server, device, scopes).await?;
    let link = approval_link(server, &approval.user_code);
    let progress = CommandResult::new(
        "sign-in",
        CommandState::Pending,
        "Approve this device sign-in with your passkey.",
        json!({
            "server": origin,
            "device": device,
            "scopes": scopes,
            "user_code": approval.user_code,
            "verification_url": link,
            "expires_in_seconds": approval.lifetime.as_secs(),
        }),
    )
    .with_body(format!(
        "Open this link and approve with your passkey:\n{link}\n\nCode: {}\nDevice: {device}\nScopes: {}",
        approval.user_code,
        scopes.join(", "),
    ))
    .with_next_step("Keep this command running while you review and approve the device.");
    // Progress does not mark the command's final result, so Ctrl-C can still emit D303's 130 result.
    print_progress(&progress, json_output, false);

    let api_key = redeem_after_approval(server, &approval).await?;
    let credential = StoredCredential {
        server: origin.to_owned(),
        device: device.to_owned(),
        scopes: scopes.to_vec(),
        api_key,
    };
    store_credential(directory, credential)
        .map(|_| ())
        .map_err(|error| storage_failure(error.kind(), true))
}

fn requested_scopes(requested: &[&str]) -> Result<Vec<String>, Failure> {
    let mut scopes = SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect::<Vec<_>>();
    for scope in requested {
        if !ADDITIONAL_SCOPES.contains(scope) && !SCOPES.contains(scope) {
            return Err(Failure::InvalidScope);
        }
        if !scopes.iter().any(|existing| existing == scope) {
            scopes.push((*scope).to_owned());
        }
    }
    Ok(scopes)
}

fn server_url(input: &str) -> Result<Url, Failure> {
    let server = Url::parse(input).map_err(|_| Failure::InvalidServer)?;
    if server.scheme() != "https"
        || server.host_str().is_none()
        || !server.username().is_empty()
        || server.password().is_some()
        || server.query().is_some()
        || server.fragment().is_some()
        || server.path() != "/"
    {
        return Err(Failure::InvalidServer);
    }
    Ok(server)
}

fn approval_link(server: &Url, user_code: &str) -> String {
    let mut link = server.clone();
    link.query_pairs_mut().append_pair("device_code", user_code);
    link.to_string()
}

fn server_capability_has_shape(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn local_device_name() -> String {
    let name = env::var("HOSTNAME").unwrap_or_default();
    let name = name
        .chars()
        .take(64)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let name = name
        .trim_matches(|character| character == '-' || character == '.')
        .to_owned();
    if name.is_empty() {
        "CLI device".to_owned()
    } else {
        name
    }
}

fn credential_directory() -> io::Result<PathBuf> {
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|home| home.join(".config"))
        })
        .ok_or_else(permission_denied)?;
    Ok(base.join("infraternal"))
}

fn prepare_store(directory: &Path) -> io::Result<()> {
    let locked_directory = lock_private_directory(directory)?;
    let _ = read_credential_file(&locked_directory)?;
    Ok(())
}

fn store_credential(directory: &Path, credential: StoredCredential) -> io::Result<PathBuf> {
    // Keep the lock across read, replacement and directory sync so concurrent
    // sign-ins cannot overwrite one another's credentials.
    let locked_directory = lock_private_directory(directory)?;
    let mut file = read_credential_file(&locked_directory)?;
    file.credentials.push(credential);
    let encoded = Zeroizing::new(serde_json::to_vec(&file).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "credential data could not be encoded",
        )
    })?);
    let path = directory.join(CREDENTIAL_FILE_NAME);
    replace_file_atomically(&locked_directory, &encoded)?;
    Ok(path)
}

/// Holds the locked directory inode so every credential operation can stay relative to it.
struct LockedCredentialDirectory {
    path: PathBuf,
    lock: nix::fcntl::Flock<File>,
}

impl LockedCredentialDirectory {
    /// Refuses a replaced pathname while data operations remain anchored to the held descriptor.
    fn verify_path_identity(&self) -> io::Result<()> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
        let current = options.open(&self.path)?;
        let current = current.metadata()?;
        let locked = self.lock.metadata()?;
        if !private_directory_metadata(&current)
            || !private_directory_metadata(&locked)
            || current.dev() != locked.dev()
            || current.ino() != locked.ino()
        {
            return Err(permission_denied());
        }
        Ok(())
    }
}

fn private_directory_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.is_dir()
        && owned_by_current_user(metadata)
        && metadata.permissions().mode() & 0o777 == 0o700
}

fn lock_private_directory(directory: &Path) -> io::Result<LockedCredentialDirectory> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    fs::create_dir_all(directory)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY);
    let file = options.open(directory)?;
    let metadata = file.metadata()?;
    if !metadata.is_dir() || !owned_by_current_user(&metadata) {
        return Err(permission_denied());
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        file.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    let lock = nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, error)| error)?;
    let locked_directory = LockedCredentialDirectory {
        path: directory.to_owned(),
        lock,
    };
    locked_directory.verify_path_identity()?;
    Ok(locked_directory)
}

fn owned_by_current_user(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.uid() == nix::unistd::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

fn read_credential_file(directory: &LockedCredentialDirectory) -> io::Result<CredentialFile> {
    use std::os::unix::fs::PermissionsExt;

    directory.verify_path_identity()?;
    let fd = match nix::fcntl::openat(
        &*directory.lock,
        CREDENTIAL_FILE_NAME,
        nix::fcntl::OFlag::O_RDONLY
            | nix::fcntl::OFlag::O_NOFOLLOW
            | nix::fcntl::OFlag::O_NONBLOCK
            | nix::fcntl::OFlag::O_CLOEXEC,
        nix::sys::stat::Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => {
            directory.verify_path_identity()?;
            return Ok(CredentialFile {
                version: 1,
                credentials: Vec::new(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    let file = File::from(fd);
    let metadata = file.metadata()?;
    if !metadata.is_file() || !owned_by_current_user(&metadata) {
        return Err(permission_denied());
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
        return Err(permission_denied());
    }
    if metadata.len() > MAX_CREDENTIAL_FILE_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential file is too large",
        ));
    }
    let initial_capacity = usize::try_from(metadata.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "credential file is too large"))?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(initial_capacity));
    file.take((MAX_CREDENTIAL_FILE_BYTES + 1) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() > MAX_CREDENTIAL_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential file is too large",
        ));
    }
    let file: CredentialFile = serde_json::from_slice(&encoded)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "credential file is invalid"))?;
    if file.version != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "credential file version is unsupported",
        ));
    }
    directory.verify_path_identity()?;
    Ok(file)
}

fn replace_file_atomically(directory: &LockedCredentialDirectory, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    directory.verify_path_identity()?;
    for _ in 0..32 {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary = format!(".credentials-{}-{sequence}.tmp", std::process::id());
        let fd = match nix::fcntl::openat(
            &*directory.lock,
            temporary.as_str(),
            nix::fcntl::OFlag::O_WRONLY
                | nix::fcntl::OFlag::O_CREAT
                | nix::fcntl::OFlag::O_EXCL
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        ) {
            Ok(fd) => fd,
            Err(nix::errno::Errno::EEXIST) => continue,
            Err(error) => return Err(error.into()),
        };
        let mut file = File::from(fd);
        let result = (|| {
            let metadata = file.metadata()?;
            if !metadata.is_file() || !owned_by_current_user(&metadata) {
                return Err(permission_denied());
            }
            if metadata.permissions().mode() & 0o777 != 0o600 {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
            if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
                return Err(permission_denied());
            }
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            directory.verify_path_identity()?;
            nix::fcntl::renameat(
                &*directory.lock,
                temporary.as_str(),
                &*directory.lock,
                CREDENTIAL_FILE_NAME,
            )
            .map_err(io::Error::from)?;
            directory.lock.sync_all()?;
            directory.verify_path_identity()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = nix::unistd::unlinkat(
                &*directory.lock,
                temporary.as_str(),
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            );
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique credential file",
    ))
}

fn permission_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "credential storage is not private",
    )
}

fn storage_failure(kind: io::ErrorKind, after_approval: bool) -> Failure {
    let unsafe_store = matches!(
        kind,
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::Unsupported
    );
    match (after_approval, unsafe_store) {
        (false, true) => Failure::InsecureStorage,
        (false, false) => Failure::LocalStorage,
        (true, true) => Failure::InsecureStorageAfterApproval,
        (true, false) => Failure::StorageAfterApproval,
    }
}

async fn start_approval(
    server: &Url,
    device: &str,
    scopes: &[String],
) -> Result<DeviceApproval, Failure> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(&DeviceStartRequest { device, scopes })
            .map_err(|_| Failure::BadResponse)?,
    );
    let response = post_json_with_timeout(server, "/auth/device-start", &encoded)
        .await
        .map_err(map_network_failure)?;
    if response.status != StatusCode::OK {
        return Err(map_http_failure(response.status));
    }
    let started: DeviceStartResponse =
        serde_json::from_slice(&response.body).map_err(|_| Failure::BadResponse)?;
    if !server_capability_has_shape(started.poll_token.as_str(), 43)
        || !server_capability_has_shape(&started.user_code, 16)
        || started.expires_in != MAX_DEVICE_LIFETIME_SECONDS
    {
        return Err(Failure::BadResponse);
    }
    Ok(DeviceApproval {
        poll_token: started.poll_token,
        user_code: started.user_code,
        lifetime: Duration::from_secs(started.expires_in),
    })
}

async fn redeem_after_approval(
    server: &Url,
    approval: &DeviceApproval,
) -> Result<Zeroizing<String>, Failure> {
    let deadline = Instant::now() + approval.lifetime;
    let mut delay = POLL_INTERVAL;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::Expired);
        }
        tokio::time::sleep(delay.min(remaining)).await;
        if Instant::now() >= deadline {
            return Err(Failure::Expired);
        }
        match redeem_once(server, &approval.poll_token).await? {
            Redemption::Pending => delay = POLL_INTERVAL,
            Redemption::RetryAfter(retry_after) => {
                delay = retry_after.max(Duration::from_secs(1));
            }
            Redemption::Credential(api_key) => return Ok(api_key),
        }
    }
}

async fn redeem_once(server: &Url, poll_token: &str) -> Result<Redemption, Failure> {
    let encoded = Zeroizing::new(
        serde_json::to_vec(&DeviceRedeemRequest { token: poll_token })
            .map_err(|_| Failure::BadResponse)?,
    );
    let response = post_json_with_timeout(server, "/auth/device-redeem", &encoded)
        .await
        .map_err(map_redemption_network_failure)?;
    match response.status {
        StatusCode::OK => parse_redemption_response(&response.body).map(Redemption::Credential),
        StatusCode::UNAUTHORIZED => Ok(Redemption::Pending),
        StatusCode::TOO_MANY_REQUESTS => Ok(Redemption::RetryAfter(
            response.retry_after.unwrap_or(POLL_INTERVAL),
        )),
        status => Err(map_redemption_http_failure(status)),
    }
}

fn parse_redemption_response(body: &[u8]) -> Result<Zeroizing<String>, Failure> {
    let redeemed: DeviceRedeemResponse =
        serde_json::from_slice(body).map_err(|_| Failure::RedemptionUncertain)?;
    if !server_capability_has_shape(redeemed.api_key.as_str(), 43) {
        return Err(Failure::RedemptionUncertain);
    }
    Ok(redeemed.api_key)
}

fn map_redemption_network_failure(failure: NetworkFailure) -> Failure {
    match failure {
        NetworkFailure::Request
        | NetworkFailure::ResponseBody
        | NetworkFailure::Timeout {
            request_started: true,
        } => Failure::RedemptionUncertain,
        failure => map_network_failure(failure),
    }
}

async fn post_json_with_timeout(
    server: &Url,
    path: &'static str,
    body: &[u8],
) -> Result<crate::remote::ClientResponse, NetworkFailure> {
    let mut request_started = false;
    match tokio::time::timeout(
        REQUEST_TIMEOUT,
        crate::remote::post_json(
            server,
            path,
            bytes::Bytes::copy_from_slice(body),
            None,
            MAX_RESPONSE_BYTES,
            &mut request_started,
        ),
    )
    .await
    {
        Ok(response) => response.map_err(NetworkFailure::from),
        Err(_) => Err(NetworkFailure::Timeout { request_started }),
    }
}

fn map_network_failure(failure: NetworkFailure) -> Failure {
    match failure {
        NetworkFailure::Dns => Failure::Dns,
        NetworkFailure::Tls => Failure::Tls,
        NetworkFailure::Response | NetworkFailure::ResponseBody => Failure::BadResponse,
        NetworkFailure::Connect | NetworkFailure::Request | NetworkFailure::Timeout { .. } => {
            Failure::Connect
        }
    }
}

fn map_http_failure(status: StatusCode) -> Failure {
    match status {
        StatusCode::TOO_MANY_REQUESTS => Failure::Throttled,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Failure::Refused,
        StatusCode::NOT_FOUND => Failure::MissingEndpoint,
        status if status.is_server_error() => Failure::ServerUnavailable,
        _ => Failure::BadResponse,
    }
}

fn map_redemption_http_failure(status: StatusCode) -> Failure {
    if status.is_server_error() || status.is_success() {
        Failure::RedemptionUncertain
    } else {
        map_http_failure(status)
    }
}

fn exit_for_failure(failure: Failure) -> Exit {
    match failure {
        Failure::InvalidServer | Failure::InvalidScope => Exit::Usage,
        Failure::Dns | Failure::Connect | Failure::Tls | Failure::ServerUnavailable => {
            Exit::Unreachable
        }
        Failure::Refused => Exit::NotAllowed,
        Failure::Expired | Failure::MissingEndpoint => Exit::NotFound,
        Failure::Throttled
        | Failure::BadResponse
        | Failure::Runtime
        | Failure::InsecureStorage
        | Failure::LocalStorage => Exit::Failed,
        Failure::InsecureStorageAfterApproval
        | Failure::StorageAfterApproval
        | Failure::RedemptionUncertain => Exit::Partial,
    }
}

fn fail(json_output: bool, failure: Failure) -> ExitCode {
    let (state, message, next) = match failure {
        Failure::InvalidServer => (
            CommandState::Refused,
            "Use an HTTPS server origin, such as https://infra.example.org.",
            "Remove any path, credentials, query or fragment from the server address.",
        ),
        Failure::InvalidScope => (
            CommandState::Refused,
            "That API-key scope is not supported.",
            "Choose a supported scope: hosts:write, terminal:connect or actions:dry-run.",
        ),
        Failure::Dns => (
            CommandState::Unknown,
            "Could not find this server's address.",
            "Check the server hostname and try again.",
        ),
        Failure::Connect => (
            CommandState::Unknown,
            "Could not connect to this server.",
            "Confirm the server is running and reachable over HTTPS, then try again.",
        ),
        Failure::Tls => (
            CommandState::Refused,
            "Could not verify this server's HTTPS certificate.",
            "Install a valid certificate for this server and try again.",
        ),
        Failure::Throttled => (
            CommandState::Refused,
            "The server is limiting sign-in requests.",
            "Wait before starting another sign-in, then try again.",
        ),
        Failure::Expired => (
            CommandState::Refused,
            "This sign-in code expired before approval.",
            "Run infraternal sign-in <server> again and approve the new code within 10 minutes.",
        ),
        Failure::Refused => (
            CommandState::Refused,
            "The server refused this sign-in.",
            "Start a new sign-in and approve it with the server's passkey before it expires.",
        ),
        Failure::MissingEndpoint => (
            CommandState::Unavailable,
            "This server does not support device sign-in.",
            "Upgrade the server to a version that supports device sign-in, then try again.",
        ),
        Failure::ServerUnavailable => (
            CommandState::Unknown,
            "The server could not complete this sign-in request.",
            "Check the server status and try again.",
        ),
        Failure::BadResponse => (
            CommandState::Failed,
            "The server returned a response this command could not use.",
            "Check that the server is up to date, then try again.",
        ),
        Failure::Runtime => (
            CommandState::Failed,
            "Could not start the sign-in request.",
            "Restart the CLI and try again.",
        ),
        Failure::InsecureStorage => (
            CommandState::Failed,
            "Cannot store credentials securely on this device.",
            "Use a regular config directory owned by you with private permissions, then retry.",
        ),
        Failure::LocalStorage => (
            CommandState::Failed,
            "Could not prepare private credential storage.",
            "Check that your infraternal config directory is writable, then retry.",
        ),
        Failure::InsecureStorageAfterApproval => (
            CommandState::Failed,
            "The server approved this device, but its credential could not be saved privately.",
            "The server key remains active. Ask the account owner to revoke this device, fix the private config directory, then run sign-in again.",
        ),
        Failure::StorageAfterApproval => (
            CommandState::Failed,
            "The server approved this device, but its credential could not be saved.",
            "The server key remains active. Ask the account owner to revoke this device, check the config directory's space and permissions, then run sign-in again.",
        ),
        Failure::RedemptionUncertain => (
            CommandState::Unknown,
            "The server may have approved this device, but the CLI could not confirm receipt of its credential.",
            "Check the server's device keys and revoke a matching key before retrying sign-in.",
        ),
    };
    emit(
        CommandResult::new("sign-in", state, message, json!({})).with_next_step(next),
        json_output,
        exit_for_failure(failure),
    )
}
