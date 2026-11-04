//! Drives real issued certificates through the production authority and checks each refusal.
use super::*;
use crate::{
    mesh_issue::{self, PersonRequest},
    mesh_login,
};
use infraternal_plugin_api::login_access::LoginGrant;
use russh::keys::{Algorithm, Certificate, PrivateKey, signature::Signer as _, ssh_key::Signature};

/// The person every fixture certificate is issued to.
const PERSON: &str = "0b5c8a64-7d1f-4c43-9d0e-0c6a8a5b7f10";
/// The mesh address the certificate is bound to.
const SOURCE: &str = "10.254.0.7";
/// The mesh node that owns [`SOURCE`].
const SOURCE_NODE: u64 = 7;
/// This node, the SSH target.
const TARGET_NODE: u64 = 9;

/// A runtime that opens nothing; admission is under test, not shells.
struct NoRuntime;
#[allow(clippy::unused_async_trait_impl)]
impl SessionRuntime for NoRuntime {
    async fn open(
        &self,
        _: &str,
        _: &str,
        _: SessionKind,
        _: Option<Terminal>,
    ) -> Result<Attachment, Refusal> {
        Err(Refusal::LoginAccess)
    }
}

/// Accounts.
fn accounts(name: &str) -> Option<u32> {
    match name {
        "root" => Some(0),
        "kayg" => Some(1000),
        "deploy" => Some(998),
        _ => None,
    }
}

/// A CA and one certificate it issued.
struct Fixture {
    ca: PrivateKey,
    certificate: Certificate,
}

/// Fixture.
fn fixture() -> Fixture {
    let ca = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519).unwrap();
    let subject = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
        .unwrap()
        .public_key()
        .clone();
    let sign = |body: &[u8]| {
        let signature: Signature = ca.try_sign(body).ok()?;
        signature.as_bytes().try_into().ok()
    };
    let certificate = mesh_issue::person_certificate(
        ca_key(&ca),
        &sign,
        &PersonRequest {
            subject: &subject,
            person: PERSON,
            source_address: SOURCE.parse().unwrap(),
            now: now(),
            lifetime: mesh_issue::MAX_LIFETIME,
        },
    )
    .unwrap();
    Fixture { ca, certificate }
}

/// Ca key.
fn ca_key(ca: &PrivateKey) -> [u8; 32] {
    ca.public_key().key_data().ed25519().unwrap().0
}

/// Now.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Snapshot.
fn snapshot(fixture: &Fixture, sequence: u64, grant: LoginGrant) -> Snapshot {
    Snapshot {
        sequence,
        node: TARGET_NODE,
        ca: ca_key(&fixture.ca),
        certificates: vec![Issued {
            digest: crate::mesh_certificate::digest(&fixture.certificate).unwrap(),
            person: PERSON.into(),
            source_node: SOURCE_NODE,
            source_address: SOURCE.parse().unwrap(),
            valid_before: fixture.certificate.valid_before(),
        }],
        grants: [(PERSON.to_owned(), grant)].into(),
    }
}

/// Own kayg.
fn own_kayg() -> LoginGrant {
    LoginGrant {
        own_username: Some("kayg".into()),
        ..LoginGrant::default()
    }
}

/// Mesh.
fn mesh(ssh_allowed: bool) -> MeshView {
    MeshView {
        node: TARGET_NODE,
        addresses: vec!["10.254.0.9".parse().unwrap()],
        interface: "infraternal0".into(),
        peers: [(
            SOURCE_NODE,
            MeshPeer {
                addresses: vec![SOURCE.parse().unwrap(), "fd00::7".parse().unwrap()],
                ssh_allowed,
            },
        )]
        .into(),
    }
}

/// New authority.
fn new_authority() -> Authority<NoRuntime> {
    Authority::new(NoRuntime, accounts)
}

/// Admit.
async fn admit(
    authority: &Authority<NoRuntime>,
    fixture: &Fixture,
    source: &str,
    account: &str,
) -> Result<(), Refusal> {
    let guard = authority.current().await?;
    mesh_login::authorize(
        &guard,
        &fixture.certificate,
        source.parse().unwrap(),
        authority.target_node().await.ok_or(Refusal::Revoked)?,
        account,
        now(),
    )
    .map(|_| ())
}

/// Ready.
async fn ready(grant: LoginGrant, ssh_allowed: bool) -> (Authority<NoRuntime>, Fixture) {
    let fixture = fixture();
    let authority = new_authority();
    authority.set_mesh(Some(mesh(ssh_allowed))).await;
    authority
        .install(snapshot(&fixture, 1, grant))
        .await
        .unwrap();
    (authority, fixture)
}

/// Both checks pass for the persons own account.
#[tokio::test]
async fn both_checks_pass_for_the_persons_own_account() {
    let (authority, fixture) = ready(own_kayg(), true).await;
    assert_eq!(admit(&authority, &fixture, SOURCE, "kayg").await, Ok(()));
}

/// Nothing installed refuses.
#[tokio::test]
async fn nothing_installed_refuses() {
    let fixture = fixture();
    let authority = new_authority();
    assert!(authority.current().await.is_err());
    authority.set_mesh(Some(mesh(true))).await;
    assert!(authority.current().await.is_err());
    let other = new_authority();
    other
        .install(snapshot(&fixture, 1, own_kayg()))
        .await
        .unwrap();
    assert!(other.current().await.is_err());
}

/// Network access denied refuses.
#[tokio::test]
async fn network_access_denied_refuses() {
    let (authority, fixture) = ready(own_kayg(), false).await;
    assert_eq!(
        admit(&authority, &fixture, SOURCE, "kayg").await,
        Err(Refusal::NetworkAccess)
    );
}

/// Login access denied refuses.
#[tokio::test]
async fn login_access_denied_refuses() {
    let (authority, fixture) = ready(own_kayg(), true).await;
    for account in ["root", "deploy", "absent"] {
        assert_eq!(
            admit(&authority, &fixture, SOURCE, account).await,
            Err(Refusal::LoginAccess),
            "{account}"
        );
    }
    let (empty, fixture) = ready(LoginGrant::default(), true).await;
    assert_eq!(
        admit(&empty, &fixture, SOURCE, "kayg").await,
        Err(Refusal::LoginAccess)
    );
}

/// Any account reaches root.
#[tokio::test]
async fn any_account_reaches_root() {
    let grant = LoginGrant {
        any_account: true,
        ..LoginGrant::default()
    };
    let (authority, fixture) = ready(grant, true).await;
    assert_eq!(admit(&authority, &fixture, SOURCE, "root").await, Ok(()));
    // An account this host does not have is still refused.
    assert_eq!(
        admit(&authority, &fixture, SOURCE, "absent").await,
        Err(Refusal::LoginAccess)
    );
}

/// Unregistered certificate refuses.
#[tokio::test]
async fn unregistered_certificate_refuses() {
    let (authority, _) = ready(own_kayg(), true).await;
    let other = fixture();
    // Signed by a different CA and never registered here.
    assert_eq!(
        admit(&authority, &other, SOURCE, "kayg").await,
        Err(Refusal::Revoked)
    );
}

/// Certificate from another address refuses.
#[tokio::test]
async fn certificate_from_another_address_refuses() {
    let (authority, fixture) = ready(own_kayg(), true).await;
    // The certificate is bound to 10.254.0.7; the same peer's IPv6 address is not it.
    assert!(
        admit(&authority, &fixture, "fd00::7", "kayg")
            .await
            .is_err()
    );
    assert!(
        admit(&authority, &fixture, "10.254.0.8", "kayg")
            .await
            .is_err()
    );
}

/// Removing a certificate revokes it.
#[tokio::test]
async fn removing_a_certificate_revokes_it() {
    let (authority, fixture) = ready(own_kayg(), true).await;
    let mut next = snapshot(&fixture, 2, own_kayg());
    next.certificates.clear();
    authority.install(next).await.unwrap();
    assert_eq!(
        admit(&authority, &fixture, SOURCE, "kayg").await,
        Err(Refusal::Revoked)
    );
}

/// Older or repeated snapshots are refused.
#[tokio::test]
async fn older_or_repeated_snapshots_are_refused() {
    let (authority, fixture) = ready(own_kayg(), true).await;
    let mut wider = snapshot(&fixture, 1, LoginGrant::default());
    wider.grants.insert(
        PERSON.into(),
        LoginGrant {
            any_account: true,
            ..LoginGrant::default()
        },
    );
    assert_eq!(authority.install(wider.clone()).await, Err(Stale));
    wider.sequence = 0;
    assert_eq!(authority.install(wider).await, Err(Stale));
    assert_eq!(
        admit(&authority, &fixture, SOURCE, "root").await,
        Err(Refusal::LoginAccess)
    );
}

/// Snapshot for another node refuses.
#[tokio::test]
async fn snapshot_for_another_node_refuses() {
    let fixture = fixture();
    let authority = new_authority();
    authority.set_mesh(Some(mesh(true))).await;
    let mut wrong = snapshot(&fixture, 1, own_kayg());
    wrong.node = TARGET_NODE + 1;
    authority.install(wrong).await.unwrap();
    assert!(authority.current().await.is_err());
}

/// Leaving the mesh refuses.
#[tokio::test]
async fn leaving_the_mesh_refuses() {
    let (authority, _) = ready(own_kayg(), true).await;
    authority.set_mesh(None).await;
    assert!(authority.current().await.is_err());
}

/// Snapshot wire form refuses unknown fields.
#[test]
fn snapshot_wire_form_refuses_unknown_fields() {
    let fixture = fixture();
    let mut json = serde_json::to_value(snapshot(&fixture, 1, own_kayg())).unwrap();
    assert!(serde_json::from_value::<Snapshot>(json.clone()).is_ok());
    json["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Snapshot>(json).is_err());
}
