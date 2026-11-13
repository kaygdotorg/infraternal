//! Supplies production-schema coordinator snapshots to isolated real-daemon proofs [165,169,216].
//!
//! Each JSON line creates or updates two or three test identities and prints the exact
//! snapshot chunks consumed by production mesh nodes. With three, the first is the server's own
//! node, and the proof can drive the product's direct-path candidates (#515): `probes` carries
//! each node's real reply to the candidate identity probe, and `observe` carries the server
//! node's real presence pages. The fixture feeds both through the same code the server runs
//! (`node_coordination::parse_candidates`, `Store::record_candidates`, `presence::Tracker`,
//! `presence::publish_reflexive`), so the proof relays bytes and the product decides.

use infraternal_plugin_mesh::{
    api::MeshService,
    configuration,
    dataplane::{Config, DefaultPolicy, Identity},
    policy::model::NodeId,
};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;

/// One line of test input for compiling production-schema mesh snapshots.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// The authenticated identities to attach on the first request: two, or three with the
    /// server's own node first.
    #[serde(default)]
    identities: Option<Vec<Identity>>,
    /// The coordinator-observed UDP endpoints (control IP plus listen port) for those identities.
    #[serde(default)]
    endpoints: Option<Vec<SocketAddr>>,
    /// Each identity's raw reply to `mesh.identity {"candidates":true}`, in identity order.
    #[serde(default)]
    probes: Option<Vec<serde_json::Value>>,
    /// The server node's raw `mesh.peers {"presence":true}` pages from one poll.
    #[serde(default)]
    observe: Option<Vec<serde_json::Value>>,
    /// The access or enrollment operation to apply.
    mode: String,
}
/// The dataplane host names the fixture attaches, in identity order; the first is the server.
const HOSTS: [&str; 3] = ["server", "proof", "peer"];
/// Adds `count` extra members to the store, each with a unique public key and
/// no private key or traffic, so tests can measure a larger mesh.
async fn seed_extra_members(
    store: &infraternal_plugin_mesh::store::Store,
    count: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..count {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&index.to_le_bytes());
        key[31] = 128;
        // These public-only inventory fixtures have no private key or traffic.
        store
            .attach(
                &format!("public-{index}"),
                infraternal_plugin_mesh::policy::model::PublicKey(key),
                None,
                false,
            )
            .await?;
    }
    Ok(())
}
/// Attach every identity with its observed endpoint, as the coordinator does on each connection.
async fn attach_all(
    store: &infraternal_plugin_mesh::store::Store,
    identities: &[Identity],
    endpoints: &[SocketAddr],
) -> Result<Vec<NodeId>, Box<dyn std::error::Error>> {
    let mut members = Vec::new();
    for (index, identity) in identities.iter().enumerate() {
        let (node, _) = store
            .attach(
                HOSTS[index],
                identity.public_key,
                endpoints.get(index).copied(),
                index == 0,
            )
            .await?;
        members.push(node);
    }
    Ok(members)
}
/// Compile test coordinator requests into the same snapshots production nodes consume.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let extra_members: u64 = std::env::args()
        .nth(1)
        .map_or(Ok(0), |value| value.parse())?;
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await?;
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await?;
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await?;
    let service = MeshService::new(pool);
    let store = service.dataplane();
    let mut members: Option<Vec<NodeId>> = None;
    let mut peer_identities: Option<Vec<Identity>> = None;
    let mut applied: Option<Vec<Config>> = None;
    let mut tracker = infraternal_plugin_mesh::presence::Tracker::default();
    for line in io::stdin().lock().lines() {
        let Request {
            identities: request_identities,
            endpoints,
            probes,
            observe,
            mode,
        } = serde_json::from_str(&line?)?;
        if mode == "unbound-identity" {
            let identities: [Identity; 2] = request_identities
                .ok_or("identities required")?
                .try_into()
                .map_err(|_| "two identities required")?;
            return enrollment_policy(&service, identities).await;
        }
        if let Some(identities) = request_identities {
            if members.is_some() {
                return Err("already enrolled".into());
            }
            if !(2..=3).contains(&identities.len()) {
                return Err("two or three identities required".into());
            }
            if identities.len() == 3 {
                // The server's own node peers with every member through its control plane, as in production,
                // so it can observe them even while Access denies the pair (D215, D352).
                let control_plane = infraternal_plugin_mesh::policy::rules::TrafficPolicy::Ports(
                    [infraternal_plugin_mesh::policy::rules::Port {
                        protocol: infraternal_plugin_mesh::policy::rules::Protocol::Tcp,
                        number: 7443,
                    }]
                    .into(),
                );
                store.set_control_plane(std::sync::Arc::new(move || control_plane.clone()));
            }
            let endpoints = match endpoints {
                Some(endpoints) => endpoints,
                None => identities
                    .iter()
                    .enumerate()
                    .map(|(index, identity)| {
                        format!("10.220.0.{}:{}", index + 1, identity.port).parse()
                    })
                    .collect::<Result<_, _>>()?,
            };
            members = Some(attach_all(&store, &identities, &endpoints).await?);
            peer_identities = Some(identities);
            seed_extra_members(&store, extra_members).await?;
        } else if let Some(endpoints) = endpoints {
            let identities = peer_identities.as_ref().ok_or("identities required")?;
            attach_all(&store, identities, &endpoints).await?;
        }
        let members = members.clone().ok_or("identities required")?;
        if let Some(probes) = probes {
            for (node, reply) in members.iter().zip(probes) {
                let reported = infraternal_plugin_mesh::node_coordination::parse_candidates(
                    &serde_json::to_vec(&reply)?,
                );
                store.record_candidates(*node, reported.as_deref()).await?;
            }
        }
        if let Some(pages) = observe {
            let mut rows = Vec::new();
            for page in pages {
                infraternal_plugin_mesh::presence::read_peers(
                    &serde_json::to_vec(&page)?,
                    &mut rows,
                )
                .ok_or("presence page invalid")?;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            tracker.record(Some((true, rows)), now);
            infraternal_plugin_mesh::presence::publish_reflexive(&service, &tracker).await;
        }
        let now = 1_800_000_000;
        if mode == "port" {
            service.execute("owner", "mesh.grant.create", &serde_json::to_vec(&json!({"name":"proof-port","from":{"Node":members[0].0},"to":{"Node":members[1].0},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":5211}]}}))?, now).await.map_err(|_|"Access grant refused")?;
        } else if mode != "keep" {
            let policy = match mode.as_str() {
                "allow" => DefaultPolicy::Allow,
                "deny" => DefaultPolicy::Deny,
                _ => return Err("unknown mode".into()),
            };
            let preview = service
                .execute(
                    "owner",
                    "mesh.default.preview",
                    &serde_json::to_vec(&json!({"default_policy":policy}))?,
                    now,
                )
                .await
                .map_err(|_| "preview refused")?;
            service
                .execute(
                    "owner",
                    "mesh.default.set",
                    &serde_json::to_vec(
                        &json!({"default_policy":policy,"expected_revision":preview["revision"]}),
                    )?,
                    now,
                )
                .await
                .map_err(|_| "default refused")?;
        }
        let mut next = Vec::new();
        for node in &members {
            next.push(
                store
                    .config(*node)
                    .await
                    .map_err(|_| "node configuration refused")?,
            );
        }
        let mut chunks = Vec::new();
        for (index, config) in next.iter().enumerate() {
            chunks.push(configuration::chunks(
                applied.as_ref().map(|old| &old[index]),
                config,
            )?);
        }
        let addresses: Vec<_> = next.iter().map(|config| config.addresses).collect();
        println!("{}", json!({"addresses":addresses,"chunks":chunks}));
        io::stdout().flush()?;
        applied = Some(next);
    }
    Ok(())
}

/// Feed actual kernel identities through migrated inventory and grant compilation.
/// A refused public-key claim must remain separate from the granted inventory;
/// explicit permission afterwards proves the same service and tunnel were live.
async fn enrollment_policy(
    service: &MeshService,
    identities: [Identity; 2],
) -> Result<(), Box<dyn std::error::Error>> {
    use infraternal_plugin_mesh::policy::model::PublicKey;
    let store = service.dataplane();
    store
        .attach("server", PublicKey([1; 32]), None, true)
        .await?;
    let (target, _) = store
        .attach(
            "target",
            identities[1].public_key,
            Some(format!("10.220.0.2:{}", identities[1].port).parse()?),
            false,
        )
        .await?;
    let now = 1_800_000_000;
    let victim = service
        .execute(
            "owner",
            "mesh.node.enroll",
            &serde_json::to_vec(&json!({"name":"intended-host","public_key":PublicKey([3;32])}))?,
            now,
        )
        .await
        .map_err(|_| "enrollment refused")?["node_id"]
        .as_u64()
        .ok_or("invalid state")?;
    enrollment_grant(service, "intended-service", victim, target.0, now).await?;
    let preview = service
        .execute(
            "owner",
            "mesh.default.preview",
            &serde_json::to_vec(&json!({"default_policy":"Deny"}))?,
            now,
        )
        .await
        .map_err(|_| "preview refused")?;
    service
        .execute(
            "owner",
            "mesh.default.set",
            &serde_json::to_vec(&json!({
                "default_policy":"Deny","expected_revision":preview["revision"]
            }))?,
            now,
        )
        .await
        .map_err(|_| "default refused")?;
    let refused = store
        .attach(
            "different-authenticated-host",
            PublicKey([3; 32]),
            None,
            false,
        )
        .await
        .is_err();
    let (source, _) = store
        .attach(
            "different-authenticated-host",
            identities[0].public_key,
            Some(format!("10.220.0.1:{}", identities[0].port).parse()?),
            false,
        )
        .await?;
    let denied = [
        store
            .config(source)
            .await
            .map_err(|_| "configuration refused")?,
        store
            .config(target)
            .await
            .map_err(|_| "configuration refused")?,
    ];
    enrollment_grant(service, "explicit-service", source.0, target.0, now).await?;
    let allowed = [
        store
            .config(source)
            .await
            .map_err(|_| "configuration refused")?,
        store
            .config(target)
            .await
            .map_err(|_| "configuration refused")?,
    ];
    let proof = json!({"refused":refused,"addresses":[denied[0].addresses,denied[1].addresses],
        "denied":[configuration::chunks(None,&denied[0])?,configuration::chunks(None,&denied[1])?],
        "allowed":[configuration::chunks(None,&allowed[0])?,configuration::chunks(None,&allowed[1])?]});
    println!("{proof}");
    io::stdout().flush()?;
    Ok(())
}

/// Use the same narrow grant for intended and explicitly permitted identities.
async fn enrollment_grant(
    service: &MeshService,
    name: &str,
    source: u64,
    target: u64,
    now: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    service
        .execute(
            "owner",
            "mesh.grant.create",
            &serde_json::to_vec(&json!({
                "name":name,"from":{"Node":source},"to":{"Node":target},
                "both_ways":false,"ports":{"Ports":[{"protocol":"Udp","number":5540}]}
            }))?,
            now,
        )
        .await
        .map_err(|_| "grant refused")?;
    Ok(())
}
