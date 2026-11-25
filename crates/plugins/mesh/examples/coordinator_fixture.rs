//! Supplies production-schema coordinator snapshots to isolated real-daemon proofs [165,169,216].
//!
//! Each JSON line creates or updates two to four test identities and prints the exact
//! snapshot chunks consumed by production mesh nodes. With three or four, the first is the
//! server's own node, and the proof can drive the product's direct-path candidates (#515):
//! `probes` carries each node's real reply to the candidate identity probe, `side_socket_probes`
//! its real reply to the side-socket probe (#260), and `observe` carries
//! the server node's real presence pages. The fixture feeds both through the same code the server runs
//! (`node_coordination::parse_candidates`, `Store::record_candidates`, `presence::Tracker`,
//! `presence::publish_reflexive`), so the proof relays bytes and the product decides.

use infraternal_plugin_mesh::{
    api::MeshService,
    configuration,
    dataplane::{Config, DefaultPolicy, Identity},
    policy::model::{NodeId, PublicKey},
};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;

/// One line of test input for compiling production-schema mesh snapshots.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    /// The authenticated identities to attach on the first request: two, or up to four with the
    /// server's own node first.
    #[serde(default)]
    identities: Option<Vec<Identity>>,
    /// The coordinator-observed UDP endpoints (control IP plus listen port) for those identities.
    #[serde(default)]
    endpoints: Option<Vec<SocketAddr>>,
    /// Each identity's raw reply to `mesh.identity {"candidates":true}`, in identity order.
    #[serde(default)]
    probes: Option<Vec<serde_json::Value>>,
    /// Each identity's raw reply to `mesh.identity {"side_socket":true}`, in identity order (#260,
    /// J1211). The fixture records them through the code the server runs, so a node that takes
    /// marked datagrams on its second socket is marked in its peers' snapshots.
    #[serde(default)]
    side_socket_probes: Option<Vec<serde_json::Value>>,
    /// The server node's raw `mesh.peers {"presence":true}` pages from one poll.
    #[serde(default)]
    observe: Option<Vec<serde_json::Value>>,
    /// Send a complete snapshot as though an authenticated node reconnected.
    #[serde(default)]
    full_snapshot: bool,
    /// The access or enrollment operation to apply.
    mode: String,
    /// Identifies the key rotation that owns each rekey phase.
    #[serde(default)]
    operation_id: Option<String>,
    /// Candidate key prepared by the live infraternal agent.
    #[serde(default)]
    candidate_public_key: Option<PublicKey>,
    /// Number of simulated public-only peers to add or remove.
    #[serde(default)]
    count: Option<u64>,
}
/// The dataplane host names the fixture attaches, in identity order; the first is the server.
const HOSTS: [&str; 4] = ["server", "proof", "peer", "third"];
/// Adds `count` extra members with valid unique public keys and no private key
/// or traffic, so tests can measure a larger mesh and trigger real handshakes.
async fn seed_extra_members(
    store: &infraternal_plugin_mesh::store::Store,
    first_index: u64,
    count: u64,
    endpoint_port: u16,
) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    let endpoint = format!("10.220.0.2:{endpoint_port}").parse()?;
    let mut node_ids = Vec::with_capacity(usize::try_from(count)?);
    for index in first_index..first_index.saturating_add(count) {
        let mut key = [0; 32];
        key[..8].copy_from_slice(&index.to_le_bytes());
        // Give every fixture a distinct public key and send its handshake attempts to the
        // local test endpoint. These peers have no private keys and cannot complete a handshake.
        key[31] = 64;
        let (node, _) = store
            .attach(
                &format!("public-{index}"),
                PublicKey(key),
                Some(endpoint),
                false,
            )
            .await?;
        node_ids.push(node.0);
    }
    Ok(node_ids)
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
            .attach_named(
                HOSTS[index],
                identity.public_key,
                endpoints.get(index).copied(),
                index == 0,
                Some(HOSTS[index]),
            )
            .await?;
        members.push(node);
    }
    Ok(members)
}
/// Serve production-schema coordinator requests over stdin and return JSON responses.
///
/// The optional arguments seed public-only peers and select a persistent SQLite
/// path, which lets the isolated mesh tests exercise churn and server restarts.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let extra_members_count: u64 = arguments.next().map_or(Ok(0), |value| value.parse())?;
    let state_path: Option<PathBuf> = arguments.next().map(PathBuf::from);
    let connect_options = state_path.map_or_else(
        || sqlx::sqlite::SqliteConnectOptions::new().in_memory(true),
        |path| {
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
        },
    );
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options)
        .await?;
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await?;
    sqlx::query("INSERT OR IGNORE INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await?;
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let mut members: Option<Vec<NodeId>> = None;
    let mut peer_identities: Option<Vec<Identity>> = None;
    let mut applied: Option<Vec<Config>> = None;
    let mut tracker = infraternal_plugin_mesh::presence::Tracker::default();
    let mut extra_member_ids = Vec::new();
    let mut next_extra_member = 0_u64;
    let mut peer_endpoint_port = None;
    for line in io::stdin().lock().lines() {
        let Request {
            identities: request_identities,
            endpoints,
            probes,
            side_socket_probes,
            observe,
            full_snapshot,
            mode,
            operation_id,
            candidate_public_key,
            count,
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
            if !(2..=4).contains(&identities.len()) {
                return Err("two to four identities required".into());
            }
            if identities.len() >= 3 {
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
            let attached = attach_all(&store, &identities, &endpoints).await?;
            for node_id in &attached {
                sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1 WHERE id=?")
                    .bind(i64::try_from(node_id.0)?)
                    .execute(&pool)
                    .await?;
            }
            members = Some(attached);
            peer_endpoint_port = Some(identities[1].port);
            extra_member_ids =
                seed_extra_members(&store, 0, extra_members_count, identities[1].port).await?;
            next_extra_member = extra_members_count;
            peer_identities = Some(identities);
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
        if let Some(replies) = side_socket_probes {
            for (node, reply) in members.iter().zip(replies) {
                let reported = infraternal_plugin_mesh::node_coordination::parse_side_socket(
                    &serde_json::to_vec(&reply)?,
                );
                store.record_side_port(*node, reported).await?;
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
        if mode == "peer-add" {
            let count = count.ok_or("count required")?;
            if count == 0 || next_extra_member.saturating_add(count) > 200 {
                return Err("simulated peer limit exceeded".into());
            }
            let endpoint_port = peer_endpoint_port.ok_or("peer endpoint is unavailable")?;
            extra_member_ids
                .extend(seed_extra_members(&store, next_extra_member, count, endpoint_port).await?);
            next_extra_member += count;
            service.invalidate_dataplane().await;
        } else if mode == "peer-remove" {
            let count = count.ok_or("count required")?;
            if count == 0 || count > extra_member_ids.len() as u64 {
                return Err("simulated peer removal exceeds current inventory".into());
            }
            for node_id in extra_member_ids.drain(..usize::try_from(count)?) {
                service
                    .execute(
                        "owner",
                        "mesh.node.delete",
                        &serde_json::to_vec(&json!({"node_id":node_id}))?,
                        now,
                    )
                    .await
                    .map_err(|_| "simulated peer removal refused")?;
            }
            service.invalidate_dataplane().await;
        }
        if matches!(mode.as_str(), "rotation-begin" | "rotation-timer-begin") {
            let node_id = i64::try_from(members[1].0)?;
            let operation_id = operation_id.as_deref().ok_or("operation_id required")?;
            let timer_expired = mode == "rotation-timer-begin";
            let rotation =
                begin_fixture_rotation(&pool, node_id, operation_id, timer_expired).await?;
            println!("{}", json!({"rotation":rotation}));
            io::stdout().flush()?;
            continue;
        }
        let rotation = match mode.as_str() {
            "rotation-overlap" => Some(
                update_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0)?,
                    operation_id.as_deref().ok_or("operation_id required")?,
                    candidate_public_key.ok_or("candidate key required")?,
                    "overlap",
                )
                .await?,
            ),
            "rotation-retiring" => Some(
                update_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0)?,
                    operation_id.as_deref().ok_or("operation_id required")?,
                    PublicKey([0; 32]),
                    "retiring",
                )
                .await?,
            ),
            "rotation-cleanup" => Some(
                update_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0)?,
                    operation_id.as_deref().ok_or("operation_id required")?,
                    PublicKey([0; 32]),
                    "cleanup",
                )
                .await?,
            ),
            "rotation-finish" => Some(
                finish_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0)?,
                    operation_id.as_deref().ok_or("operation_id required")?,
                )
                .await?,
            ),
            _ => None,
        };
        if mode == "port" {
            service.execute("owner", "mesh.grant.create", &serde_json::to_vec(&json!({"name":"proof-port","from":{"Node":members[0].0},"to":{"Node":members[1].0},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":5211}]}}))?, now).await.map_err(|_|"Access grant refused")?;
        } else if matches!(mode.as_str(), "allow" | "deny") {
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
        } else if !matches!(mode.as_str(), "keep" | "peer-add" | "peer-remove")
            && rotation.is_none()
        {
            return Err("unknown mode".into());
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
            // A reconnect receives a complete view even though this fixture process remembers
            // the configuration it compiled before the node disconnected.
            let previous = if full_snapshot {
                None
            } else {
                applied.as_ref().map(|old| &old[index])
            };
            chunks.push(configuration::chunks(previous, config)?);
        }
        let addresses: Vec<_> = next.iter().map(|config| config.addresses).collect();
        println!(
            "{}",
            json!({"addresses":addresses,"chunks":chunks,"rotation":rotation})
        );
        io::stdout().flush()?;
        applied = Some(next);
    }
    Ok(())
}

/// Record the coordinator's prepared operation before the real node creates a candidate key.
async fn begin_fixture_rotation(
    pool: &sqlx::SqlitePool,
    node_id: i64,
    operation_id: &str,
    timer_expired: bool,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let row =
        sqlx::query("SELECT sequence,rotation_phase FROM mesh_node_key_rotation WHERE node_id=?")
            .bind(node_id)
            .fetch_one(pool)
            .await?;
    let phase: Option<String> = sqlx::Row::try_get(&row, "rotation_phase")?;
    if phase.is_some() {
        return Err("rotation already open".into());
    }
    let sequence = sqlx::Row::try_get::<i64, _>(&row, "sequence")?
        .checked_add(1)
        .ok_or("rotation sequence exhausted")?;
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    if timer_expired {
        sqlx::query(
            "UPDATE mesh_node_key_rotation SET last_rotation=unixepoch()-schedule_period_secs,schedule_boot_id='j526-fixture',schedule_monotonic=0 WHERE node_id=?",
        )
        .bind(node_id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE mesh_node_key_rotation SET rotation_phase='preparing',operation_id=?,sequence=? WHERE node_id=? AND rotation_phase IS NULL",
    )
    .bind(operation_id)
    .bind(sequence)
    .bind(node_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(
        json!({"operation_id":operation_id,"sequence":sequence,"phase":"preparing","timer_due":timer_expired}),
    )
}

/// Publish the candidate key while retaining the predecessor during the live data-path overlap.
async fn update_fixture_rotation(
    pool: &sqlx::SqlitePool,
    service: &MeshService,
    node_id: i64,
    operation_id: &str,
    candidate: PublicKey,
    phase: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    let row = sqlx::query(
        "SELECT n.public_key,r.rotation_phase,r.operation_id,r.rotation_revision FROM mesh_nodes AS n JOIN mesh_node_key_rotation AS r ON r.node_id=n.id WHERE n.id=?",
    )
    .bind(node_id)
    .fetch_one(&mut *tx)
    .await?;
    let current: Vec<u8> = sqlx::Row::try_get(&row, "public_key")?;
    let current_phase: Option<String> = sqlx::Row::try_get(&row, "rotation_phase")?;
    let current_operation: Option<String> = sqlx::Row::try_get(&row, "operation_id")?;
    if current_operation.as_deref() != Some(operation_id) {
        return Err("rotation operation mismatch".into());
    }
    let revision: i64 = sqlx::query_scalar(
        "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
    )
    .fetch_one(&mut *tx)
    .await?;
    match phase {
        "overlap" => {
            if current_phase.as_deref() != Some("preparing") || current.as_slice() == candidate.0 {
                return Err("rotation overlap transition refused".into());
            }
            sqlx::query("UPDATE mesh_nodes SET public_key=? WHERE id=?")
                .bind(candidate.0.as_slice())
                .bind(node_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET candidate_public_key=?,previous_public_key=?,rotation_phase='overlap',rotation_started_at=unixepoch(),rotation_boot_id='j526-fixture',rotation_monotonic=0,rotation_revision=?,local_committed=0 WHERE node_id=? AND operation_id=?",
            )
            .bind(candidate.0.as_slice())
            .bind(&current)
            .bind(revision)
            .bind(node_id)
            .bind(operation_id)
            .execute(&mut *tx)
            .await?;
        }
        "retiring" => {
            if current_phase.as_deref() != Some("overlap") {
                return Err("rotation commit transition refused".into());
            }
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET candidate_public_key=NULL,rotation_phase='retiring',rotation_revision=?,local_committed=1 WHERE node_id=? AND operation_id=?",
            )
            .bind(revision)
            .bind(node_id)
            .bind(operation_id)
            .execute(&mut *tx)
            .await?;
        }
        "cleanup" => {
            if current_phase.as_deref() != Some("retiring") {
                return Err("rotation cleanup transition refused".into());
            }
            sqlx::query(
                "UPDATE mesh_node_key_rotation SET previous_public_key=NULL,rotation_phase='cleanup',rotation_revision=? WHERE node_id=? AND operation_id=?",
            )
            .bind(revision)
            .bind(node_id)
            .bind(operation_id)
            .execute(&mut *tx)
            .await?;
        }
        _ => return Err("unknown rotation phase".into()),
    }
    tx.commit().await?;
    service.invalidate_dataplane().await;
    Ok(json!({"phase":phase,"revision":revision,"timer_due":false}))
}

/// Clear the completed operation and schedule the next interval from the fixture's wall clock.
async fn finish_fixture_rotation(
    pool: &sqlx::SqlitePool,
    service: &MeshService,
    node_id: i64,
    operation_id: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut tx = infraternal_plugin_api::storage::begin_immediate(pool).await?;
    let row = sqlx::query("SELECT rotation_period_secs FROM mesh_dataplane WHERE singleton=1")
        .fetch_one(&mut *tx)
        .await?;
    let period: i64 = sqlx::Row::try_get(&row, "rotation_period_secs")?;
    let result = sqlx::query(
        "UPDATE mesh_node_key_rotation SET last_rotation=unixepoch(),schedule_boot_id='j526-fixture',schedule_monotonic=0,schedule_period_secs=?,candidate_public_key=NULL,previous_public_key=NULL,rotation_phase=NULL,rotation_started_at=NULL,rotation_boot_id=NULL,rotation_monotonic=NULL,operation_id=NULL,rotation_revision=NULL,local_committed=0 WHERE node_id=? AND rotation_phase='cleanup' AND operation_id=?",
    )
    .bind(period)
    .bind(node_id)
    .bind(operation_id)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() != 1 {
        return Err("rotation finish transition refused".into());
    }
    let revision: i64 = sqlx::query_scalar(
        "UPDATE mesh_state SET revision=revision+1 WHERE singleton=1 RETURNING revision",
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    service.invalidate_dataplane().await;
    Ok(json!({"phase":"finished","revision":revision,"timer_due":false}))
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
