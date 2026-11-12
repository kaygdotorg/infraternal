//! Supplies production-schema coordinator configurations to the isolated real-daemon proof [165,169,216].
use infraternal_plugin_mesh::{
    api::MeshService,
    configuration,
    dataplane::{Config, DefaultPolicy, Identity},
    policy::model::PublicKey,
};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// One interactive request for the real-schema coordinator fixture.
struct Request {
    /// Initial identities for the first snapshot, omitted for later operations.
    #[serde(default)]
    identities: Option<[Identity; 2]>,
    /// The policy or lifecycle operation to execute.
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
/// Adds `count` extra members to the store, each with a unique public key and
/// no private key or traffic, so tests can measure a larger mesh.
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
        key[31] = 128;
        // These public-only fixtures share the live endpoint so traffic to their routes triggers real handshake attempts.
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
    let service = MeshService::new(pool);
    let store = service.dataplane();
    let mut members = None;
    let mut applied: Option<[Config; 2]> = None;
    let mut extra_member_ids = Vec::new();
    let mut next_extra_member = 0_u64;
    let mut peer_endpoint_port = None;
    for line in io::stdin().lock().lines() {
        let request: Request = serde_json::from_str(&line?)?;
        if request.mode == "unbound-identity" {
            return enrollment_policy(&service, request.identities.ok_or("identities required")?)
                .await;
        }
        if let Some(identities) = request.identities {
            if members.is_some() {
                return Err("already enrolled".into());
            }
            let (server, _) = store
                .attach(
                    "server",
                    identities[0].public_key,
                    Some(format!("10.220.0.1:{}", identities[0].port).parse()?),
                    true,
                )
                .await?;
            let (node, _) = store
                .attach(
                    "proof",
                    identities[1].public_key,
                    Some(format!("10.220.0.2:{}", identities[1].port).parse()?),
                    false,
                )
                .await?;
            members = Some([server, node]);
            peer_endpoint_port = Some(identities[1].port);
            for (node_id, _) in [server, node] {
                sqlx::query("UPDATE mesh_nodes SET key_rotation_supported=1 WHERE id=?")
                    .bind(i64::try_from(node_id.0)?)
                    .execute(&pool)
                    .await?;
            }
            extra_member_ids = seed_extra_members(
                &store,
                0,
                extra_members_count,
                identities[1].port,
            )
            .await?;
            next_extra_member = extra_members_count;
        }
        let members = members.ok_or("identities required")?;
        let now = 1_800_000_000;
        if request.mode == "peer-add" {
            let count = request.count.ok_or("count required")?;
            if count == 0 || next_extra_member.saturating_add(count) > 200 {
                return Err("simulated peer limit exceeded".into());
            }
            let endpoint_port = peer_endpoint_port.ok_or("peer endpoint is unavailable")?;
            extra_member_ids.extend(
                seed_extra_members(&store, next_extra_member, count, endpoint_port).await?,
            );
            next_extra_member += count;
            service.invalidate_dataplane().await;
        } else if request.mode == "peer-remove" {
            let count = request.count.ok_or("count required")?;
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
        if matches!(request.mode.as_str(), "rotation-begin" | "rotation-timer-begin") {
            let node_id = i64::try_from(members[1].0.0)?;
            let operation_id = request.operation_id.as_deref().ok_or("operation_id required")?;
            let timer_expired = request.mode == "rotation-timer-begin";
            let rotation = begin_fixture_rotation(
                &pool,
                node_id,
                operation_id,
                timer_expired,
            )
            .await?;
            println!("{}", json!({"rotation":rotation}));
            io::stdout().flush()?;
            continue;
        }
        let rotation = match request.mode.as_str() {
            "rotation-overlap" => Some(
                update_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0.0)?,
                    request.operation_id.as_deref().ok_or("operation_id required")?,
                    request.candidate_public_key.ok_or("candidate key required")?,
                    "overlap",
                )
                .await?,
            ),
            "rotation-retiring" => Some(
                update_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0.0)?,
                    request.operation_id.as_deref().ok_or("operation_id required")?,
                    PublicKey([0; 32]),
                    "retiring",
                )
                .await?,
            ),
            "rotation-cleanup" => Some(
                update_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0.0)?,
                    request.operation_id.as_deref().ok_or("operation_id required")?,
                    PublicKey([0; 32]),
                    "cleanup",
                )
                .await?,
            ),
            "rotation-finish" => Some(
                finish_fixture_rotation(
                    &pool,
                    &service,
                    i64::try_from(members[1].0.0)?,
                    request.operation_id.as_deref().ok_or("operation_id required")?,
                )
                .await?,
            ),
            _ => None,
        };
        if request.mode == "port" {
            service.execute("owner", "mesh.grant.create", &serde_json::to_vec(&json!({"name":"proof-port","from":{"Node":members[0].0},"to":{"Node":members[1].0},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":5211}]}}))?, now).await.map_err(|_|"Access grant refused")?;
        } else {
            if matches!(request.mode.as_str(), "allow" | "deny") {
                let policy = if request.mode == "allow" {
                    DefaultPolicy::Allow
                } else {
                    DefaultPolicy::Deny
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
            } else if matches!(request.mode.as_str(), "peer-add" | "peer-remove") {
                // Peer inventory changes above are compiled into the same ordered snapshot as policy changes.
            } else if rotation.is_none() {
                return Err("unknown mode".into());
            }
        }
        let next = [
            store
                .config(members[0])
                .await
                .map_err(|_| "server configuration refused")?,
            store
                .config(members[1])
                .await
                .map_err(|_| "node configuration refused")?,
        ];
        let chunks = [
            configuration::chunks(applied.as_ref().map(|old| &old[0]), &next[0])?,
            configuration::chunks(applied.as_ref().map(|old| &old[1]), &next[1])?,
        ];
        println!(
            "{}",
            json!({"addresses":[next[0].addresses,next[1].addresses],"chunks":chunks,"rotation":rotation})
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
    let row = sqlx::query("SELECT sequence,rotation_phase FROM mesh_node_key_rotation WHERE node_id=?")
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
    Ok(json!({"operation_id":operation_id,"sequence":sequence,"phase":"preparing","timer_due":timer_expired}))
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
