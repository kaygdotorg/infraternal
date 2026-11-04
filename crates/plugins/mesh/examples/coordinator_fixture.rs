//! Supplies production-schema coordinator configurations to the isolated real-daemon proof [165,169,216].
use infraternal_plugin_mesh::{
    api::MeshService,
    configuration,
    dataplane::{Config, DefaultPolicy, Identity},
};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufRead, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    identities: Option<[Identity; 2]>,
    mode: String,
}
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
    let mut members = None;
    let mut applied: Option<[Config; 2]> = None;
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
            seed_extra_members(&store, extra_members).await?;
        }
        let members = members.ok_or("identities required")?;
        let now = 1_800_000_000;
        if request.mode == "port" {
            service.execute("owner", "mesh.grant.create", &serde_json::to_vec(&json!({"name":"proof-port","from":{"Node":members[0].0},"to":{"Node":members[1].0},"both_ways":false,"ports":{"Ports":[{"protocol":"Tcp","number":5211}]}}))?, now).await.map_err(|_|"Access grant refused")?;
        } else {
            let policy = match request.mode.as_str() {
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
            json!({"addresses":[next[0].addresses,next[1].addresses],"chunks":chunks})
        );
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
