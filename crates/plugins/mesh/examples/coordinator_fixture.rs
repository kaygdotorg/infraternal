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
