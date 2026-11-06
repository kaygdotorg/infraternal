//! Drives real coordinator publication through authenticated-channel fixtures; only public frames cross stdin/stdout [134,166,198], #173.
use infraternal_plugin_api::{PluginOperation, node_channel::NodeChannel};
use infraternal_plugin_mesh::{
    MeshPlugin, api::MeshService, dataplane::Identity, policy::model::PublicKey,
};
use infraternal_server::{enrollment::EnrollmentStore, plugins::PluginRuntime};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};
use std::{collections::BTreeMap, sync::Arc};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Apply = (usize, Vec<u8>, tokio::sync::oneshot::Sender<Vec<u8>>);
struct Channel {
    index: usize,
    host: String,
    identity: Identity,
    ip: std::net::IpAddr,
    notices: tokio::sync::watch::Sender<()>,
    frames: tokio::sync::mpsc::Sender<Apply>,
}
impl NodeChannel for Channel {
    fn id(&self) -> &str {
        &self.host
    }
    fn observed_ip(&self) -> std::net::IpAddr {
        self.ip
    }
    fn is_server(&self) -> bool {
        false
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<()> {
        self.notices.subscribe()
    }
    fn call(&self, action: &str, input: Vec<u8>) -> PluginOperation<'_, Vec<u8>> {
        let action = action.to_owned();
        Box::pin(async move {
            if action == "mesh.identity" {
                return serde_json::to_vec(&Some(&self.identity)).map_err(|_| "encoding refused");
            }
            if action != "mesh.configure" {
                return Err("action refused");
            }
            let (sender, receiver) = tokio::sync::oneshot::channel();
            self.frames
                .send((self.index, input, sender))
                .await
                .map_err(|_| "channel closed")?;
            receiver.await.map_err(|_| "reply missing")
        })
    }
}
#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Request {
    Init {
        identities: [Identity; 3],
        extra_members: u64,
        #[serde(default)]
        change: Option<Change>,
    },
    Ack {
        call: u64,
        reply: Value,
    },
    Revoke,
    Change {
        operation: Change,
    },
}
#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
enum Change {
    PeerRetirement,
    RuleRemoval,
    DefaultTightening,
}
struct State {
    authority: EnrollmentStore,
    runtime: PluginRuntime,
    service: MeshService,
    pool: sqlx::SqlitePool,
}
// Keep migrated inventory, access setup and admitted channels together.
async fn initialize(
    identities: [Identity; 3],
    extra: u64,
    frames: tokio::sync::mpsc::Sender<Apply>,
    change: Option<Change>,
) -> Result<State, Error> {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(4)
        .connect("sqlite::memory:")
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner')").execute(&pool).await?;
    let host = uuid::Uuid::from_u128(42);
    sqlx::query("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?,'owner','rootful',0,1)").bind(host.as_bytes().as_slice()).execute(&pool).await?;
    let service = MeshService::new(pool.clone());
    let mesh = service.dataplane();
    mesh.attach("server", PublicKey([1; 32]), None, true)
        .await?;
    let hosts = [host.to_string(), "peer-1".to_owned(), "peer-2".to_owned()];
    let ips = ["10.220.0.1", "10.220.0.2", "10.221.0.3"];
    let mut nodes = Vec::new();
    for (index, identity) in identities.iter().enumerate() {
        nodes.push(
            mesh.attach(
                &hosts[index],
                identity.public_key,
                Some(format!("{}:{}", ips[index], identity.port).parse()?),
                false,
            )
            .await?
            .0,
        );
    }
    for index in 0..extra {
        // Public-only synthetic identities need realistic byte widths so the
        // bounded JSON frames have the same size distribution as live keys.
        let mut key: [u8; 32] = Sha256::digest(format!("mesh-policy-public-peer-{index}")).into();
        key[31] &= 127;
        mesh.attach(&format!("public-{index}"), PublicKey(key), None, false)
            .await?;
    }
    if matches!(
        change,
        Some(Change::RuleRemoval | Change::DefaultTightening)
    ) {
        let revision =
            sqlx::query_scalar::<_, i64>("SELECT revision FROM mesh_state WHERE singleton=1")
                .fetch_one(&pool)
                .await?;
        service
            .execute(
                "owner",
                "mesh.default.set",
                &serde_json::to_vec(
                    &json!({"default_policy":if change == Some(Change::DefaultTightening) {"Allow"} else {"Deny"},"expected_revision":revision}),
                )?,
                1_800_000_000,
            )
            .await
            .map_err(|_| "default refused")?;
    }
    if change != Some(Change::DefaultTightening) {
        for (index, target) in nodes.iter().enumerate().skip(1) {
            for port in if change.is_some() {
                vec![5540, 5541]
            } else {
                vec![5540]
            } {
                let protocols = if change.is_some() {
                    vec!["Tcp", "Udp"]
                } else {
                    vec!["Udp"]
                };
                let ports: Vec<_> = protocols
                    .iter()
                    .map(|protocol| json!({"protocol":protocol,"number":port}))
                    .collect();
                let name = if port == 5540 {
                    format!("service-{index}")
                } else {
                    format!("permitted-{index}")
                };
                service.execute("owner", "mesh.grant.create", &serde_json::to_vec(&json!({"name":name,"from":{"Node":nodes[0].0},"to":{"Node":target.0},"both_ways":false,"ports":{"Ports":ports}}))?, 1_800_000_000).await.map_err(|_|"access refused")?;
            }
        }
    }
    let runtime = PluginRuntime::new(vec![Arc::new(MeshPlugin::new(pool.clone()))], "server")
        .with_store(pool.clone())
        .await
        .map_err(|_| "runtime refused")?;
    let authority = EnrollmentStore::new(pool.clone());
    authority.bind_plugins(&runtime);
    for (index, identity) in identities.into_iter().enumerate() {
        runtime
            .attach_node(Arc::new(Channel {
                index,
                host: hosts[index].clone(),
                identity,
                ip: ips[index].parse()?,
                notices: tokio::sync::watch::channel(()).0,
                frames: frames.clone(),
            }))
            .await
            .map_err(|_| "attachment refused")?;
    }
    Ok(State {
        authority,
        runtime,
        service,
        pool,
    })
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let (frames, mut deliveries) = tokio::sync::mpsc::channel::<Apply>(32);
    let (input, mut lines) = tokio::sync::mpsc::channel(8);
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if input.blocking_send(line).is_err() {
                break;
            }
        }
    });
    let mut stdout = std::io::stdout();
    let mut pending = BTreeMap::new();
    let mut sequence = 0_u64;
    let mut state = None;
    let (committed, mut commits) = tokio::sync::mpsc::channel(1);
    loop {
        let output = tokio::select! {
            frame = deliveries.recv() => {
                let Some((node,input,reply))=frame else { break; };
                sequence=sequence.checked_add(1).ok_or("call exhausted")?;
                pending.insert(sequence,reply);
                Some(json!({"type":"apply","call":sequence,"node":node,"chunk":serde_json::from_slice::<Value>(&input)?}))
            },
            result = commits.recv() => {
                let Some(result)=result else { break; };
                Some(json!({"type":"revoked","success":result}))
            },
            line = lines.recv() => {
                let Some(line)=line else { break; };
                let line=line?;
                match serde_json::from_str::<Request>(&line)? {
                    Request::Init {identities,extra_members,change} => {
                        if state.is_some() { return Err("already initialized".into()); }
                        state=Some(initialize(identities,extra_members,frames.clone(),change).await?);
                        None
                    },
                    Request::Ack {call,reply} => {
                        pending.remove(&call).ok_or("unknown reply")?.send(serde_json::to_vec(&reply)?).map_err(|_|"worker retired")?;
                        None
                    },
                    Request::Change {operation} => {
                        let state = state.as_ref().ok_or("not initialized")?;
                        let service = state.service.clone();
                        let runtime = state.runtime.clone();
                        let pool = state.pool.clone();
                        let authority = state.authority.clone();
                        let committed = committed.clone();
                        tokio::spawn(async move {
                            let success = async {
                                match operation {
                                    Change::PeerRetirement => authority.revoke("owner",uuid::Uuid::from_u128(42),1_800_000_001).await?,
                                    Change::RuleRemoval => {
                                        for index in 1..=2 {
                                            service.execute("owner","mesh.grant.delete",&serde_json::to_vec(&json!({"name":format!("service-{index}")}))?,1_800_000_001).await.map_err(|_|"access refused")?;
                                        }
                                    },
                                    Change::DefaultTightening => {
                                        let revision = sqlx::query_scalar::<_,i64>("SELECT revision FROM mesh_state WHERE singleton=1").fetch_one(&pool).await?;
                                        service.execute("owner","mesh.default.set",&serde_json::to_vec(&json!({"default_policy":"Deny","expected_revision":revision}))?,1_800_000_001).await.map_err(|_|"default refused")?;
                                    }
                                }
                                // This trusted fixture writes through the real service, then
                                // wakes the runtime's independently constructed service cache.
                                // The production socket writer shares its service with workers.
                                runtime.authority_changed().await;
                                Ok::<(),Error>(())
                            }.await.is_ok();
                            let _ = committed.send(success).await;
                        });
                        None
                    },
                    Request::Revoke => {
                        let authority=state.as_ref().ok_or("not initialized")?.authority.clone();
                        let committed=committed.clone();
                        tokio::spawn(async move {
                            let success=authority.revoke("owner",uuid::Uuid::from_u128(42),1_800_000_001).await.is_ok();
                            let _=committed.send(success).await;
                        });
                        None
                    }
                }
            }
        };
        if let Some(output) = output {
            stdout.write_all(format!("{output}\n").as_bytes())?;
            stdout.flush()?;
        }
    }
    Ok(())
}
