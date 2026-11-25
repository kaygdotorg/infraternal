//! Subnet routes end to end through storage (D197 M3): a node's advertisement, the owner's approval,
//! the snapshots that follow, and revocation. These pin the security rules that matter most: nothing
//! is routed without approval, only the owner approves (with fresh authority when a session asks),
//! overlaps are refused with the reason, a withdrawn network stops at once, and a revoked approval
//! takes its arrows with it.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::*;
use crate::{
    api::MeshService,
    dataplane::Config,
    policy::{
        model::{NodeId, PublicKey},
        networks::Network,
        rules::TrafficPolicy,
    },
};

/// Parse a network the test knows is valid.
fn net(text: &str) -> Network {
    text.parse().unwrap()
}

/// A migrated in-memory server with an owner `owner`, a member `alice`, and the server plus nodes
/// `router` and `client`, all able to receive subnet routes.
async fn mesh() -> (MeshService, [NodeId; 3], SqlitePool) {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../infraternal-server/migrations")
        .run(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES('owner','owner',1,'fixture','owner','Owner'),('alice','alice',0,'fixture','alice','Alice')")
        .execute(&pool)
        .await
        .unwrap();
    let service = MeshService::new(pool.clone());
    let store = service.dataplane();
    let mut ids = Vec::new();
    for (host, key) in [("server", 1), ("router", 2), ("client", 3)] {
        let (id, _) = store
            .attach(
                host,
                PublicKey([key; 32]),
                Some("198.51.100.10:10254".parse().unwrap()),
                host == "server",
            )
            .await
            .unwrap();
        store.record_routes(id, Some(&[])).await.unwrap();
        ids.push(id);
    }
    (service, ids.try_into().unwrap(), pool)
}

/// Run a route action as the owner without a session freshness check (the adapter's part).
async fn owner(service: &MeshService, action: &str, input: Value) -> Value {
    service
        .execute("owner", action, &serde_json::to_vec(&input).unwrap(), 1_000)
        .await
        .unwrap()
}

/// The networks `config`'s node reaches through `router`.
fn through(config: &Config, router: NodeId) -> Vec<Network> {
    config.peers[&router]
        .networks
        .through
        .iter()
        .map(|network| network.network)
        .collect()
}

/// Nothing is routed before the owner approves; non-owners and stale sessions cannot; withdrawal pauses and revoke re-lists under a new id.
#[tokio::test]
async fn an_advertised_network_is_routed_only_after_the_owner_approves_it() {
    let (service, [_, router, client], pool) = mesh().await;
    let store = service.dataplane();
    assert!(
        store
            .record_routes(router, Some(&[net("192.168.1.0/24")]))
            .await
            .unwrap()
    );
    // Advertised, not approved: no snapshot mentions it.
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
    let listed = owner(&service, LIST, json!({})).await;
    assert_eq!(listed["routes"][0]["state"], "waiting for approval");

    // A member who is not the owner cannot approve.
    let denied = service
        .execute(
            "alice",
            APPROVE,
            br#"{"node_id":2,"network":"192.168.1.0/24"}"#,
            1_000,
        )
        .await;
    assert_eq!(denied, Err(MeshApiError::Denied));
    // A session whose passkey authority is not fresh cannot either.
    let settings = store.mesh_settings().await.unwrap();
    let stale = execute(
        &pool,
        &settings,
        Actor::User {
            id: "owner",
            fresh: Some("no-such-session"),
        },
        Request::Approve(Approve {
            node_id: router.0,
            network: net("192.168.1.0/24"),
            masquerade: true,
        }),
        1_000,
    )
    .await;
    assert_eq!(stale, Err(MeshApiError::FreshRequired));

    let approved = owner(
        &service,
        APPROVE,
        json!({"node_id": router.0, "network": "192.168.1.0/24"}),
    )
    .await;
    assert_eq!(approved["state"], "approved");
    let route = approved["route_id"].as_u64().unwrap();
    // Allow by default (Community): the client may reach it; the router serves it to the client.
    let client_view = store.config(client).await.unwrap();
    assert_eq!(through(&client_view, router), [net("192.168.1.0/24")]);
    assert_eq!(
        client_view.peers[&router].networks.through[0].outbound,
        TrafficPolicy::All
    );
    let router_view = store.config(router).await.unwrap();
    let served = &router_view.peers[&client].networks.served[0];
    assert_eq!(served.network, net("192.168.1.0/24"));
    assert!(!served.keep_source, "masquerade is the default");

    // The node stops advertising it: routing stops, the approval stays for later.
    assert!(store.record_routes(router, Some(&[])).await.unwrap());
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
    assert_eq!(
        owner(&service, LIST, json!({})).await["routes"][0]["state"],
        "approved, not advertised"
    );
    assert!(
        store
            .record_routes(router, Some(&[net("192.168.1.0/24")]))
            .await
            .unwrap()
    );
    assert_eq!(
        through(&store.config(client).await.unwrap(), router),
        [net("192.168.1.0/24")]
    );

    // Revoke: routing stops and the network waits for approval again under a new identity.
    let revoked = owner(&service, REVOKE, json!({"route_id": route})).await;
    assert_eq!(revoked["state"], "revoked");
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
    let listed = owner(&service, LIST, json!({})).await;
    assert_eq!(listed["routes"][0]["state"], "waiting for approval");
    assert_ne!(listed["routes"][0]["route_id"].as_u64(), Some(route));
}

/// Overlaps, the mesh range and unadvertised networks are refused with the reason, and the list shows it in advance.
#[tokio::test]
async fn overlaps_and_unroutable_networks_are_refused_with_the_reason() {
    let (service, [_, router, client], _pool) = mesh().await;
    let store = service.dataplane();
    store
        .record_routes(router, Some(&[net("192.168.0.0/16")]))
        .await
        .unwrap();
    store
        .record_routes(client, Some(&[net("192.168.7.0/24"), net("10.254.9.0/24")]))
        .await
        .unwrap();
    owner(
        &service,
        APPROVE,
        json!({"node_id": router.0, "network": "192.168.0.0/16"}),
    )
    .await;
    let overlap = owner(
        &service,
        APPROVE,
        json!({"node_id": client.0, "network": "192.168.7.0/24"}),
    )
    .await;
    assert_eq!(overlap["state"], "refused");
    assert!(
        overlap["reason"]
            .as_str()
            .unwrap()
            .contains("overlaps 192.168.0.0/16, which is already approved"),
        "{overlap}"
    );
    let mesh_range = owner(
        &service,
        APPROVE,
        json!({"node_id": client.0, "network": "10.254.9.0/24"}),
    )
    .await;
    assert!(
        mesh_range["reason"]
            .as_str()
            .unwrap()
            .contains("mesh's own range"),
        "{mesh_range}"
    );
    // The list says why before anyone tries.
    let listed = owner(&service, LIST, json!({})).await;
    let waiting: Vec<_> = listed["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|route| route["state"] == "waiting for approval")
        .collect();
    assert_eq!(waiting.len(), 2);
    assert!(waiting.iter().all(|route| route["refused"].is_string()));
    // A network the node does not advertise cannot be approved.
    let absent = owner(
        &service,
        APPROVE,
        json!({"node_id": client.0, "network": "172.16.0.0/24"}),
    )
    .await;
    assert!(
        absent["reason"]
            .as_str()
            .unwrap()
            .contains("does not advertise"),
        "{absent}"
    );
}

/// Under deny by default only an arrow to the network grants it, with its ports; networks are never sources; revoke removes the arrow.
#[tokio::test]
async fn arrows_to_a_network_decide_who_reaches_it_and_go_with_its_revocation() {
    let (service, [server, router, client], pool) = mesh().await;
    let store = service.dataplane();
    owner(
        &service,
        "mesh.default.set",
        json!({"default_policy": "Deny", "expected_revision": revision(&pool).await}),
    )
    .await;
    store
        .record_routes(router, Some(&[net("192.168.1.0/24")]))
        .await
        .unwrap();
    let route = owner(
        &service,
        APPROVE,
        json!({"node_id": router.0, "network": "192.168.1.0/24", "masquerade": false}),
    )
    .await["route_id"]
        .as_u64()
        .unwrap();
    // Deny by default: approved, but nobody may reach it yet.
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
    // An arrow from the client to the network grants exactly its ports.
    let created = owner(
        &service,
        "mesh.grant.create",
        json!({"name": "client-lan", "from": {"Node": client.0}, "to": {"Network": route}, "both_ways": false, "ports": {"Ports": [{"protocol": "Tcp", "number": 5432}]}}),
    )
    .await;
    assert!(created["grant_id"].is_u64(), "{created}");
    let view = store.config(client).await.unwrap();
    assert_eq!(through(&view, router), [net("192.168.1.0/24")]);
    let outbound = &view.peers[&router].networks.through[0].outbound;
    assert!(matches!(outbound, TrafficPolicy::Ports(ports) if ports.len() == 1));
    assert_eq!(
        through(&store.config(server).await.unwrap(), router),
        [],
        "a node outside the arrow gets nothing"
    );
    let router_view = store.config(router).await.unwrap();
    assert!(router_view.peers[&client].networks.served[0].keep_source);
    // A network is never an arrow's source, and never two-way.
    for grant in [
        json!({"name": "from-lan", "from": {"Network": route}, "to": {"Node": client.0}, "both_ways": false}),
        json!({"name": "both", "from": {"Node": client.0}, "to": {"Network": route}, "both_ways": true}),
    ] {
        assert_eq!(
            service
                .execute(
                    "owner",
                    "mesh.grant.create",
                    &serde_json::to_vec(&grant).unwrap(),
                    1_000
                )
                .await,
            Err(MeshApiError::InvalidInput),
            "{grant}"
        );
    }
    // Revoking removes the arrow too, so it can never point at a later approval.
    let revoked = owner(&service, REVOKE, json!({"route_id": route})).await;
    assert_eq!(revoked["arrows_removed"], 1);
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
    let arrows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mesh_grants WHERE to_kind='network'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(arrows, 0);
}

/// The mesh revision now.
async fn revision(pool: &SqlitePool) -> i64 {
    sqlx::query_scalar("SELECT revision FROM mesh_state WHERE singleton=1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A node that cannot decode subnet routes never receives them, as client or as router.
#[tokio::test]
async fn a_node_that_does_not_understand_routes_never_receives_them() {
    let (service, [_, router, client], _pool) = mesh().await;
    let store = service.dataplane();
    store
        .record_routes(router, Some(&[net("192.168.1.0/24")]))
        .await
        .unwrap();
    owner(
        &service,
        APPROVE,
        json!({"node_id": router.0, "network": "192.168.1.0/24"}),
    )
    .await;
    // The client reinstalls an older build: its probe answer says nothing about routes.
    assert!(store.record_routes(client, None).await.unwrap());
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
    // A router that stops understanding routes stops being one.
    assert!(store.record_routes(router, None).await.unwrap());
    store.record_routes(client, Some(&[])).await.unwrap();
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);
}

/// Root on the server machine approves without a session (D400), audited as the owner via the local socket.
#[tokio::test]
async fn the_local_operator_approves_without_a_session() {
    let (service, [_, router, client], pool) = mesh().await;
    let store = service.dataplane();
    store
        .record_routes(router, Some(&[net("192.168.1.0/24")]))
        .await
        .unwrap();
    let approved = service
        .execute_local_route(
            APPROVE,
            br#"{"node_id":2,"network":"192.168.1.0/24"}"#,
            1_000,
        )
        .await
        .unwrap();
    assert_eq!(approved["state"], "approved", "{approved}");
    assert_eq!(
        through(&store.config(client).await.unwrap(), router),
        [net("192.168.1.0/24")]
    );
    // The audit names the owner and says the call came from the server machine.
    let detail: String = sqlx::query_scalar(
        "SELECT detail_json FROM mesh_audit WHERE action='mesh.route.approve' AND user_id='owner'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(detail.contains(r#""via":"local""#), "{detail}");
}

/// A declined network stops waiting and is remembered through a withdrawal and a re-advertisement; only the owner
/// declines; an approved network cannot be declined (that is a revoke); Approve still works and clears the decline.
#[tokio::test]
async fn a_declined_network_is_remembered_until_the_owner_approves_it() {
    let (service, [_, router, client], pool) = mesh().await;
    let store = service.dataplane();
    store
        .record_routes(router, Some(&[net("192.168.1.0/24")]))
        .await
        .unwrap();
    let route = owner(&service, LIST, json!({})).await["routes"][0]["route_id"]
        .as_u64()
        .unwrap();
    let denied = service
        .execute(
            "alice",
            DECLINE,
            &serde_json::to_vec(&json!({"route_id": route})).unwrap(),
            1_000,
        )
        .await;
    assert_eq!(denied, Err(MeshApiError::Denied));

    let before = revision(&pool).await;
    let declined = owner(&service, DECLINE, json!({"route_id": route})).await;
    assert_eq!(declined["state"], "declined");
    assert_eq!(
        revision(&pool).await,
        before + 1,
        "a decline is one revision"
    );
    // Declining again writes nothing.
    let again = owner(&service, DECLINE, json!({"route_id": route})).await;
    assert!(again.get("revision").is_none(), "{again}");
    assert_eq!(revision(&pool).await, before + 1);
    let listed = owner(&service, LIST, json!({})).await;
    assert_eq!(listed["routes"][0]["state"], "declined");
    assert_eq!(listed["routes"][0]["advertised"], true);
    assert!(listed["routes"][0].get("refused").is_none());

    // The machine withdraws it and advertises it again: still declined, same identity.
    store.record_routes(router, Some(&[])).await.unwrap();
    let withdrawn = owner(&service, LIST, json!({})).await;
    assert_eq!(withdrawn["routes"][0]["state"], "declined");
    assert_eq!(withdrawn["routes"][0]["advertised"], false);
    store
        .record_routes(router, Some(&[net("192.168.1.0/24")]))
        .await
        .unwrap();
    let back = owner(&service, LIST, json!({})).await;
    assert_eq!(back["routes"][0]["state"], "declined");
    assert_eq!(back["routes"][0]["route_id"].as_u64(), Some(route));
    assert_eq!(through(&store.config(client).await.unwrap(), router), []);

    // Approve still works and takes the decline back.
    let approved = owner(
        &service,
        APPROVE,
        json!({"node_id": router.0, "network": "192.168.1.0/24"}),
    )
    .await;
    assert_eq!(approved["state"], "approved");
    assert_eq!(
        through(&store.config(client).await.unwrap(), router),
        [net("192.168.1.0/24")]
    );
    let declined_at: Option<i64> =
        sqlx::query_scalar("SELECT declined_at FROM mesh_routes WHERE id=?")
            .bind(i64::try_from(route).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(declined_at, None);
    // An approved network is revoked, never declined.
    let refused = service
        .execute(
            "owner",
            DECLINE,
            &serde_json::to_vec(&json!({"route_id": route})).unwrap(),
            1_000,
        )
        .await;
    assert_eq!(refused, Err(MeshApiError::NotFound));
    // Revoke puts it back to waiting (not declined), with a new identity.
    owner(&service, REVOKE, json!({"route_id": route})).await;
    let waiting = owner(&service, LIST, json!({})).await;
    assert_eq!(waiting["routes"][0]["state"], "waiting for approval");
}
