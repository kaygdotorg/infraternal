//! Removal's uninstall request reaches the connected infraternal agent (#409, #235).
//!
//! Remove asks the host's infraternal agent to uninstall itself with one
//! control call, `remote.host.uninstall`, on the agent's authenticated control
//! stream. These tests use real TLS, the production router and a real enrolled
//! certificate, and play the agent's side of the stream by hand. That way they
//! check what the server writes on the wire, not what it means to write.
//!
//! The regression they pin: the server's actor kept an allow-list of control
//! actions it would send, and the list held only the certificate actions, so
//! every uninstall was refused inside the server and never sent. Remove then
//! reported "unreachable", cut the link and left the agent running.
use super::*;

/// Connects as the enrolled host with `caps` in its Hello, and waits until the
/// server has registered the live link, so a control call can be routed to it.
async fn connected(
    fixture: &Fixture,
    identity: &infraternal_agent::remote_tls::Identity,
    host: uuid::Uuid,
    caps: u64,
) -> (
    infraternal_agent::remote_tls::Connection,
    infraternal_agent::transport::Receive,
) {
    use infraternal_agent::{
        remote_tls,
        transport::{Receive, Transmit},
    };
    let config = remote_tls::client_config(identity, std::slice::from_ref(&fixture.root)).unwrap();
    let connection = remote_tls::dial(
        fixture.listeners.as_ref().unwrap().local_addr().unwrap(),
        "localhost",
        &config,
    )
    .await
    .unwrap();
    Transmit::default()
        .send(
            &connection.channel,
            0,
            &Frame::Hello {
                version: 1,
                caps,
                client_info: "uninstall delivery regression",
            },
        )
        .await
        .unwrap();
    let mut receive = Receive::default();
    assert!(matches!(
        receive.next(&connection.channel).await.unwrap().frame,
        Frame::Hello { .. }
    ));
    let hosts = &fixture.listeners.as_ref().unwrap().diagnostic_hosts;
    tokio::time::timeout(Duration::from_secs(5), async {
        while hosts.actor(host).await.is_none() {
            // sleep: the link registers just after its Hello reply; poll the registry briefly.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the server never registered the live link");
    (connection, receive)
}

/// Removal's uninstall request is written on the live control stream, with
/// exactly this host's id and no dry run, and the agent's acceptance comes
/// back to the removal as `requested`, with the kernel objects it leaves.
///
/// The agent here offers no certificate renewal in its Hello: an uninstall
/// must not depend on any optional link capability.
#[tokio::test]
async fn removal_uninstall_reaches_the_connected_agent() {
    use infraternal_agent::transport::Transmit;
    let directory = Directory::new();
    let fixture = fixture_at(
        &directory,
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let (host, identity) = super::renewal::enrolled_at_half_life(&fixture).await;
    let (connection, mut receive) = connected(&fixture, &identity, host, 0).await;
    let hosts = fixture.listeners.as_ref().unwrap().diagnostic_hosts.clone();
    let removal =
        tokio::spawn(async move { crate::remote_removal::request_uninstall(&hosts, host).await });
    // Skip anything else the server sends first (a session census, for
    // example) until the uninstall call arrives.
    let (call_id, input) = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let decoded = receive.next(&connection.channel).await.unwrap();
            if let Frame::Call {
                call_id,
                action_id,
                input_json,
            } = decoded.frame
                && action_id == infraternal_plugin_remote::UNINSTALL.id
            {
                assert_eq!(
                    decoded.stream_id, 0,
                    "uninstall must use the control stream"
                );
                break (call_id, input_json.to_vec());
            }
        }
    })
    .await
    .expect("the server never sent the uninstall request to the connected agent");
    let input: serde_json::Value = serde_json::from_slice(&input).unwrap();
    assert_eq!(
        input,
        serde_json::json!({"host": host.simple().to_string(), "dry_run": false})
    );
    Transmit::default()
        .send(
            &connection.channel,
            0,
            &Frame::Result {
                call_id,
                ok: true,
                json: br#"{"state":"accepted","cleanup":"pending","left":["infraternal0"]}"#,
            },
        )
        .await
        .unwrap();
    let (cleanup, left) = tokio::time::timeout(Duration::from_secs(3), removal)
        .await
        .expect("removal did not finish after the agent accepted")
        .unwrap();
    assert_eq!(cleanup, "requested");
    assert_eq!(left, ["infraternal0"]);
}
