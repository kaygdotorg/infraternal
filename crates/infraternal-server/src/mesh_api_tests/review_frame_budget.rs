//! Independent D170-scale check of the <=64 KiB Mesh frame requirement recorded on #108.
use super::*;

#[tokio::test]
async fn review_mesh_design_point_frames_fit_shared_socket_budget() {
    const MESH_FRAME_BUDGET: usize = 64 * 1024;
    let fixture = Fixture::new().await;
    seed_scale_inventory(&fixture).await;
    let snapshot = fixture
        .service
        .list(OWNER, MeshFilter::default(), NOW)
        .await
        .unwrap();
    let inventory_json = serde_json::to_vec(&snapshot).unwrap();
    let event_json = serde_json::to_vec(&json!({"type":"snapshot","snapshot":snapshot})).unwrap();
    let mut result = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Result {
            call_id: 1,
            ok: true,
            json: &inventory_json,
        },
        &mut result,
    )
    .unwrap();
    let mut event = Vec::new();
    encode_muxed_frame_into(
        0,
        &Frame::Event {
            sub_id: 1,
            event_json: &event_json,
        },
        &mut event,
    )
    .unwrap();
    println!(
        "nodes=1000 tags=100 grants=3000 memberships=10000 result_bytes={} event_bytes={} mesh_frame_budget={MESH_FRAME_BUDGET}",
        result.len(),
        event.len()
    );
    fixture.cleanup().await;
    // Framing is checked at the production encoder, including mux and frame
    // headers. A legal protocol maximum is not the shared-socket scheduling budget.
    assert!(
        result.len() <= MESH_FRAME_BUDGET,
        "Mesh Result exceeds shared-socket budget"
    );
    assert!(
        event.len() <= MESH_FRAME_BUDGET,
        "Mesh Event exceeds shared-socket budget"
    );
}
