//! Layer 2: NATS Topology Tests (<10s)
//!
//! - Embedded NATS server (nats-server binary, ephemeral port)
//! - Verify: publish evidence.new → trustmark.updated fires
//! - Verify: publish botawiki.claim.new → quarantine.vote fires
//! - All topic pairs from D3 covered
//! - Runs: every commit to cluster/

// TODO: These tests require nats-server binary available in PATH
// or a test helper that starts an embedded NATS server.
//
// Example pattern (from plan):
//
// #[tokio::test]
// async fn evidence_new_triggers_trustmark_update() {
//     let server = start_embedded_nats().await;
//     let nc = async_nats::connect(server.addr()).await.unwrap();
//     let receipt = test_fixtures::valid_receipt();
//     nc.publish("evidence.new", receipt.to_bytes()).await.unwrap();
//     let mut sub = nc.subscribe("trustmark.updated").await.unwrap();
//     let msg = tokio::time::timeout(
//         Duration::from_millis(500), sub.next()
//     ).await.expect("trustmark.updated not received in time");
//     let score: TrustmarkScore = decode(msg.payload);
//     assert_eq!(score, TrustmarkScore::compute(&receipt));
// }
//
// Topic pairs to test (D3):
//   evidence.new          → trustmark.updated
//   botawiki.claim.new    → botawiki.quarantine.vote
//   mesh.key.update       → (key directory update)
//   broadcast.emergency   → (dashboard alert)
//   scheduler.request     → scheduler.assigned
