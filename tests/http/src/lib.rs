//! Layer 3: HTTP Contract Tests (<15s)
//!
//! - axum TestClient (no real server)
//! - Verify: Edge Gateway rejects unsigned request → 401 + receipt
//! - Verify: Botawiki read returns correct schema
//! - Verify: adapter REST client parses responses correctly
//! - Runs: every commit to cluster/ or adapter/

// TODO: Implement once gateway and botawiki routes are built
//
// Example pattern:
//
// #[tokio::test]
// async fn gateway_rejects_unsigned_request() {
//     let app = gateway::app(test_config());
//     let response = app
//         .oneshot(Request::builder()
//             .uri("/api/v1/evidence")
//             .body(Body::empty())
//             .unwrap())
//         .await
//         .unwrap();
//     assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
// }
