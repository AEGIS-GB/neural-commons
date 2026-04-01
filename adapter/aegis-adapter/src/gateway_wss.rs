//! Gateway WebSocket client -- real-time channel to the cluster Gateway.
//!
//! Connects to `ws://{gateway_url}/ws`, performs challenge-response authentication
//! using NC-Ed25519 signing, and enters a message loop that dispatches incoming
//! messages by type.
//!
//! On disconnect, auto-reconnects after 5 seconds.

use std::sync::Arc;

use aegis_crypto::ed25519::SigningKey;
use futures::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

/// Reconnection delay after disconnect.
const RECONNECT_DELAY_SECS: u64 = 5;

/// Incoming WebSocket message types from the Gateway.
#[derive(Debug, Clone, serde::Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WssMessage {
    /// Gateway challenge for authentication handshake.
    Challenge { nonce: String, ts_ms: i64 },
    /// TRUSTMARK score update for a bot.
    TrustmarkUpdate { bot_id: String, score_bp: u32 },
    /// Cluster-wide broadcast message.
    Broadcast { kind: String, message: String },
    /// Mesh relay from another adapter.
    MeshRelay { from: String, body: String },
    /// Keep-alive ping from server.
    Ping,
}

/// Authentication response sent to the Gateway after receiving a challenge.
#[derive(Debug, serde::Serialize)]
struct AuthResponse {
    #[serde(rename = "type")]
    msg_type: String,
    pubkey: String,
    sig: String,
}

/// Handler trait for processing incoming WSS messages.
/// Implemented by the adapter to wire messages to local state.
pub trait WssHandler: Send + Sync + 'static {
    /// Handle a TrustmarkUpdate message.
    fn on_trustmark_update(&self, bot_id: &str, score_bp: u32);
    /// Handle a Broadcast message.
    fn on_broadcast(&self, kind: &str, message: &str);
    /// Handle a MeshRelay message.
    fn on_mesh_relay(&self, from: &str, body: &str);
}

/// Gateway WebSocket connection manager.
///
/// Maintains a persistent connection to the Gateway's WebSocket endpoint.
/// Handles challenge-response auth, message dispatch, and auto-reconnect.
pub struct GatewayWss {
    gateway_url: String,
    signing_key: Arc<SigningKey>,
}

impl GatewayWss {
    /// Create a new WSS connection manager.
    pub fn new(gateway_url: &str, signing_key: Arc<SigningKey>) -> Self {
        Self {
            gateway_url: gateway_url.trim_end_matches('/').to_string(),
            signing_key,
        }
    }

    /// Build the WebSocket URL from the HTTP gateway URL.
    fn ws_url(&self) -> String {
        let url = self
            .gateway_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");
        format!("{}/ws", url)
    }

    /// Sign the challenge nonce+timestamp for authentication.
    fn sign_challenge(&self, nonce: &str, ts_ms: i64) -> (String, String) {
        let signing_input = serde_json::json!({
            "nonce": nonce,
            "ts_ms": ts_ms,
        });

        let canonical = aegis_crypto::rfc8785::canonicalize(&signing_input)
            .expect("failed to canonicalize challenge");

        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(&canonical);
        let pubkey_hex = aegis_crypto::ed25519::pubkey_hex(&self.signing_key.verifying_key());
        let sig_hex = hex::encode(signature.to_bytes());

        (pubkey_hex, sig_hex)
    }

    /// Attempt a single connection + message loop.
    ///
    /// Returns when the connection drops or an error occurs.
    async fn connect_and_run<H: WssHandler>(&self, handler: &H) -> Result<(), String> {
        let url = self.ws_url();
        tracing::info!(url = %url, "connecting to gateway WSS");

        let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| format!("WSS connection failed: {e}"))?;

        let (mut write, mut read) = ws_stream.split();

        // Wait for challenge message
        let challenge_msg = read
            .next()
            .await
            .ok_or_else(|| "WSS stream ended before challenge".to_string())?
            .map_err(|e| format!("WSS read error: {e}"))?;

        let challenge_text = match challenge_msg {
            Message::Text(t) => t.to_string(),
            other => return Err(format!("expected text challenge, got: {other:?}")),
        };

        let challenge: WssMessage = serde_json::from_str(&challenge_text)
            .map_err(|e| format!("failed to parse challenge: {e}"))?;

        let (nonce, ts_ms) = match challenge {
            WssMessage::Challenge { nonce, ts_ms } => (nonce, ts_ms),
            other => return Err(format!("expected Challenge, got: {other:?}")),
        };

        // Sign and respond
        let (pubkey, sig) = self.sign_challenge(&nonce, ts_ms);
        let auth_resp = AuthResponse {
            msg_type: "auth_response".to_string(),
            pubkey,
            sig,
        };
        let auth_json = serde_json::to_string(&auth_resp)
            .map_err(|e| format!("failed to serialize auth response: {e}"))?;

        write
            .send(Message::Text(auth_json.into()))
            .await
            .map_err(|e| format!("failed to send auth response: {e}"))?;

        tracing::info!("gateway WSS authenticated");

        // Message loop
        while let Some(msg_result) = read.next().await {
            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("WSS read error: {e}");
                    break;
                }
            };

            match msg {
                Message::Text(text) => match serde_json::from_str::<WssMessage>(&text) {
                    Ok(wss_msg) => {
                        dispatch_message(handler, &wss_msg);
                    }
                    Err(e) => {
                        tracing::debug!(text = %text, "WSS: ignoring unparseable message: {e}");
                    }
                },
                Message::Ping(data) => {
                    if let Err(e) = write.send(Message::Pong(data)).await {
                        tracing::warn!("WSS: failed to send pong: {e}");
                        break;
                    }
                }
                Message::Close(_) => {
                    tracing::info!("gateway WSS: received close frame");
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// Dispatch a parsed WSS message to the handler.
fn dispatch_message<H: WssHandler>(handler: &H, msg: &WssMessage) {
    match msg {
        WssMessage::TrustmarkUpdate { bot_id, score_bp } => {
            tracing::debug!(bot_id = %bot_id, score_bp, "WSS: trustmark update");
            handler.on_trustmark_update(bot_id, *score_bp);
        }
        WssMessage::Broadcast { kind, message } => {
            tracing::info!(kind = %kind, "WSS: broadcast received");
            handler.on_broadcast(kind, message);
        }
        WssMessage::MeshRelay { from, body } => {
            tracing::debug!(from = %from, "WSS: mesh relay received");
            handler.on_mesh_relay(from, body);
        }
        WssMessage::Ping => {
            tracing::trace!("WSS: application-level ping");
        }
        WssMessage::Challenge { .. } => {
            tracing::warn!("WSS: unexpected challenge message after auth");
        }
    }
}

/// Spawn a persistent WSS connection task with auto-reconnect.
///
/// On disconnect, waits 5 seconds before retrying. Runs until the tokio
/// runtime shuts down.
pub fn spawn_wss_task<H: WssHandler>(
    gateway_url: &str,
    signing_key: Arc<SigningKey>,
    handler: Arc<H>,
) {
    let wss = Arc::new(GatewayWss::new(gateway_url, signing_key));
    tokio::spawn(async move {
        loop {
            match wss.connect_and_run(handler.as_ref()).await {
                Ok(()) => {
                    tracing::info!(
                        "gateway WSS disconnected, reconnecting in {RECONNECT_DELAY_SECS}s"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "gateway WSS error, reconnecting in {RECONNECT_DELAY_SECS}s"
                    );
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(RECONNECT_DELAY_SECS)).await;
        }
    });
    tracing::info!(
        reconnect_delay_secs = RECONNECT_DELAY_SECS,
        "gateway WSS connection task started"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_crypto::ed25519::generate_keypair;

    #[test]
    fn parse_trustmark_update() {
        let json = r#"{"type":"trustmark_update","bot_id":"abc123","score_bp":8500}"#;
        let msg: WssMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            WssMessage::TrustmarkUpdate {
                bot_id: "abc123".to_string(),
                score_bp: 8500,
            }
        );
    }

    #[test]
    fn parse_broadcast() {
        let json = r#"{"type":"broadcast","kind":"announcement","message":"hello cluster"}"#;
        let msg: WssMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            WssMessage::Broadcast {
                kind: "announcement".to_string(),
                message: "hello cluster".to_string(),
            }
        );
    }

    #[test]
    fn parse_mesh_relay() {
        let json = r#"{"type":"mesh_relay","from":"peer-abc","body":"{\"data\":1}"}"#;
        let msg: WssMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            WssMessage::MeshRelay {
                from: "peer-abc".to_string(),
                body: "{\"data\":1}".to_string(),
            }
        );
    }

    #[test]
    fn parse_ping() {
        let json = r#"{"type":"ping"}"#;
        let msg: WssMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg, WssMessage::Ping);
    }

    #[test]
    fn parse_challenge() {
        let json = r#"{"type":"challenge","nonce":"abc123def","ts_ms":1700000000000}"#;
        let msg: WssMessage = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            WssMessage::Challenge {
                nonce: "abc123def".to_string(),
                ts_ms: 1700000000000,
            }
        );
    }

    #[test]
    fn sign_challenge_produces_valid_output() {
        let key = generate_keypair();
        let wss = GatewayWss::new("http://localhost:8080", Arc::new(key));

        let (pubkey, sig) = wss.sign_challenge("test-nonce", 1700000000000);

        assert_eq!(pubkey.len(), 64, "pubkey should be 32 bytes hex");
        assert_eq!(sig.len(), 128, "signature should be 64 bytes hex");
    }

    #[test]
    fn ws_url_construction() {
        let key = generate_keypair();

        let wss = GatewayWss::new("http://localhost:8080", Arc::new(key));
        assert_eq!(wss.ws_url(), "ws://localhost:8080/ws");

        let key2 = generate_keypair();
        let wss2 = GatewayWss::new("https://gateway.example.com", Arc::new(key2));
        assert_eq!(wss2.ws_url(), "wss://gateway.example.com/ws");

        let key3 = generate_keypair();
        let wss3 = GatewayWss::new("http://localhost:8080/", Arc::new(key3));
        assert_eq!(wss3.ws_url(), "ws://localhost:8080/ws");
    }

    /// Test handler that records received messages.
    struct TestHandler {
        trustmark_updates: std::sync::Mutex<Vec<(String, u32)>>,
        broadcasts: std::sync::Mutex<Vec<(String, String)>>,
        mesh_relays: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                trustmark_updates: std::sync::Mutex::new(Vec::new()),
                broadcasts: std::sync::Mutex::new(Vec::new()),
                mesh_relays: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl WssHandler for TestHandler {
        fn on_trustmark_update(&self, bot_id: &str, score_bp: u32) {
            self.trustmark_updates
                .lock()
                .unwrap()
                .push((bot_id.to_string(), score_bp));
        }
        fn on_broadcast(&self, kind: &str, message: &str) {
            self.broadcasts
                .lock()
                .unwrap()
                .push((kind.to_string(), message.to_string()));
        }
        fn on_mesh_relay(&self, from: &str, body: &str) {
            self.mesh_relays
                .lock()
                .unwrap()
                .push((from.to_string(), body.to_string()));
        }
    }

    #[test]
    fn dispatch_trustmark_update() {
        let handler = TestHandler::new();
        let msg = WssMessage::TrustmarkUpdate {
            bot_id: "bot1".to_string(),
            score_bp: 9000,
        };
        dispatch_message(&handler, &msg);
        let updates = handler.trustmark_updates.lock().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0], ("bot1".to_string(), 9000));
    }

    #[test]
    fn dispatch_broadcast() {
        let handler = TestHandler::new();
        let msg = WssMessage::Broadcast {
            kind: "alert".to_string(),
            message: "test alert".to_string(),
        };
        dispatch_message(&handler, &msg);
        let broadcasts = handler.broadcasts.lock().unwrap();
        assert_eq!(broadcasts.len(), 1);
        assert_eq!(
            broadcasts[0],
            ("alert".to_string(), "test alert".to_string())
        );
    }

    #[test]
    fn dispatch_mesh_relay() {
        let handler = TestHandler::new();
        let msg = WssMessage::MeshRelay {
            from: "peer-1".to_string(),
            body: "relay data".to_string(),
        };
        dispatch_message(&handler, &msg);
        let relays = handler.mesh_relays.lock().unwrap();
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0], ("peer-1".to_string(), "relay data".to_string()));
    }
}
