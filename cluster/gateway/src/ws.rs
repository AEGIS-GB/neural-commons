//! WebSocket Secure (WSS) — server-push channel to adapters (D3)
//!
//! Lifecycle:
//!   1. Adapter upgrades HTTP → WSS
//!   2. Challenge-response auth (one-time, using transport key m/44'/784'/3'/0')
//!   3. Gateway forwards mesh relay messages to authenticated bot
//!   4. Ping/pong every 30s
//!   5. On disconnect: unregister from connection registry
//!   6. On reconnect: deliver pending dead-drops
//!
//! Namespace isolation: bot X's WSS receives only bot.X.> messages

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::response::IntoResponse;
use ed25519_dalek::Verifier;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn};

use crate::auth::{WssChallenge, WssChallengeResponse};

/// Ping/pong interval in seconds
pub const PING_INTERVAL_SECS: u64 = 30;

/// Maximum concurrent WSS connections per Gateway instance
pub const MAX_CONCURRENT_CONNECTIONS: usize = 5000;

/// Timeout for challenge-response auth (seconds)
pub const AUTH_TIMEOUT_SECS: u64 = 10;

/// Gateway shared state for WSS routes.
/// Passed via axum State extractor.
pub struct GatewayWsState {
    pub wss_registry: Arc<WssConnectionRegistry>,
}

/// Registry of active WSS connections, keyed by bot_id (pubkey hex).
/// Each entry holds an mpsc::Sender that forwards messages to the bot's WebSocket.
pub struct WssConnectionRegistry {
    connections: RwLock<HashMap<String, mpsc::Sender<String>>>,
}

impl WssConnectionRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
        }
    }

    /// Register a bot's WebSocket connection.
    pub async fn register(&self, bot_id: &str, sender: mpsc::Sender<String>) {
        self.connections
            .write()
            .await
            .insert(bot_id.to_string(), sender);
        info!(bot_id, "WSS connection registered");
    }

    /// Unregister a bot's WebSocket connection.
    pub async fn unregister(&self, bot_id: &str) {
        self.connections.write().await.remove(bot_id);
        info!(bot_id, "WSS connection unregistered");
    }

    /// Check if a bot has an active WSS connection.
    pub async fn is_online(&self, bot_id: &str) -> bool {
        self.connections.read().await.contains_key(bot_id)
    }

    /// Send a message to a connected bot. Returns true if sent successfully.
    pub async fn send_to(&self, bot_id: &str, msg: &str) -> bool {
        let connections = self.connections.read().await;
        if let Some(sender) = connections.get(bot_id) {
            sender.send(msg.to_string()).await.is_ok()
        } else {
            false
        }
    }

    /// Return the number of active connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Return a list of all connected bot IDs.
    pub async fn list_peers(&self) -> Vec<String> {
        self.connections.read().await.keys().cloned().collect()
    }
}

/// GET /ws — WebSocket upgrade with challenge-response auth.
pub async fn ws_upgrade(
    ws: WebSocketUpgrade,
    State(state): State<Arc<GatewayWsState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

/// Handle an upgraded WebSocket connection.
///
/// 1. Send challenge: {"nonce": "<random_hex>", "ts_ms": <i64>}
/// 2. Wait for response: {"pubkey": "<hex>", "sig": "<hex>"}
/// 3. Verify signature over JCS({nonce, ts_ms})
/// 4. Register connection in WssConnectionRegistry
/// 5. Enter message forwarding loop
/// 6. On disconnect: unregister
async fn handle_ws(socket: WebSocket, state: Arc<GatewayWsState>) {
    let (mut sender, mut receiver) = socket.split();

    // 1. Generate and send challenge
    let nonce = generate_nonce();
    let ts_ms = now_epoch_ms();
    let challenge = WssChallenge {
        nonce: nonce.clone(),
        ts_ms,
    };
    let challenge_json = match serde_json::to_string(&challenge) {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "failed to serialize WSS challenge");
            return;
        }
    };
    if sender
        .send(Message::Text(challenge_json.into()))
        .await
        .is_err()
    {
        warn!("failed to send WSS challenge");
        return;
    }

    // 2. Wait for challenge response with timeout
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
        receiver.next(),
    )
    .await;

    let bot_id = match response {
        Ok(Some(Ok(Message::Text(text)))) => {
            match verify_challenge_response(&text, &nonce, ts_ms) {
                Ok(pubkey) => pubkey,
                Err(e) => {
                    warn!(error = %e, "WSS challenge-response verification failed");
                    let _ = sender
                        .send(Message::Text(
                            serde_json::json!({"error": e}).to_string().into(),
                        ))
                        .await;
                    return;
                }
            }
        }
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
            info!("WSS client disconnected during auth");
            return;
        }
        Ok(Some(Err(e))) => {
            warn!(error = %e, "WSS receive error during auth");
            return;
        }
        Ok(Some(Ok(_))) => {
            warn!("unexpected message type during WSS auth");
            return;
        }
        Err(_) => {
            warn!("WSS challenge-response timed out");
            return;
        }
    };

    // 3. Send auth success
    let _ = sender
        .send(Message::Text(
            serde_json::json!({"status": "authenticated", "bot_id": &bot_id})
                .to_string()
                .into(),
        ))
        .await;

    // 4. Register connection with mpsc channel for message forwarding
    let (msg_tx, mut msg_rx) = mpsc::channel::<String>(256);
    state.wss_registry.register(&bot_id, msg_tx).await;

    info!(bot_id = %bot_id, "WSS authenticated and registered");

    // 5. Message forwarding loop
    // Forward messages from the registry channel to the WebSocket
    let forward_task = tokio::spawn(async move {
        forward_messages(&mut sender, &mut msg_rx).await;
    });

    // Read loop: handle incoming messages from the bot (ping/pong, etc.)
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Close(_)) => break,
            Ok(Message::Ping(data)) => {
                // Pong is handled automatically by axum's WebSocket
                let _ = data; // consume
            }
            Ok(Message::Text(_)) => {
                // Client-initiated messages are not used in this direction
                // (bots send via POST /mesh/send, not via WSS)
            }
            Err(e) => {
                warn!(bot_id = %bot_id, error = %e, "WSS receive error");
                break;
            }
            _ => {}
        }
    }

    // 6. Cleanup
    state.wss_registry.unregister(&bot_id).await;
    forward_task.abort();
    info!(bot_id = %bot_id, "WSS connection closed");
}

/// Forward messages from the mpsc channel to the WebSocket sender.
async fn forward_messages(
    sender: &mut SplitSink<WebSocket, Message>,
    msg_rx: &mut mpsc::Receiver<String>,
) {
    while let Some(msg) = msg_rx.recv().await {
        if sender.send(Message::Text(msg.into())).await.is_err() {
            break;
        }
    }
}

/// Verify the challenge-response from a bot.
/// Returns the bot_id (pubkey hex) on success.
fn verify_challenge_response(
    response_text: &str,
    expected_nonce: &str,
    expected_ts_ms: i64,
) -> Result<String, String> {
    let response: WssChallengeResponse =
        serde_json::from_str(response_text).map_err(|e| format!("invalid response JSON: {e}"))?;

    // Parse pubkey
    let pubkey_bytes =
        hex::decode(&response.pubkey).map_err(|e| format!("invalid pubkey hex: {e}"))?;
    let pubkey_array: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_array)
        .map_err(|e| format!("invalid Ed25519 key: {e}"))?;

    // Parse signature
    let sig_bytes = hex::decode(&response.sig).map_err(|e| format!("invalid sig hex: {e}"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "sig must be 64 bytes".to_string())?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    // Build challenge payload and canonicalize
    let challenge = WssChallenge {
        nonce: expected_nonce.to_string(),
        ts_ms: expected_ts_ms,
    };
    let canonical = aegis_crypto::canonicalize(&challenge)
        .map_err(|e| format!("canonicalization failed: {e}"))?;

    // Verify signature
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| "signature verification failed".to_string())?;

    Ok(response.pubkey)
}

/// Generate a random 32-byte hex nonce.
fn generate_nonce() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Current Unix epoch milliseconds.
fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// Relay message envelope sent to bots via WSS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEnvelope {
    /// Sender bot_id (pubkey hex)
    pub from: String,
    /// Message content
    pub body: String,
    /// Message type
    pub msg_type: String,
    /// Timestamp (epoch ms)
    pub ts_ms: i64,
}

/// Dead-drop TTL: 72 hours in milliseconds (D25).
pub const DEAD_DROP_TTL_MS: i64 = 72 * 60 * 60 * 1000;

/// Maximum dead-drops per identity (D25).
pub const MAX_DEAD_DROPS_PER_IDENTITY: usize = 500;

/// Summary of dead-drop queue state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDropSummary {
    pub total: usize,
    pub recipients_count: usize,
    pub recipients: Vec<DeadDropRecipient>,
}

/// Per-recipient dead-drop queue info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDropRecipient {
    pub bot_id: String,
    pub count: usize,
    pub oldest_age_ms: Option<i64>,
}

/// A queued message for an offline bot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadDrop {
    /// Sender bot_id (pubkey hex)
    pub from: String,
    /// Message content
    pub body: String,
    /// Message type
    pub msg_type: String,
    /// Timestamp when stored (epoch ms)
    pub ts_ms: i64,
    /// Expiry timestamp (epoch ms): ts_ms + 72h
    pub expires_ms: i64,
}

/// In-memory dead-drop store for offline bot message queuing.
///
/// Messages are stored until the recipient connects via WSS, at which point
/// they are drained and delivered. Expired messages (>72h) are cleaned up
/// periodically. Each identity is limited to 500 queued messages (D25).
pub struct DeadDropStore {
    drops: RwLock<HashMap<String, Vec<DeadDrop>>>,
    max_per_identity: usize,
}

impl DeadDropStore {
    /// Create a new dead-drop store with the default 500-per-identity limit.
    pub fn new() -> Self {
        Self {
            drops: RwLock::new(HashMap::new()),
            max_per_identity: MAX_DEAD_DROPS_PER_IDENTITY,
        }
    }

    /// Store a dead-drop message for an offline recipient.
    /// Returns an error if the recipient's queue exceeds the per-identity limit.
    pub async fn store(
        &self,
        to: &str,
        from: &str,
        body: &str,
        msg_type: &str,
    ) -> Result<(), String> {
        let mut drops = self.drops.write().await;
        let queue = drops.entry(to.to_string()).or_default();
        if queue.len() >= self.max_per_identity {
            return Err(format!(
                "dead-drop quota exceeded ({} max)",
                self.max_per_identity
            ));
        }
        let ts_ms = now_epoch_ms();
        queue.push(DeadDrop {
            from: from.to_string(),
            body: body.to_string(),
            msg_type: msg_type.to_string(),
            ts_ms,
            expires_ms: ts_ms + DEAD_DROP_TTL_MS,
        });
        Ok(())
    }

    /// Drain all pending dead-drops for a recipient (on WSS connect).
    /// Returns the messages and removes them from the store.
    pub async fn drain(&self, bot_id: &str) -> Vec<DeadDrop> {
        let mut drops = self.drops.write().await;
        let now = now_epoch_ms();
        drops
            .remove(bot_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|d| d.expires_ms > now) // skip expired
            .collect()
    }

    /// Remove all expired dead-drops (>72h TTL) across all identities.
    pub async fn cleanup_expired(&self) {
        let now = now_epoch_ms();
        let mut drops = self.drops.write().await;
        for queue in drops.values_mut() {
            queue.retain(|d| d.expires_ms > now);
        }
        // Remove empty queues
        drops.retain(|_, q| !q.is_empty());
    }

    /// Return the count of pending dead-drops for a specific recipient.
    pub async fn count_for(&self, bot_id: &str) -> usize {
        let drops = self.drops.read().await;
        drops.get(bot_id).map(|q| q.len()).unwrap_or(0)
    }

    /// Return the total count of all dead-drops across all identities.
    pub async fn total_count(&self) -> usize {
        let drops = self.drops.read().await;
        drops.values().map(|q| q.len()).sum()
    }

    /// Return all non-expired dead-drops for a specific bot.
    pub async fn get_for_bot(&self, bot_id: &str) -> Vec<DeadDrop> {
        let drops = self.drops.read().await;
        let now = now_epoch_ms();
        drops
            .get(bot_id)
            .map(|q| q.iter().filter(|d| d.expires_ms > now).cloned().collect())
            .unwrap_or_default()
    }

    /// Return a summary of all dead-drop queues.
    pub async fn summary(&self) -> DeadDropSummary {
        let drops = self.drops.read().await;
        let now = now_epoch_ms();
        let mut recipients = Vec::new();
        let mut total = 0usize;

        for (bot_id, queue) in drops.iter() {
            let count = queue.len();
            total += count;
            let oldest_age_ms = queue.iter().map(|d| now - d.ts_ms).max();
            recipients.push(DeadDropRecipient {
                bot_id: bot_id.clone(),
                count,
                oldest_age_ms,
            });
        }

        DeadDropSummary {
            total,
            recipients_count: recipients.len(),
            recipients,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[tokio::test]
    async fn registry_register_and_check_online() {
        let registry = WssConnectionRegistry::new();
        let (tx, _rx) = mpsc::channel(16);
        registry.register("bot_aaa", tx).await;
        assert!(registry.is_online("bot_aaa").await);
        assert!(!registry.is_online("bot_bbb").await);
    }

    #[tokio::test]
    async fn registry_unregister_removes_connection() {
        let registry = WssConnectionRegistry::new();
        let (tx, _rx) = mpsc::channel(16);
        registry.register("bot_aaa", tx).await;
        assert!(registry.is_online("bot_aaa").await);
        registry.unregister("bot_aaa").await;
        assert!(!registry.is_online("bot_aaa").await);
    }

    #[tokio::test]
    async fn registry_send_to_connected_bot() {
        let registry = WssConnectionRegistry::new();
        let (tx, mut rx) = mpsc::channel(16);
        registry.register("bot_aaa", tx).await;

        let sent = registry.send_to("bot_aaa", "hello bot").await;
        assert!(sent);

        let received = rx.recv().await.unwrap();
        assert_eq!(received, "hello bot");
    }

    #[tokio::test]
    async fn registry_send_to_offline_bot_returns_false() {
        let registry = WssConnectionRegistry::new();
        let sent = registry.send_to("nonexistent", "hello").await;
        assert!(!sent);
    }

    #[tokio::test]
    async fn registry_connection_count() {
        let registry = WssConnectionRegistry::new();
        assert_eq!(registry.connection_count().await, 0);

        let (tx1, _rx1) = mpsc::channel(16);
        registry.register("bot_1", tx1).await;
        assert_eq!(registry.connection_count().await, 1);

        let (tx2, _rx2) = mpsc::channel(16);
        registry.register("bot_2", tx2).await;
        assert_eq!(registry.connection_count().await, 2);

        registry.unregister("bot_1").await;
        assert_eq!(registry.connection_count().await, 1);
    }

    #[tokio::test]
    async fn registry_reregister_replaces_connection() {
        let registry = WssConnectionRegistry::new();
        let (tx1, _rx1) = mpsc::channel(16);
        registry.register("bot_aaa", tx1).await;

        let (tx2, mut rx2) = mpsc::channel(16);
        registry.register("bot_aaa", tx2).await;

        // Old channel should be replaced
        assert_eq!(registry.connection_count().await, 1);

        // Messages go to new channel
        let sent = registry.send_to("bot_aaa", "new channel").await;
        assert!(sent);
        let msg = rx2.recv().await.unwrap();
        assert_eq!(msg, "new channel");
    }

    #[test]
    fn verify_challenge_response_valid_signature() {
        let sk = aegis_crypto::ed25519::generate_keypair();
        let nonce = generate_nonce();
        let ts_ms = now_epoch_ms();

        // Build challenge and sign it
        let challenge = WssChallenge {
            nonce: nonce.clone(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&challenge).unwrap();
        let sig = sk.sign(&canonical);

        let response = WssChallengeResponse {
            pubkey: hex::encode(sk.verifying_key().as_bytes()),
            sig: hex::encode(sig.to_bytes()),
        };
        let response_json = serde_json::to_string(&response).unwrap();

        let result = verify_challenge_response(&response_json, &nonce, ts_ms);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), hex::encode(sk.verifying_key().as_bytes()));
    }

    #[test]
    fn verify_challenge_response_wrong_nonce_fails() {
        let sk = aegis_crypto::ed25519::generate_keypair();
        let nonce = generate_nonce();
        let ts_ms = now_epoch_ms();

        let challenge = WssChallenge {
            nonce: nonce.clone(),
            ts_ms,
        };
        let canonical = aegis_crypto::canonicalize(&challenge).unwrap();
        let sig = sk.sign(&canonical);

        let response = WssChallengeResponse {
            pubkey: hex::encode(sk.verifying_key().as_bytes()),
            sig: hex::encode(sig.to_bytes()),
        };
        let response_json = serde_json::to_string(&response).unwrap();

        // Verify with different nonce
        let result = verify_challenge_response(&response_json, "wrong_nonce", ts_ms);
        assert!(result.is_err());
    }

    #[test]
    fn verify_challenge_response_invalid_json_fails() {
        let result = verify_challenge_response("not json", "nonce", 12345);
        assert!(result.is_err());
    }

    #[test]
    fn relay_envelope_serialization() {
        let envelope = RelayEnvelope {
            from: "abc123".to_string(),
            body: "hello world".to_string(),
            msg_type: "relay".to_string(),
            ts_ms: 1700000000000,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: RelayEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.from, "abc123");
        assert_eq!(parsed.body, "hello world");
        assert_eq!(parsed.msg_type, "relay");
    }

    // ── Dead-drop tests ──

    #[tokio::test]
    async fn dead_drop_store_and_drain() {
        let store = DeadDropStore::new();
        store
            .store("bot_b", "bot_a", "hello offline", "relay")
            .await
            .unwrap();
        store
            .store("bot_b", "bot_a", "second message", "relay")
            .await
            .unwrap();

        assert_eq!(store.count_for("bot_b").await, 2);
        assert_eq!(store.count_for("bot_a").await, 0);

        let messages = store.drain("bot_b").await;
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].body, "hello offline");
        assert_eq!(messages[1].body, "second message");

        // After drain, queue is empty
        assert_eq!(store.count_for("bot_b").await, 0);
    }

    #[tokio::test]
    async fn dead_drop_quota_enforced() {
        let store = DeadDropStore {
            drops: RwLock::new(HashMap::new()),
            max_per_identity: 3, // Small limit for testing
        };

        for i in 0..3 {
            store
                .store("bot_b", "bot_a", &format!("msg {i}"), "relay")
                .await
                .unwrap();
        }

        // 4th message should fail
        let result = store.store("bot_b", "bot_a", "msg 3", "relay").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("quota exceeded"));
    }

    #[tokio::test]
    async fn dead_drop_500_limit() {
        let store = DeadDropStore::new();

        // Fill to exactly 500
        for i in 0..500 {
            store
                .store("target_bot", "sender", &format!("msg {i}"), "relay")
                .await
                .unwrap();
        }

        // 501st should fail
        let result = store
            .store("target_bot", "sender", "msg 500", "relay")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("500 max"));
    }

    #[tokio::test]
    async fn dead_drop_expired_messages_cleaned_up() {
        let store = DeadDropStore::new();

        // Insert a message, then manually set it as expired
        store
            .store("bot_b", "bot_a", "expired msg", "relay")
            .await
            .unwrap();

        // Manually expire the message by adjusting expires_ms
        {
            let mut drops = store.drops.write().await;
            let queue = drops.get_mut("bot_b").unwrap();
            queue[0].expires_ms = now_epoch_ms() - 1000; // expired 1s ago
        }

        store.cleanup_expired().await;
        assert_eq!(store.count_for("bot_b").await, 0);
        assert_eq!(store.total_count().await, 0);
    }

    #[tokio::test]
    async fn dead_drop_drain_skips_expired() {
        let store = DeadDropStore::new();

        store
            .store("bot_b", "bot_a", "valid msg", "relay")
            .await
            .unwrap();
        store
            .store("bot_b", "bot_a", "expired msg", "relay")
            .await
            .unwrap();

        // Expire the second message
        {
            let mut drops = store.drops.write().await;
            let queue = drops.get_mut("bot_b").unwrap();
            queue[1].expires_ms = now_epoch_ms() - 1000;
        }

        let messages = store.drain("bot_b").await;
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, "valid msg");
    }

    #[tokio::test]
    async fn dead_drop_ttl_is_72h() {
        let store = DeadDropStore::new();
        store
            .store("bot_b", "bot_a", "test", "relay")
            .await
            .unwrap();

        let drops = store.drops.read().await;
        let queue = drops.get("bot_b").unwrap();
        let drop = &queue[0];
        let expected_ttl = DEAD_DROP_TTL_MS;
        let actual_ttl = drop.expires_ms - drop.ts_ms;
        assert_eq!(actual_ttl, expected_ttl);
    }

    #[tokio::test]
    async fn dead_drop_total_count() {
        let store = DeadDropStore::new();
        store.store("a", "x", "m1", "relay").await.unwrap();
        store.store("b", "x", "m2", "relay").await.unwrap();
        store.store("b", "x", "m3", "relay").await.unwrap();
        assert_eq!(store.total_count().await, 3);
    }

    #[tokio::test]
    async fn registry_list_peers() {
        let registry = WssConnectionRegistry::new();
        let (tx1, _rx1) = mpsc::channel(16);
        let (tx2, _rx2) = mpsc::channel(16);
        registry.register("bot_a", tx1).await;
        registry.register("bot_b", tx2).await;

        let mut peers = registry.list_peers().await;
        peers.sort();
        assert_eq!(peers, vec!["bot_a".to_string(), "bot_b".to_string()]);
    }

    #[tokio::test]
    async fn dead_drop_summary() {
        let store = DeadDropStore::new();
        store.store("bot_a", "x", "m1", "relay").await.unwrap();
        store.store("bot_a", "x", "m2", "relay").await.unwrap();
        store.store("bot_b", "x", "m3", "relay").await.unwrap();

        let summary = store.summary().await;
        assert_eq!(summary.total, 3);
        assert_eq!(summary.recipients_count, 2);

        let a = summary
            .recipients
            .iter()
            .find(|r| r.bot_id == "bot_a")
            .unwrap();
        assert_eq!(a.count, 2);
        assert!(a.oldest_age_ms.is_some());

        let b = summary
            .recipients
            .iter()
            .find(|r| r.bot_id == "bot_b")
            .unwrap();
        assert_eq!(b.count, 1);
    }

    #[tokio::test]
    async fn dead_drop_get_for_bot() {
        let store = DeadDropStore::new();
        store.store("bot_a", "x", "m1", "relay").await.unwrap();
        store.store("bot_a", "y", "m2", "ping").await.unwrap();
        store.store("bot_b", "x", "m3", "relay").await.unwrap();

        let result = store.get_for_bot("bot_a").await;
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].body, "m1");
        assert_eq!(result[1].body, "m2");

        let result_b = store.get_for_bot("bot_b").await;
        assert_eq!(result_b.len(), 1);

        let result_c = store.get_for_bot("nonexistent").await;
        assert_eq!(result_c.len(), 0);
    }

    #[tokio::test]
    async fn dead_drop_get_for_bot_skips_expired() {
        let store = DeadDropStore::new();
        store.store("bot_a", "x", "valid", "relay").await.unwrap();
        store.store("bot_a", "y", "expired", "relay").await.unwrap();

        // Expire the second message
        {
            let mut drops = store.drops.write().await;
            let queue = drops.get_mut("bot_a").unwrap();
            queue[1].expires_ms = now_epoch_ms() - 1000;
        }

        let result = store.get_for_bot("bot_a").await;
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].body, "valid");
    }

    #[tokio::test]
    async fn dead_drop_serialization() {
        let drop = DeadDrop {
            from: "sender".to_string(),
            body: "hello".to_string(),
            msg_type: "relay".to_string(),
            ts_ms: 1700000000000,
            expires_ms: 1700000000000 + DEAD_DROP_TTL_MS,
        };
        let json = serde_json::to_string(&drop).unwrap();
        let parsed: DeadDrop = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.from, "sender");
        assert_eq!(parsed.body, "hello");
        assert_eq!(parsed.expires_ms, 1700000000000 + DEAD_DROP_TTL_MS);
    }
}
