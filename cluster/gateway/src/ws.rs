//! WebSocket Secure (WSS) — server-push channel to adapters (D3)
//!
//! Lifecycle:
//!   1. Adapter upgrades HTTP → WSS
//!   2. Challenge-response auth (one-time, using transport key m/44'/784'/3'/0')
//!   3. Gateway subscribes to bot-specific NATS subjects
//!   4. Messages forwarded: mesh, tier notifications, contamination alerts, config updates
//!   5. Ping/pong every 30s
//!   6. On disconnect: JetStream durable consumer queues messages
//!   7. On reconnect: adapter sends last_known_seq, replay from JetStream
//!
//! Namespace isolation: bot X's WSS receives only bot.X.> messages

// TODO: Implement WSS handler
// - upgrade_handler: HTTP → WSS upgrade with challenge-response
// - message_loop: forward NATS messages to WSS, handle ping/pong
// - reconnect: accept last_known_seq, replay from JetStream durable consumer
// - disconnect: clean up, JetStream consumer pauses (messages queue)

/// Ping/pong interval in seconds
pub const PING_INTERVAL_SECS: u64 = 30;

/// Maximum concurrent WSS connections per Gateway instance
pub const MAX_CONCURRENT_CONNECTIONS: usize = 5000;
