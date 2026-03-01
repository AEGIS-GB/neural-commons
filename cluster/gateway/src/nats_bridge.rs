//! NATS Bridge — translates HTTP/WSS to internal NATS (D3)
//!
//! Edge Gateway is the SOLE adapter-facing entry point.
//! NATS is internal only — adapters never touch it directly.
//!
//! Translation:
//!   HTTP POST /evidence → NATS publish evidence.new
//!   HTTP POST /rollup → NATS publish evidence.rollup
//!   NATS trustmark.updated → WSS push to bot
//!   NATS broadcast.* → WSS push to all connected bots

// TODO: Implement NATS bridge
// - publish_evidence(receipt_core) → evidence.new
// - publish_rollup(rollup) → evidence.rollup
// - subscribe_for_bot(bot_id) → bot.{bot_id}.>, trustmark.updated, broadcast.*
// - create_durable_consumer(bot_id) → JetStream durable consumer for offline replay
