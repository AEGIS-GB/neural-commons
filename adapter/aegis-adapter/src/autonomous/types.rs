//! Structured relay message types for mesh communication.
//!
//! These types represent the structured payloads exchanged between
//! mesh peers via the relay inbox. Each variant is tagged with a
//! `type` field for serde discriminant-based deserialization.

use serde::{Deserialize, Serialize};

/// Typed relay message payloads exchanged between mesh peers.
///
/// The body of a `RelayMessage` (from `cognitive_bridge::RelayMessage`)
/// is deserialized into this enum. Unknown or malformed bodies fall
/// back to `FreeText`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TypedRelayMessage {
    PeerStatus {
        trustmark_bp: u32,
        chain_seq: u64,
        uptime_ms: u64,
        screening: ScreeningStats,
    },
    ThreatIntel {
        pattern_type: String,
        excerpt: String,
        evidence_hash: String,
        severity_bp: u32,
    },
    KnowledgeShare {
        namespace: String,
        claim_id: String,
        content: String,
    },
    ChainVerifyRequest {
        start_seq: u64,
        end_seq: u64,
    },
    ChainVerifyResponse {
        receipts: Vec<serde_json::Value>,
    },
    VoteRequest {
        claim_id: String,
        attester_id: String,
        namespace: String,
        payload: serde_json::Value,
    },
    FreeText {
        body: String,
    },
}

/// Screening statistics snapshot for peer status broadcasts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreeningStats {
    pub screened: u64,
    pub quarantined: u64,
    pub admitted: u64,
    pub window_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_status_roundtrip() {
        let msg = TypedRelayMessage::PeerStatus {
            trustmark_bp: 8500,
            chain_seq: 42,
            uptime_ms: 3_600_000,
            screening: ScreeningStats {
                screened: 100,
                quarantined: 3,
                admitted: 97,
                window_secs: 3600,
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            TypedRelayMessage::PeerStatus { trustmark_bp, .. } => {
                assert_eq!(trustmark_bp, 8500);
            }
            _ => panic!("expected PeerStatus"),
        }
    }

    #[test]
    fn threat_intel_roundtrip() {
        let msg = TypedRelayMessage::ThreatIntel {
            pattern_type: "prompt_injection".to_string(),
            excerpt: "ignore previous instructions".to_string(),
            evidence_hash: "abc123".to_string(),
            severity_bp: 9000,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            TypedRelayMessage::ThreatIntel { severity_bp, .. } => {
                assert_eq!(severity_bp, 9000);
            }
            _ => panic!("expected ThreatIntel"),
        }
    }

    #[test]
    fn vote_request_roundtrip() {
        let msg = TypedRelayMessage::VoteRequest {
            claim_id: "claim-1".to_string(),
            attester_id: "bot-abc".to_string(),
            namespace: "b/skills".to_string(),
            payload: serde_json::json!({"content": "test"}),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            TypedRelayMessage::VoteRequest { claim_id, .. } => {
                assert_eq!(claim_id, "claim-1");
            }
            _ => panic!("expected VoteRequest"),
        }
    }

    #[test]
    fn free_text_roundtrip() {
        let msg = TypedRelayMessage::FreeText {
            body: "hello mesh".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: TypedRelayMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            TypedRelayMessage::FreeText { body } => {
                assert_eq!(body, "hello mesh");
            }
            _ => panic!("expected FreeText"),
        }
    }

    #[test]
    fn all_variants_serialize() {
        let variants: Vec<TypedRelayMessage> = vec![
            TypedRelayMessage::PeerStatus {
                trustmark_bp: 5000,
                chain_seq: 1,
                uptime_ms: 1000,
                screening: ScreeningStats {
                    screened: 0,
                    quarantined: 0,
                    admitted: 0,
                    window_secs: 0,
                },
            },
            TypedRelayMessage::ThreatIntel {
                pattern_type: "t".to_string(),
                excerpt: "e".to_string(),
                evidence_hash: "h".to_string(),
                severity_bp: 1,
            },
            TypedRelayMessage::KnowledgeShare {
                namespace: "ns".to_string(),
                claim_id: "c".to_string(),
                content: "x".to_string(),
            },
            TypedRelayMessage::ChainVerifyRequest {
                start_seq: 1,
                end_seq: 10,
            },
            TypedRelayMessage::ChainVerifyResponse {
                receipts: vec![serde_json::json!({"seq": 1})],
            },
            TypedRelayMessage::VoteRequest {
                claim_id: "c".to_string(),
                attester_id: "a".to_string(),
                namespace: "ns".to_string(),
                payload: serde_json::json!({}),
            },
            TypedRelayMessage::FreeText {
                body: "hi".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            assert!(json.contains("\"type\""), "should have type discriminant");
        }
    }
}
