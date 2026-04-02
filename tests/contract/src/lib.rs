//! Layer 1: Schema Contract Tests (<30s)
//!
//! D1/D2 compliant: ReceiptCore + ReceiptContext, basis points, no floats,
//! all binary fields lowercase hex, optional fields omitted not null.
//! Runs: every commit, both workspaces.

#[cfg(test)]
mod receipt_tests {
    use aegis_crypto::rfc8785;
    use aegis_schemas::receipt::{
        EnterpriseContext, GENESIS_PREV_HASH, Receipt, ReceiptContext, ReceiptCore, ReceiptType,
        RollupDetail, RollupHistogram, generate_blinding_nonce,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    fn sample_receipt_core() -> ReceiptCore {
        ReceiptCore {
            id: Uuid::now_v7(),
            bot_id: "a".repeat(64), // lowercase hex pubkey
            receipt_type: ReceiptType::ApiCall,
            ts_ms: 1740000000000,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            payload_hash: "b".repeat(64),
            seq: 1,
            sig: "c".repeat(128), // lowercase hex signature
        }
    }

    fn sample_receipt_context() -> ReceiptContext {
        ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: Some("api_call".to_string()),
            subject: Some("openai-chat".to_string()),
            trigger: None,
            outcome: Some("success".to_string()),
            detail: Some(serde_json::json!({"model": "gpt-4", "tokens": 150})),
            enterprise: None,
            request_id: None,
        }
    }

    fn sample_receipt() -> Receipt {
        Receipt {
            core: sample_receipt_core(),
            context: sample_receipt_context(),
        }
    }

    #[test]
    fn receipt_core_round_trip_json() {
        let core = sample_receipt_core();
        let json = serde_json::to_string(&core).unwrap();
        let deserialized: ReceiptCore = serde_json::from_str(&json).unwrap();
        assert_eq!(core.id, deserialized.id);
        assert_eq!(core.receipt_type, deserialized.receipt_type);
        assert_eq!(core.seq, deserialized.seq);
        assert_eq!(core.ts_ms, deserialized.ts_ms);
        assert_eq!(core.bot_id, deserialized.bot_id);
        assert_eq!(core.prev_hash, deserialized.prev_hash);
        assert_eq!(core.payload_hash, deserialized.payload_hash);
        assert_eq!(core.sig, deserialized.sig);
    }

    #[test]
    fn receipt_core_canonical_deterministic() {
        let core = sample_receipt_core();
        let canonical1 = rfc8785::canonicalize(&core).unwrap();
        let canonical2 = rfc8785::canonicalize(&core).unwrap();
        assert_eq!(
            canonical1, canonical2,
            "Canonical JSON must be deterministic"
        );
    }

    #[test]
    fn receipt_context_round_trip_json() {
        let context = sample_receipt_context();
        let json = serde_json::to_string(&context).unwrap();
        let deserialized: ReceiptContext = serde_json::from_str(&json).unwrap();
        assert_eq!(context.blinding_nonce, deserialized.blinding_nonce);
        assert_eq!(context.action, deserialized.action);
        assert_eq!(context.outcome, deserialized.outcome);
    }

    #[test]
    fn blinding_nonce_is_mandatory_and_hex() {
        let context = sample_receipt_context();
        assert_eq!(context.blinding_nonce.len(), 64); // 32 bytes = 64 hex chars
        assert!(
            context
                .blinding_nonce
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        );
    }

    #[test]
    fn blinding_nonce_is_unique_per_call() {
        let n1 = generate_blinding_nonce();
        let n2 = generate_blinding_nonce();
        assert_ne!(n1, n2, "Each blinding nonce must be unique");
    }

    #[test]
    fn genesis_prev_hash_is_64_zeros() {
        assert_eq!(GENESIS_PREV_HASH.len(), 64);
        assert!(GENESIS_PREV_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn optional_fields_omitted_not_null() {
        // D2: Optional fields must be omitted, never null
        let context = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: None,
            subject: None,
            trigger: None,
            outcome: None,
            detail: None,
            enterprise: None,
            request_id: None,
        };
        let json = serde_json::to_value(&context).unwrap();
        // These fields should NOT be present (omitted, not null)
        assert!(
            json.get("action").is_none(),
            "None fields must be omitted, not null"
        );
        assert!(json.get("subject").is_none());
        assert!(json.get("trigger").is_none());
        assert!(json.get("outcome").is_none());
        assert!(json.get("detail").is_none());
        assert!(json.get("enterprise").is_none());
        // blinding_nonce MUST be present
        assert!(json.get("blinding_nonce").is_some());
    }

    #[test]
    fn enterprise_context_nested_not_flattened() {
        let context = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: Some("test".to_string()),
            subject: None,
            trigger: None,
            outcome: None,
            detail: None,
            enterprise: Some(EnterpriseContext {
                fleet_id: Some("fleet-001".to_string()),
                warden_key: Some("ed25519pubkeyhex".to_string()),
                policy_url: None,
                issuer_key_id: None,
                compliance_extensions: None,
                fleet_aggregate: None,
            }),
            request_id: None,
        };
        let json = serde_json::to_value(&context).unwrap();
        // Enterprise is a nested object, not flattened
        let enterprise = json
            .get("enterprise")
            .expect("enterprise should be present");
        assert!(enterprise.is_object());
        assert_eq!(
            enterprise.get("fleet_id").unwrap().as_str().unwrap(),
            "fleet-001"
        );
        assert_eq!(
            enterprise.get("warden_key").unwrap().as_str().unwrap(),
            "ed25519pubkeyhex"
        );
        // Optional enterprise fields should be omitted
        assert!(enterprise.get("policy_url").is_none());
        assert!(enterprise.get("issuer_key_id").is_none());
    }

    #[test]
    fn full_receipt_round_trip() {
        let receipt = sample_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.core.id, deserialized.core.id);
        assert_eq!(receipt.core.seq, deserialized.core.seq);
        assert_eq!(
            receipt.context.blinding_nonce,
            deserialized.context.blinding_nonce
        );
    }

    #[test]
    fn receipt_type_serializes_as_snake_case() {
        let core = sample_receipt_core();
        let json = serde_json::to_value(&core).unwrap();
        assert_eq!(json["type"].as_str().unwrap(), "api_call");

        // Test all important types
        let types_expected = vec![
            (ReceiptType::WriteBarrier, "write_barrier"),
            (ReceiptType::SlmAnalysis, "slm_analysis"),
            (ReceiptType::SlmParseFailure, "slm_parse_failure"),
            (ReceiptType::MemoryIntegrity, "memory_integrity"),
            (ReceiptType::MerkleRollup, "merkle_rollup"),
            (ReceiptType::Evolution, "evolution"),
            (ReceiptType::AuthorizedWrite, "authorized_write"),
            (ReceiptType::BarrierUpdate, "barrier_update"),
            (ReceiptType::DlpDetection, "dlp_detection"),
        ];
        for (rt, expected) in types_expected {
            let val = serde_json::to_value(&rt).unwrap();
            assert_eq!(val.as_str().unwrap(), expected, "ReceiptType {:?}", rt);
        }
    }

    #[test]
    fn ts_ms_is_integer_not_float() {
        let core = sample_receipt_core();
        let json = serde_json::to_value(&core).unwrap();
        let ts = json.get("ts_ms").unwrap();
        assert!(
            ts.is_i64() || ts.is_u64(),
            "ts_ms must be integer, not float"
        );
    }

    #[test]
    fn rollup_detail_round_trip() {
        let mut type_counts = HashMap::new();
        type_counts.insert("api_call".to_string(), 80u64);
        type_counts.insert("write_barrier".to_string(), 15u64);
        type_counts.insert("slm_analysis".to_string(), 5u64);

        let rollup = RollupDetail {
            seq_start: 1,
            seq_end: 100,
            receipt_count: 100,
            merkle_root: "d".repeat(64),
            head_hash: "e".repeat(64),
            histogram: RollupHistogram {
                type_counts,
                severity_counts: None,
            },
        };

        let json = serde_json::to_string(&rollup).unwrap();
        let deserialized: RollupDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.seq_start, 1);
        assert_eq!(deserialized.seq_end, 100);
        assert_eq!(deserialized.receipt_count, 100);
        // Verify: seq_end - seq_start + 1 == receipt_count (no gaps)
        assert_eq!(
            deserialized.seq_end - deserialized.seq_start + 1,
            deserialized.receipt_count
        );
    }
}

#[cfg(test)]
mod claim_tests {
    use aegis_crypto::rfc8785;
    use aegis_schemas::BasisPoints;
    use aegis_schemas::claim::{Claim, ClaimType, TemporalScope};
    use uuid::Uuid;

    fn sample_claim() -> Claim {
        Claim {
            id: Uuid::now_v7(),
            claim_type: ClaimType::Lore,
            namespace: "b/lore".to_string(),
            attester_id: "abc123def456".to_string(),
            confidence_bp: BasisPoints::new(8500).unwrap(), // 85.00% in basis points
            temporal_scope: TemporalScope {
                start_ms: 1740000000000,
                end_ms: None,
            },
            provenance: vec![Uuid::now_v7()],
            schema_version: 1,
            confabulation_score_bp: None,
            temporal_coherence_flag: None,
            distinct_warden_count: None,
            payload: serde_json::json!({"summary": "test lore entry"}),
        }
    }

    #[test]
    fn claim_round_trip_json() {
        let claim = sample_claim();
        let json = serde_json::to_string(&claim).unwrap();
        let deserialized: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim.id, deserialized.id);
        assert_eq!(claim.claim_type, deserialized.claim_type);
        assert_eq!(claim.confidence_bp, deserialized.confidence_bp);
    }

    #[test]
    fn claim_canonical_deterministic() {
        let claim = sample_claim();
        let canonical1 = rfc8785::canonicalize(&claim).unwrap();
        let canonical2 = rfc8785::canonicalize(&claim).unwrap();
        assert_eq!(canonical1, canonical2);
    }

    #[test]
    fn claim_no_floats_in_serialized() {
        let claim = sample_claim();
        let json = serde_json::to_value(&claim).unwrap();
        // confidence must be integer basis points, not float
        let conf = json.get("confidence_bp").unwrap();
        assert!(conf.is_u64(), "confidence_bp must be integer, not float");
        assert_eq!(conf.as_u64().unwrap(), 8500);
    }

    #[test]
    fn claim_optional_fields_omitted() {
        let claim = sample_claim();
        let json = serde_json::to_value(&claim).unwrap();
        assert!(json.get("confabulation_score_bp").is_none());
        assert!(json.get("temporal_coherence_flag").is_none());
        assert!(json.get("distinct_warden_count").is_none());
        // end_ms is inside temporal_scope, not at top level // end_ms is inside temporal_scope
        let scope = json.get("temporal_scope").unwrap();
        assert!(
            scope.get("end_ms").is_none(),
            "None end_ms should be omitted"
        );
    }

    #[test]
    fn temporal_scope_uses_epoch_ms() {
        let claim = sample_claim();
        let json = serde_json::to_value(&claim).unwrap();
        let scope = json.get("temporal_scope").unwrap();
        let start = scope.get("start_ms").unwrap();
        assert!(
            start.is_i64() || start.is_u64(),
            "start_ms must be integer epoch ms"
        );
    }
}

#[cfg(test)]
mod trustmark_tests {
    use aegis_crypto::rfc8785;
    use aegis_schemas::BasisPoints;
    use aegis_schemas::trustmark::{Tier, TrustmarkDimensions, TrustmarkScore};

    #[test]
    fn trustmark_round_trip() {
        let score = TrustmarkScore {
            score_bp: BasisPoints::new(7500).unwrap(), // 75.00%
            dimensions: TrustmarkDimensions {
                relay_reliability: BasisPoints::new(8000).unwrap(),
                persona_integrity: BasisPoints::new(9000).unwrap(),
                chain_integrity: BasisPoints::new(10000).unwrap(),
                contribution_volume: BasisPoints::new(5000).unwrap(),
                temporal_consistency: BasisPoints::new(7000).unwrap(),
                vault_hygiene: BasisPoints::new(6000).unwrap(),
                response_hygiene: BasisPoints::new(8000).unwrap(),
            },
            tier: Tier::Tier2,
            computed_at_ms: 1740000000000,
        };
        let json = serde_json::to_string(&score).unwrap();
        let deserialized: TrustmarkScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.score_bp, BasisPoints::new(7500).unwrap());
        assert_eq!(deserialized, score); // PartialEq now works (no floats!)
    }

    #[test]
    fn trustmark_canonical_deterministic() {
        let score = TrustmarkScore {
            score_bp: BasisPoints::new(5000).unwrap(),
            dimensions: TrustmarkDimensions {
                relay_reliability: BasisPoints::new(5000).unwrap(),
                persona_integrity: BasisPoints::new(5000).unwrap(),
                chain_integrity: BasisPoints::new(5000).unwrap(),
                contribution_volume: BasisPoints::new(5000).unwrap(),
                temporal_consistency: BasisPoints::new(5000).unwrap(),
                vault_hygiene: BasisPoints::new(5000).unwrap(),
                response_hygiene: BasisPoints::new(5000).unwrap(),
            },
            tier: Tier::Tier1,
            computed_at_ms: 1740000000000,
        };
        let c1 = rfc8785::canonicalize(&score).unwrap();
        let c2 = rfc8785::canonicalize(&score).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn trustmark_no_floats() {
        let score = TrustmarkScore {
            score_bp: BasisPoints::new(8500).unwrap(),
            dimensions: TrustmarkDimensions {
                relay_reliability: BasisPoints::new(8000).unwrap(),
                persona_integrity: BasisPoints::new(9000).unwrap(),
                chain_integrity: BasisPoints::new(10000).unwrap(),
                contribution_volume: BasisPoints::new(5000).unwrap(),
                temporal_consistency: BasisPoints::new(7000).unwrap(),
                vault_hygiene: BasisPoints::new(6000).unwrap(),
                response_hygiene: BasisPoints::new(8000).unwrap(),
            },
            tier: Tier::Tier3,
            computed_at_ms: 1740000000000,
        };
        let json = serde_json::to_value(&score).unwrap();
        let score_val = json.get("score_bp").unwrap();
        assert!(score_val.is_u64(), "score_bp must be integer basis points");
        // Check all dimension values are integers
        let dims = json.get("dimensions").unwrap();
        for key in [
            "relay_reliability",
            "persona_integrity",
            "chain_integrity",
            "contribution_volume",
            "temporal_consistency",
            "vault_hygiene",
        ] {
            let val = dims.get(key).unwrap();
            assert!(val.is_u64(), "{} must be integer basis points", key);
        }
    }

    #[test]
    fn tier_ordering() {
        assert!(Tier::Tier1 < Tier::Tier2);
        assert!(Tier::Tier2 < Tier::Tier3);
    }

    #[test]
    fn tier_serializes_snake_case() {
        assert_eq!(serde_json::to_value(Tier::Tier1).unwrap(), "tier1");
        assert_eq!(serde_json::to_value(Tier::Tier2).unwrap(), "tier2");
        assert_eq!(serde_json::to_value(Tier::Tier3).unwrap(), "tier3");
    }
}

#[cfg(test)]
mod crypto_tests {
    use aegis_crypto::bip39::{
        KDF_VERSION, KeyPurpose, create_identity, derive_signing_key, generate_mnemonic,
        mnemonic_to_seed, restore_from_mnemonic,
    };
    use aegis_crypto::ed25519::{fingerprint_hex, pubkey_hex};
    use ed25519_dalek::Signer;

    #[test]
    fn identity_round_trip() {
        let (mnemonic, key, metadata) = create_identity("").unwrap();
        assert_eq!(metadata.kdf_version, KDF_VERSION);
        assert!(!metadata.passphrase_protected);

        let restored = restore_from_mnemonic(&mnemonic, "", KeyPurpose::Signing).unwrap();
        assert_eq!(key.to_bytes(), restored.to_bytes());

        // Signatures must match
        let msg = b"test message for round-trip";
        let sig1 = key.sign(msg);
        let sig2 = restored.sign(msg);
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    #[test]
    fn domain_separated_keys_differ() {
        let mnemonic = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&mnemonic, "").unwrap();

        let signing = derive_signing_key(&seed, KeyPurpose::Signing).unwrap();
        let transport = derive_signing_key(&seed, KeyPurpose::TransportAuth).unwrap();
        let vault = derive_signing_key(&seed, KeyPurpose::VaultKdf).unwrap();
        let mesh = derive_signing_key(&seed, KeyPurpose::MeshEncryption).unwrap();

        // All four purposes produce different keys
        let keys = [
            signing.to_bytes(),
            transport.to_bytes(),
            vault.to_bytes(),
            mesh.to_bytes(),
        ];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i], keys[j],
                    "Keys at purpose {} and {} must differ",
                    i, j
                );
            }
        }
    }

    #[test]
    fn fingerprint_is_lowercase_hex() {
        let (_, key, _) = create_identity("").unwrap();
        let fp = fingerprint_hex(&key.verifying_key());
        assert_eq!(fp.len(), 64); // 32 bytes = 64 hex chars
        assert!(
            fp.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn pubkey_is_lowercase_hex() {
        let (_, key, _) = create_identity("").unwrap();
        let pk = pubkey_hex(&key.verifying_key());
        assert_eq!(pk.len(), 64);
        assert!(
            pk.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn passphrase_changes_keys() {
        let mnemonic = generate_mnemonic().unwrap();
        let seed_empty = mnemonic_to_seed(&mnemonic, "").unwrap();
        let seed_pass = mnemonic_to_seed(&mnemonic, "my passphrase").unwrap();
        assert_ne!(seed_empty, seed_pass);
    }
}

#[cfg(test)]
mod adversarial_tests {
    use aegis_crypto::rfc8785;
    use aegis_schemas::BasisPoints;
    use aegis_schemas::receipt::{
        GENESIS_PREV_HASH, Receipt, ReceiptContext, ReceiptCore, ReceiptType, RollupDetail,
        RollupHistogram, generate_blinding_nonce,
    };
    use aegis_schemas::trustmark::{Tier, TrustmarkDimensions, TrustmarkScore};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[test]
    fn test_basis_points_overflow_rejected() {
        // Values above 10000 must be rejected
        assert!(BasisPoints::new(10001).is_none());
        assert!(BasisPoints::new(20000).is_none());
        assert!(BasisPoints::new(u32::MAX).is_none());

        // Deserialization must also reject
        let result: Result<BasisPoints, _> = serde_json::from_str("10001");
        assert!(result.is_err());
        let result: Result<BasisPoints, _> = serde_json::from_str("99999");
        assert!(result.is_err());

        // Boundary: 10000 is valid
        assert!(BasisPoints::new(10000).is_some());
    }

    #[test]
    fn test_receipt_context_optional_fields_omitted() {
        // All optional fields set to None should be omitted from JSON, not null
        let context = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: None,
            subject: None,
            trigger: None,
            outcome: None,
            detail: None,
            enterprise: None,
            request_id: None,
        };
        let json = serde_json::to_value(&context).unwrap();

        // None fields must be absent, not present as null
        assert!(
            json.get("action").is_none(),
            "action must be omitted, not null"
        );
        assert!(
            json.get("subject").is_none(),
            "subject must be omitted, not null"
        );
        assert!(
            json.get("trigger").is_none(),
            "trigger must be omitted, not null"
        );
        assert!(
            json.get("outcome").is_none(),
            "outcome must be omitted, not null"
        );
        assert!(
            json.get("detail").is_none(),
            "detail must be omitted, not null"
        );
        assert!(
            json.get("enterprise").is_none(),
            "enterprise must be omitted, not null"
        );
        assert!(
            json.get("enforcement_mode").is_none(),
            "enforcement_mode must be omitted, not null"
        );

        // blinding_nonce must always be present
        assert!(json.get("blinding_nonce").is_some());

        // Round-trip through serialization
        let json_str = serde_json::to_string(&context).unwrap();
        let deserialized: ReceiptContext = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized.action, None);
        assert_eq!(deserialized.subject, None);
    }

    #[test]
    fn test_unicode_bot_id_in_receipt() {
        // Non-ASCII bot_id must canonicalize deterministically
        let unicode_bot_id = "\u{1F600}\u{1F47B}\u{2764}\u{FE0F}emoji-bot-\u{00E9}\u{00FC}";
        let core = ReceiptCore {
            id: Uuid::now_v7(),
            bot_id: unicode_bot_id.to_string(),
            receipt_type: ReceiptType::ApiCall,
            ts_ms: 1740000000000,
            prev_hash: GENESIS_PREV_HASH.to_string(),
            payload_hash: "b".repeat(64),
            seq: 1,
            sig: "c".repeat(128),
        };

        // Canonicalize twice and verify determinism
        let canonical1 = rfc8785::canonicalize(&core).unwrap();
        let canonical2 = rfc8785::canonicalize(&core).unwrap();
        assert_eq!(
            canonical1, canonical2,
            "canonical JSON must be deterministic with unicode bot_id"
        );

        // Round-trip must preserve the unicode
        let json = serde_json::to_string(&core).unwrap();
        let deserialized: ReceiptCore = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.bot_id, unicode_bot_id);
    }

    #[test]
    fn test_trustmark_score_boundary_values() {
        // Test BasisPoints at exact boundaries: 0, 1, 9999, 10000
        let boundaries = [0u32, 1, 9999, 10000];
        for &val in &boundaries {
            let bp = BasisPoints::new(val)
                .unwrap_or_else(|| panic!("BasisPoints({val}) should be valid"));
            assert_eq!(bp.value(), val);

            // Serialize and deserialize
            let json = serde_json::to_string(&bp).unwrap();
            let deserialized: BasisPoints = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.value(), val);
        }

        // Build a full TrustmarkScore at boundary values
        let score = TrustmarkScore {
            score_bp: BasisPoints::new(0).unwrap(),
            dimensions: TrustmarkDimensions {
                relay_reliability: BasisPoints::new(0).unwrap(),
                persona_integrity: BasisPoints::new(1).unwrap(),
                chain_integrity: BasisPoints::new(9999).unwrap(),
                contribution_volume: BasisPoints::new(10000).unwrap(),
                temporal_consistency: BasisPoints::new(0).unwrap(),
                vault_hygiene: BasisPoints::new(10000).unwrap(),
                response_hygiene: BasisPoints::new(5000).unwrap(),
            },
            tier: Tier::Tier1,
            computed_at_ms: 1740000000000,
        };
        let json = serde_json::to_string(&score).unwrap();
        let deserialized: TrustmarkScore = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.dimensions.persona_integrity.value(), 1);
        assert_eq!(deserialized.dimensions.chain_integrity.value(), 9999);
        assert_eq!(deserialized.dimensions.contribution_volume.value(), 10000);
        assert_eq!(deserialized.dimensions.vault_hygiene.value(), 10000);
    }

    #[test]
    fn test_rollup_receipt_count_mismatch() {
        // Create a RollupDetail with mismatched counts
        let mut type_counts = HashMap::new();
        type_counts.insert("api_call".to_string(), 50u64);
        type_counts.insert("write_barrier".to_string(), 10u64);

        let rollup = RollupDetail {
            seq_start: 1,
            seq_end: 100,
            receipt_count: 100, // claims 100 receipts
            merkle_root: "d".repeat(64),
            head_hash: "e".repeat(64),
            histogram: RollupHistogram {
                type_counts: type_counts.clone(),
                severity_counts: None,
            },
        };

        // The histogram type_counts sum to 60, but receipt_count claims 100.
        // This mismatch should be detectable by consumers.
        let histogram_total: u64 = rollup.histogram.type_counts.values().sum();
        assert_ne!(
            histogram_total, rollup.receipt_count,
            "mismatch should be detectable: histogram total ({}) != receipt_count ({})",
            histogram_total, rollup.receipt_count
        );

        // Verify the rollup serializes and deserializes correctly despite mismatch
        let json = serde_json::to_string(&rollup).unwrap();
        let deserialized: RollupDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.receipt_count, 100);
        let deser_total: u64 = deserialized.histogram.type_counts.values().sum();
        assert_eq!(deser_total, 60);

        // Verify seq range vs receipt_count consistency check
        let seq_range_count = rollup.seq_end - rollup.seq_start + 1;
        assert_eq!(
            seq_range_count, rollup.receipt_count,
            "seq range matches receipt_count (this is the primary invariant)"
        );
    }

    #[test]
    fn receipt_context_request_id_round_trip() {
        let ctx = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: None,
            subject: None,
            trigger: None,
            outcome: None,
            detail: None,
            enterprise: None,
            request_id: Some("01234567-89ab-cdef-0123-456789abcdef".to_string()),
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("request_id"));
        let parsed: ReceiptContext = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.request_id,
            Some("01234567-89ab-cdef-0123-456789abcdef".to_string())
        );
    }

    #[test]
    fn receipt_context_request_id_omitted_when_none() {
        let ctx = ReceiptContext {
            blinding_nonce: generate_blinding_nonce(),
            enforcement_mode: None,
            action: None,
            subject: None,
            trigger: None,
            outcome: None,
            detail: None,
            enterprise: None,
            request_id: None,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("request_id"));
    }
}
