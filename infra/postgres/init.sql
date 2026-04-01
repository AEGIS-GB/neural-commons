-- Neural Commons — PostgreSQL initialization
-- Runs on first container start only

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Schema: trustmark
CREATE SCHEMA IF NOT EXISTS trustmark;

-- Schema: botawiki
CREATE SCHEMA IF NOT EXISTS botawiki;

-- Schema: ledger
CREATE SCHEMA IF NOT EXISTS ledger;

-- Schema: evidence
CREATE SCHEMA IF NOT EXISTS evidence;

-- Schema: identity
CREATE SCHEMA IF NOT EXISTS identity;

-- Placeholder tables — real migrations managed by sqlx
-- These ensure the schemas exist for development

-- TRUSTMARK scores
CREATE TABLE IF NOT EXISTS trustmark.scores (
    bot_fingerprint TEXT PRIMARY KEY,
    score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    relay_reliability DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    persona_integrity DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    chain_integrity DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    contribution_volume DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    temporal_consistency DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    vault_hygiene DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    tier INTEGER NOT NULL DEFAULT 1,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Botawiki claims
CREATE TABLE IF NOT EXISTS botawiki.claims (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    claim_type TEXT NOT NULL,
    namespace TEXT NOT NULL,
    attester_id TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    temporal_scope_start TIMESTAMPTZ NOT NULL,
    temporal_scope_end TIMESTAMPTZ,
    provenance JSONB NOT NULL DEFAULT '[]',
    schema_version TEXT NOT NULL DEFAULT '0.1.0',
    confabulation_score DOUBLE PRECISION,
    temporal_coherence_flag BOOLEAN,
    distinct_warden_count INTEGER,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'quarantine',  -- quarantine, canonical, disputed, tombstoned
    embedding vector(384),  -- all-MiniLM-L6-v2 dimensions (D34)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_claims_type ON botawiki.claims(claim_type);
CREATE INDEX IF NOT EXISTS idx_claims_namespace ON botawiki.claims(namespace);
CREATE INDEX IF NOT EXISTS idx_claims_attester ON botawiki.claims(attester_id);
CREATE INDEX IF NOT EXISTS idx_claims_status ON botawiki.claims(status);

-- Compute credit balances
CREATE TABLE IF NOT EXISTS ledger.balances (
    bot_fingerprint TEXT PRIMARY KEY,
    credits DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    lifetime_earned DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    lifetime_spent DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Evidence receipts (cluster-aggregated from all bots)
CREATE TABLE IF NOT EXISTS evidence.receipts (
    id TEXT PRIMARY KEY,
    bot_fingerprint TEXT NOT NULL,
    seq BIGINT NOT NULL,
    receipt_type TEXT NOT NULL,
    ts_ms BIGINT NOT NULL,
    core_json TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    request_id TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_bot ON evidence.receipts(bot_fingerprint, seq);
CREATE INDEX IF NOT EXISTS idx_evidence_ts ON evidence.receipts(ts_ms);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence.receipts(receipt_type);
CREATE INDEX IF NOT EXISTS idx_evidence_request_id ON evidence.receipts(request_id);

-- Identity registry (cluster-side)
CREATE TABLE IF NOT EXISTS identity.bots (
    fingerprint TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sovereignty_state TEXT NOT NULL DEFAULT 'active',
    key_version INTEGER NOT NULL DEFAULT 1
);
