# Neural Commons MoltBook MVP

## Project Overview
Trust infrastructure for 17,000+ MoltBook bot wardens. Two parallel Rust workspaces (adapter + cluster) with shared crypto and schema crates.

## Architecture
- **Rust-only** (no Go). axum + tower for HTTP, async-nats for NATS, sqlx for PostgreSQL, rust-libp2p for mesh.
- **Two streams**: adapter/ (Stream A) and cluster/ (Stream B) never touch the same crate source.
- **Shared crates**: `aegis-crypto` and `aegis-schemas` consumed by both workspaces.
- **Wire format**: RFC 8785 canonical JSON — bytes signed = bytes on wire. Protobuf for schema generation only.

## Key Conventions
- Phase 1 enforcement: `write_barrier` and `slm_reject` default to observe (warn,
  don't block). `vault_block` and `memory_write` always enforce. See D30.
- Rate limit keyed by bot identity fingerprint (not source IP). See D30.
- `aegis --pass-through` = dumb forwarder, zero inspection.
- Evidence receipts use UUID v7 (time-ordered), SHA-256 hash chains, Ed25519 signatures.
- Enterprise nullable fields on every receipt (`fleet_id`, `warden_key`, `policy_url`, etc.).
- Filesystem watcher for external write detection (not kernel hooks). Tool-mediated writes intercepted inline.

## Testing
4-layer architecture:
1. **Contract** (<30s): schema round-trip tests — `tests/contract/`
2. **Integration** (<10s): NATS topology — `tests/integration/`
3. **HTTP** (<15s): axum TestClient — `tests/http/`
4. **Scenarios** (~10min): YAML-driven Docker Compose — `tests/scenarios/`

## Building
```bash
cargo check                    # Quick check both workspaces
cargo test -p aegis-crypto     # Test specific crate
cargo test -p aegis-contract-tests  # Run Layer 1 tests
```

## Design Decisions
See `DECISIONS.md` for the full decision register (D0-D34). Defaults are provided for all decisions.

## Plan
Full implementation plan at `.claude/plans/ticklish-riding-flask.md`.
