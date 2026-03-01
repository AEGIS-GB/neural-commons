# Layer 4: Full-Stack Scenario Tests (~10 min)

YAML-driven scenario tests. Docker Compose spins up NATS + PostgreSQL + MinIO + adapter + cluster services.

## Scenarios (to be implemented)

1. `install-flow.yml` — fresh install → key gen → first scan → dashboard
2. `evidence-chain.yml` — 1000 API calls → valid hash chain → Merkle rollup
3. `trustmark-scoring.yml` — evidence → TRUSTMARK computation → tier gate
4. `botawiki-lifecycle.yml` — claim submission → quarantine → validation → canonical
5. `mesh-relay.yml` — two Tier 3 bots → encrypted mesh message exchange
6. `full-journey.yml` — install → Tier 1 → 2 → 3 → write + query + mesh

## Running

```bash
# Requires Docker Compose
cd tests/e2e
docker compose up -d
cd ../scenarios
cargo test --release -- --test-threads=1
```
