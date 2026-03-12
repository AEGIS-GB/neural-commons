# Trace Request Lifecycle

Trace the full request lifecycle through the Aegis adapter proxy. Read the source files and report what you find — do not modify any code.

## Steps

### 1. Trace `forward_request()` in `adapter/aegis-proxy/src/proxy.rs`

Read the function and report:
- Provider detection logic (what function is called, what happens for unknown providers)
- Rate limiter check (what key is used, what happens when exceeded)
- How the request body is read and hashed
- How the upstream URL is constructed
- SSE streaming detection (what headers are checked: `Content-Type: text/event-stream` and `Transfer-Encoding: chunked`)
- How streaming responses are forwarded (chunk channel, incremental SHA-256 hasher task, evidence oneshot)
- How non-streaming responses are buffered and inspected

### 2. Check all 4 hooks in `adapter/aegis-adapter/src/hooks.rs`

For each hook, report **REAL** or **STUB**:

- **EvidenceHookImpl** — Does it call `recorder.record_simple()`? Does `on_request` and `on_response` both record? Report: REAL or STUB
- **SlmHookImpl** — Does it call `aegis_slm::loopback::screen_content()`? Does it use `spawn_blocking`? Does it handle Admit/Quarantine/Reject? Report: REAL or STUB
- **BarrierHookImpl** — Does it check `protected_files.lock()` and `mgr.is_critical()`? Does it record WriteBarrier receipts? Does it send SSE alerts? Report: REAL or STUB
- **VaultHookImpl** — Does it call `scanner::scan_text()`? Does it return `VaultDecision::Detected` with secret summaries? Report: REAL or STUB

### 3. Verify server startup wiring in `adapter/aegis-adapter/src/server.rs`

Check and report:
- Is the dashboard router created and mounted? (look for `aegis_dashboard::routes::routes()` and the `dashboard` parameter passed to `aegis_proxy::proxy::start()`)
- Is the memory monitor spawned? (look for `tokio::spawn` with `monitor.run()`)
- Is the barrier filesystem watcher started? (look for `notify::RecommendedWatcher` and `tokio::spawn`)
- Is the alert broadcast channel created? (look for `tokio::sync::broadcast::channel`)
- Are all 4 hooks wired in `create_middleware_hooks()`? (evidence, barrier, slm, vault)

### 4. Check the evidence chain in `adapter/aegis-evidence/src/store.rs`

Report:
- Storage backend (SQLite WAL mode?)
- Tables created (receipts, chain_state, rollups?)
- `append_receipt()` — is it transactional?
- `verify_full_chain()` — does it walk from genesis checking prev_hash links?

## Output Format

```
## Request Lifecycle Trace

### forward_request() — aegis-proxy/src/proxy.rs
[your findings]

### Middleware Hooks — aegis-adapter/src/hooks.rs
- EvidenceHookImpl: REAL/STUB — [details]
- SlmHookImpl:      REAL/STUB — [details]
- BarrierHookImpl:  REAL/STUB — [details]
- VaultHookImpl:    REAL/STUB — [details]

### Server Startup Wiring — aegis-adapter/src/server.rs
- Dashboard mounted:       YES/NO
- Memory monitor spawned:  YES/NO
- Barrier watcher started: YES/NO
- Alert broadcast channel: YES/NO
- All 4 hooks wired:       YES/NO

### Evidence Chain — aegis-evidence/src/store.rs
[your findings]
```
