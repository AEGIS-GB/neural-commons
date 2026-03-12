# Check Wiring — Adapter Connection Audit

Audit all 17 connection points in the Aegis adapter. Read the source files and verify each point is correctly wired. Do not modify any code.

## Connection Points to Verify

Read the following source files and check each connection point. Report **PASS** or **FAIL** for each.

### Server Wiring (`adapter/aegis-adapter/src/server.rs`)

1. **Dashboard mounted** — Is `aegis_dashboard::routes::routes(dashboard_state)` called and the result passed to `aegis_proxy::proxy::start()` as the dashboard parameter?
2. **Upstream default correct** — Is the default upstream URL `https://api.anthropic.com` in `adapter/aegis-proxy/src/config.rs` `ProxyConfig::default()`?
3. **Memory monitor spawned** — Is there a `tokio::spawn` block that calls `monitor.run()` with `MemoryMonitor::new()`? Is it guarded by `mode != PassThrough`?
4. **Barrier watcher spawned** — Is there a `tokio::spawn` block with `notify::RecommendedWatcher`? Is it guarded by `mode != PassThrough`?
5. **Alert broadcast channel created** — Is `tokio::sync::broadcast::channel` called? Is the sender passed to hooks and dashboard state?

### Proxy Wiring (`adapter/aegis-proxy/src/proxy.rs`)

6. **SSE streaming path exists** — Does `forward_request()` check for `Content-Type: text/event-stream` OR `Transfer-Encoding: chunked` and handle streaming separately from buffered responses?

### Hook Wiring (`adapter/aegis-adapter/src/hooks.rs`)

7. **Evidence hook real** — Does `EvidenceHookImpl` call `self.recorder.record_simple()` in both `on_request` and `on_response`?
8. **SLM hook real** — Does `SlmHookImpl` call `aegis_slm::loopback::screen_content()` via `spawn_blocking`?
9. **Barrier hook real** — Does `BarrierHookImpl` check `self.protected_files.lock()` and call `self.recorder.record_simple()` for WriteBarrier events?
10. **Vault hook real** — Does `VaultHookImpl` call `scanner::scan_text()` and return `VaultDecision::Detected` when findings are non-empty?

### Dashboard Wiring (`adapter/aegis-dashboard/src/routes.rs`)

11. **`/api/status` endpoint** — Is there a `GET /api/status` route that returns mode, uptime, receipt_count?
12. **`/api/evidence` endpoint** — Is there a `GET /api/evidence` route that returns total_receipts, chain_head_seq?
13. **`/api/memory` endpoint** — Is there a `GET /api/memory` route?
14. **`/api/vault` endpoint** — Is there a `GET /api/vault` route?
15. **`/api/access` endpoint** — Is there a `GET /api/access` route?
16. **`/api/alerts` endpoint** — Is there a `GET /api/alerts` route?
17. **`/api/alerts/stream` endpoint** — Is there a `GET /api/alerts/stream` SSE route?

### CLI Wiring (`adapter/aegis-cli/src/main.rs`)

18. **`setup openclaw` command exists** — Is there a `setup openclaw` subcommand?
19. **Vault CLI wired** — Is `aegis vault summary` wired to VaultStorage?

## Output Format

Report as a checklist with a summary score:

```
## Adapter Wiring Audit

### Server Wiring
- [ ] 1. Dashboard mounted — PASS/FAIL: [details]
- [ ] 2. Upstream default correct — PASS/FAIL: [details]
- [ ] 3. Memory monitor spawned — PASS/FAIL: [details]
- [ ] 4. Barrier watcher spawned — PASS/FAIL: [details]
- [ ] 5. Alert broadcast channel — PASS/FAIL: [details]

### Proxy Wiring
- [ ] 6. SSE streaming path — PASS/FAIL: [details]

### Hook Wiring
- [ ] 7. Evidence hook real — PASS/FAIL: [details]
- [ ] 8. SLM hook real — PASS/FAIL: [details]
- [ ] 9. Barrier hook real — PASS/FAIL: [details]
- [ ] 10. Vault hook real — PASS/FAIL: [details]

### Dashboard Wiring
- [ ] 11. /api/status — PASS/FAIL
- [ ] 12. /api/evidence — PASS/FAIL
- [ ] 13. /api/memory — PASS/FAIL
- [ ] 14. /api/vault — PASS/FAIL
- [ ] 15. /api/access — PASS/FAIL
- [ ] 16. /api/alerts — PASS/FAIL
- [ ] 17. /api/alerts/stream — PASS/FAIL

### CLI Wiring
- [ ] 18. setup openclaw — PASS/FAIL
- [ ] 19. vault CLI wired — PASS/FAIL

## Summary: X/19 PASS
```
