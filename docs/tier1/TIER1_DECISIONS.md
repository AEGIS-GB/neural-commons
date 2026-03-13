# Tier 1 Implementation Decisions

**Document Date:** 2026-03-10  
**Status:** LOCKED — Ready for implementation

---

## Related Documents

| Document | Purpose |
|----------|---------|
| **This document** | Quick reference spec — all locked decisions, config, CLI |
| **TIER1_DEFERRALS_AND_ROADMAP.md** | What's NOT in Tier 1 — deferrals, limitations, tech debt |
| **Tier1_Implementation_Plan_FINAL.md** | Detailed implementation guide with code examples |

---

## Quick Reference

| Component | Decision |
|-----------|----------|
| Dashboard auth | None (localhost-only) |
| Dashboard path | Configurable, default `/dashboard` |
| Upstream default | `https://api.anthropic.com` + warning |
| Streaming | Incremental SHA-256, passthrough SSE+chunked |
| Vault redaction | Active for non-streaming responses |
| Vault scan streams | Skip in Tier 1 |
| Traffic inspector | In-memory ring buffer, 200 entries, 32KB body cap |
| WebSocket | Defer to Phase 2 |
| Barrier detection | Filesystem watcher + proxy body inspection |
| Barrier enforce restore | In-memory snapshot (no git dependency) |
| Protected files | SOUL, AGENTS, IDENTITY, TOOLS, BOOT, MEMORY, .env* |
| Memory → SSE | All change events |
| Memory/Barrier state | Separate, shared evidence recorder |
| SLM engine | Ollama (HTTP) |
| SLM model source | Download via Ollama on first run |
| SLM fallback | Heuristic patterns |
| SLM disable | `--no-slm` flag supported |
| SLM default model | llama3.2:1b (recommend 3B in docs) |
| GPU | Auto-detect via Ollama |
| Binary hosting | GitHub Releases |
| Binary signing | Defer to Phase 2 |
| Install SLM prompt | Yes, ask warden |
| Update mechanism | `aegis update` command |
| Setup command | `aegis setup <framework>` (generalized) |
| OpenClaw fields | baseUrl only |
| Providers supported | Anthropic + OpenAI |
| Unknown providers | Return 422 |
| Provider bypass | `allow_any_provider: true` config |
| Vault endpoint fields | All (total, by-type, recent 20, timestamps, source) |
| Vault masking | Partial (`sk-a****xyz`) |
| Vault endpoint auth | None |
| Access log scope | All API calls |
| Access log limit | Last 50 entries |
| CLI vault list | Metadata default, `--decrypt` flag |
| CLI vault commands | list, get, delete, summary |
| Rate limit key | Per-bot (Ed25519 fingerprint) |
| Rate limit values | 1000 req/min, burst 50 |
| Rate limit persist | No (reset on restart) |
| Fixture source | Synthetic from API docs |
| Fixture edge cases | Streaming, large context, 429, 401, 500 |
| Injection fixtures | Yes, include attack examples |

---

## Component Details

### 1. Dashboard Router

```toml
# config.toml
[dashboard]
path = "/dashboard"  # optional, this is the default
```

- No authentication required
- Path configurable via config.toml
- Default: `/dashboard`

---

### 2. Upstream URL

```toml
# config.toml
[proxy]
upstream_url = "https://api.anthropic.com"  # default if not set
```

- Default: `https://api.anthropic.com`
- Log warning on startup if using default: "Using default upstream_url (Anthropic). Set explicitly in config.toml for other providers."

---

### 3. SSE Streaming

- Detect via `Content-Type: text/event-stream` OR `Transfer-Encoding: chunked`
- Stream response to client immediately
- Compute SHA-256 incrementally as chunks pass through
- Record evidence receipt when stream completes
- Vault redaction for non-streaming responses (see 3b)
- Skip vault scanning for streamed responses
- Traffic capture: streaming chunks accumulated up to 32KB for traffic inspector
- WebSocket deferred to Phase 2

---

### 3b. Vault Redaction (Non-Streaming)

- After vault scan detects credentials in upstream response body, `scanner::redact_text()` replaces them with masked versions before forwarding to client
- Redaction replaces from end-to-start to preserve byte offsets
- Masking format: first 4 chars + `****` + last 4 chars (or `****` if ≤ 8 chars)
- Only active for non-streaming responses (streaming vault scan deferred, see D-005)
- Response JSON structure preserved — only credential values inside content are masked

---

### 3c. Traffic Inspector

- In-memory ring buffer (`VecDeque`) with 200-entry cap
- Captures: method, path, status, request body, response body, duration, streaming flag
- Bodies truncated to 32KB per entry
- Dashboard tab with summary list (no bodies) and detail view (full bodies + parsed chat messages)
- Chat view parses OpenAI-compatible request/response into message list
- Polls every 2s, no persistence across restarts

---

### 4. Write Barrier

- Detection: Filesystem watcher (inotify/FSEvents/ReadDirectoryChangesW) + proxy body inspection
- Proxy body inspection: scans request body text for references to protected filenames (case-insensitive)
- Enforce mode restore: in-memory snapshot store (no git dependency)
  - Critical files snapshotted at startup
  - On tamper detection: atomic restore (write .tmp → rename)
  - Files missing at startup cannot be restored (warning logged)

**Default protected files:**
```
SOUL.md          (critical: true, sensitivity: standard)
AGENTS.md        (critical: true, sensitivity: standard)
IDENTITY.md      (critical: true, sensitivity: standard)
TOOLS.md         (critical: true, sensitivity: standard)
BOOT.md          (critical: true, sensitivity: standard)
MEMORY.md        (critical: true, sensitivity: standard)
*.memory.md      (critical: true, sensitivity: standard, depth ≤ 3)
.env*            (critical: true, sensitivity: credential, depth ≤ 2)
config.toml      (critical: false, sensitivity: standard)
```

---

### 5. Memory Monitor

- Push ALL change events to SSE (full visibility)
- Separate runtime state from barrier
- Share evidence recorder with barrier
- Events: FileTracked, FileChanged, FileDeleted, FileAppeared, ScanComplete

---

### 6. SLM (Small Language Model)

**Engine:** HTTP to Ollama (`http://localhost:11434`)

**Model acquisition:**
```bash
# Prompted during install
ollama pull llama3.2:1b
```

**Fallback chain:**
1. Ollama with configured model
2. Heuristic pattern matching (regex-based)
3. If `--no-slm`: skip entirely, admit all

**Default model:** `llama3.2:1b`  
**Recommended:** `llama3.2:3b` (document in README)

**GPU:** Auto-detected by Ollama (no manual config in Tier 1)

---

### 7. Install Script

**Binary source:** GitHub Releases (`github.com/nockchain/aegis/releases`)

**Signature verification:** Deferred to Phase 2  
**Warning displayed:** "Binary signature verification not yet implemented. Verify checksums manually."

**SLM model prompt:**
```
Download SLM model now? (~2GB, requires Ollama) [y/N]
```

**Update mechanism:** `aegis update` command

---

### 8. Setup Command

**Syntax:** `aegis setup <framework>`

**Supported frameworks (Tier 1):**
- `openclaw`

**OpenClaw fields modified:**
- `baseUrl` only

**Example:**
```bash
aegis setup openclaw                    # uses default http://localhost:3141
aegis setup openclaw --proxy-url http://localhost:8080
aegis setup openclaw --dry-run          # show changes without applying
aegis setup openclaw --revert           # restore from backup
```

---

### 9. Provider Detection

**Supported providers:**
- Anthropic (detected via `anthropic-version` header)
- OpenAI (detected via `Authorization: Bearer sk-*` pattern)

**Unknown providers:** Return HTTP 422
```json
{
  "error": {
    "type": "unsupported_provider",
    "message": "Unknown API provider. Tier 1 supports Anthropic and OpenAI."
  }
}
```

**Bypass:**
```toml
# config.toml
[proxy]
allow_any_provider = true
```

---

### 10. Dashboard `/api/vault` Endpoint

**Response fields:**
- `total_secrets`: count
- `by_type`: `{ "api_key": 3, "bearer_token": 1, ... }`
- `recent_findings`: last 20 entries
  - `ts_ms`: timestamp
  - `credential_type`: string
  - `masked_preview`: `"sk-a****xyz"` format
  - `source`: `"response"` | `"scan"`

**Authentication:** None (localhost-only)

**Masking algorithm:**
```
if len <= 8: "****"
else: first 4 chars + "****" + last 4 chars
```

---

### 11. Dashboard `/api/access` Endpoint

**Scope:** All API calls (not just tool calls)

**Limit:** Last 50 entries

**Response fields per entry:**
- `ts_ms`: timestamp
- `method`: HTTP method
- `path`: request path
- `status`: response status code
- `duration_ms`: round-trip time
- `receipt_seq`: evidence chain sequence number

---

### 12. CLI Vault Commands

**Commands:**
```bash
aegis vault list              # metadata only
aegis vault list --decrypt    # include decrypted values
aegis vault get <id>          # retrieve specific secret
aegis vault delete <id>       # delete secret
aegis vault delete <id> --force  # skip confirmation
aegis vault summary           # counts and breakdown
```

---

### 13. Rate Limiting

**Key:** Per-bot (Ed25519 public key fingerprint)

**Limits:**
- 1000 requests per minute
- Burst: 50 requests

**Persistence:** None (resets on restart)

**Response when exceeded:** HTTP 429 with `Retry-After` header

---

### 14. Test Fixtures

**Source:** Synthetic, generated from API documentation

**Location:** `tests/fixtures/openclaw/`

**Categories:**
- `chat/` — completion requests
- `errors/` — 401, 429, 500 responses  
- `injection/` — attack pattern examples
- `openai/` — OpenAI API format

**Edge cases covered:**
- Streaming (SSE)
- Large context (>100k tokens)
- Rate limit errors (429)
- Auth failures (401)
- Server errors (500)

**Injection fixtures:** Yes, include examples of all 14 D4 patterns

---

## Config File Reference

Complete `config.toml` with all Tier 1 options:

```toml
[proxy]
listen_addr = "127.0.0.1:3141"
upstream_url = "https://api.anthropic.com"
allow_any_provider = false
max_body_size = 10485760  # 10MB

[dashboard]
path = "/dashboard"

[slm]
enabled = true
engine = "ollama"
ollama_url = "http://localhost:11434"
model = "llama3.2:1b"
fallback_to_heuristics = true

[rate_limit]
requests_per_minute = 1000
burst_size = 50

[barrier]
enabled = true
# protected_files use built-in defaults

[memory]
enabled = true
# patterns use built-in defaults

[evidence]
db_path = "~/.aegis/data/evidence.db"

[mode]
default = "observe"  # or "enforce"
```

---

## CLI Reference

```bash
# Core commands
aegis                           # start adapter (default)
aegis --enforce                 # start in enforce mode
aegis --no-slm                  # start without SLM
aegis --config /path/to.toml    # custom config

# Setup
aegis setup openclaw            # configure OpenClaw
aegis setup openclaw --revert   # undo configuration

# Scanning
aegis scan                      # scan workspace for credentials
aegis scan --path /some/dir     # scan specific directory

# Vault
aegis vault list
aegis vault list --decrypt
aegis vault get <id>
aegis vault delete <id>
aegis vault summary

# Evidence
aegis export                    # export evidence chain
aegis export --verify           # export with integrity check

# Memory
aegis memory list               # list monitored files
aegis memory status             # show monitoring status

# Maintenance
aegis update                    # check for and install updates
aegis dashboard                 # open dashboard in browser
```

---

*This document is the source of truth for Tier 1 implementation.*
