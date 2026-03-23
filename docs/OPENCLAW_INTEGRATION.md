# Aegis + OpenClaw Integration Guide

Route your OpenClaw bot's LLM traffic through Aegis for inspection, evidence recording, and credential scanning.

---

## Architecture

```
                          ┌──────────────┐
  Telegram / Dashboard    │   OpenClaw   │
  ────────────────────►   │   Gateway    │
                          │  (:18789)    │
                          └──────┬───────┘
                                 │
                    o4-mini ◄────┤ primary model (OpenAI direct)
                                 │
                    subagent ────┤ lmstudio/qwen/qwen3-8b
                                 │
              aegis-channel-trust plugin
              signs & registers channel ──► POST /aegis/register-channel
                                 │
                                 ▼
                          ┌──────────────┐
                          │    Aegis     │
                          │   Proxy      │
                          │  (:3141)     │
                          │              │
                          │  1. Verify channel cert (Ed25519)
                          │  2. Resolve trust level
                          │  3. 4-layer screening pipeline
                          │  4. Record evidence receipt
                          └──────┬───────┘
                                 │
                                 ▼
                          ┌──────────────┐
                          │  LM Studio   │
                          │  (Qwen 3)    │
                          │  (:1234)     │
                          └──────────────┘
```

In Tier 1, Aegis proxies the **local LM Studio traffic** (Qwen subagent calls). The primary model (o4-mini on OpenAI) goes direct. To proxy both, run a second Aegis instance (see [Advanced: Dual Proxy](#advanced-dual-proxy)).

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Aegis | v0.2.0+ | Proxy, inspection, evidence chain |
| OpenClaw | 2026.3.7+ | Bot framework |
| LM Studio | 0.3+ | Local model serving |
| Qwen 3 8B | - | Subagent model |

---

## Quick Setup

### 1. Configure Aegis

Create `~/.aegis/config/config.toml`:

```toml
mode = "observe_only"

[proxy]
listen_addr = "127.0.0.1:3141"
upstream_url = "http://localhost:1234"
max_body_size = 10485760
rate_limit_per_minute = 1000
allow_any_provider = true     # Required: LM Studio uses OpenAI-compatible API

[slm]
enabled = false               # Disable for local traffic (optional)

[memory]
memory_paths = []
hash_interval_secs = 30

[dashboard]
path = "/dashboard"
```

Key settings:
- `upstream_url` points to LM Studio
- `allow_any_provider = true` is required because LM Studio is not Anthropic or OpenAI

### 2. Configure OpenClaw

Edit `~/.openclaw/openclaw.json`. Three sections need changes:

#### a) Point LM Studio provider at Aegis

```json
"models": {
  "providers": {
    "lmstudio": {
      "baseUrl": "http://127.0.0.1:3141/v1",
      "apiKey": "local",
      "api": "openai-responses",
      "models": [
        {
          "id": "qwen/qwen3-8b",
          "name": "Qwen3 8B Local",
          "contextWindow": 32768,
          "maxTokens": 8192
        }
      ]
    }
  }
}
```

**Critical:** The model `id` must be `"qwen/qwen3-8b"` (without the `lmstudio/` prefix). OpenClaw's `parseModelRef()` splits on the first slash — `lmstudio/qwen/qwen3-8b` becomes provider=`lmstudio`, model=`qwen/qwen3-8b`. If the catalog `id` includes the prefix, the lookup fails and falls back silently to o4-mini.

#### b) Add Qwen to the models allowlist

```json
"agents": {
  "defaults": {
    "models": {
      "openai/o4-mini": {},
      "lmstudio/qwen/qwen3-8b": {}
    }
  }
}
```

If `agents.defaults.models` is non-empty, it acts as an **allowlist**. Any model not listed silently falls back to the primary model. The Qwen 8B model must be listed.

#### c) Enable the chat completions endpoint (for testing)

```json
"gateway": {
  "http": {
    "endpoints": {
      "chatCompletions": { "enabled": true }
    }
  }
}
```

This enables `POST /v1/chat/completions` on the gateway for programmatic testing. Not required for Telegram/dashboard usage.

### 3. Load Qwen with sufficient context

OpenClaw sends all tool definitions in the system prompt (~11K tokens). Qwen must be loaded with at least 16K context:

```bash
lms load qwen/qwen3-8b --context-length 32768
```

Verify:
```bash
lms ps
# Should show: CONTEXT 32768
```

If Qwen is loaded with 4096 (the default after reload), subagent calls will fail with `Cannot truncate prompt with n_keep > n_ctx`.

### 4. Start services

```bash
# Terminal 1: LM Studio (if not already running)
lms server start

# Terminal 2: Aegis
aegis --no-slm --config ~/.aegis/config/config.toml

# OpenClaw gateway (systemd user service, usually auto-starts)
systemctl --user status openclaw-gateway
```

### 5. Verify

```bash
# Proxy chain works
curl http://127.0.0.1:3141/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"qwen/qwen3-8b","messages":[{"role":"user","content":"Say hello"}]}'

# Dashboard shows traffic
open http://127.0.0.1:3141/dashboard
```

---

## How It Works

### Request Flow

1. User sends message via Telegram or OpenClaw dashboard
2. OpenClaw main agent (o4-mini on OpenAI) processes the request
3. If the task requires generation, o4-mini spawns a subagent with `sessions_spawn`
4. OpenClaw creates a subagent session with model `lmstudio/qwen/qwen3-8b`
5. OpenClaw resolves the model: provider=`lmstudio`, baseUrl=`http://127.0.0.1:3141/v1`
6. Subagent sends `POST /v1/responses` (streaming) to Aegis
7. Aegis records the request, forwards to LM Studio (:1234)
8. LM Studio runs Qwen inference, streams response back
9. Aegis captures the streamed response (up to 256KB), records evidence receipt
10. Response flows back to the subagent session
11. o4-mini receives the result and delivers it to the user

### What Aegis Captures

| Feature | Status | Details |
|---------|--------|---------|
| 4-layer screening | Active | Heuristic (<1ms) + ProtectAI classifier (~30ms) + SLM (2-3s async) + metaprompt |
| Channel trust | Active | Ed25519 signed channel certs, trust-based screening policy |
| Request body | Full | Complete prompt including system instructions and tool definitions |
| Response body | Up to 256KB | Streaming SSE events captured incrementally |
| Evidence receipt | Per request | SHA-256 hash chain entry with request/response hashes + channel trust |
| Vault scanning | Active | Scans for credentials in request/response bodies |
| Traffic inspector | Active | Full request/response visible in dashboard with screening detail |
| Barrier monitoring | Active | Watches workspace files for tampering |

### API Endpoints Used

OpenClaw uses these LM Studio endpoints through Aegis:

| Endpoint | Used By | Description |
|----------|---------|-------------|
| `POST /v1/responses` | Subagent sessions | Primary API (streaming, supports tool calls) |
| `GET /lmstudio-greeting` | SDK health check | LM Studio presence detection |
| `GET /v1/models` | Model validation | Lists available models |

---

## Configuration Reference

### Aegis config.toml

```toml
# Required for OpenClaw integration
[proxy]
upstream_url = "http://localhost:1234"  # LM Studio
allow_any_provider = true               # LMS uses OpenAI-compatible format

# Optional: disable SLM for local traffic
[slm]
enabled = false
```

### OpenClaw openclaw.json

```json
{
  "agents": {
    "defaults": {
      "model": {
        "primary": "openai/o4-mini",
        "fallbacks": ["lmstudio/qwen/qwen3-8b"]
      },
      "subagents": {
        "model": "lmstudio/qwen/qwen3-8b",
        "maxConcurrent": 1,
        "runTimeoutSeconds": 300
      },
      "models": {
        "openai/o4-mini": {},
        "lmstudio/qwen/qwen3-8b": {}
      }
    }
  },
  "models": {
    "providers": {
      "lmstudio": {
        "baseUrl": "http://127.0.0.1:3141/v1",
        "apiKey": "local",
        "api": "openai-responses",
        "models": [
          {
            "id": "qwen/qwen3-8b",
            "name": "Qwen3 8B Local",
            "contextWindow": 32768,
            "maxTokens": 8192
          }
        ]
      }
    }
  },
  "gateway": {
    "http": {
      "endpoints": {
        "chatCompletions": { "enabled": true }
      }
    }
  }
}
```

---

## Troubleshooting

### Subagent uses o4-mini instead of Qwen

**Symptom:** Subagent runs.json shows `model: lmstudio/qwen/qwen3-8b` but the session transcript shows `model=o4-mini`.

**Causes (check in order):**

1. **Model catalog ID has provider prefix**
   - Wrong: `"id": "lmstudio/qwen/qwen3-8b"`
   - Correct: `"id": "qwen/qwen3-8b"`
   - OpenClaw's `parseModelRef()` splits `lmstudio/qwen/qwen3-8b` into provider=`lmstudio` + model=`qwen/qwen3-8b`, then looks for `qwen/qwen3-8b` in the catalog. If the catalog has `lmstudio/qwen/qwen3-8b`, no match.

2. **Model not in allowlist**
   - Add `"lmstudio/qwen/qwen3-8b": {}` to `agents.defaults.models`
   - If the allowlist exists and the model isn't in it, OpenClaw silently falls back.

3. **LM Studio unreachable**
   - Verify: `curl http://127.0.0.1:3141/v1/models`
   - Check Aegis is running and upstream_url points to LM Studio.

### Subagent fails with context error

**Symptom:** LM Studio logs show `Cannot truncate prompt with n_keep (11656) >= n_ctx (4096)`

**Fix:** Reload Qwen with larger context:
```bash
lms unload qwen/qwen3-8b
lms load qwen/qwen3-8b --context-length 32768
```

### Traffic inspector shows request but not the generated text

**Symptom:** Dashboard Traffic tab shows the entry but the response body is all tool definitions.

**Cause:** Streaming responses with large tool schemas can exceed the capture limit. Aegis v0.2.0 uses 32KB; v0.2.1+ uses 256KB.

**Fix:** Update to latest Aegis build.

### OpenClaw config changes not taking effect

OpenClaw hot-reloads most config changes. Check:
```bash
journalctl --user -u openclaw-gateway --since "1 minute ago" | grep reload
```

If it says `config change requires gateway restart`, restart:
```bash
systemctl --user restart openclaw-gateway
```

### How to verify the full chain

```bash
# 1. Stop Aegis
systemctl stop aegis

# 2. Try subagent — if it still produces output, it's NOT going through Aegis
curl -X POST http://127.0.0.1:18789/v1/chat/completions \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"model":"openclaw:main","messages":[{"role":"user","content":"Spawn Qwen subagent to say hello"}]}'

# 3. If subagent succeeds with Aegis down → config is wrong
# 4. If subagent fails → Aegis is correctly in the path
```

---

## Testing

Run the integration test suite:

```bash
./tests/openclaw_integration_test.sh
```

Skip slow subagent tests:
```bash
./tests/openclaw_integration_test.sh --skip-subagent
```

The test suite validates:
- Service health (Aegis, LM Studio, OpenClaw, Qwen context)
- Direct proxy (curl → Aegis → LMS)
- OpenClaw configuration correctness
- Gateway → Aegis → LMS flow
- Subagent model routing (verifies Qwen, not o4-mini fallback)
- Dashboard API endpoints
- Vault credential scanning

---

## Advanced: Dual Proxy

To also proxy o4-mini (OpenAI) traffic through Aegis, run a second instance:

```bash
# Instance 1: LM Studio (Qwen subagent traffic)
aegis --config ~/.aegis/config/config.toml --no-slm
# Listens :3141, upstream :1234

# Instance 2: OpenAI (o4-mini primary traffic)
aegis --config ~/.aegis/config/openai.toml --no-slm
# Listens :3142, upstream https://api.openai.com
```

`~/.aegis/config/openai.toml`:
```toml
mode = "observe_only"

[proxy]
listen_addr = "127.0.0.1:3142"
upstream_url = "https://api.openai.com"
allow_any_provider = false     # OpenAI is a known provider

[slm]
enabled = false
```

Then in `openclaw.json`, add an OpenAI provider override:
```json
"openai": {
  "baseUrl": "http://127.0.0.1:3142/v1"
}
```

---

## Channel Trust

Aegis resolves a trust level per-channel, which determines how aggressively content is screened. The `aegis-channel-trust` OpenClaw plugin handles this automatically.

### How It Works

1. A Telegram message arrives → OpenClaw's `message_received` hook fires
2. The `aegis-channel-trust` plugin signs a channel registration with the bot's Ed25519 identity key
3. Plugin POSTs to `POST /aegis/register-channel` with `{channel, user, ts, sig}`
4. Aegis verifies the signature and resolves trust level from `[trust]` config patterns
5. All subsequent LLM requests use that trust level for screening decisions

### Trust Levels

| Channel Pattern | Trust Level | Classifier | SSRF |
|-----------------|------------|------------|------|
| `telegram:dm:owner` | full | Advisory | Allowed |
| `telegram:dm:*` | trusted | Advisory | Blocked |
| `telegram:group:*` | public | Blocking | Blocked |
| `openclaw:web:*` | trusted | Advisory | Blocked |
| `cli:local:*` | full | Advisory | Allowed |
| No registration | unknown | Blocking | Blocked |

### Plugin Installation

The plugin is at `plugins/aegis-channel-trust/`. To enable it in OpenClaw:

1. Add the plugin to OpenClaw's plugin config
2. Add `aegis-channel-trust` to `plugins.allow` in `openclaw.json`
3. Ensure `.aegis/identity.key` exists (Aegis creates it on first start)

The plugin searches for the identity key in:
- Configured path (default: `.aegis/identity.key`)
- `$CWD/.aegis/identity.key`
- `$HOME/.aegis/data/identity.key`
- `$HOME/aegis/neural-commons/.aegis/identity.key`

### Security Model

The plugin signs registrations with the bot's **private** Ed25519 key. Aegis verifies against the **public** key configured in `[trust] signing_pubkey`. Without the private key, a channel cannot be registered — unsigned requests are rejected (HTTP 401).

This means:
- Prompt injection cannot fake a channel registration (no key access)
- The warden controls which channels get which trust level (config patterns)
- The trust level determines screening behavior, not the registrant's claim

### CLI Testing

Test channel registration manually without the plugin:

```bash
# Register a channel
aegis trust register openclaw:web:test-session
aegis trust register telegram:dm:owner --user telegram:user:12345

# Check current trust state
aegis trust context

# Show pubkey (for config.toml setup)
aegis trust pubkey
```

### Configuration

Add to `.aegis/config.toml`:

```toml
[trust]
default_level = "unknown"
signing_pubkey = "<from 'aegis trust pubkey'>"

[[trust.channels]]
pattern = "telegram:dm:owner"
level = "full"

[[trust.channels]]
pattern = "telegram:dm:*"
level = "trusted"

[[trust.channels]]
pattern = "telegram:group:*"
level = "public"

[[trust.channels]]
pattern = "openclaw:web:*"
level = "trusted"
```

### Dashboard

The **Channel Trust** tab in the dashboard shows all registered channels, their trust levels, request counts, and per-channel screening history.

---

## Security Notes

- The OpenClaw gateway token is sensitive — it provides full operator access. Keep it on localhost only.
- Aegis runs in **observe-only** mode by default. It logs but never blocks traffic.
- The Telegram bot token in `openclaw.json` should not be committed to version control.
- Evidence receipts are stored locally in SQLite. Back up `~/.aegis/data/evidence.db`.
- The identity key (`.aegis/identity.key`) is the root of trust for channel registration. Protect it like a private key.
