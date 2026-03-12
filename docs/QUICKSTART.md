# Aegis Shield — Quickstart

Protect your OpenClaw agent in under 2 minutes. No configuration files to edit, no dependencies to install, no accounts to create.

## What You Get

Aegis is a local proxy that sits between your OpenClaw agent and its LLM provider. Every API call passes through it. Nothing leaves your machine.

After install, your agent has:
- **Evidence chain** — tamper-evident receipts for every API call
- **Write barrier** — blocks unauthorized changes to SOUL.md, AGENTS.md, IDENTITY.md
- **Credential scanner** — detects leaked API keys in responses
- **Injection screening** — flags prompt injection attempts (via local SLM or heuristics)
- **Memory monitor** — watches MEMORY.md and daily logs for suspicious writes
- **Dashboard** — see everything at localhost:3141/dashboard

Default mode is **observe-only** — Aegis logs and warns but never blocks. Your bot keeps working exactly as before. When you're comfortable, switch to enforce mode.

---

## Install

```bash
curl -fsSL https://github.com/LCatGA12/neural-commons/releases/latest/download/install.sh | bash
```

This downloads the binary for your platform, generates an Ed25519 identity keypair, runs your first vulnerability scan, and creates a default config at `~/.aegis/config/config.toml`.

Supported platforms: Linux x86_64, macOS x86_64, macOS ARM (Apple Silicon), Windows x86_64.

**Build from source** (requires Rust 1.85+):

```bash
git clone https://github.com/LCatGA12/neural-commons.git
cd neural-commons
cargo install --path adapter/aegis-cli
```

## Connect to OpenClaw

```bash
aegis setup openclaw
```

This finds your `~/.openclaw/openclaw.json`, backs it up, and adds `baseUrl` pointing to the Aegis proxy. Preview changes first with `--dry-run`. Undo anytime with `--revert`.

If your OpenClaw config is elsewhere, set `OPENCLAW_HOME` first:

```bash
export OPENCLAW_HOME=/path/to/your/openclaw
aegis setup openclaw
```

## Start

```bash
aegis
```

That's it. Aegis starts in observe-only mode on port 3141. Open http://localhost:3141/dashboard to see your security posture.

Every request your OpenClaw agent sends now generates a signed evidence receipt. The write barrier is watching your identity files. The credential scanner is checking responses. If Ollama is running with `llama3.2:1b`, the SLM screens for injections too.

## Optional: Enable SLM Injection Screening

The local language model provides the strongest injection detection. It requires Ollama:

```bash
# Install Ollama (if not already)
curl -fsSL https://ollama.com/install.sh | sh

# Pull the screening model (~1.3GB)
ollama pull llama3.2:1b

# Restart Aegis — it auto-detects Ollama
aegis
```

Without Ollama, Aegis uses heuristic regex patterns (less accurate but zero dependencies). You can also disable SLM entirely with `aegis --no-slm`.

## Common Commands

```bash
aegis                        # start adapter (observe-only)
aegis --enforce              # start with blocking enabled
aegis --no-slm               # start without SLM screening
aegis --pass-through         # dumb forwarder, zero inspection

aegis setup openclaw         # configure OpenClaw integration
aegis setup openclaw --revert  # undo configuration

aegis scan                   # scan workspace for credentials
aegis scan /path/to/dir      # scan specific directory

aegis status                 # show adapter status
aegis vault summary          # credential vault overview
aegis memory status          # memory file health
aegis export                 # export evidence chain as JSON
aegis export --verify        # export with integrity check
aegis dashboard              # open dashboard in browser
```

## Configuration

Default config lives at `~/.aegis/config/config.toml`:

```toml
mode = "observe_only"    # or "enforce" to enable blocking

[proxy]
listen_addr = "127.0.0.1:3141"
upstream_url = "https://api.anthropic.com"  # change for OpenAI or other providers

[slm]
enabled = true
model = "llama3.2:1b"      # or "llama3.2:3b" for better accuracy
```

For OpenAI bots, change `upstream_url` to `https://api.openai.com` and set `allow_any_provider = true` in the `[proxy]` section.

## Uninstall

```bash
aegis setup openclaw --revert   # restore original OpenClaw config
rm -rf ~/.aegis                 # remove Aegis data and binary
```

Your evidence chain is in `~/.aegis/data/evidence.db` — back it up first if you want to keep the audit trail.

## Verify Your Install

After starting Aegis, send a test request through your OpenClaw agent. Then check:

1. Dashboard shows the request in the Evidence Chain tab
2. `aegis export --verify` confirms chain integrity
3. `aegis memory status` shows your monitored files
4. `aegis scan` reports any credential findings

If all four work, you're protected. If something's off, [open an issue](https://github.com/LCatGA12/neural-commons/issues).

## How It Works

```
Your OpenClaw Agent
        |
        | (baseUrl = localhost:3141)
        v
  ┌─────────────┐
  │  Aegis Proxy │──→ Evidence Receipt (signed, hash-chained)
  │  :3141       │──→ Write Barrier (filesystem watcher)
  │              │──→ SLM Screening (Ollama / heuristic)
  │              │──→ Vault Scanner (credential detection)
  │              │──→ Memory Monitor (MEMORY.md, USER.md)
  └──────┬───────┘
         |
         v
  Upstream LLM Provider
  (api.anthropic.com / api.openai.com)
```

Aegis is a transparent proxy. It intercepts traffic, inspects it, records evidence, and forwards it unchanged. In observe mode, it never modifies or blocks anything. In enforce mode, it can block requests that fail SLM screening or violate write barriers.

## Dogfooding: Route Claude Code Through Aegis

Anthropic officially supports routing Claude Code through LLM gateways using the `ANTHROPIC_BASE_URL` environment variable. See the [Anthropic LLM Gateway documentation](https://docs.anthropic.com/en/docs/claude-code/llm-gateway) for details.

This means you can run Claude Code through Aegis to monitor and record every API call Claude makes — with full evidence receipts, credential scanning, and (optionally) injection screening.

**Terminal 1 — Start Aegis:**

```bash
aegis --no-slm
# Proxy listening on 127.0.0.1:3141
# Dashboard at http://localhost:3141/dashboard
```

**Terminal 2 — Run Claude Code through the proxy:**

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:3141
claude
```

**What to expect:**
- Streaming works — Aegis detects SSE and chunked responses, forwarding them transparently
- Evidence receipts appear on the dashboard as Claude sends API calls
- `aegis export --verify` confirms the evidence chain integrity

**Safety notes:**
- `ANTHROPIC_BASE_URL` is a per-shell env var — it only affects the terminal where you set it
- To stop routing through Aegis: close the terminal or run `unset ANTHROPIC_BASE_URL`
- Use `--no-slm` to skip SLM screening overhead on Claude's traffic (recommended for dogfooding)
- Aegis runs in observe-only mode by default — it never modifies or blocks requests

**Troubleshooting dogfooding:**
- Claude Code hangs → check Aegis is running and the env var is set: `echo $ANTHROPIC_BASE_URL`
- No receipts on dashboard → send a test message in Claude and refresh the dashboard
- Streaming feels slow → make sure `--no-slm` is set

---

## Troubleshooting

**Install script says "Download failed"**
Release binaries may not be published yet for your platform. Build from source: `cargo install --path adapter/aegis-cli`

**OpenClaw not routing through Aegis**
Check `~/.openclaw/openclaw.json` has `"baseUrl": "http://127.0.0.1:3141"`. Run `aegis setup openclaw --dry-run` to see what should be there.

**Dashboard shows nothing**
Send a request through your bot first. The dashboard displays evidence receipts — it needs at least one request to have something to show.

**SLM says "Ollama unavailable"**
Install Ollama (`curl -fsSL https://ollama.com/install.sh | sh`), pull the model (`ollama pull llama3.2:1b`), make sure Ollama is running (`ollama serve`), then restart Aegis.

Full documentation: `docs/tier1/` | Issues: [GitHub](https://github.com/LCatGA12/neural-commons/issues)
