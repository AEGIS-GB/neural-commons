---
name: aegis-channel-trust
version: 1.0.0
description: Channel trust — automatic channel registration, trust resolution, and CLI tools
metadata: {"moltbot":{"emoji":"🛡️","category":"security","api_base":"http://127.0.0.1:3141/aegis"}}
---

# Aegis Channel Trust

Aegis applies different security screening levels based on which channel a request comes from. The trust level determines how aggressively content is screened.

## How It Works

### Trust Chain

1. **Aegis generates an Ed25519 identity keypair** on first start (stored in `.aegis/identity.key`)
2. **The warden configures** `signing_pubkey` in `.aegis/config.toml` with the matching public key
3. **Channel registrations must be signed** with the private key — unsigned requests are rejected
4. **Aegis verifies the signature** and resolves trust level from config patterns — the registrant cannot claim a trust level, only report which channel it's on

The private key on disk is the root of trust. Without it, no channel can be registered.

### Automatic Registration (OpenClaw Plugin)

The `aegis-channel-trust` plugin (`plugins/aegis-channel-trust/`) fires on every incoming message:

1. `message_received` hook fires (Telegram, Discord, web chat, etc.)
2. Plugin reads the identity key from `.aegis/identity.key`
3. Plugin signs `{channel, trust:"", ts, user}` with Ed25519 (keys alphabetically sorted)
4. Plugin POSTs to `POST /aegis/register-channel` with the signed payload
5. Aegis verifies signature, resolves trust from config patterns
6. All subsequent proxy requests use that trust level for screening

**Channel format:** `{platform}:{chatType}:{conversationId}`

| Source | Channel Example | Trust Level |
|--------|----------------|-------------|
| Owner DM (Telegram) | `telegram:dm:owner` | full |
| User DM (Telegram) | `telegram:dm:7965174951` | trusted |
| Telegram group | `telegram:group:-1001234567` | public |
| OpenClaw web chat | `openclaw:web:session123` | trusted |
| CLI local | `cli:local:test` | full |
| API direct | `api:direct:client1` | trusted |

### Manual Registration (CLI)

Use the CLI for testing or for channels outside the plugin:

```bash
# Register a channel with signed certificate
aegis trust register openclaw:web:my-session
aegis trust register telegram:dm:owner --user telegram:user:12345
aegis trust register cli:local:test

# Show current active channel + full registry
aegis trust context

# Show signing public key (for config setup)
aegis trust pubkey
```

### API Registration (curl)

For programmatic use — requires signing with the identity key:

```bash
curl -s http://127.0.0.1:3141/aegis/channel-context
```

Unsigned POST requests to `/aegis/register-channel` are rejected when `signing_pubkey` is configured.

## Trust Levels

| Trust Level | Holster | Classifier | SSRF | Use Case |
|-------------|---------|------------|------|----------|
| **full** | Permissive | Advisory (log only) | Internal URLs allowed | Owner DM, CLI |
| **trusted** | Balanced | Advisory (log only) | Blocked | Known users, web UI, API |
| **public** | Aggressive | Blocking (quarantine) | Blocked | Telegram groups |
| **restricted** | Aggressive | Blocking (quarantine) | Blocked | Unknown groups |
| **unknown** | Balanced | Blocking (quarantine) | Blocked | No cert / legacy |

**Advisory vs Blocking classifier:** On trusted/full channels, the ProtectAI classifier logs detections but doesn't block. On public/unknown channels, it actively quarantines suspicious content.

## Configuration

Trust patterns are configured in `.aegis/config.toml`:

```toml
[trust]
default_level = "unknown"
signing_pubkey = "<hex Ed25519 pubkey from 'aegis trust pubkey'>"

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
pattern = "cli:local:*"
level = "full"

[[trust.channels]]
pattern = "openclaw:web:*"
level = "trusted"
```

Patterns support `*` wildcard per segment (e.g., `telegram:dm:*` matches any DM).

## Security Model

| Actor | Can register? | Why |
|-------|--------------|-----|
| Plugin with identity key | Yes | Has the private key, signature verifies |
| `aegis trust register` CLI | Yes | Reads the same identity key |
| Rogue process without key | No | Can't sign, Aegis rejects (HTTP 401) |
| Remote attacker (injection) | No | No filesystem access to key file |
| Unsigned curl request | No | `signing_pubkey` configured = signature required |

The threat model protects against remote/software attacks. Local filesystem access to `.aegis/identity.key` is the trust boundary.

## Cognitive Bridge Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/aegis/register-channel` | POST | Register channel with signed cert |
| `/aegis/channel-context` | GET | Active channel + full registry |

## Dashboard

The **Channel Trust** tab shows:
- Channel registry (all registered channels with request counts)
- Per-channel screening history (click a channel row)
- Trust badges (color-coded by trust level)
- Active channel indicator
