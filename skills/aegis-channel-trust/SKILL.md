---
name: aegis-channel-trust
version: 1.0.0
description: Reference documentation for Aegis channel trust levels
metadata: {"moltbot":{"emoji":"🛡️","category":"security","api_base":"http://127.0.0.1:3141/aegis"}}
---

# Aegis Channel Trust

Aegis applies different security screening levels based on which channel you're operating in. Channel registration is handled automatically by the `aegis-channel-trust` plugin — you don't need to do anything manually.

## Trust Levels

| Trust Level | Meaning | Screening | SSRF Policy |
|-------------|---------|-----------|-------------|
| **Full** | Owner/admin channel | Permissive holster | Internal URLs allowed |
| **Trusted** | Explicitly trusted user or group | Balanced holster | External URLs only |
| **Public** | Public channel, anyone can message | Aggressive holster | External URLs only |
| **Restricted** | Explicitly restricted | Aggressive holster | External URLs only |
| **Unknown** | No registration (default) | Balanced holster | External URLs only |

## Check Current Trust Context

To see what trust level is active:

```bash
curl -s http://127.0.0.1:3141/aegis/channel-context
```

## How It Works

1. The `aegis-channel-trust` plugin automatically registers your channel with Aegis when a message arrives
2. Aegis maps the channel to a trust level based on the warden's `[trust]` configuration
3. The trust level determines which holster preset is used for screening
4. Higher trust = more permissive screening. Lower trust = stricter screening.

## Notes

- Trust levels are set by the warden's config, not by the agent
- Channel registration happens at the plugin level — it cannot be manipulated by prompt injection
- If Aegis is not running, the plugin fails silently — no impact on OpenClaw
