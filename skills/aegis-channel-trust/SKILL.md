---
name: aegis-channel-trust
version: 1.0.0
description: Registers channel context with Aegis for trust-based security screening
metadata: {"moltbot":{"emoji":"🛡️","category":"security","api_base":"http://127.0.0.1:3141/aegis"}}
---

# Aegis Channel Trust

This skill registers your current channel context with Aegis so that security screening is calibrated to the trust level of the channel you're operating in.

## MANDATORY: Register Channel on Every New Conversation

**At the very start of every new conversation or session**, you MUST call the Aegis channel registration endpoint. This is not optional — without it, Aegis cannot apply the correct security policy for this channel.

### How to Register

Make an HTTP POST request to register your channel context:

```bash
curl -s -X POST http://127.0.0.1:3141/aegis/register-channel \
  -H "Content-Type: application/json" \
  -d '{
    "channel": "<CHANNEL_ID>",
    "user": "<USER_ID>"
  }'
```

### Channel ID Format

Use the format `platform:type:id`:

| Platform | Type | Example |
|----------|------|---------|
| Telegram | Group | `telegram:group:12345` |
| Telegram | DM | `telegram:dm:67890` |
| Discord | Channel | `discord:channel:12345` |
| API | Direct | `api:direct:local` |
| CLI | Local | `cli:local:owner` |

### User ID Format

Use the format `platform:user:id`:
- `telegram:user:12345`
- `discord:user:67890`
- `api:user:local`

### What Happens After Registration

Aegis maps your channel to a trust level based on the warden's configuration:

| Trust Level | What it means | SSRF Policy |
|-------------|--------------|-------------|
| **Full** | Owner/admin — highest trust | Internal URLs allowed |
| **Trusted** | Explicitly trusted user or group | External URLs only |
| **Public** | Public channel, anyone can message | External URLs only, strict screening |
| **Restricted** | Explicitly restricted | External URLs only, strictest screening |
| **Unknown** | No registration (default) | Standard screening |

### Check Current Context

To verify your current channel trust context:

```bash
curl -s http://127.0.0.1:3141/aegis/channel-context
```

### Important Security Notes

- You **cannot** claim a trust level — you only report which channel you're on
- Aegis determines the trust level based on the warden's `[trust]` configuration
- Trust affects screening sensitivity: public channels get stricter screening
- Trust affects SSRF policy: only `full` trust allows internal network URLs
- Registration persists for the lifetime of the Aegis process
