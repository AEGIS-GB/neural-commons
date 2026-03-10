# OpenClaw → Anthropic Golden Test Fixtures

Captured request/response pairs representing the wire format between OpenClaw
and the Anthropic Messages API, as intercepted by aegis-proxy.

Used by the OpenClaw Compatibility Harness (Phase 1 work item).

## Architecture Context

OpenClaw IS the bot. It makes outbound HTTPS calls to LLM providers.
The proxy sits between OpenClaw and `api.anthropic.com`:

```
OpenClaw (bot) → aegis-proxy (127.0.0.1:AEGIS_PORT) → api.anthropic.com
```

Integration is a single config change:
```json
// ~/.openclaw/openclaw.json
{ "models": { "providers": { "anthropic": { "baseUrl": "http://127.0.0.1:AEGIS_PORT" } } } }
```

## Required Coverage (D31: coverage gate, not count gate)

Every distinct protocol behaviour must be covered. Count falls out of coverage
automatically (~12-15 fixtures covers all branches).

### Anthropic non-streaming (`single` format)
- [x] Simple single-turn message
- [ ] Multi-turn conversation (3+ turns)
- [ ] System prompt present
- [ ] Max tokens near limit

### Anthropic streaming SSE (`streaming` format)
- [x] Basic streaming response (content chunks + message_stop)
- [ ] Streaming with usage block

### Anthropic tool call sequence (`sequence` format)
- [x] Single tool call round (3 exchanges: request → tool_use → tool_result → final)
- [ ] Parallel tool calls in one response

### Error responses (`single` format)
- [ ] 400 Bad Request (malformed body)
- [x] 401 Unauthorized (bad API key)
- [ ] 429 Rate Limited (with retry-after header)
- [ ] 500 Internal Server Error (Anthropic-side)

### Unknown provider rejection (proxy-generated, `single` format)
- [x] Request without anthropic-version header → 422

## Fixture Formats (D31-B)

### Single-turn (non-streaming)
```json
{
  "name": "descriptive-name",
  "format": "single",
  "request": {
    "method": "POST",
    "path": "/v1/messages",
    "headers": { "anthropic-version": "2023-06-01", "x-api-key": "{{OPENCLAW_TOKEN}}" },
    "body": {}
  },
  "response": {
    "status": 200,
    "headers": {},
    "body": {}
  },
  "metadata": {
    "category": "anthropic-non-streaming",
    "source": "mock",
    "notes": ""
  }
}
```

### Streaming SSE
```json
{
  "name": "descriptive-name",
  "format": "streaming",
  "request": {
    "method": "POST",
    "path": "/v1/messages",
    "headers": { "anthropic-version": "2023-06-01", "x-api-key": "{{OPENCLAW_TOKEN}}" },
    "body": { "stream": true }
  },
  "chunks": [
    "event: message_start\ndata: {...}\n\n",
    "event: content_block_delta\ndata: {...}\n\n",
    "event: message_stop\ndata: {...}\n\n"
  ],
  "metadata": {
    "category": "anthropic-streaming",
    "source": "mock",
    "notes": ""
  }
}
```

### Multi-round tool call sequence
```json
{
  "name": "descriptive-name",
  "format": "sequence",
  "sequence": [
    { "request": {}, "response": {} },
    { "request": {}, "response": {} },
    { "request": {}, "response": {} }
  ],
  "metadata": {
    "category": "anthropic-tool-sequence",
    "source": "mock",
    "notes": ""
  }
}
```

## Conventions

- **Token placeholder:** Use `{{OPENCLAW_TOKEN}}` for any `x-api-key` header values
- **Source field:** `"real"` for captures from a live OpenClaw instance, `"mock"` for hand-crafted fixtures
- **File naming:** `<category>_<description>.json` (e.g., `anthropic_simple_message.json`)
