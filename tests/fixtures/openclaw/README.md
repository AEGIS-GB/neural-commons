# OpenClaw Golden Test Fixtures

Captured request/response pairs from a real OpenClaw instance.
Used by the OpenClaw Compatibility Harness (first Phase 1 work item).

## Required Coverage (D31: minimum 20 pairs)

- [ ] Auth flow (login, token refresh)
- [ ] Standard API call (chat completion or equivalent)
- [ ] Streaming response (SSE or chunked)
- [ ] WebSocket upgrade + message exchange
- [ ] Error responses (4xx, 5xx)
- [ ] Multi-turn conversation
- [ ] File/attachment upload (if applicable)

## Format

Each fixture is a JSON file:
```json
{
  "name": "standard-chat-completion",
  "request": {
    "method": "POST",
    "path": "/v1/chat/completions",
    "headers": {},
    "body": {}
  },
  "response": {
    "status": 200,
    "headers": {},
    "body": {}
  },
  "metadata": {
    "category": "api-call",
    "streaming": false,
    "notes": ""
  }
}
```

## Recording

These fixtures are captured by the OpenClaw Compatibility Harness (Phase 1a).
HIL required: someone with OpenClaw access must run the harness.
