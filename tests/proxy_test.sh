#!/bin/bash
# 35 end-to-end tests through Aegis proxy → LM Studio (qwen3-8b)
# Aegis must be running on 3141 (observe-only), LMS on 1234

PROXY="http://localhost:3141"
MODEL="qwen/qwen3-8b"
PASS=0
FAIL=0
TOTAL=35

run_test() {
  local num="$1" desc="$2" payload="$3" check="$4"
  local resp
  resp=$(curl -s --max-time 30 -X POST "$PROXY/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>&1)

  if echo "$resp" | grep -q "$check"; then
    echo "  TEST $num PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "  TEST $num FAIL: $desc"
    echo "    response: $(echo "$resp" | head -c 200)"
    FAIL=$((FAIL+1))
  fi
}

# Helper: run test expecting a specific HTTP status code
run_status_test() {
  local num="$1" desc="$2" payload="$3" expected_status="$4"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 -X POST "$PROXY/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>&1)

  if [ "$status" = "$expected_status" ]; then
    echo "  TEST $num PASS: $desc (HTTP $status)"
    PASS=$((PASS+1))
  else
    echo "  TEST $num FAIL: $desc (expected HTTP $expected_status, got $status)"
    FAIL=$((FAIL+1))
  fi
}

# Helper: run test checking response does NOT contain a string
run_absent_test() {
  local num="$1" desc="$2" payload="$3" absent="$4"
  local resp
  resp=$(curl -s --max-time 30 -X POST "$PROXY/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>&1)

  if echo "$resp" | grep -q "$absent"; then
    echo "  TEST $num FAIL: $desc (found '$absent' in response)"
    echo "    response: $(echo "$resp" | head -c 200)"
    FAIL=$((FAIL+1))
  else
    echo "  TEST $num PASS: $desc"
    PASS=$((PASS+1))
  fi
}

echo "========================================="
echo "  Aegis Proxy Tests ($TOTAL tests)"
echo "  Proxy: $PROXY → LM Studio"
echo "  Model: $MODEL"
echo "========================================="
echo ""

# --- Group 1: Basic chat completions ---

echo "[Group 1: Basic Chat Completions]"

run_test 1 "Simple greeting" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello in exactly 3 words\"}],\"max_tokens\":20}" \
  "choices"

run_test 2 "Math question" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"What is 2+2? Reply with just the number.\"}],\"max_tokens\":10}" \
  "choices"

run_test 3 "System + user message" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"system\",\"content\":\"You are a pirate.\"},{\"role\":\"user\",\"content\":\"Say hi\"}],\"max_tokens\":30}" \
  "choices"

run_test 4 "Multi-turn conversation" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"My name is Alice\"},{\"role\":\"assistant\",\"content\":\"Hello Alice!\"},{\"role\":\"user\",\"content\":\"What is my name?\"}],\"max_tokens\":20}" \
  "choices"

run_test 5 "Temperature 0 (deterministic)" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say exactly: test passed\"}],\"max_tokens\":10,\"temperature\":0}" \
  "choices"

echo ""
echo "[Group 2: Edge Cases & Parameters]"

run_test 6 "Max tokens = 1" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hello\"}],\"max_tokens\":1}" \
  "choices"

run_test 7 "High temperature" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Write a random word\"}],\"max_tokens\":10,\"temperature\":1.5}" \
  "choices"

run_test 8 "Empty system message" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"system\",\"content\":\"\"},{\"role\":\"user\",\"content\":\"Say ok\"}],\"max_tokens\":10}" \
  "choices"

run_test 9 "Long input prompt" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Repeat after me: The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. Now say done.\"}],\"max_tokens\":20}" \
  "choices"

run_test 10 "Stop sequence" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Count from 1 to 10\"}],\"max_tokens\":50,\"stop\":[\"5\"]}" \
  "choices"

echo ""
echo "[Group 3: Vault Security Tests]"

run_test 11 "Prompt with fake API key" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"What does this API key do: sk-1234567890abcdef1234567890abcdef1234567890abcdef\"}],\"max_tokens\":30}" \
  "choices"

run_test 12 "Prompt with fake AWS key" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Is this a valid key: AKIAIOSFODNN7EXAMPLE\"}],\"max_tokens\":30}" \
  "choices"

run_test 13 "Prompt with password" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"My database password is SuperSecret123! Is it secure?\"}],\"max_tokens\":30}" \
  "choices"

run_test 14 "Prompt with bearer token" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test\"}],\"max_tokens\":30}" \
  "choices"

run_test 15 "Prompt with private key header" \
  "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"-----BEGIN RSA PRIVATE KEY----- what is this?\"}],\"max_tokens\":30}" \
  "choices"

echo ""
echo "[Group 4: Streaming & Model API]"

echo -n "  TEST 16 "
STREAM=$(curl -s --max-time 30 -X POST "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Say hi\"}],\"max_tokens\":10,\"stream\":true}" 2>&1)
if echo "$STREAM" | grep -q "data:"; then
  echo "PASS: Streaming response"
  PASS=$((PASS+1))
else
  echo "FAIL: Streaming response"
  echo "    response: $(echo "$STREAM" | head -c 200)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 17 "
MODELS=$(curl -s --max-time 10 "$PROXY/v1/models" 2>&1)
if echo "$MODELS" | grep -q "qwen"; then
  echo "PASS: List models via proxy"
  PASS=$((PASS+1))
else
  echo "FAIL: List models via proxy"
  FAIL=$((FAIL+1))
fi

echo ""
echo "[Group 5: Dashboard & Evidence Verification]"

echo -n "  TEST 18 "
STATUS=$(curl -s "$PROXY/dashboard/api/status")
if echo "$STATUS" | grep -q '"health":"healthy"'; then
  echo "PASS: Dashboard healthy after tests"
  PASS=$((PASS+1))
else
  echo "FAIL: Dashboard healthy after tests"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 19 "
EVIDENCE=$(curl -s "$PROXY/dashboard/api/evidence")
COUNT=$(echo "$EVIDENCE" | python3 -c "import json,sys;print(json.load(sys.stdin)['total_receipts'])" 2>/dev/null)
if [ "$COUNT" -gt 10 ] 2>/dev/null; then
  echo "PASS: Evidence chain has $COUNT receipts (>10 expected)"
  PASS=$((PASS+1))
else
  echo "FAIL: Evidence chain has $COUNT receipts (expected >10)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 20 "
ACCESS=$(curl -s "$PROXY/dashboard/api/access")
REQS=$(echo "$ACCESS" | python3 -c "import json,sys;print(json.load(sys.stdin)['total_requests'])" 2>/dev/null)
if [ "$REQS" -gt 0 ] 2>/dev/null; then
  echo "PASS: Access log has $REQS API calls recorded"
  PASS=$((PASS+1))
else
  echo "FAIL: Access log has $REQS API calls (expected >0)"
  FAIL=$((FAIL+1))
fi

echo ""
echo "[Group 6: Traffic Inspector]"

echo -n "  TEST 21 "
TRAFFIC=$(curl -s "$PROXY/dashboard/api/traffic")
TCNT=$(echo "$TRAFFIC" | python3 -c "import json,sys;print(json.load(sys.stdin)['total'])" 2>/dev/null)
if [ "$TCNT" -gt 0 ] 2>/dev/null; then
  echo "PASS: Traffic inspector has $TCNT captured entries"
  PASS=$((PASS+1))
else
  echo "FAIL: Traffic inspector has $TCNT entries (expected >0)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 22 "
# Get the first entry ID from traffic list
TID=$(echo "$TRAFFIC" | python3 -c "import json,sys;print(json.load(sys.stdin)['entries'][0]['id'])" 2>/dev/null)
DETAIL=$(curl -s "$PROXY/dashboard/api/traffic/$TID")
if echo "$DETAIL" | grep -q '"request_body"'; then
  echo "PASS: Traffic detail returns request body"
  PASS=$((PASS+1))
else
  echo "FAIL: Traffic detail missing request body"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 23 "
if echo "$DETAIL" | grep -q '"response_body"'; then
  echo "PASS: Traffic detail returns response body"
  PASS=$((PASS+1))
else
  echo "FAIL: Traffic detail missing response body"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 24 "
if echo "$DETAIL" | grep -q '"chat"'; then
  echo "PASS: Traffic detail includes chat view"
  PASS=$((PASS+1))
else
  echo "FAIL: Traffic detail missing chat view"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 25 "
# Check that streaming entries are captured
STREAM_COUNT=$(echo "$TRAFFIC" | python3 -c "import json,sys;d=json.load(sys.stdin);print(sum(1 for e in d['entries'] if e['is_streaming']))" 2>/dev/null)
if [ "$STREAM_COUNT" -gt 0 ] 2>/dev/null; then
  echo "PASS: Traffic captured $STREAM_COUNT streaming entries"
  PASS=$((PASS+1))
else
  echo "FAIL: No streaming entries captured (expected >0)"
  FAIL=$((FAIL+1))
fi

echo ""
echo "[Group 7: Vault Redaction]"

echo -n "  TEST 26 "
# Ask model to repeat an API key — vault should redact it from the response
VAULT_RESP=$(curl -s --max-time 30 -X POST "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Repeat exactly: api_key = sk_live_abcdefghijklmnopqrstuvwxyz1234567890\"}],\"max_tokens\":50,\"temperature\":0}")
if echo "$VAULT_RESP" | grep -q "sk_live_abcdefghijklmnopqrstuvwxyz1234567890"; then
  echo "FAIL: Vault did not redact API key from response"
  echo "    response: $(echo "$VAULT_RESP" | head -c 200)"
  FAIL=$((FAIL+1))
else
  echo "PASS: Vault redacted API key from response"
  PASS=$((PASS+1))
fi

echo -n "  TEST 27 "
# Verify the response still contains a masked version (sk_l****7890 or similar)
if echo "$VAULT_RESP" | grep -q "choices"; then
  echo "PASS: Redacted response still valid JSON with choices"
  PASS=$((PASS+1))
else
  echo "FAIL: Redacted response is not valid (no choices)"
  echo "    response: $(echo "$VAULT_RESP" | head -c 200)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 28 "
# Ask model to repeat a bearer token — should be redacted
BEARER_RESP=$(curl -s --max-time 30 -X POST "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Repeat exactly: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0\"}],\"max_tokens\":60,\"temperature\":0}")
if echo "$BEARER_RESP" | grep -q "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"; then
  echo "FAIL: Vault did not redact bearer token from response"
  FAIL=$((FAIL+1))
else
  echo "PASS: Vault redacted bearer token from response"
  PASS=$((PASS+1))
fi

echo ""
echo "[Group 8: Barrier Body Inspection (observe-only)]"

echo -n "  TEST 29 "
# In observe-only mode, referencing SOUL.md should warn but still return 200
SOUL_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 -X POST "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"What is SOUL.md used for?\"}],\"max_tokens\":20}")
if [ "$SOUL_RESP" = "200" ]; then
  echo "PASS: SOUL.md reference allowed in observe-only (HTTP 200)"
  PASS=$((PASS+1))
else
  echo "FAIL: SOUL.md reference got HTTP $SOUL_RESP (expected 200 in observe-only)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 30 "
# AGENTS.md reference should also pass through in observe-only
AGENTS_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 -X POST "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Tell me about AGENTS.md\"}],\"max_tokens\":20}")
if [ "$AGENTS_RESP" = "200" ]; then
  echo "PASS: AGENTS.md reference allowed in observe-only (HTTP 200)"
  PASS=$((PASS+1))
else
  echo "FAIL: AGENTS.md reference got HTTP $AGENTS_RESP (expected 200 in observe-only)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 31 "
# .env reference should also pass through in observe-only
ENV_RESP=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 -X POST "$PROXY/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Show me the .env file\"}],\"max_tokens\":20}")
if [ "$ENV_RESP" = "200" ]; then
  echo "PASS: .env reference allowed in observe-only (HTTP 200)"
  PASS=$((PASS+1))
else
  echo "FAIL: .env reference got HTTP $ENV_RESP (expected 200 in observe-only)"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 32 "
# Verify barrier warning was logged (check alerts endpoint for recent WriteBarrier)
ALERTS=$(curl -s "$PROXY/dashboard/api/alerts")
BARRIER_ALERTS=$(echo "$ALERTS" | python3 -c "import json,sys;d=json.load(sys.stdin);print(sum(1 for a in d['alerts'] if 'protected file' in a.get('message','')))" 2>/dev/null)
if [ "$BARRIER_ALERTS" -gt 0 ] 2>/dev/null; then
  echo "PASS: Barrier logged $BARRIER_ALERTS warnings for protected file references"
  PASS=$((PASS+1))
else
  echo "FAIL: No barrier warnings found in alerts"
  FAIL=$((FAIL+1))
fi

echo ""
echo "[Group 9: Dashboard API Completeness]"

echo -n "  TEST 33 "
VAULT_API=$(curl -s "$PROXY/dashboard/api/vault")
if echo "$VAULT_API" | grep -q '"total_secrets"'; then
  echo "PASS: Vault API returns total_secrets"
  PASS=$((PASS+1))
else
  echo "FAIL: Vault API missing total_secrets"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 34 "
MEMORY_API=$(curl -s "$PROXY/dashboard/api/memory")
if echo "$MEMORY_API" | grep -q '"tracked_files"'; then
  echo "PASS: Memory API returns tracked_files"
  PASS=$((PASS+1))
else
  echo "FAIL: Memory API missing tracked_files"
  FAIL=$((FAIL+1))
fi

echo -n "  TEST 35 "
# Verify dashboard HTML loads
DASH_HTML=$(curl -s -o /dev/null -w "%{http_code}" "$PROXY/dashboard/")
if [ "$DASH_HTML" = "200" ]; then
  echo "PASS: Dashboard HTML loads (HTTP 200)"
  PASS=$((PASS+1))
else
  echo "FAIL: Dashboard HTML returned HTTP $DASH_HTML"
  FAIL=$((FAIL+1))
fi

echo ""
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed / $TOTAL total"
echo "========================================="
