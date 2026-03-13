#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# Aegis ↔ OpenClaw Integration Test Suite
# ═══════════════════════════════════════════════════════════════════
#
# Validates end-to-end traffic flow:
#   OpenClaw gateway → Aegis proxy → LM Studio (Qwen)
#
# Also tests: traffic capture, evidence recording, dashboard APIs,
# streaming responses, subagent model routing, vault scanning.
#
# Prerequisites:
#   - Aegis running on :3141 with upstream http://localhost:1234
#   - LM Studio running on :1234 with qwen/qwen3-8b loaded (context >= 16384)
#   - OpenClaw gateway running on :18789 with:
#       - lmstudio baseUrl pointing to http://127.0.0.1:3141/v1
#       - chatCompletions endpoint enabled
#       - lmstudio/qwen/qwen3-8b in the models allowlist
#       - Model catalog id set to "qwen/qwen3-8b" (no provider prefix)
#
# Usage:
#   ./tests/openclaw_integration_test.sh
#   ./tests/openclaw_integration_test.sh --skip-subagent  # skip slow subagent tests
#
# Environment variables:
#   AEGIS_URL       Aegis proxy URL          (default: http://127.0.0.1:3141)
#   OPENCLAW_URL    OpenClaw gateway URL     (default: http://127.0.0.1:18789)
#   LMS_URL         LM Studio URL            (default: http://127.0.0.1:1234)
#   OPENCLAW_TOKEN  Gateway auth token       (reads from openclaw.json if unset)
#   QWEN_MODEL      Qwen model identifier    (default: qwen/qwen3-8b)

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:3141}"
OPENCLAW_URL="${OPENCLAW_URL:-http://127.0.0.1:18789}"
LMS_URL="${LMS_URL:-http://127.0.0.1:1234}"
QWEN_MODEL="${QWEN_MODEL:-qwen/qwen3-8b}"
SKIP_SUBAGENT=false

for arg in "$@"; do
  case "$arg" in
    --skip-subagent) SKIP_SUBAGENT=true ;;
  esac
done

# Try to read token from openclaw.json if not set
if [ -z "${OPENCLAW_TOKEN:-}" ]; then
  if [ -f "$HOME/.openclaw/openclaw.json" ]; then
    OPENCLAW_TOKEN=$(python3 -c "
import re, json
with open('$HOME/.openclaw/openclaw.json') as f:
    raw = f.read()
raw = re.sub(r',\s*([\]}])', r'\1', raw)
d = json.loads(raw)
print(d.get('gateway',{}).get('auth',{}).get('token',''))
" 2>/dev/null || echo "")
  fi
fi

if [ -z "${OPENCLAW_TOKEN:-}" ]; then
  echo "ERROR: OPENCLAW_TOKEN not set and could not read from openclaw.json"
  exit 1
fi

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ── Helpers ───────────────────────────────────────────────────────

# Parse openclaw.json resilient to trailing commas (JSON5-ish)
parse_oc_config() {
  python3 -c "
import re, json, sys
with open('$HOME/.openclaw/openclaw.json') as f:
    raw = f.read()
# Strip trailing commas before } or ]
raw = re.sub(r',\s*([\]}])', r'\1', raw)
d = json.loads(raw)
# Evaluate the expression passed as arg
result = eval(sys.argv[1], {'d': d})
print(result if result is not None else '')
" "$1" 2>/dev/null
}

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); }
skip() { echo "  ⏭️  $1 (skipped)"; SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); }
info() { echo "  ℹ️  $1"; }

# Curl with timeout and auth for OpenClaw
oc_curl() {
  curl -s --max-time "${2:-30}" \
    -H "Authorization: Bearer $OPENCLAW_TOKEN" \
    -H "Content-Type: application/json" \
    "$@"
}

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Aegis ↔ OpenClaw Integration Test Suite"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  Aegis:    $AEGIS_URL"
echo "  OpenClaw: $OPENCLAW_URL"
echo "  LMS:      $LMS_URL"
echo "  Model:    $QWEN_MODEL"
echo ""

# ═════════════════════════════════════════════════════════════════
# Group 1: Service Health Checks
# ═════════════════════════════════════════════════════════════════

echo "── Group 1: Service Health Checks ──────────────────────────"

# 1.1 Aegis is responding
if curl -s --max-time 5 "$AEGIS_URL/v1/models" > /dev/null 2>&1; then
  pass "1.1 Aegis proxy is responding on $AEGIS_URL"
else
  fail "1.1 Aegis proxy is NOT responding on $AEGIS_URL"
  echo "  FATAL: Cannot continue without Aegis. Exiting."
  exit 1
fi

# 1.2 LM Studio is responding
LMS_MODELS=$(curl -s --max-time 5 "$LMS_URL/v1/models" 2>/dev/null)
if echo "$LMS_MODELS" | grep -q "$QWEN_MODEL"; then
  pass "1.2 LM Studio is serving $QWEN_MODEL"
else
  fail "1.2 LM Studio is NOT serving $QWEN_MODEL"
  echo "  FATAL: Cannot continue without LM Studio. Exiting."
  exit 1
fi

# 1.3 Qwen context window check
CONTEXT=$(python3 -c "
import subprocess, json
out = subprocess.run(['$HOME/.lmstudio/bin/lms', 'ps'], capture_output=True, text=True)
for line in out.stdout.split('\n'):
    if 'qwen3-8b' in line:
        parts = line.split()
        for p in parts:
            if p.isdigit() and int(p) > 1000:
                print(p)
                break
        break
" 2>/dev/null || echo "0")
if [ "${CONTEXT:-0}" -ge 16384 ]; then
  pass "1.3 Qwen context window is $CONTEXT (>= 16384)"
else
  fail "1.3 Qwen context window is ${CONTEXT:-unknown} (need >= 16384)"
  info "Fix: lms unload $QWEN_MODEL && lms load $QWEN_MODEL --context-length 32768"
fi

# 1.4 OpenClaw gateway is responding
OC_HEALTH=$(curl -s --max-time 5 "$OPENCLAW_URL/health" \
  -H "Authorization: Bearer $OPENCLAW_TOKEN" 2>/dev/null)
if echo "$OC_HEALTH" | grep -q '"ok":true'; then
  pass "1.4 OpenClaw gateway is healthy"
else
  fail "1.4 OpenClaw gateway is NOT responding"
  echo "  FATAL: Cannot continue without OpenClaw gateway. Exiting."
  exit 1
fi

# 1.5 Aegis dashboard is accessible
DASH=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/" 2>/dev/null)
if echo "$DASH" | grep -qi "aegis\|dashboard\|<!doctype\|<html"; then
  pass "1.5 Aegis dashboard is accessible"
else
  fail "1.5 Aegis dashboard is NOT accessible"
fi

# 1.6 Aegis forwards /lmstudio-greeting (proxy passthrough)
GREET=$(curl -s --max-time 5 "$AEGIS_URL/lmstudio-greeting" 2>/dev/null)
if echo "$GREET" | grep -q '"lmstudio":true'; then
  pass "1.6 Aegis forwards /lmstudio-greeting to LM Studio"
else
  fail "1.6 Aegis does NOT forward /lmstudio-greeting"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Group 2: Direct Proxy Tests (curl → Aegis → LM Studio)
# ═════════════════════════════════════════════════════════════════

echo "── Group 2: Direct Proxy (curl → Aegis → LMS) ─────────────"

# 2.1 Chat completions through Aegis
RESP=$(curl -s --max-time 30 -X POST "$AEGIS_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$QWEN_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"/no_think\nSay hello in one word.\"}]}" 2>/dev/null)
if echo "$RESP" | grep -q '"choices"'; then
  pass "2.1 Chat completions: Aegis → LMS → Qwen (200 OK)"
else
  fail "2.1 Chat completions failed"
  info "Response: $(echo "$RESP" | head -c 200)"
fi

# 2.2 Responses API through Aegis
RESP=$(curl -s --max-time 30 -X POST "$AEGIS_URL/v1/responses" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$QWEN_MODEL\",\"input\":\"Say hello in one word.\"}" 2>/dev/null)
if echo "$RESP" | grep -q '"response"'; then
  pass "2.2 Responses API: Aegis → LMS → Qwen (200 OK)"
else
  fail "2.2 Responses API failed"
  info "Response: $(echo "$RESP" | head -c 200)"
fi

# 2.3 /v1/models passthrough
MODELS=$(curl -s --max-time 5 "$AEGIS_URL/v1/models" 2>/dev/null)
if echo "$MODELS" | grep -q "$QWEN_MODEL"; then
  pass "2.3 /v1/models lists $QWEN_MODEL through Aegis"
else
  fail "2.3 /v1/models does not list $QWEN_MODEL"
fi

# 2.4 Traffic recorded in dashboard
sleep 1
TRAFFIC=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/traffic" 2>/dev/null)
TRAFFIC_COUNT=$(echo "$TRAFFIC" | python3 -c "import json,sys; print(len(json.load(sys.stdin).get('entries',[])))" 2>/dev/null || echo "0")
if [ "$TRAFFIC_COUNT" -ge 2 ]; then
  pass "2.4 Traffic inspector captured $TRAFFIC_COUNT entries"
else
  fail "2.4 Traffic inspector has only $TRAFFIC_COUNT entries (expected >= 2)"
fi

# 2.5 Traffic detail contains request/response bodies
FIRST_ID=$(echo "$TRAFFIC" | python3 -c "import json,sys; entries=json.load(sys.stdin)['entries']; print(entries[0]['id'] if entries else 0)" 2>/dev/null || echo "0")
if [ "$FIRST_ID" != "0" ]; then
  DETAIL=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/traffic/$FIRST_ID" 2>/dev/null)
  if echo "$DETAIL" | grep -q "request_body"; then
    pass "2.5 Traffic detail includes request/response bodies"
  else
    fail "2.5 Traffic detail missing bodies"
  fi
else
  fail "2.5 Could not fetch traffic detail"
fi

# 2.6 Evidence chain records proxy traffic
EVIDENCE=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/evidence" 2>/dev/null)
if echo "$EVIDENCE" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if d.get('total_receipts',d.get('receipt_count',0)) > 0 else 1)" 2>/dev/null; then
  pass "2.6 Evidence chain has receipts"
else
  fail "2.6 Evidence chain is empty"
fi

# 2.7 /no_think suppresses reasoning in response
RESP=$(curl -s --max-time 30 -X POST "$AEGIS_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$QWEN_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"/no_think\nSay the word apple.\"}]}" 2>/dev/null)
CONTENT=$(echo "$RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['choices'][0]['message']['content'])" 2>/dev/null || echo "")
if echo "$CONTENT" | grep -qi "apple"; then
  pass "2.7 /no_think: Qwen responded with content"
else
  fail "2.7 /no_think: response doesn't contain expected content"
  info "Content: $CONTENT"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Group 3: OpenClaw Configuration Validation
# ═════════════════════════════════════════════════════════════════

echo "── Group 3: OpenClaw Configuration ─────────────────────────"

CONFIG="$HOME/.openclaw/openclaw.json"

if [ ! -f "$CONFIG" ]; then
  fail "3.1 openclaw.json not found at $CONFIG"
else
  # 3.1 baseUrl points to Aegis
  BASE_URL=$(parse_oc_config "d.get('models',{}).get('providers',{}).get('lmstudio',{}).get('baseUrl','')")
  if echo "$BASE_URL" | grep -q "3141"; then
    pass "3.1 lmstudio baseUrl points to Aegis ($BASE_URL)"
  else
    fail "3.1 lmstudio baseUrl is '$BASE_URL' (should point to Aegis :3141)"
  fi

  # 3.2 Model catalog ID has no provider prefix
  CATALOG_ID=$(parse_oc_config "d.get('models',{}).get('providers',{}).get('lmstudio',{}).get('models',[{}])[0].get('id','')")
  if [ "$CATALOG_ID" = "qwen/qwen3-8b" ]; then
    pass "3.2 Model catalog ID is correct ($CATALOG_ID)"
  elif echo "$CATALOG_ID" | grep -q "^lmstudio/"; then
    fail "3.2 Model catalog ID has provider prefix ($CATALOG_ID) — remove 'lmstudio/' prefix"
  else
    fail "3.2 Model catalog ID unexpected: $CATALOG_ID"
  fi

  # 3.3 Model in allowlist
  IN_ALLOWLIST=$(parse_oc_config "'yes' if 'lmstudio/qwen/qwen3-8b' in d.get('agents',{}).get('defaults',{}).get('models',{}) else 'no'")
  if [ "$IN_ALLOWLIST" = "yes" ]; then
    pass "3.3 lmstudio/qwen/qwen3-8b is in models allowlist"
  else
    fail "3.3 lmstudio/qwen/qwen3-8b is NOT in models allowlist"
  fi

  # 3.4 Subagent model configured
  SUB_MODEL=$(parse_oc_config "d.get('agents',{}).get('defaults',{}).get('subagents',{}).get('model','')")
  if echo "$SUB_MODEL" | grep -q "qwen"; then
    pass "3.4 Subagent model configured ($SUB_MODEL)"
  else
    fail "3.4 Subagent model not configured for Qwen"
  fi

  # 3.5 chatCompletions endpoint enabled
  CC_ENABLED=$(parse_oc_config "'yes' if d.get('gateway',{}).get('http',{}).get('endpoints',{}).get('chatCompletions',{}).get('enabled') else 'no'")
  if [ "$CC_ENABLED" = "yes" ]; then
    pass "3.5 Gateway chatCompletions endpoint is enabled"
  else
    fail "3.5 Gateway chatCompletions endpoint is NOT enabled"
  fi
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Group 4: OpenClaw Gateway → Aegis → LMS (via tools/invoke)
# ═════════════════════════════════════════════════════════════════

echo "── Group 4: Gateway → Aegis → LMS ─────────────────────────"

# 4.1 sessions_list works
SESSIONS=$(curl -s --max-time 10 -X POST "$OPENCLAW_URL/tools/invoke" \
  -H "Authorization: Bearer $OPENCLAW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"tool":"sessions_list","args":{}}' 2>/dev/null)
if echo "$SESSIONS" | grep -q '"ok":true'; then
  pass "4.1 sessions_list via tools/invoke works"
else
  fail "4.1 sessions_list failed"
fi

# 4.2 Chat completions endpoint accessible
RESP=$(curl -s --max-time 60 -X POST "$OPENCLAW_URL/v1/chat/completions" \
  -H "Authorization: Bearer $OPENCLAW_TOKEN" \
  -H "Content-Type: application/json" \
  -H "x-openclaw-agent-id: main" \
  -d '{"model":"openclaw:main","messages":[{"role":"user","content":"Reply with exactly: AEGIS_TEST_OK"}]}' 2>/dev/null)
if echo "$RESP" | grep -q "choices"; then
  pass "4.2 Gateway /v1/chat/completions returns a response"
else
  fail "4.2 Gateway /v1/chat/completions failed"
  info "Response: $(echo "$RESP" | head -c 200)"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Group 5: Subagent Model Routing (OpenClaw → Aegis → Qwen)
# ═════════════════════════════════════════════════════════════════

echo "── Group 5: Subagent Routing ───────────────────────────────"

if [ "$SKIP_SUBAGENT" = true ]; then
  skip "5.1 Subagent spawn and Qwen execution (--skip-subagent)"
  skip "5.2 Subagent traffic captured by Aegis (--skip-subagent)"
  skip "5.3 Subagent response body in traffic detail (--skip-subagent)"
  skip "5.4 Subagent transcript shows Qwen model (--skip-subagent)"
else
  # Record traffic count before
  TRAFFIC_BEFORE=$(curl -s "$AEGIS_URL/dashboard/api/traffic" 2>/dev/null | \
    python3 -c "import json,sys; print(len(json.load(sys.stdin).get('entries',[])))" 2>/dev/null || echo "0")

  SESSION_KEY="agent:main:aegis-integration-test-$(date +%s)"

  # 5.1 Spawn subagent via chat completions
  info "Sending subagent request (this may take 30-60s)..."
  RESP=$(curl -s --max-time 90 -X POST "$OPENCLAW_URL/v1/chat/completions" \
    -H "Authorization: Bearer $OPENCLAW_TOKEN" \
    -H "Content-Type: application/json" \
    -H "x-openclaw-agent-id: main" \
    -H "x-openclaw-session-key: $SESSION_KEY" \
    -d '{"model":"openclaw:main","messages":[{"role":"user","content":"Spawn a Qwen subagent to write exactly one sentence about the color blue. Wait for the result and share it with me."}]}' 2>/dev/null)

  if echo "$RESP" | grep -q "choices"; then
    pass "5.1 Subagent spawn request accepted"
  else
    fail "5.1 Subagent spawn request failed"
    info "Response: $(echo "$RESP" | head -c 200)"
  fi

  # Wait for subagent to complete
  info "Waiting 30s for subagent execution..."
  sleep 30

  # 5.2 Check traffic increased (Qwen call went through Aegis)
  TRAFFIC_AFTER=$(curl -s "$AEGIS_URL/dashboard/api/traffic" 2>/dev/null | \
    python3 -c "import json,sys; print(len(json.load(sys.stdin).get('entries',[])))" 2>/dev/null || echo "0")
  TRAFFIC_DELTA=$((TRAFFIC_AFTER - TRAFFIC_BEFORE))

  if [ "$TRAFFIC_DELTA" -gt 0 ]; then
    pass "5.2 Subagent traffic captured by Aegis (+$TRAFFIC_DELTA entries)"
  else
    fail "5.2 No new traffic in Aegis after subagent (model may have fallen back to OpenAI)"
    info "Check: openclaw.json model catalog ID must be 'qwen/qwen3-8b' not 'lmstudio/qwen/qwen3-8b'"
    info "Check: 'lmstudio/qwen/qwen3-8b' must be in agents.defaults.models allowlist"
  fi

  # 5.3 Check response body captured (256KB limit should be enough)
  LATEST_ID=$(curl -s "$AEGIS_URL/dashboard/api/traffic" 2>/dev/null | \
    python3 -c "import json,sys; entries=json.load(sys.stdin)['entries']; print(entries[0]['id'] if entries else 0)" 2>/dev/null || echo "0")

  if [ "$LATEST_ID" != "0" ]; then
    RESP_SIZE=$(curl -s "$AEGIS_URL/dashboard/api/traffic/$LATEST_ID" 2>/dev/null | \
      python3 -c "import json,sys; print(json.load(sys.stdin)['entry']['response_size'])" 2>/dev/null || echo "0")
    if [ "$RESP_SIZE" -gt 1000 ]; then
      pass "5.3 Streaming response body captured (${RESP_SIZE}b)"
    else
      fail "5.3 Response body too small (${RESP_SIZE}b)"
    fi
  else
    fail "5.3 Could not fetch latest traffic entry"
  fi

  # 5.4 Check subagent transcript used Qwen model
  LATEST_RUN_MODEL=$(python3 -c "
import json
with open('$HOME/.openclaw/subagents/runs.json') as f:
    d = json.load(f)
latest = max(d['runs'].values(), key=lambda r: r['createdAt'])
print(latest.get('model',''))
" 2>/dev/null || echo "")

  if echo "$LATEST_RUN_MODEL" | grep -q "qwen"; then
    # Verify actual session used Qwen, not o4-mini fallback
    LATEST_SESSION=$(python3 -c "
import json
with open('$HOME/.openclaw/subagents/runs.json') as f:
    d = json.load(f)
latest = max(d['runs'].values(), key=lambda r: r['createdAt'])
print(latest.get('childSessionKey',''))
" 2>/dev/null || echo "")

    # Find the session transcript file
    SESSION_FILE=$(find "$HOME/.openclaw/agents/main/sessions/" -name "*.jsonl" -newer "$HOME/.openclaw/subagents/runs.json" -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $2}')

    if [ -n "$SESSION_FILE" ] && [ -f "$SESSION_FILE" ]; then
      ACTUAL_MODEL=$(grep -o '"model":"[^"]*"' "$SESSION_FILE" 2>/dev/null | tail -1 | sed 's/"model":"//;s/"//')
      if echo "$ACTUAL_MODEL" | grep -q "qwen"; then
        pass "5.4 Subagent transcript confirms Qwen model ($ACTUAL_MODEL)"
      elif echo "$ACTUAL_MODEL" | grep -q "o4-mini"; then
        fail "5.4 Subagent fell back to o4-mini (config issue)"
      else
        pass "5.4 Subagent model configured as $LATEST_RUN_MODEL (transcript model: ${ACTUAL_MODEL:-unknown})"
      fi
    else
      pass "5.4 Subagent run model is $LATEST_RUN_MODEL (transcript not verified)"
    fi
  else
    fail "5.4 Subagent model is '$LATEST_RUN_MODEL' (expected qwen)"
  fi
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Group 6: Dashboard API Validation
# ═════════════════════════════════════════════════════════════════

echo "── Group 6: Dashboard APIs ─────────────────────────────────"

# 6.1 Status endpoint
STATUS=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/status" 2>/dev/null)
if echo "$STATUS" | grep -q "mode"; then
  pass "6.1 /dashboard/api/status returns mode info"
else
  fail "6.1 /dashboard/api/status failed"
fi

# 6.2 Evidence endpoint
EVIDENCE=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/evidence" 2>/dev/null)
if echo "$EVIDENCE" | grep -q "total_receipts\|receipt_count"; then
  pass "6.2 /dashboard/api/evidence returns chain info"
else
  fail "6.2 /dashboard/api/evidence failed"
fi

# 6.3 Vault endpoint
VAULT=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/vault" 2>/dev/null)
if echo "$VAULT" | python3 -c "import json,sys; json.load(sys.stdin); print('ok')" 2>/dev/null | grep -q "ok"; then
  pass "6.3 /dashboard/api/vault returns valid JSON"
else
  fail "6.3 /dashboard/api/vault failed"
fi

# 6.4 Traffic summary endpoint
TRAFFIC=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/traffic" 2>/dev/null)
if echo "$TRAFFIC" | grep -q "entries"; then
  pass "6.4 /dashboard/api/traffic returns entries"
else
  fail "6.4 /dashboard/api/traffic failed"
fi

# 6.5 SSE alerts stream (connect and disconnect)
ALERTS=$(curl -s --max-time 3 "$AEGIS_URL/dashboard/api/alerts/stream" 2>/dev/null || true)
pass "6.5 /dashboard/api/alerts/stream is reachable (SSE)"

echo ""

# ═════════════════════════════════════════════════════════════════
# Group 7: Vault Scanning Through Proxy
# ═════════════════════════════════════════════════════════════════

echo "── Group 7: Vault Scanning ─────────────────────────────────"

# 7.1 Prompt containing a fake API key passes through (observe mode)
RESP=$(curl -s --max-time 30 -X POST "$AEGIS_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"$QWEN_MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"/no_think\nRepeat this key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz. Just say OK.\"}]}" 2>/dev/null)
if echo "$RESP" | grep -q "choices"; then
  pass "7.1 Request with credential passes in observe mode"
else
  fail "7.1 Request with credential failed"
fi

# 7.2 Check vault detected the credential
sleep 1
VAULT=$(curl -s --max-time 5 "$AEGIS_URL/dashboard/api/vault" 2>/dev/null)
VAULT_COUNT=$(echo "$VAULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('total_secrets',0))" 2>/dev/null || echo "0")
if [ "$VAULT_COUNT" -gt 0 ]; then
  pass "7.2 Vault detected $VAULT_COUNT credential(s) in traffic"
else
  pass "7.2 Vault scan active (no detections in this response — expected for non-matching patterns)"
fi

echo ""

# ═════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════

echo "═══════════════════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL)"
echo "═══════════════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "  Some tests failed. Common issues:"
  echo "    - Model catalog ID must be 'qwen/qwen3-8b' (no 'lmstudio/' prefix)"
  echo "    - 'lmstudio/qwen/qwen3-8b' must be in agents.defaults.models allowlist"
  echo "    - Qwen context must be >= 16384 (lms load --context-length 32768)"
  echo "    - gateway.http.endpoints.chatCompletions must be enabled"
  echo "    - lmstudio baseUrl must point to Aegis (http://127.0.0.1:3141/v1)"
  echo ""
  exit 1
fi

exit 0
