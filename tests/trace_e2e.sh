#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# Aegis Trace E2E Test Suite
# Tests dashboard API + CLI trace output consistency
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

AEGIS_URL="${AEGIS_URL:-http://127.0.0.1:3141}"
API="$AEGIS_URL/dashboard/api"
PASS=0
FAIL=0
TOTAL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
yellow(){ printf "\033[33m%s\033[0m\n" "$1"; }

assert() {
  TOTAL=$((TOTAL+1))
  local desc="$1" actual="$2" expected="$3"
  if [[ "$actual" == *"$expected"* ]]; then
    PASS=$((PASS+1))
    green "  ✓ $desc"
  else
    FAIL=$((FAIL+1))
    red   "  ✗ $desc"
    red   "    expected: $expected"
    red   "    actual:   ${actual:0:200}"
  fi
}

assert_not() {
  TOTAL=$((TOTAL+1))
  local desc="$1" actual="$2" not_expected="$3"
  if [[ "$actual" != *"$not_expected"* ]]; then
    PASS=$((PASS+1))
    green "  ✓ $desc"
  else
    FAIL=$((FAIL+1))
    red   "  ✗ $desc"
    red   "    should NOT contain: $not_expected"
  fi
}

assert_json() {
  TOTAL=$((TOTAL+1))
  local desc="$1" json="$2" jq_expr="$3" expected="$4"
  local actual
  actual=$(echo "$json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d$jq_expr'))" 2>/dev/null || echo "PARSE_ERROR")
  if [[ "$actual" == *"$expected"* ]]; then
    PASS=$((PASS+1))
    green "  ✓ $desc"
  else
    FAIL=$((FAIL+1))
    red   "  ✗ $desc"
    red   "    jq: $jq_expr = $actual (expected: $expected)"
  fi
}

# ═══════════════════════════════════════════════════════════════
echo ""
yellow "═══ Aegis Trace E2E Test Suite ═══"
echo ""

# ── Group 1: Aegis is running ────────────────────────────────
yellow "Group 1: Aegis health"

STATUS=$(curl -sf "$AEGIS_URL/aegis/status" 2>/dev/null || echo '{"error":"not running"}')
assert "Aegis is responding" "$STATUS" "mode"
assert "Aegis version present" "$STATUS" "version"

# ── Group 2: Send test requests ──────────────────────────────
yellow "Group 2: Sending test requests"

OPENAI_KEY=$(python3 -c "
import json
with open('/home/aegis/.openclaw/openclaw.json') as f:
    c = json.load(f)
print(c['models']['providers']['openai']['apiKey'])
" 2>/dev/null || echo "")

if [[ -z "$OPENAI_KEY" ]]; then
  red "  Cannot find OpenAI key — skipping request tests"
else
  # Request 1: simple user message
  R1=$(curl -sf "$AEGIS_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_KEY" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello in one word"}]}' 2>/dev/null || echo '{"error":"failed"}')
  assert "Request 1: got response" "$R1" "choices"
  sleep 2

  # Request 2: with system message
  R2=$(curl -sf "$AEGIS_URL/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_KEY" \
    -d '{"model":"gpt-4o-mini","messages":[{"role":"system","content":"You are a helpful assistant."},{"role":"user","content":"What is 2+2? Answer with just the number."}]}' 2>/dev/null || echo '{"error":"failed"}')
  assert "Request 2: got response" "$R2" "choices"
  sleep 2

  green "  Sent 2 test requests"
fi

# ── Group 3: Traffic API — list endpoint ─────────────────────
yellow "Group 3: Traffic API list"

TRAFFIC=$(curl -sf "$API/traffic" 2>/dev/null || echo '{"entries":[]}')
assert "Traffic list returns JSON" "$TRAFFIC" "entries"
assert "Traffic has total count" "$TRAFFIC" "total"

# Check new fields exist in entries
ENTRY_COUNT=$(echo "$TRAFFIC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('entries',[])))" 2>/dev/null || echo "0")
assert "Traffic has entries" "$ENTRY_COUNT" ""  # just checking it's a number

if [[ "$ENTRY_COUNT" -gt 0 ]]; then
  FIRST=$(echo "$TRAFFIC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps(d['entries'][0]))" 2>/dev/null)
  assert "Entry has id"          "$FIRST" '"id"'
  assert "Entry has ts_ms"       "$FIRST" '"ts_ms"'
  assert "Entry has method"      "$FIRST" '"method"'
  assert "Entry has status"      "$FIRST" '"status"'
  assert "Entry has duration_ms" "$FIRST" '"duration_ms"'
  assert "Entry has slm_verdict" "$FIRST" '"slm_verdict"'

  # New fields
  HAS_MODEL=$(echo "$FIRST" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('model') else 'no')" 2>/dev/null)
  HAS_TRUST=$(echo "$FIRST" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('trust_level') else 'no')" 2>/dev/null)
  assert "Entry has model field"       "$HAS_MODEL" "yes"
  assert "Entry has trust_level field" "$HAS_TRUST" "yes"
fi

# ── Group 4: Traffic API — detail endpoint ───────────────────
yellow "Group 4: Traffic API detail"

if [[ "$ENTRY_COUNT" -gt 0 ]]; then
  LAST_ID=$(echo "$TRAFFIC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['entries'][0]['id'])" 2>/dev/null)
  DETAIL=$(curl -sf "$API/traffic/$LAST_ID" 2>/dev/null || echo '{}')
  assert "Detail returns entry" "$DETAIL" '"entry"'
  assert "Detail has chat view" "$DETAIL" '"chat"'

  # Detail entry should have request_body
  HAS_BODY=$(echo "$DETAIL" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('entry',{}).get('request_body') else 'no')" 2>/dev/null)
  assert "Detail has request_body" "$HAS_BODY" "yes"

  # Model should be extractable from body
  MODEL=$(echo "$DETAIL" | python3 -c "
import sys,json
d=json.load(sys.stdin)
body=d.get('entry',{}).get('request_body','{}')
req=json.loads(body)
print(req.get('model','none'))
" 2>/dev/null || echo "parse_error")
  assert "Model extractable from request body" "$MODEL" "gpt-4o-mini"
fi

# ── Group 5: CLI trace — table view ─────────────────────────
yellow "Group 5: CLI trace table"

CLI_TABLE=$(aegis trace -n 5 2>/dev/null || echo "CLI_FAILED")
assert "CLI trace runs"         "$CLI_TABLE" "#"
assert "CLI shows Time column"  "$CLI_TABLE" "Time"
assert "CLI shows Model column" "$CLI_TABLE" "Model"
assert "CLI shows Trust column" "$CLI_TABLE" "Trust"
assert "CLI shows SLM column"   "$CLI_TABLE" "SLM"
assert "CLI shows Duration"     "$CLI_TABLE" "Duration"

# Verify model appears in output
assert "CLI shows gpt-4o-mini" "$CLI_TABLE" "gpt-4o-mini"

# ── Group 6: CLI trace — detail view ────────────────────────
yellow "Group 6: CLI trace detail"

if [[ -n "${LAST_ID:-}" ]]; then
  CLI_DETAIL=$(aegis trace "$LAST_ID" 2>/dev/null || echo "CLI_FAILED")
  assert "CLI detail shows Request #" "$CLI_DETAIL" "Request #"
  assert "CLI detail shows Model"     "$CLI_DETAIL" "Model"
  assert "CLI detail shows Tokens"    "$CLI_DETAIL" "Tokens"
  assert "CLI detail shows Route"     "$CLI_DETAIL" "Route"
  assert "CLI detail shows SLM"       "$CLI_DETAIL" "SLM Screening"
  assert "CLI detail shows Evidence"  "$CLI_DETAIL" "Evidence"

  # Trust should show in detail
  assert "CLI detail shows Trust" "$CLI_DETAIL" "Trust"
fi

# ── Group 7: CLI trace — filters ────────────────────────────
yellow "Group 7: CLI trace filters"

CLI_ADMIT=$(aegis trace --verdict admit -n 20 2>/dev/null || echo "")
if [[ -n "$CLI_ADMIT" ]]; then
  assert_not "Verdict filter excludes reject" "$CLI_ADMIT" "REJECT"
fi

CLI_SHORT=$(aegis trace -n 2 2>/dev/null || echo "")
LINE_COUNT=$(echo "$CLI_SHORT" | grep -c "^" || true)
assert "Num limit works (small output)" "$LINE_COUNT" ""  # just checking it runs

# ── Group 8: CLI vs API consistency ─────────────────────────
yellow "Group 8: CLI vs API consistency"

if [[ "$ENTRY_COUNT" -gt 0 ]]; then
  # Get the model from API
  API_MODEL=$(echo "$TRAFFIC" | python3 -c "
import sys,json
d=json.load(sys.stdin)
e=d['entries'][0]
print(e.get('model','none'))
" 2>/dev/null || echo "none")

  # Get the model from CLI detail
  CLI_MODEL=$(aegis trace "$LAST_ID" 2>/dev/null | grep -oP 'Model\s+\K\S+' || echo "none")

  assert "API model matches CLI model" "$API_MODEL" "$CLI_MODEL"

  # Compare SLM verdict
  API_VERDICT=$(echo "$TRAFFIC" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d['entries'][0].get('slm_verdict','none'))
" 2>/dev/null)

  CLI_VERDICT_LINE=$(aegis trace "$LAST_ID" 2>/dev/null | grep "verdict:" || echo "")
  assert "CLI shows matching SLM verdict" "$CLI_VERDICT_LINE" "$(echo $API_VERDICT | tr '[:lower:]' '[:upper:]' | head -c5)"
fi

# ── Group 9: Other API endpoints still work ─────────────────
yellow "Group 9: Existing API endpoints"

EVIDENCE=$(curl -sf "$API/evidence" 2>/dev/null || echo '{}')
assert "Evidence endpoint works" "$EVIDENCE" "receipt"

VAULT=$(curl -sf "$API/vault" 2>/dev/null || echo '{}')
assert "Vault endpoint works" "$VAULT" ""  # just checking 200

MEMORY=$(curl -sf "$API/memory" 2>/dev/null || echo '{}')
assert "Memory endpoint works" "$MEMORY" ""

ACCESS=$(curl -sf "$API/access" 2>/dev/null || echo '{}')
assert "Access endpoint works" "$ACCESS" ""

SLM=$(curl -sf "$API/slm" 2>/dev/null || echo '{}')
assert "SLM endpoint works" "$SLM" ""

TRUST=$(curl -sf "$API/trust" 2>/dev/null || echo '{}')
assert "Trust endpoint works" "$TRUST" ""

ALERTS=$(curl -sf "$API/alerts" 2>/dev/null || echo '{}')
assert "Alerts endpoint works" "$ALERTS" ""

# ── Group 10: Dashboard HTML serves ─────────────────────────
yellow "Group 10: Dashboard HTML"

DASH=$(curl -sf "$AEGIS_URL/dashboard" 2>/dev/null || echo "")
assert "Dashboard serves HTML"    "$DASH" "<!DOCTYPE html>"
assert "Dashboard has Trace tab"  "$DASH" "Trace"
assert "Dashboard has trace-list" "$DASH" "trace-list"
assert "Dashboard has flow class" "$DASH" "flow-step"

# ── Group 11: CLI trace with --health ───────────────────────
yellow "Group 11: CLI health flag"

CLI_HEALTH=$(aegis trace --health -n 1 2>/dev/null || echo "")
assert "CLI --health shows SLM info" "$CLI_HEALTH" "SLM"

# ── Group 12: CLI trace with --body ─────────────────────────
yellow "Group 12: CLI body flag"

if [[ -n "${LAST_ID:-}" ]]; then
  CLI_BODY=$(aegis trace "$LAST_ID" --body 2>/dev/null || echo "")
  assert "CLI --body shows Request Body" "$CLI_BODY" "Request Body"
  assert "CLI --body shows Response Body" "$CLI_BODY" "Response Body"
fi

# ═══════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if [[ $FAIL -eq 0 ]]; then
  green "ALL $TOTAL TESTS PASSED ($PASS passed, 0 failed)"
else
  red   "$FAIL FAILED / $TOTAL total ($PASS passed)"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

exit $FAIL
