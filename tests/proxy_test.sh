#!/bin/bash
# 20 end-to-end tests through Aegis proxy → LM Studio (qwen3-8b)
# Aegis must be running on 3141, LMS on 1234

PROXY="http://localhost:3141"
MODEL="qwen/qwen3-8b"
PASS=0
FAIL=0

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

echo "========================================="
echo "  Aegis Proxy Tests (20 tests)"
echo "  Proxy: $PROXY → LM Studio"
echo "  Model: $MODEL"
echo "========================================="
echo ""

# --- Basic chat completions ---

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
echo "========================================="
echo "  Results: $PASS passed, $FAIL failed / 20 total"
echo "========================================="
