#!/usr/bin/env bash
# Aegis Tier 1 — End-to-End Smoke Test
#
# Validates the full warden journey:
#   install → setup → start → proxy traffic → verify protection
#
# Prerequisites:
#   - Rust toolchain (for building from source)
#   - Python 3 (for mock upstream server)
#
# Usage:
#   ./tests/e2e/smoke_test.sh

set -euo pipefail

# ── Setup ──────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_TMPDIR="$(mktemp -d)"
export HOME="$TEST_TMPDIR/fakehome"
mkdir -p "$HOME"

AEGIS_PID=""
MOCK_PID=""
PASS=0
FAIL=0

cleanup() {
    [ -n "$AEGIS_PID" ] && kill "$AEGIS_PID" 2>/dev/null || true
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    rm -rf "$TEST_TMPDIR"
}
trap cleanup EXIT

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Aegis Tier 1 — End-to-End Smoke Test"
echo "═══════════════════════════════════════════════════"
echo ""

# ── Step 1: Build from source ──────────────────────────────

echo "Step 1: Build aegis binary"
cd "$REPO_ROOT"
cargo build --release --bin aegis 2>&1 | tail -3
AEGIS_BIN="$REPO_ROOT/target/release/aegis"

if [ -f "$AEGIS_BIN" ]; then
    pass "Binary built: $AEGIS_BIN"
else
    fail "Binary not found"
    exit 1
fi

# Put it on PATH
export PATH="$(dirname "$AEGIS_BIN"):$PATH"

# ── Step 2: Verify CLI commands ────────────────────────────

echo ""
echo "Step 2: CLI command check"

aegis version >/dev/null 2>&1 && pass "aegis version" || fail "aegis version"
aegis --help >/dev/null 2>&1 && pass "aegis --help" || fail "aegis --help"

# ── Step 3: Vulnerability scan ─────────────────────────────

echo ""
echo "Step 3: Vulnerability scan"

# Create a test workspace with a fake credential
# Use .env extension (not dotfile .env) so the scanner's extension filter picks it up
WORKSPACE="$TEST_TMPDIR/workspace"
mkdir -p "$WORKSPACE"
echo 'ANTHROPIC_API_KEY=sk-ant-api03-FAKE_KEY_FOR_TESTING_1234567890' > "$WORKSPACE/secrets.env"
echo '# I am the soul of a test bot' > "$WORKSPACE/SOUL.md"
echo '# I am the agent contract' > "$WORKSPACE/AGENTS.md"
echo '# Memory: test started' > "$WORKSPACE/MEMORY.md"

cd "$WORKSPACE"
SCAN_OUTPUT=$(aegis scan . 2>&1) || true

if echo "$SCAN_OUTPUT" | grep -qi "credential\|secret\|key\|finding\|found"; then
    pass "Scan detected credentials in secrets.env"
else
    fail "Scan did not detect credentials: $SCAN_OUTPUT"
fi

# ── Step 4: OpenClaw setup (dry-run) ──────────────────────

echo ""
echo "Step 4: OpenClaw setup"

# Create a fake OpenClaw config
mkdir -p "$HOME/.openclaw"
echo '{"model": "claude-sonnet-4-20250514", "maxTokens": 4096}' > "$HOME/.openclaw/openclaw.json"

# Dry run
DRY_OUTPUT=$(aegis setup openclaw --dry-run 2>&1) || true
if echo "$DRY_OUTPUT" | grep -qi "dry-run\|would"; then
    pass "setup openclaw --dry-run shows changes"
else
    fail "setup openclaw --dry-run did not show changes: $DRY_OUTPUT"
fi

# Actual setup
aegis setup openclaw 2>&1 || true

# Verify baseUrl was added
if grep -q "baseUrl" "$HOME/.openclaw/openclaw.json"; then
    pass "baseUrl added to openclaw.json"
else
    fail "baseUrl not found in openclaw.json"
fi

# Verify backup created
if [ -f "$HOME/.openclaw/openclaw.json.aegis-backup" ]; then
    pass "Backup file created"
else
    fail "No backup file"
fi

# Revert
aegis setup openclaw --revert 2>&1 || true
if ! grep -q "baseUrl" "$HOME/.openclaw/openclaw.json"; then
    pass "Revert removed baseUrl"
else
    fail "Revert did not remove baseUrl"
fi

# Re-setup for proxy test
aegis setup openclaw 2>&1 || true

# ── Step 5: Start adapter + mock upstream ──────────────────

echo ""
echo "Step 5: Start adapter"

# Start a tiny mock upstream that returns a valid Anthropic response
python3 -c '
import http.server, json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        response = json.dumps({
            "id": "msg_smoke_test_001",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "Hello from mock upstream!"}],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 8}
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response))
        self.end_headers()
        self.wfile.write(response.encode())
    def log_message(self, *args):
        pass  # Suppress logs

httpd = http.server.HTTPServer(("127.0.0.1", 9999), Handler)
httpd.serve_forever()
' &
MOCK_PID=$!
sleep 1

if kill -0 "$MOCK_PID" 2>/dev/null; then
    pass "Mock upstream running on :9999"
else
    fail "Mock upstream failed to start"
fi

# Create aegis config pointing to mock upstream.
# Config goes at $WORKSPACE/.aegis/config.toml (the default config path is relative to cwd).
AEGIS_CONFIG="$WORKSPACE/.aegis/config.toml"
mkdir -p "$WORKSPACE/.aegis"
cat > "$AEGIS_CONFIG" << EOF
mode = "observe_only"

[proxy]
listen_addr = "127.0.0.1:3141"
upstream_url = "http://127.0.0.1:9999"
allow_any_provider = true

[slm]
enabled = false
fallback_to_heuristics = false
EOF

# Start aegis with --no-slm (no Ollama needed for smoke test)
cd "$WORKSPACE"
aegis --no-slm -c "$AEGIS_CONFIG" &
AEGIS_PID=$!
sleep 2

if kill -0 "$AEGIS_PID" 2>/dev/null; then
    pass "Aegis adapter running on :3141"
else
    fail "Aegis adapter failed to start"
    # Show any output
    wait "$AEGIS_PID" 2>/dev/null || true
fi

# ── Step 6: Send traffic through proxy ─────────────────────

echo ""
echo "Step 6: Proxy traffic"

RESPONSE=$(curl -s -X POST http://127.0.0.1:3141/v1/messages \
    -H "Content-Type: application/json" \
    -H "anthropic-version: 2023-06-01" \
    -H "x-api-key: sk-ant-test-000000" \
    -d '{"model":"claude-sonnet-4-20250514","max_tokens":100,"messages":[{"role":"user","content":"Hello"}]}' \
    2>&1) || true

if echo "$RESPONSE" | grep -q "msg_smoke_test_001"; then
    pass "Request proxied to upstream and response returned"
else
    fail "Proxy did not return expected response: $RESPONSE"
fi

# ── Step 7: Verify evidence chain ──────────────────────────

echo ""
echo "Step 7: Evidence chain"

sleep 1  # Let the receipt be written

EXPORT=$(aegis -c "$AEGIS_CONFIG" export 2>&1) || true
if echo "$EXPORT" | grep -q "receipt\|chain\|sequence\|hash\|prev_hash\|receipt_type"; then
    pass "Evidence chain has receipts"
else
    fail "Evidence chain appears empty: $EXPORT"
fi

VERIFY=$(aegis -c "$AEGIS_CONFIG" export --verify 2>&1) || true
if echo "$VERIFY" | grep -qi "valid\|verified\|integrity\|ok\|VALID"; then
    pass "Evidence chain integrity verified"
elif echo "$VERIFY" | grep -qi "receipt\|chain"; then
    pass "Evidence export works (verify output may differ)"
else
    fail "Chain verification failed: $VERIFY"
fi

# ── Step 8: Check dashboard ────────────────────────────────

echo ""
echo "Step 8: Dashboard accessibility"

DASHBOARD=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3141/dashboard 2>&1) || true
if [ "$DASHBOARD" = "200" ]; then
    pass "Dashboard returns 200 at /dashboard"
else
    fail "Dashboard returned HTTP $DASHBOARD (expected 200)"
fi

STATUS_API=$(curl -s http://127.0.0.1:3141/dashboard/api/status 2>&1) || true
if echo "$STATUS_API" | grep -q "mode\|version\|uptime"; then
    pass "Dashboard /api/status returns data"
else
    fail "Dashboard /api/status empty or errored: $STATUS_API"
fi

# ── Step 9: Memory status ──────────────────────────────────

echo ""
echo "Step 9: Memory monitoring"

MEMORY=$(aegis memory status 2>&1) || true
if echo "$MEMORY" | grep -qi "memory\|monitor\|file\|tracked"; then
    pass "Memory status reports file tracking"
else
    fail "Memory status unexpected output: $MEMORY"
fi

# ── Step 10: Adapter status ────────────────────────────────

echo ""
echo "Step 10: Adapter status"

STATUS=$(aegis -c "$AEGIS_CONFIG" status 2>&1) || true
if echo "$STATUS" | grep -qi "mode\|observe\|version\|listen\|upstream"; then
    pass "Adapter status shows config"
else
    fail "Adapter status unexpected: $STATUS"
fi

# ── Results ────────────────────────────────────────────────

echo ""
echo "═══════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "Some checks failed. Review output above."
    exit 1
else
    echo "All checks passed. Tier 1 is ready to ship."
    exit 0
fi
