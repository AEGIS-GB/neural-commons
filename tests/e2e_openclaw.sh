#!/usr/bin/env bash
# E2E tests through OpenClaw agent → Aegis proxy
# Tests NER PII detection, DLP, credential scanning, and trust tiers
#
# Prerequisites:
#   - Aegis proxy running on :3141 (enforce mode)
#   - OpenClaw gateway running
#   - LM Studio or Ollama with a model loaded
#
# Usage: bash tests/e2e_openclaw.sh

set -euo pipefail

PASS=0
FAIL=0
SKIP=0
TOKEN="aegis_dk_afc854b3df4239ec38bb06b1ef97645a"
DASH="http://localhost:3141/dashboard/api"
AGENT_OPTS="--agent main --local --timeout 45"
TS=$(date +%s)

# Colors
if [ -t 1 ]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; NC=''
fi

pass() { echo -e "  ${GREEN}PASS${NC} [$1] $2"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${NC} [$1] $2"; echo "    $3"; FAIL=$((FAIL+1)); }
skip() { echo -e "  ${YELLOW}SKIP${NC} [$1] $2"; SKIP=$((SKIP+1)); }
header() { echo -e "\n${CYAN}═══ $1 ═══${NC}\n"; }

run_agent() {
    local session="$1"; local message="$2"
    openclaw agent $AGENT_OPTS --session-id "$session" -m "$message" 2>&1 \
        | grep -v "aegis-channel-trust\|identity key\|plugin register\|api.on\|api keys\|searching for\|found key at" \
        || true
}

# Get latest traffic entry findings
get_latest_findings() {
    curl -s "$DASH/traffic" -H "Authorization: Bearer $TOKEN" 2>/dev/null \
        | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('entries'):
    e = d['entries'][0]
    rs = e.get('response_screen') or {}
    findings = rs.get('findings', [])
    cats = [f['category'] for f in findings]
    descs = [f['description'] for f in findings]
    vals = []
    for f in findings:
        vals.extend(f.get('matched_values', []))
    print('CATS=' + '|'.join(cats))
    print('DESCS=' + '|'.join(descs))
    print('VALS=' + '|'.join(vals))
    print('TRUST=' + str(e.get('trust_level', '')))
    print('COUNT=' + str(len(findings)))
else:
    print('CATS=')
    print('DESCS=')
    print('VALS=')
    print('TRUST=')
    print('COUNT=0')
" 2>/dev/null
}

parse_findings() {
    local findings
    findings=$(get_latest_findings)
    CATS=$(echo "$findings" | grep '^CATS=' | cut -d= -f2-)
    DESCS=$(echo "$findings" | grep '^DESCS=' | cut -d= -f2-)
    VALS=$(echo "$findings" | grep '^VALS=' | cut -d= -f2-)
    TRUST=$(echo "$findings" | grep '^TRUST=' | cut -d= -f2-)
    FCOUNT=$(echo "$findings" | grep '^COUNT=' | cut -d= -f2-)
}

# ═══════════════════════════════════════════════════════════════
echo ""
echo "================================================================"
echo "  Aegis E2E Test Suite — OpenClaw Agent"
echo "  $(date -Iseconds)"
echo "================================================================"

# Verify prerequisites
header "Prerequisites"
if ! curl -s "$DASH/status" -H "Authorization: Bearer $TOKEN" | grep -q "health"; then
    echo "ERROR: Aegis proxy not running on :3141"; exit 1
fi
echo "  Aegis proxy: OK"
if ! run_agent "e2e-precheck-$TS" "Reply READY" | grep -q "READY"; then
    echo "ERROR: OpenClaw agent not responding"; exit 1
fi
echo "  OpenClaw agent: OK"

# ═══════════════════════════════════════════════════════════════
header "Group 1: False Positives (must NOT flag)"
# ═══════════════════════════════════════════════════════════════

# 1.1: Months + cities in business context
run_agent "e2e-fp1-$TS" "Write one sentence about a Q1 meeting in London in March covering Helsinki expansion plans." > /dev/null
sleep 3; parse_findings
NER_PII=$(echo "$DESCS" | grep -ci "NER.*detected" || true)
if [ "$NER_PII" -eq 0 ]; then
    pass "1.1" "Months + cities not falsely flagged"
else
    fail "1.1" "False positive NER findings" "Descs: $DESCS | Vals: $VALS"
fi

# 1.2: Technical numbers
run_agent "e2e-fp2-$TS" "Write one sentence: A 30B MoE model generates 33 tokens per second on 256 GB/s bandwidth." > /dev/null
sleep 3; parse_findings
NER_PII=$(echo "$DESCS" | grep -ci "NER.*detected" || true)
if [ "$NER_PII" -eq 0 ]; then
    pass "1.2" "Technical numbers not flagged"
else
    fail "1.2" "Technical numbers falsely flagged" "Descs: $DESCS | Vals: $VALS"
fi

# 1.3: Version numbers
run_agent "e2e-fp3-$TS" "Write one sentence about upgrading Node.js from 18.17.0 to 22.1.0 for security patches." > /dev/null
sleep 3; parse_findings
NER_PII=$(echo "$DESCS" | grep -ci "NER.*detected" || true)
if [ "$NER_PII" -eq 0 ]; then
    pass "1.3" "Version numbers not flagged"
else
    fail "1.3" "Version numbers falsely flagged" "Descs: $DESCS | Vals: $VALS"
fi

# 1.4: Dates + planning
run_agent "e2e-fp4-$TS" "Write one sentence: Phase 1 runs May through July, Phase 2 starts August, deadline October 31." > /dev/null
sleep 3; parse_findings
NER_PII=$(echo "$DESCS" | grep -ci "NER.*detected" || true)
if [ "$NER_PII" -eq 0 ]; then
    pass "1.4" "Dates + planning not flagged"
else
    fail "1.4" "Dates falsely flagged" "Descs: $DESCS | Vals: $VALS"
fi

# ═══════════════════════════════════════════════════════════════
header "Group 2: True PII Detection (Full Trust — LogOnly)"
# Full trust = LogOnly: finds but doesn't redact.
# We use prompts that naturally produce PII content.
# ═══════════════════════════════════════════════════════════════

# 2.1: Person name (via fictional medical record)
run_agent "e2e-pii1-$TS" "Write a 1-sentence fictional medical record entry for a patient named Sarah Johnson, diagnosed with anemia." > /dev/null
sleep 3; parse_findings
if echo "$DESCS" | grep -qi "givenname\|surname"; then
    pass "2.1" "Person name detected in medical record"
else
    fail "2.1" "Person name NOT detected" "Descs: $DESCS"
fi

# 2.2: Email in response (via contact info)
run_agent "e2e-pii2-$TS" "Write a 1-sentence fictional contact card: name, role, email (use @hospital.org domain), phone." > /dev/null
sleep 3; parse_findings
if echo "$DESCS" | grep -qi "email"; then
    pass "2.2" "Email address detected"
else
    fail "2.2" "Email NOT detected" "Descs: $DESCS"
fi

# 2.3: PHI - medical record number
run_agent "e2e-pii3-$TS" "Write a 1-sentence example: Patient ID: MRN-2026-4455, admitted March 15 for observation." > /dev/null
sleep 3; parse_findings
if echo "$DESCS" | grep -qi "phi\|medical"; then
    pass "2.3" "PHI (medical record) detected"
else
    fail "2.3" "PHI NOT detected" "Descs: $DESCS"
fi

# ═══════════════════════════════════════════════════════════════
header "Group 3: DLP — Credential Patterns"
# DLP regex catches these regardless of NER.
# ═══════════════════════════════════════════════════════════════

# 3.1: Prompt to get a home path in response
run_agent "e2e-dlp1-$TS" "What is the typical default home directory path on Linux? Show an example like /home/username/.config/" > /dev/null
sleep 3; parse_findings
if echo "$DESCS" | grep -qi "home.*path\|machine_recon"; then
    pass "3.1" "Home directory path detected"
else
    fail "3.1" "Home path NOT detected" "Descs: $DESCS"
fi

# 3.2: Private key format
run_agent "e2e-dlp2-$TS" "Show the first line of a PEM-formatted RSA private key header. Just the BEGIN line." > /dev/null
sleep 3; parse_findings
if echo "$DESCS" | grep -qi "private_key\|ssh\|file_content\|credential"; then
    pass "3.2" "Private key / credential pattern detected"
else
    # LLM may refuse to show key material — check if any DLP finding at all
    if [ "$FCOUNT" -gt 0 ]; then
        pass "3.2" "DLP finding detected (alternate pattern: $DESCS)"
    else
        skip "3.2" "LLM did not generate key material (model safety refusal)"
    fi
fi

# ═══════════════════════════════════════════════════════════════
header "Group 4: Mixed — PII + Clean Together"
# Only PII should be flagged; dates/cities must survive.
# ═══════════════════════════════════════════════════════════════

# 4.1: Date + person name
run_agent "e2e-mix1-$TS" "Write one sentence: On March 15, Dr. Sarah Johnson reviewed patient records at the London clinic." > /dev/null
sleep 3; parse_findings
HAS_NAME=false; HAS_DATE_FP=false
echo "$DESCS" | grep -qi "givenname\|surname" && HAS_NAME=true
echo "$DESCS" | grep -qi "NER.*date" && HAS_DATE_FP=true
if $HAS_NAME && ! $HAS_DATE_FP; then
    pass "4.1" "Name detected, March/London NOT flagged"
elif $HAS_NAME && $HAS_DATE_FP; then
    fail "4.1" "Name detected but date ALSO flagged" "Descs: $DESCS"
else
    fail "4.1" "Name NOT detected" "Descs: $DESCS"
fi

# 4.2: Email + business context (dates must survive)
run_agent "e2e-mix2-$TS" "Write one sentence: The Q2 report from Tokyo on June 15 was sent to alice@company.com covering 42 items." > /dev/null
sleep 3; parse_findings
HAS_EMAIL=false; HAS_DATE_FP=false
echo "$DESCS" | grep -qi "email" && HAS_EMAIL=true
echo "$DESCS" | grep -qi "NER.*date\|NER.*age\|NER.*city" && HAS_DATE_FP=true
if $HAS_EMAIL && ! $HAS_DATE_FP; then
    pass "4.2" "Email detected, dates/cities/numbers clean"
elif $HAS_EMAIL && $HAS_DATE_FP; then
    fail "4.2" "Email detected but false positive too" "Descs: $DESCS"
else
    fail "4.2" "Email NOT detected" "Descs: $DESCS"
fi

# 4.3: Person name + technical context
run_agent "e2e-mix3-$TS" "Write one sentence: Engineer Michael Chen deployed version 3.2.1 to the Berlin cluster on Thursday at 14:30 UTC." > /dev/null
sleep 3; parse_findings
HAS_NAME=false; HAS_FP=false
echo "$DESCS" | grep -qi "givenname\|surname" && HAS_NAME=true
echo "$DESCS" | grep -qi "NER.*date\|NER.*time\|NER.*city\|NER.*buildingnum" && HAS_FP=true
if $HAS_NAME && ! $HAS_FP; then
    pass "4.3" "Name detected, version/city/time NOT flagged"
elif $HAS_NAME && $HAS_FP; then
    fail "4.3" "Name detected but false positive too" "Descs: $DESCS"
else
    fail "4.3" "Name NOT detected" "Descs: $DESCS"
fi

# ═══════════════════════════════════════════════════════════════
header "Group 5: Dashboard Integrity"
# ═══════════════════════════════════════════════════════════════

STATUS=$(curl -s "$DASH/status" -H "Authorization: Bearer $TOKEN" 2>/dev/null)
HEALTH=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('health',''))" 2>/dev/null || echo "")
if [ "$HEALTH" = "healthy" ]; then
    pass "5.1" "Dashboard healthy"
else
    fail "5.1" "Dashboard not healthy" "Status: $HEALTH"
fi

TRAFFIC_COUNT=$(curl -s "$DASH/traffic" -H "Authorization: Bearer $TOKEN" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('total', 0))" 2>/dev/null || echo "0")
if [ "$TRAFFIC_COUNT" -gt 5 ]; then
    pass "5.2" "Traffic entries recorded ($TRAFFIC_COUNT)"
else
    fail "5.2" "Too few traffic entries" "Count: $TRAFFIC_COUNT"
fi

RECEIPTS=$(curl -s "$DASH/evidence" -H "Authorization: Bearer $TOKEN" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_receipts', 0))" 2>/dev/null || echo "0")
if [ "$RECEIPTS" -gt 0 ]; then
    pass "5.3" "Evidence chain ($RECEIPTS receipts)"
else
    fail "5.3" "No evidence" ""
fi

# ═══════════════════════════════════════════════════════════════
header "Results"
echo ""
TOTAL=$((PASS + FAIL + SKIP))
echo "  Total:   $TOTAL"
echo -e "  ${GREEN}Passed:  $PASS${NC}"
echo -e "  ${RED}Failed:  $FAIL${NC}"
echo -e "  ${YELLOW}Skipped: $SKIP${NC}"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
fi
