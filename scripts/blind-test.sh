#!/usr/bin/env bash
# Blind test: a fresh headless Claude reproduces a lab from report + lab only.
# The empty working dir is what keeps it blind: no reference/, demo.sh or earlier runs/.
#
#   scripts/blind-test.sh [lab dir]     default: labs/grafana-cve-2023-1410
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LAB="${1:-$ROOT/labs/grafana-cve-2023-1410}"
DIR="$(mktemp -d -t proofbench-blind)"
cp -r "$LAB/report.md" "$LAB/lab" "$DIR/"
cd "$DIR"
export PATH="$ROOT/bin:$PATH"
echo "blind dir: $DIR  (transcript: $DIR/transcript.jsonl)"

# Tools are scoped: proofbench, Docker and read-only shell, no blanket Bash.
claude -p --model opus --plugin-dir "$ROOT" --output-format stream-json --verbose \
  --allowedTools "Read" "Write" "Edit" "Glob" "Grep" "WebFetch" "WebSearch" "Agent" "Skill" \
  "Bash(pb:*)" "Bash($ROOT/bin/pb:*)" "Bash(docker:*)" "Bash(ls:*)" "Bash(cat:*)" \
  "Bash(grep:*)" "Bash(curl:*)" "Bash(python3:*)" "Bash(sed:*)" "Bash(head:*)" \
  "Bash(tail:*)" "Bash(jq:*)" "Bash(mkdir:*)" \
  -- "/proofbench:reproduce report.md --lab lab — also run the patched negative control, then report the outcome." \
  > transcript.jsonl

jq -r 'select(.type=="result") | .result, "cost $\(.total_cost_usd)  turns \(.num_turns)"' transcript.jsonl
