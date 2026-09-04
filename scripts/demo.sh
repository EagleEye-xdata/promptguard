#!/usr/bin/env bash
set -euo pipefail
API="${API_URL:-http://localhost:8000}"
TARGET_ID=$(curl -fsS "$API/targets" | python -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
RUN_ID=$(curl -fsS -X POST "$API/tests" -H 'content-type: application/json' -d "{\"target_id\":$TARGET_ID,\"count\":20,\"mutations\":[\"base64\",\"roleplay_wrap\"],\"variants_per_attack\":1}" | python -c 'import json,sys; print(json.load(sys.stdin)["test_run_id"])')
while [ "$(curl -fsS "$API/tests/$RUN_ID" | python -c 'import json,sys; print(json.load(sys.stdin)["status"])')" != completed ]; do sleep 1; done
mkdir -p reports
curl -fsS "$API/reports/$RUN_ID?format=md" -o "reports/run-$RUN_ID.md"
echo "Report: reports/run-$RUN_ID.md"
echo "UI: http://localhost:5173"
