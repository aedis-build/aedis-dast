#!/usr/bin/env bash
# Tests of the summary and the gate without ZAP: the unit self-test, then the fixture report against the fixture
# acceptances (one expired, one limited to a path). Needs python3 with PyYAML (the runner has it).
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
python3 dast-summary.py --self-test

# Medium gate: CSP (10038) blocks because its acceptance expired; SRI (90003) is accepted on /llms-full.txt only.
if python3 dast-summary.py --report test/report.json --accept test/dast-accept.yaml --fail-on Medium --out "$out/medium.json"; then
  echo "FAIL: expected the Medium gate to fail"; exit 1
fi
python3 - "$out/medium.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["result"] == "fail" and s["blocking"] == 1 and s["accepted"] == 1, s
assert s["counts"] == {"Informational": 0, "Low": 1, "Medium": 2, "High": 0}, s["counts"]
blocking = [a for a in s["alerts"] if a["risk"] == "Medium" and not a["accepted"]]
assert [a["pluginId"] for a in blocking] == ["10038"], blocking
PY

# High gate: the same report passes, the Medium findings only count.
python3 dast-summary.py --report test/report.json --accept test/dast-accept.yaml --fail-on High --out "$out/high.json"
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['result']=='pass' and s['blocking']==0, s" "$out/high.json"

# No acceptance file at all: nothing is accepted.
python3 dast-summary.py --report test/report.json --accept /nonexistent.yaml --fail-on High --out "$out/none.json"
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['accepted']==0, s" "$out/none.json"
echo "fixture tests ok"
