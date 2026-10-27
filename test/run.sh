#!/usr/bin/env bash
# Tests of the summary and the gate without ZAP, Nuclei or a network: the unit self-tests, then the fixture reports
# (ZAP JSON, Nuclei JSONL, edge captures) against the fixture acceptances. Needs python3 with PyYAML (the runner has it).
set -euo pipefail
cd "$(dirname "$0")/.."
out="$(mktemp -d)"
python3 dast-summary.py --self-test
python3 scripts/auth-files.py --self-test

# Medium gate over the three tools: zap:10038 blocks (expired acceptance), the edge header findings of the bare test
# server block (csp, nosniff, frame), zap:90003 and nuclei:http-missing-security-headers are accepted on
# /llms-full.txt, the sid cookie is accepted by title; the unreachable edge host and the session that never logged
# in are warnings, not findings.
if python3 dast-summary.py --zap test/report.json --nuclei test/nuclei.jsonl --edge-dir test/edge --accept test/dast-accept.yaml \
     --fail-on Medium --target http://localhost:8080/ --targets http://localhost:8080/ --auth-mode session --out "$out/medium.json"; then
  echo "FAIL: expected the Medium gate to fail"; exit 1
fi
python3 - "$out/medium.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
assert s["schema"] == "aedis.platform/dast-summary/v2" and s["result"] == "fail", s["result"]
assert s["counts"] == {"high": 0, "medium": 7, "low": 2, "info": 1}, s["counts"]  # 10036 fires on / and /index.html
assert s["blocking"] == 4 and s["accepted"] == 3, (s["blocking"], s["accepted"])
blocking = sorted(f["id"] for f in s["findings"] if f["severity"] == "medium" and not f["accepted"])
assert blocking == ["edge:csp-missing", "edge:frame-protection-missing", "edge:nosniff-missing", "zap:10038"], blocking
assert {f["tool"] for f in s["findings"]} == {"zap", "nuclei", "edge"}
assert s["authMode"] == "session" and s["authenticated"] is False
assert any("expired" in w for w in s["warnings"]) and any("unreachable" in w for w in s["warnings"]) and any("unauthenticated" in w for w in s["warnings"]), s["warnings"]
assert s["tools"] == {"zap": {"ran": True, "findings": 4}, "nuclei": {"ran": True, "findings": 2}, "edge": {"ran": True, "findings": 4}}, s["tools"]
PY

# High gate: the same findings pass, and an authenticated run leaves no warning about the session.
python3 dast-summary.py --zap test/report.json --nuclei test/nuclei.jsonl --edge-dir test/edge --accept test/dast-accept.yaml \
  --fail-on High --auth-mode client-credentials --authenticated --out "$out/high.json"
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['result']=='pass' and s['blocking']==0 and s['authenticated'] and not any('unauthenticated' in w for w in s['warnings']), s" "$out/high.json"

# v1 shape: only the ZAP report and no acceptance file, nothing is accepted and Nuclei/edge did not run.
python3 dast-summary.py --zap test/report.json --accept /nonexistent.yaml --fail-on High --out "$out/v1.json"
python3 -c "import json,sys; s=json.load(open(sys.argv[1])); assert s['accepted']==0 and s['tools']['nuclei']['ran'] is False and s['tools']['edge']['ran'] is False, s" "$out/v1.json"
echo "fixture tests ok"
