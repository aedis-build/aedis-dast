#!/usr/bin/env python3
"""Joins what ZAP, Nuclei and the edge check found into one summary, aedis.platform/dast-summary/v2, and applies the
gate: any finding at or above --fail-on that is not accepted fails.

Findings are normalized across tools: severity high/medium/low/info (Nuclei critical counts as high), `tool`, `id`
(`zap:<pluginId>`, `nuclei:<templateId>`, `edge:<check>`), `path`, `url`, truncated `evidence`. Acceptances
(dast-accept.yaml) match by `id` (`pluginId` is kept as the v1 alias of `zap:<pluginId>`), optional `paths` (prefixes
of the finding's path), optional `title` (substring) and a required `until` (YYYY-MM-DD): an expired or dateless
acceptance is ignored and listed in `warnings`.

The edge check reads what the action collected with curl: <edge-dir>/<i>.headers (curl -D, with redirects) and
<edge-dir>/<i>.meta (url=, https_code=, http=<code> <redirect url>, tls11=accepted|rejected|skipped). Missing HSTS
(--edge-hsts-severity, high for production), CSP, X-Content-Type-Options, X-Frame-Options/frame-ancestors, a cookie
without Secure/HttpOnly/SameSite, HTTP not redirected to HTTPS and TLS 1.1 accepted are findings; an unreachable
host is a warning, not a finding.

Usage: dast-summary.py --out dast-summary.json [--zap report.json ...] [--nuclei findings.jsonl ...] [--edge-dir dir]
         [--accept dast-accept.yaml] [--fail-on High|Medium] [--target URL] [--targets "url1,url2"]
         [--auth-mode none|client-credentials|session] [--authenticated] [--edge-hsts-severity medium|high]
         [--warnings-file warnings.txt]
       dast-summary.py --self-test
"""
import argparse, glob, json, os, re, sys
from datetime import date, datetime, timezone
from urllib.parse import urlparse

SCHEMA = "aedis.platform/dast-summary/v2"
ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
NUCLEI_SEV = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "info": "info"}
RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}
FAIL_ON = {"High": "high", "Medium": "medium"}
EVIDENCE = 300


def path_of(url):
    return urlparse(url or "").path or "/"


def finding(tool, ident, severity, title, url, evidence):
    return {"tool": tool, "id": ident, "severity": severity, "title": title or ident, "path": path_of(url) if url else "",
            "url": url or "", "evidence": str(evidence or "")[:EVIDENCE], "accepted": None}


def zap_findings(report):
    """One finding per alert and path (a plugin firing on ten URLs under /api is one finding per distinct path)."""
    out, seen = [], set()
    for site in report.get("site", []):
        for a in site.get("alerts", []):
            ident, sev = f"zap:{a.get('pluginid')}", ZAP_RISK.get(str(a.get("riskcode")), "info")
            instances = a.get("instances") or [{}]
            for i in instances:
                f = finding("zap", ident, sev, a.get("alert") or a.get("name"), i.get("uri", ""), i.get("evidence") or i.get("param"))
                if (ident, f["path"]) in seen:
                    continue
                seen.add((ident, f["path"])); out.append(f)
    return out


def nuclei_findings(lines):
    out = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        info = r.get("info", {})
        url = r.get("matched-at") or r.get("url") or r.get("host", "")
        out.append(finding("nuclei", f"nuclei:{r.get('template-id')}", NUCLEI_SEV.get(str(info.get("severity", "info")).lower(), "info"),
                           info.get("name"), url, r.get("extracted-results") or r.get("matcher-name")))
    return out


def _header_blocks(text):
    """Header blocks of a curl -D capture, one per response (with -L the redirects come first)."""
    blocks, cur = [], None
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.startswith("HTTP/"):
            cur = []; blocks.append(cur)
        elif cur is not None and ":" in line:
            k, v = line.split(":", 1); cur.append((k.strip().lower(), v.strip()))
    return blocks


def edge_findings(headers_text, meta, hsts_severity="medium"):
    """(reachable, findings) for one edge URL from its curl capture and meta lines."""
    url, code = meta.get("url", ""), meta.get("https_code", "000")
    blocks = _header_blocks(headers_text)
    if not blocks or code == "000":
        return False, []
    last = dict(blocks[-1])
    https = url.startswith("https://")
    out = []

    def add(check, sev, title, evidence):
        out.append(finding("edge", f"edge:{check}", sev, title, url, evidence))

    hsts = last.get("strict-transport-security", "")
    if https and not re.search(r"max-age\s*=\s*[1-9]\d*", hsts, re.I):
        add("hsts-missing", hsts_severity, "Strict-Transport-Security missing", hsts or "no header")
    csp = last.get("content-security-policy", "")
    if not csp:
        add("csp-missing", "medium", "Content-Security-Policy missing", "no header")
    nosniff = last.get("x-content-type-options", "")
    if nosniff.lower() != "nosniff":
        add("nosniff-missing", "medium", "X-Content-Type-Options: nosniff missing", nosniff or "no header")
    xfo = last.get("x-frame-options", "")
    if xfo.upper() not in ("DENY", "SAMEORIGIN") and "frame-ancestors" not in csp.lower():
        add("frame-protection-missing", "medium", "No X-Frame-Options nor CSP frame-ancestors (clickjacking)", xfo or "no header")
    for c in (v for b in blocks for k, v in b if k == "set-cookie"):
        name = c.split("=", 1)[0].strip()
        attrs = {a.strip().split("=", 1)[0].lower() for a in c.split(";")[1:]}
        missing = [n for n, k in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")) if k not in attrs]
        if missing:
            add("cookie-insecure", "medium", f"Cookie {name} without {', '.join(missing)}", f"{name}: missing {', '.join(missing)}")
    http_code, _, redirect = meta.get("http", "").partition(" ")
    if https and http_code and http_code != "000" and not (http_code.startswith("3") and redirect.lower().startswith("https://")):
        add("http-not-redirected", "medium", "HTTP (port 80) not redirected to HTTPS", f"HTTP {http_code} {redirect}".strip())
    if meta.get("tls11") == "accepted":
        add("legacy-tls", "medium", "TLS 1.0/1.1 accepted", "handshake with --tls-max 1.1 accepted")
    return True, out


def read_edge_dir(edge_dir):
    """Edge captures as [(headers_text, meta dict)] from <i>.headers and <i>.meta pairs."""
    pairs = []
    for meta_file in sorted(glob.glob(os.path.join(edge_dir or "", "*.meta"))):
        meta = dict(line.rstrip("\n").split("=", 1) for line in open(meta_file, encoding="utf-8", errors="replace") if "=" in line)
        headers_file = meta_file[:-5] + ".headers"
        text = open(headers_file, encoding="utf-8", errors="replace").read() if os.path.exists(headers_file) else ""
        pairs.append((text, meta))
    return pairs


def load_accepts(data, today):
    """(rules, warnings) from a dast-accept.yaml document; v1 `pluginId` becomes `zap:<pluginId>`."""
    rules, warnings = [], []
    for a in (data or {}).get("accept", []) or []:
        ident = a.get("id") or (f"zap:{a['pluginId']}" if a.get("pluginId") is not None else None)
        if not ident:
            warnings.append("acceptance without id or pluginId ignored"); continue
        until = a.get("until")
        if not until:
            warnings.append(f"acceptance {ident} without until ignored"); continue
        if date.fromisoformat(str(until)) < today:
            warnings.append(f"acceptance {ident} expired on {until}: the finding blocks again"); continue
        paths = a.get("paths") or ([a["path"]] if a.get("path") else [])
        rules.append({"id": ident, "paths": paths, "title": a.get("title"), "reason": a.get("reason") or "", "until": str(until)})
    return rules, warnings


def accepted_by(f, rules):
    for r in rules:
        if r["id"] != f["id"]:
            continue
        if r["paths"] and not any(f["path"].startswith(p) for p in r["paths"]):
            continue
        if r["title"] and r["title"].lower() not in (f["title"] or "").lower():
            continue
        return r["reason"]
    return None


def summarize(zap_reports=(), nuclei_lines=(), edges=(), accepts=(), fail_on="High", target="", targets=(), auth_mode="none",
              authenticated=False, hsts_severity="medium", warnings=()):
    warnings = list(warnings)
    findings = []
    for rep in zap_reports:
        findings += zap_findings(rep)
    findings += nuclei_findings(nuclei_lines or [])
    edge_ran, edge_count = bool(edges), 0
    for text, meta in edges:
        reachable, found = edge_findings(text, meta, hsts_severity)
        if not reachable:
            warnings.append(f"edge: {meta.get('url') or 'host'} unreachable, headers not checked")
        edge_count += len(found); findings += found
    findings.sort(key=lambda f: (-RANK[f["severity"]], f["tool"], f["id"], f["path"]))
    for f in findings:
        f["accepted"] = accepted_by(f, accepts)
    threshold = RANK[FAIL_ON[fail_on]]
    blocking = [f for f in findings if RANK[f["severity"]] >= threshold and not f["accepted"]]
    if auth_mode != "none" and not authenticated:
        warnings.append(f"auth {auth_mode}: no credentials or login failed, the scan ran unauthenticated")
    return {"schema": SCHEMA, "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "target": target, "targets": list(targets), "failOn": fail_on, "authMode": auth_mode, "authenticated": bool(authenticated),
            "result": "pass" if not blocking else "fail",
            "counts": {s: sum(1 for f in findings if f["severity"] == s) for s in RANK},
            "blocking": len(blocking), "accepted": sum(1 for f in findings if f["accepted"]),
            "tools": {"zap": {"ran": bool(zap_reports), "findings": sum(1 for f in findings if f["tool"] == "zap")},
                      "nuclei": {"ran": nuclei_lines is not None, "findings": sum(1 for f in findings if f["tool"] == "nuclei")},
                      "edge": {"ran": edge_ran, "findings": edge_count}},
            "warnings": warnings, "findings": findings}


def self_test():
    today = date(2026, 6, 1)
    zap = {"site": [{"alerts": [{"pluginid": 40012, "alert": "XSS", "riskcode": "3", "instances": [{"uri": "http://h/a?q=1"}, {"uri": "http://h/a?q=2"}]},
                                {"pluginid": 10038, "alert": "CSP", "riskcode": "2", "instances": [{"uri": "http://h/"}, {"uri": "http://h/llms-full.txt"}]}]}]}
    s = summarize([zap])
    assert s["result"] == "fail" and s["counts"] == {"high": 1, "medium": 2, "low": 0, "info": 0}, s["counts"]  # same path twice is one finding
    # Acceptance by id (v2), by pluginId (v1 alias), by path prefix, by title; expired and dateless are warnings.
    rules, warns = load_accepts({"accept": [
        {"id": "zap:40012", "until": "2999-01-01", "reason": "r"},
        {"pluginId": 10038, "until": "2999-01-01", "paths": ["/llms"], "reason": "scoped"},
        {"id": "zap:1", "until": "2020-01-01", "reason": "old"},
        {"id": "zap:2", "reason": "no date"}]}, today)
    assert len(rules) == 2 and len(warns) == 2 and "expired" in warns[0], warns
    s = summarize([zap], accepts=rules, fail_on="Medium")
    assert s["result"] == "fail" and s["blocking"] == 1 and s["accepted"] == 2, (s["blocking"], s["accepted"])
    assert summarize([zap], accepts=rules, fail_on="High")["result"] == "pass"
    title_rule, _ = load_accepts({"accept": [{"id": "zap:10038", "until": "2999-01-01", "title": "csp", "reason": "t"}]}, today)
    assert summarize([zap], accepts=title_rule, fail_on="Medium")["accepted"] == 2
    # Nuclei: critical counts as high; the gate is per finding, whatever the tool.
    nuclei = ['{"template-id": "cve-2024-1", "info": {"name": "RCE", "severity": "critical"}, "matched-at": "http://h/x"}',
              '{"template-id": "tech-detect", "info": {"name": "Tech", "severity": "info"}, "matched-at": "http://h/"}', ""]
    s = summarize(nuclei_lines=nuclei)
    assert s["counts"]["high"] == 1 and s["counts"]["info"] == 1 and s["result"] == "fail" and s["tools"]["nuclei"]["findings"] == 2
    n_rule, _ = load_accepts({"accept": [{"id": "nuclei:cve-2024-1", "until": "2999-01-01", "paths": ["/x"], "reason": "r"}]}, today)
    assert summarize(nuclei_lines=nuclei, accepts=n_rule)["result"] == "pass"
    # Edge: a bare server has every header finding; a hardened one none; unreachable is a warning.
    bare = "HTTP/1.1 200 OK\r\nServer: x\r\nSet-Cookie: sid=1; Path=/\r\n\r\n"
    meta = {"url": "https://h/", "https_code": "200", "http": "200 ", "tls11": "accepted"}
    s = summarize(edges=[(bare, meta)], hsts_severity="high")
    ids = sorted(f["id"] for f in s["findings"])
    assert ids == ["edge:cookie-insecure", "edge:csp-missing", "edge:frame-protection-missing", "edge:hsts-missing", "edge:http-not-redirected",
                   "edge:legacy-tls", "edge:nosniff-missing"], ids
    assert s["result"] == "fail" and next(f for f in s["findings"] if f["id"] == "edge:hsts-missing")["severity"] == "high"
    hard = ("HTTP/1.1 301\r\nLocation: https://h/\r\n\r\nHTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n"
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\n"
            "Set-Cookie: sid=1; Secure; HttpOnly; SameSite=Lax\r\n\r\n")
    s = summarize(edges=[(hard, {"url": "https://h/", "https_code": "200", "http": "301 https://h/", "tls11": "rejected"})])
    assert s["findings"] == [] and s["result"] == "pass" and s["tools"]["edge"]["ran"]
    s = summarize(edges=[("", {"url": "https://down/", "https_code": "000"})])
    assert s["findings"] == [] and s["warnings"] == ["edge: https://down/ unreachable, headers not checked"]
    # Plain-HTTP edge URL: HSTS and the redirect do not apply.
    s = summarize(edges=[(bare, {"url": "http://h:8080/", "https_code": "200", "tls11": "skipped"})])
    assert "edge:hsts-missing" not in [f["id"] for f in s["findings"]] and "edge:http-not-redirected" not in [f["id"] for f in s["findings"]]
    # Authentication is recorded; asked for but not obtained is a warning.
    s = summarize(auth_mode="session", authenticated=False)
    assert s["authMode"] == "session" and not s["authenticated"] and s["warnings"]
    assert summarize(auth_mode="client-credentials", authenticated=True)["warnings"] == []
    assert summarize()["result"] == "pass" and summarize()["schema"] == SCHEMA
    assert summarize(nuclei_lines=None)["tools"]["nuclei"] == {"ran": False, "findings": 0}
    print("self-test ok")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--zap", nargs="*", default=[])
    a.add_argument("--nuclei", nargs="*", default=None)
    a.add_argument("--edge-dir")
    a.add_argument("--accept")
    a.add_argument("--fail-on", default="High", choices=["High", "Medium"])
    a.add_argument("--target", default="")
    a.add_argument("--targets", default="")
    a.add_argument("--auth-mode", default="none", choices=["none", "client-credentials", "session"])
    a.add_argument("--authenticated", action="store_true")
    a.add_argument("--edge-hsts-severity", default="medium", choices=["medium", "high"])
    a.add_argument("--warnings-file")
    a.add_argument("--out", default="dast-summary.json")
    a.add_argument("--self-test", action="store_true")
    args = a.parse_args()
    if args.self_test:
        self_test(); return 0
    warnings = []
    if args.warnings_file and os.path.exists(args.warnings_file):
        warnings += [w for w in open(args.warnings_file, encoding="utf-8").read().splitlines() if w.strip()]
    accepts = []
    if args.accept and os.path.exists(args.accept):
        import yaml  # PyYAML ships with the runner
        accepts, w = load_accepts(yaml.safe_load(open(args.accept, encoding="utf-8")), date.today())
        warnings += w
    zap_reports = [json.load(open(f, encoding="utf-8")) for f in args.zap if os.path.exists(f)]
    nuclei_lines = None
    if args.nuclei is not None:
        nuclei_lines = [line for f in args.nuclei if os.path.exists(f) for line in open(f, encoding="utf-8")]
    edges = read_edge_dir(args.edge_dir) if args.edge_dir else []
    s = summarize(zap_reports, nuclei_lines, edges, accepts, args.fail_on, args.target,
                  [t for t in args.targets.split(",") if t], args.auth_mode, args.authenticated, args.edge_hsts_severity, warnings)
    json.dump(s, open(args.out, "w", encoding="utf-8"), indent=2)
    c = s["counts"]
    print(f"DAST {args.target}: {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info; "
          f"{s['accepted']} accepted; {s['blocking']} blocking (>= {args.fail_on}); authenticated={s['authenticated']}")
    for f in s["findings"]:
        if RANK[f["severity"]] >= RANK[FAIL_ON[args.fail_on]] and not f["accepted"]:
            print(f"  [{f['severity']}] {f['id']} {f['title']} {f['path']}")
    for w in s["warnings"]:
        print(f"::warning::{w}")
    return 1 if s["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
