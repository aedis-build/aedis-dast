# Aedis DAST

GitHub Action that scans a URL your job already serves and **fails the job when a finding at or above the configured
risk is not accepted**. With only `target-url` it runs the [OWASP ZAP](https://www.zaproxy.org) baseline; the rest is
opt-in: ZAP once per path or by OpenAPI contract, [Nuclei](https://github.com/projectdiscovery/nuclei) in two passes
(templates by tag, then DAST fuzzing), authentication (OAuth2 client credentials or a session your own command logs
in) and an edge check of security headers, cookies, HTTP redirect and TLS. Everything lands in one JSON summary
(`aedis.platform/dast-summary/v2`) with a normalized severity, so one acceptance file and one gate cover every tool.
Acceptances live in the repository, each with an expiry date and, optionally, the paths it is limited to, so a risk
is never accepted silently or forever. Part of the [Aedis Platform](https://github.com/aedis-build/aedis-platform),
usable on its own.

## Usage

```yaml
jobs:
  dast:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Start the application on http://localhost:8080
        run: |
          docker run -d --rm -p 8080:8080 ghcr.io/acme/app:sha-abc123
          curl --retry 30 --retry-all-errors --retry-delay 2 -fsS -o /dev/null http://localhost:8080/
      - uses: aedis-build/aedis-dast@<sha of the release tag> # vX.Y.Z
        with:
          target-url: http://localhost:8080/
          fail-on: Medium
```

Pin the action by the commit SHA of a release tag with the tag in the comment, as above: Dependabot
(`package-ecosystem: github-actions`) then opens the repin pull request at every release, SHA and comment together.
The scanners run from images pinned by digest in `action.yml`, with the host network, so anything the job serves on
`localhost` is reachable. Needs Docker on the runner (`ubuntu-latest` has it).

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `target-url` | required | URL of the exposed surface, e.g. `http://localhost:8080/` |
| `target-paths` | `""` | Extra targets, comma- or newline-separated: paths under `target-url` (`/api/orders`) or full URLs; the ZAP baseline runs once per target and Nuclei takes them all |
| `openapi` | `""` | OpenAPI contract (URL or file): ZAP scans every documented operation (`zap-api-scan.py`) instead of spidering |
| `zap-rules-file` | `""` | ZAP rules file (`<pluginId>\tIGNORE\|WARN\|FAIL\t(<note>)` per line), passed to the scan as `-c` |
| `accept-file` | `dast-accept.yaml` | Risk acceptance file (below); a missing file accepts nothing |
| `fail-on` | `High` | Lowest severity that fails the job, over the unaccepted findings of every tool: `High` or `Medium` |
| `summary-name` | `dast-summary` | Artifact with `dast-summary.json` |
| `report-name` | `dast-report` | Artifact with the ZAP reports (HTML, JSON, Markdown per target), the Nuclei outputs and the edge captures |
| `nuclei` | `false` | Run Nuclei in two passes (below) |
| `nuclei-tags` | `cve,misconfig,exposure,auth,jwt,ssrf,sqli,xss,rce` | Template tags of the first pass |
| `nuclei-exclude-tags` | `dos,bruteforce` | Tags left out of the first pass |
| `nuclei-rate-limit` | `25` | Requests per second |
| `nuclei-concurrency` | `8` | Templates in parallel |
| `sarif-upload` | `true` | Upload the Nuclei SARIF to code scanning (categories `aedis-dast/nuclei`, `aedis-dast/nuclei-dast`); needs `security-events: write` on the job, otherwise the upload is skipped with a warning |
| `auth` | `none` | `client-credentials` or `session` (below) |
| `auth-token-url`, `auth-client-id`, `auth-client-secret`, `auth-scope` | `""` | OAuth2 token endpoint, client and optional scope for `client-credentials`; pass secrets |
| `login-command` | `""` | For `session`: a command that logs in and prints `{"headers": {...}, "cookies": {...}}` on stdout |
| `logout-paths` | `/logout,/signout,/api/auth/signout` | For `session`: paths the ZAP spider never requests |
| `edge` | `false` | Run the edge check (below) |
| `edge-urls` | origin of `target-url` | URLs the edge check requests, comma- or newline-separated |
| `edge-hsts-severity` | `medium` | Severity of a missing `Strict-Transport-Security`; `high` for production |

Output `result`: `pass` or `fail`.

## What it checks

**ZAP.** The baseline scan (passive rules, spider for two minutes, `-I` so warnings alone never fail) runs once per
target: `target-url` and each of `target-paths`. With `openapi` it runs `zap-api-scan.py` on the contract instead,
which requests every documented operation of the API with the right methods and parameters. Each target leaves
`zap/<n>.html`, `.json` and `.md` in the report artifact. Findings are `zap:<pluginId>`, one per plugin and path.

**Nuclei** (`nuclei: true`). Two passes over the same targets, severity medium and above: templates selected by tag
(CVEs, misconfigurations, exposed files and panels, auth, JWT, SSRF, SQLi, XSS, RCE by default; `dos` and
`bruteforce` never) and then the DAST templates (`-dast`), which fuzz the parameters of the targets and only run in
that mode. Raw requests are omitted from every output, so a session header never lands in the artifact. Findings are
`nuclei:<templateId>`; `critical` counts as `high`. Each pass leaves JSONL, SARIF and Markdown in the report artifact,
and the SARIF goes to code scanning when the job may write `security-events`.

**Edge** (`edge: true`). One `GET` with redirects on each of `edge-urls` (the origin by default), the plain-HTTP
counterpart and a TLS 1.1 handshake, all read-only and unauthenticated. Findings, `edge:<check>`:
`hsts-missing` (`edge-hsts-severity`), `csp-missing`, `nosniff-missing`, `frame-protection-missing` (no
`X-Frame-Options` nor CSP `frame-ancestors`), `cookie-insecure` (a `Set-Cookie` without `Secure`, `HttpOnly` or
`SameSite`), `http-not-redirected` (port 80 answers without a redirect to HTTPS) and `legacy-tls` (TLS 1.0/1.1
accepted), all medium unless said otherwise. HSTS and the redirect apply to `https://` URLs only. An unreachable host
is a warning in the summary, not a finding.

## Authentication

Credentials never reach the artifact or the log: the values are masked, kept under the runner's temp directory and
passed to ZAP as a config file (one replacer rule per header) and to Nuclei as `-H` headers. If the token or the
login cannot be obtained the scan still runs, unauthenticated, and the summary says so (`authenticated: false` plus
a warning). `authMode` and `authenticated` are always in the summary.

**Client credentials** (`auth: client-credentials`): the action posts `grant_type=client_credentials` with
`auth-client-id`, `auth-client-secret` and the optional `auth-scope` to `auth-token-url` and injects
`Authorization: Bearer <token>` in both scanners.

```yaml
      - uses: aedis-build/aedis-dast@<sha of the release tag> # vX.Y.Z
        with:
          target-url: https://api.staging.example.com/
          openapi: https://api.staging.example.com/openapi.json
          auth: client-credentials
          auth-token-url: https://auth.staging.example.com/realms/app/protocol/openid-connect/token
          auth-client-id: ${{ secrets.DAST_CLIENT_ID }}
          auth-client-secret: ${{ secrets.DAST_CLIENT_SECRET }}
```

**Session** (`auth: session`): `login-command` is any command of yours that logs a test user in and prints the
session as JSON on stdout, `{"headers": {"X-Api-Key": "..."}, "cookies": {"session": "..."}}`; cookies become one
`Cookie` header. The paths in `logout-paths` are excluded from the ZAP spider so the session survives the scan. A
generic login script for a NextAuth-style front end (CSRF token, credentials callback, session cookie) looks like
this; adapt the routes to your application and keep the secrets in the repository's secrets:

```python
#!/usr/bin/env python3
"""Logs a test user in through the application's own auth routes and prints the session cookies as JSON."""
import http.cookiejar, json, os, urllib.parse, urllib.request

base = os.environ["DAST_LOGIN_URL"].rstrip("/")  # e.g. https://app.staging.example.com
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

def call(path, data=None):
    body = urllib.parse.urlencode(data).encode() if data else None
    with opener.open(urllib.request.Request(base + path, data=body), timeout=30) as r:
        text = r.read().decode()
        return json.loads(text) if text.startswith("{") else text

csrf = call("/api/auth/csrf")["csrfToken"]
call("/api/auth/callback/credentials", {"csrfToken": csrf, "username": os.environ["DAST_USERNAME"],
                                        "password": os.environ["DAST_PASSWORD"], "json": "true"})
cookies = {c.name: c.value for c in jar}
if not any("session-token" in n for n in cookies):
    raise SystemExit("no session cookie after login")
print(json.dumps({"cookies": cookies}))
```

```yaml
      - uses: aedis-build/aedis-dast@<sha of the release tag> # vX.Y.Z
        env:
          DAST_LOGIN_URL: https://app.staging.example.com
          DAST_USERNAME: ${{ secrets.DAST_USERNAME }}
          DAST_PASSWORD: ${{ secrets.DAST_PASSWORD }}
        with:
          target-url: https://app.staging.example.com/dashboard
          auth: session
          login-command: python3 scripts/dast-login.py
          logout-paths: /logout,/api/auth/signout,/settings/password
```

## Accepting a risk

`dast-accept.yaml` in the repository (or the file named in `accept-file`):

```yaml
accept:
  - id: zap:10038                # zap:<pluginId>, nuclei:<templateId> or edge:<check>
    until: 2026-12-31            # required: past this date the finding blocks again and the summary warns
    reason: CSP is applied at the edge (WAF); evidence in ticket SEC-123
  - id: nuclei:http-missing-security-headers
    until: 2026-12-31
    reason: plain-text file served without headers; the HTML pages carry them
    paths: [/llms-full.txt]      # optional: only findings whose path starts with one of these
  - id: edge:cookie-insecure
    until: 2026-12-31
    reason: the load balancer's sticky cookie is not a session
    title: AWSALB                # optional: only findings whose title contains this
  - pluginId: 90003              # the v1 form still works: pluginId means id zap:90003
    until: 2026-12-31
    reason: plain-text file, nothing to pin with Subresource Integrity
    paths: [/llms-full.txt]
```

`test/run.sh` proves the rules on fixture reports of the three tools, and `aedis-ci` also runs the action, with the
edge check, against a static site served in the job (`e2e.yml`, by hand, adds Nuclei).

## Summary

`dast-summary.json` in the `dast-summary` artifact (`aedis.platform/dast-summary/v2`; readers of v1 keep
`schema`, `target`, `failOn`, `result`, `blocking` and `accepted`; `counts` keys are now lowercase):

```json
{
  "schema": "aedis.platform/dast-summary/v2",
  "target": "http://localhost:8080/", "targets": ["http://localhost:8080/", "http://localhost:8080/llms-full.txt"],
  "failOn": "Medium", "authMode": "session", "authenticated": true, "result": "fail",
  "counts": {"high": 0, "medium": 4, "low": 1, "info": 1}, "blocking": 1, "accepted": 3,
  "tools": {"zap": {"ran": true, "findings": 3}, "nuclei": {"ran": true, "findings": 2}, "edge": {"ran": true, "findings": 1}},
  "warnings": ["acceptance zap:10038 expired on 2020-01-01: the finding blocks again"],
  "findings": [{"tool": "zap", "id": "zap:10038", "severity": "medium", "title": "Content Security Policy (CSP) Header Not Set",
                "path": "/index.html", "url": "http://localhost:8080/index.html", "evidence": "", "accepted": null}]
}
```

## Recipes

A full job: the application and its database from a compose file, an authenticated scan with Nuclei and the edge
check, and the summary kept for 90 days.

```yaml
jobs:
  dast:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - run: docker compose -f compose.dast.yaml up -d --wait
      - uses: aedis-build/aedis-dast@<sha of the release tag> # vX.Y.Z
        id: dast
        with:
          target-url: http://localhost:8080/
          openapi: http://localhost:8080/openapi.json
          auth: client-credentials
          auth-token-url: http://localhost:8081/realms/app/protocol/openid-connect/token
          auth-client-id: ${{ secrets.DAST_CLIENT_ID }}
          auth-client-secret: ${{ secrets.DAST_CLIENT_SECRET }}
          nuclei: true
          edge: true
          fail-on: Medium
      - if: always()
        run: docker compose -f compose.dast.yaml down
```

Notifications and issues belong to the caller. An issue that tracks open findings, kept up to date by every run:

```yaml
      - name: Open or update the findings issue
        if: always() && steps.dast.outputs.result == 'fail'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          title="[DAST] unaccepted findings on ${{ github.ref_name }}"
          body="$(python3 -c "import json; s=json.load(open('dast/dast-summary.json')); print('\n'.join(f\"- {f['severity']} {f['id']} {f['title']} {f['path']}\" for f in s['findings'] if not f['accepted'] and f['severity'] in ('high','medium')))")"
          number="$(gh issue list --search "$title in:title" --state open --json number --jq '.[0].number')"
          if [ -n "$number" ]; then gh issue comment "$number" --body "$body"; else gh issue create --title "$title" --body "$body" --label security; fi
```

(the job then needs `issues: write`). A chat notification is one `curl` of the same summary to the webhook of your
choice, after the scan, with `if: always()`.

## License

Apache-2.0. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
