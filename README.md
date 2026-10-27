# Aedis DAST

GitHub Action that runs an [OWASP ZAP](https://www.zaproxy.org) baseline scan against a URL your job already serves,
writes a JSON summary (`aedis.platform/dast-summary/v1`) and **fails the job when an alert at or above the configured
risk is not accepted**. Acceptances live in the repository, each with an expiry date and, optionally, the paths it is
limited to, so a risk is never accepted silently or forever. Part of the
[Aedis Platform](https://github.com/aedis-build/aedis-platform), usable on its own.

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
          curl --retry 30 --retry-connrefused --retry-delay 2 -fsS -o /dev/null http://localhost:8080/
      - uses: aedis-build/aedis-dast@<sha of the release tag> # vX.Y.Z
        with:
          target-url: http://localhost:8080/
          fail-on: Medium
```

Pin the action by the commit SHA of a release tag with the tag in the comment, as above: Dependabot
(`package-ecosystem: github-actions`) then opens the repin pull request at every release, SHA and comment together.
The scan runs ZAP's `zap-baseline.py` from the image pinned by digest in `action.yml`, with the host network, so
anything the job serves on `localhost` is reachable. Needs Docker on the runner (`ubuntu-latest` has it).

### Inputs

| Input | Default | Meaning |
|---|---|---|
| `target-url` | required | URL of the exposed surface, e.g. `http://localhost:8080/` |
| `accept-file` | `dast-accept.yaml` | Risk acceptance file (below); a missing file accepts nothing |
| `fail-on` | `High` | Lowest risk that fails the job: `High` or `Medium` |
| `summary-name` | `dast-summary` | Name of the uploaded artifact with the ZAP report and the summary |

The artifact holds `report.json` (ZAP) and `dast-summary.json`:

```json
{
  "schema": "aedis.platform/dast-summary/v1",
  "target": "http://localhost:8080/", "failOn": "Medium", "result": "fail",
  "counts": {"Informational": 0, "Low": 1, "Medium": 2, "High": 0},
  "blocking": 1, "accepted": 1,
  "alerts": [{"pluginId": "10038", "name": "Content Security Policy (CSP) Header Not Set", "risk": "Medium", "count": 1, "accepted": null}]
}
```

### Accepting a risk

`dast-accept.yaml` in the repository (or the file named in `accept-file`):

```yaml
accept:
  - pluginId: 10038              # ZAP plugin id (the "pluginid" column of the report)
    until: 2026-12-31            # the acceptance expires: past this date the alert blocks again
    reason: CSP is applied at the edge (WAF); evidence in ticket SEC-123
  - pluginId: 90003
    until: 2026-12-31
    reason: plain-text file, nothing to pin with Subresource Integrity
    paths: [/llms-full.txt]      # optional: only when every occurrence is on one of these exact paths
```

Without `paths` the acceptance covers the whole plugin; with `paths`, an occurrence on any other path keeps blocking.
`test/run.sh` proves both rules on the fixture report in `test/`, and `aedis-ci` also runs the action against a static
site served in the job.

## License

Apache-2.0. See [LICENSE](LICENSE) and [SECURITY.md](SECURITY.md).
