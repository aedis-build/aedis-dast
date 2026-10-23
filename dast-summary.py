#!/usr/bin/env python3
"""Converte o relatório JSON do ZAP baseline no sumário aedis.platform/dast-summary/v1 e aplica o gate: qualquer
alerta com risco >= --fail-on não aceito falha. Aceites (dast-accept.yaml) têm pluginId, until (AAAA-MM-DD) e reason,
e opcionalmente paths: a lista de caminhos (exatos) a que o aceite se limita. Com paths, o alerta só é aceito se toda
ocorrência dele estiver num desses caminhos; uma ocorrência em outro caminho continua bloqueando.

Uso: dast-summary.py --report report.json [--accept dast-accept.yaml] [--fail-on High|Medium] [--out dast-summary.json] [--self-test]
"""
import argparse, json, os, sys
from urllib.parse import urlparse
from datetime import date, datetime, timezone

RISKS = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}


def load_accepts(path):
    if not path or not os.path.exists(path):
        return []
    import yaml  # PyYAML vem com o runner
    data = yaml.safe_load(open(path, encoding="utf-8")) or {}
    return [a for a in data.get("accept", []) if date.fromisoformat(str(a["until"])) >= date.today()]


def covering(accepts, pid, alert):
    """O aceite que cobre todas as ocorrências do alerta, ou None. Sem paths, o aceite vale para o plugin inteiro."""
    mine = [x for x in accepts if str(x["pluginId"]) == pid]
    whole = next((x for x in mine if not x.get("paths")), None)
    if whole:
        return whole
    uris = [i.get("uri", "") for i in alert.get("instances", [])]
    if not uris:
        return None
    for x in mine:
        if all(urlparse(u).path in x["paths"] for u in uris):
            return x
    return None


def summarize(report, accepts, fail_on, target=""):
    alerts = []
    for site in report.get("site", []):
        for a in site.get("alerts", []):
            pid = str(a.get("pluginid"))
            accepted = covering(accepts, pid, a)
            alerts.append({"pluginId": pid, "name": a.get("alert", ""), "risk": RISKS.get(str(a.get("riskcode")), "Informational"),
                           "count": int(a.get("count", len(a.get("instances", [])))),
                           "accepted": accepted["reason"] if accepted else None})
    blocking = [x for x in alerts if RANK[x["risk"]] >= RANK[fail_on] and not x["accepted"]]
    return {"schema": "aedis.platform/dast-summary/v1",
            "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "target": target, "failOn": fail_on,
            "result": "pass" if not blocking else "fail",
            "counts": {r: sum(1 for x in alerts if x["risk"] == r) for r in RANK},
            "blocking": len(blocking), "accepted": sum(1 for x in alerts if x["accepted"]), "alerts": alerts}


def self_test():
    rep = {"site": [{"alerts": [{"pluginid": 40012, "alert": "XSS", "riskcode": "3", "count": "1"},
                                {"pluginid": 10038, "alert": "CSP", "riskcode": "2", "instances": [{}, {}]}]}]}
    assert summarize(rep, [], "High")["result"] == "fail"
    assert summarize(rep, [{"pluginId": 40012, "reason": "x", "until": "2999-01-01"}], "High")["result"] == "pass"
    assert summarize(rep, [{"pluginId": 40012, "reason": "x", "until": "2999-01-01"}], "Medium")["blocking"] == 1
    assert summarize({}, [], "Medium")["result"] == "pass"
    sri = {"site": [{"alerts": [{"pluginid": 90003, "alert": "SRI", "riskcode": "2", "instances": [{"uri": "http://h:8080/llms-full.txt"}]}]}]}
    scoped = [{"pluginId": 90003, "reason": "texto puro", "until": "2999-01-01", "paths": ["/llms-full.txt"]}]
    assert summarize(sri, scoped, "Medium")["result"] == "pass"
    sri["site"][0]["alerts"][0]["instances"].append({"uri": "http://h:8080/index.html"})
    assert summarize(sri, scoped, "Medium")["result"] == "fail"
    assert summarize({"site": [{"alerts": [{"pluginid": 90003, "alert": "SRI", "riskcode": "2", "count": "1"}]}]}, scoped, "Medium")["result"] == "fail"
    print("self-test ok")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--report")
    a.add_argument("--accept")
    a.add_argument("--fail-on", default="High", choices=["High", "Medium"])
    a.add_argument("--target", default="")
    a.add_argument("--out", default="dast-summary.json")
    a.add_argument("--self-test", action="store_true")
    args = a.parse_args()
    if args.self_test:
        self_test(); return 0
    summary = summarize(json.load(open(args.report, encoding="utf-8")), load_accepts(args.accept), args.fail_on, args.target)
    json.dump(summary, open(args.out, "w", encoding="utf-8"), indent=2)
    c = summary["counts"]
    print(f"DAST {args.target}: {c['High']} high, {c['Medium']} medium, {c['Low']} low, {c['Informational']} info; "
          f"{summary['accepted']} aceitos; {summary['blocking']} bloqueantes (>= {args.fail_on})")
    for x in summary["alerts"]:
        if RANK[x["risk"]] >= RANK[args.fail_on] and not x["accepted"]:
            print(f"  [{x['risk']}] {x['pluginId']} {x['name']} ({x['count']}x)")
    return 1 if summary["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
