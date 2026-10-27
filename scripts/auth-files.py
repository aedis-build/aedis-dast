#!/usr/bin/env python3
"""Turns a session description, {"headers": {...}, "cookies": {...}} on stdin, into the files the scanners read, in a
directory outside the artifact: `headers` (one `Name: value` per line, cookies joined into one Cookie header; the
same lines feed Nuclei's -H) and `zap.conf` (ZAP -configfile: a replacer rule per header, plus a global exclusion of
the logout paths so the spider never ends the session). Every value is masked in the job log (::add-mask::) and never
printed otherwise.

Usage: auth-files.py --out <dir> [--logout-paths "/logout,/signout"] < session.json
       auth-files.py --self-test
"""
import argparse, json, os, re, sys, tempfile


def header_lines(session):
    lines = [f"{k}: {v}" for k, v in (session.get("headers") or {}).items() if v]
    cookies = session.get("cookies") or {}
    if cookies:
        lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()))
    return lines


def zap_conf(lines, logout_paths):
    conf = []
    for i, line in enumerate(lines):
        name, value = line.split(": ", 1)
        p = f"replacer.full_list({i})"
        conf += [f"{p}.description=auth-{name}", f"{p}.enabled=true", f"{p}.matchtype=REQ_HEADER", f"{p}.matchstr={name}",
                 f"{p}.regex=false", f"{p}.replacement={value}"]
    paths = [p.strip() for p in logout_paths.split(",") if p.strip()]
    if paths:
        conf += ["globalexcludeurl.url_list.url(0).regex=.*(" + "|".join(re.escape(p) for p in paths) + ").*",
                 "globalexcludeurl.url_list.url(0).description=session end", "globalexcludeurl.url_list.url(0).enabled=true"]
    return conf


def write(session, out, logout_paths):
    lines = header_lines(session)
    if not lines:
        raise SystemExit("the login command printed no headers and no cookies")
    os.makedirs(out, mode=0o700, exist_ok=True)
    for name, content in (("headers", lines), ("zap.conf", zap_conf(lines, logout_paths))):
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(content) + "\n")
        os.chmod(path, 0o600)
    for line in lines:
        print(f"::add-mask::{line.split(': ', 1)[1]}")
    for v in (session.get("cookies") or {}).values():
        print(f"::add-mask::{v}")
    print(f"session headers: {', '.join(l.split(':', 1)[0] for l in lines)}", file=sys.stderr)


def self_test():
    s = {"headers": {"Authorization": "Bearer abc def"}, "cookies": {"sid": "1", "csrf": "x=y"}}
    assert header_lines(s) == ["Authorization: Bearer abc def", "Cookie: sid=1; csrf=x=y"]
    conf = zap_conf(header_lines(s), "/logout, /api/auth/signout")
    assert "replacer.full_list(0).replacement=Bearer abc def" in conf and "replacer.full_list(1).matchstr=Cookie" in conf
    assert conf[-3] == "globalexcludeurl.url_list.url(0).regex=.*(/logout|/api/auth/signout).*", conf[-3]
    assert zap_conf(["X: 1"], "") == ["replacer.full_list(0).description=auth-X", "replacer.full_list(0).enabled=true",
                                      "replacer.full_list(0).matchtype=REQ_HEADER", "replacer.full_list(0).matchstr=X",
                                      "replacer.full_list(0).regex=false", "replacer.full_list(0).replacement=1"]
    assert header_lines({"headers": {"A": ""}}) == []
    with tempfile.TemporaryDirectory() as d:
        write(s, os.path.join(d, "auth"), "/logout")
        assert open(os.path.join(d, "auth", "headers")).read() == "Authorization: Bearer abc def\nCookie: sid=1; csrf=x=y\n"
        assert os.path.exists(os.path.join(d, "auth", "zap.conf"))
    print("self-test ok")


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--out")
    a.add_argument("--logout-paths", default="")
    a.add_argument("--self-test", action="store_true")
    args = a.parse_args()
    if args.self_test:
        self_test(); return 0
    if not args.out:
        a.error("--out is required")
    try:
        session = json.load(sys.stdin)
    except json.JSONDecodeError as e:
        raise SystemExit(f"the login command must print a JSON object with headers and/or cookies: {e}")
    write(session, args.out, args.logout_paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
