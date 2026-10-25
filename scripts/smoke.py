"""Smoke test against a running server:  python scripts/smoke.py http://127.0.0.1:8000"""

import json
import sys
import time
import urllib.request

base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, method=method, data=data)  # noqa: S310 - operator-supplied URL
    req.add_header("X-Scradar-Request", "1")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310
        return json.loads(r.read() or b"null")


assert call("GET", "/api/v1/health")["status"] == "ok"
print("version:", call("GET", "/api/v1/version"))
call("POST", "/api/v1/demo")
for _ in range(60):
    projects = call("GET", "/api/v1/projects")
    if projects and all(p["latest_scan"] and not p["active_scan"] for p in projects):
        break
    time.sleep(0.5)
else:
    raise SystemExit("demo scans did not finish")
total = sum(p["latest_scan"]["summary"]["findings"] for p in projects)
print(f"OK: {len(projects)} demo projects, {total} confirmed advisories in their latest scans")
