"""Readiness probes, run inside the lab network.

Usage: python probe.py <probes.json>   → prints a JSON list of results.

A probe passes only if the status AND the expected body fragment match.
`/health` answering 200 is not readiness: probe the exploit path's prerequisites.
"""

import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT_S = 15
BODY_EXCERPT = 300


def check(probe: dict) -> dict:
    """Run one probe. Example: {"name": "functions", "url": "http://grafana:3000/x", "status": 200, "contains": "aggregate"}."""
    req = urllib.request.Request(probe["url"], method=probe.get("method", "GET"))

    if auth := probe.get("auth"):
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")

    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            status, body = resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001 - a probe reports, never crashes the gate
        return {"name": probe["name"], "ok": False, "error": repr(e)}

    ok = status == probe.get("status", 200) and probe.get("contains", "") in body
    return {"name": probe["name"], "ok": ok, "status": status, "body": body[:BODY_EXCERPT]}


if __name__ == "__main__":
    probes = json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps([check(p) for p in probes]))
