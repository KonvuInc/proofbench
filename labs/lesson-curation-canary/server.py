"""Intentionally vulnerable, dependency-free HTTP fixture. Disposable labs only."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

MARKER = "bb8-lesson-canary-record-v1"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, status, value, allow=None):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if allow:
            self.send_header("Allow", allow)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def handle_request(self):
        path = urlsplit(self.path).path
        if path == "/health":
            return self.reply(200, {"status": "ok"})
        mode = os.environ.get("CANARY_METHOD", "GET").upper()
        if self.command == "OPTIONS":
            return self.reply(204, {}, allow=f"{mode}, OPTIONS")
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        actors = {
            os.environ["CANARY_CONTROL_TOKEN"]: ("owner", "admin"),
            os.environ["CANARY_ATTACKER_TOKEN"]: ("reader", "user"),
        }
        actor = actors.get(token)
        if actor is None:
            return self.reply(401, {"error": "authentication required"})
        if path == "/api/me":
            return self.reply(200, {"username": actor[0], "role": actor[1]})
        if path != "/api/notes/owner-note":
            return self.reply(404, {"error": "note not found"})
        if self.command != mode:
            return self.reply(405, {"error": "wrong method"}, allow=f"{mode}, OPTIONS")
        if os.environ.get("CANARY_FORCE_FAILURE") == "1":
            return self.reply(500, {"error": "controlled canary fixture failure"})
        if os.environ.get("CANARY_ENFORCE_OWNER") == "1" and actor[0] != "owner":
            return self.reply(403, {"error": "not the note owner"})
        try:
            value = (
                Path(
                    os.environ.get("CANARY_PROTECTED_VALUE_FILE", "/data/protected.txt")
                )
                .read_text()
                .strip()
            )
        except OSError:
            return self.reply(500, {"error": "protected fixture file missing"})
        # Deliberate IDOR: the vulnerable configuration omits the owner check.
        return self.reply(
            200, {"id": "owner-note", "owner": "owner", "marker": MARKER, "body": value}
        )

    do_GET = handle_request
    do_HEAD = handle_request
    do_POST = handle_request
    do_OPTIONS = handle_request


if __name__ == "__main__":
    control = os.environ["CANARY_CONTROL_TOKEN"]
    attacker = os.environ["CANARY_ATTACKER_TOKEN"]
    if not control or not attacker or control == attacker:
        raise SystemExit("two distinct nonempty lab credentials are required")
    ThreadingHTTPServer(
        (os.environ.get("CANARY_BIND", "0.0.0.0"), int(os.environ.get("PORT", "8000"))),
        Handler,
    ).serve_forever()
