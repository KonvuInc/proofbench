"""Exercise real HTTP readiness, identity, IDOR and negative controls locally."""

import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run_case(label, **overrides):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        control, attacker, protected = (secrets.token_urlsafe(24) for _ in range(3))
        seed = root / "protected.txt"
        seed.write_text(protected)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env = {
            **os.environ,
            "CANARY_BIND": "127.0.0.1",
            "PORT": str(port),
            "CANARY_CONTROL_TOKEN": control,
            "CANARY_ATTACKER_TOKEN": attacker,
            "CANARY_PROTECTED_VALUE_FILE": str(seed),
            "CANARY_METHOD": "GET",
            "CANARY_FORCE_FAILURE": "0",
            "CANARY_ENFORCE_OWNER": "0",
            **overrides,
        }
        process = subprocess.Popen(
            [sys.executable, str(HERE / "server.py")],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        def request(path, token=None, method="GET"):
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}", headers=headers, method=method
            )
            try:
                response = urllib.request.urlopen(request, timeout=2)
            except urllib.error.HTTPError as response_error:
                response = response_error
            with response:
                raw = response.read()
                return response.status, json.loads(raw) if raw else {}, response.headers

        try:
            for _ in range(100):
                try:
                    if request("/health")[0] == 200:
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError("fixture did not start")
            assert request("/api/notes/owner-note")[0] == 401
            assert request("/api/me", control)[1]["role"] == "admin"
            assert request("/api/me", attacker)[1]["role"] == "user"
            method = env["CANARY_METHOD"]
            status, body, _ = request("/api/notes/owner-note", control, method)
            if env["CANARY_FORCE_FAILURE"] == "1":
                assert status == 500
            else:
                assert status == 200 and body["marker"] == "bb8-lesson-canary-record-v1"
                assert body["body"] == protected
                result = request("/api/notes/owner-note", attacker, method)
                assert result[0] == (403 if env["CANARY_ENFORCE_OWNER"] == "1" else 200)
                if result[0] == 200:
                    assert result[1]["body"] == protected
                if method == "POST":
                    assert request("/api/notes/owner-note", control)[0] == 405
                    assert (
                        "POST"
                        in request("/api/notes/owner-note", control, "OPTIONS")[2][
                            "Allow"
                        ]
                    )
                seed.unlink()
                assert request("/health")[0] == 200
                assert request("/api/notes/owner-note", control, method)[0] == 500
            print(json.dumps({"case": label, "passed": True}))
        finally:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    run_case("healthy_get_and_real_idor")
    run_case("fixed_owner_check", CANARY_ENFORCE_OWNER="1")
    run_case("post_only_unknown_control", CANARY_METHOD="POST")
    run_case("controlled_http_500", CANARY_FORCE_FAILURE="1")
