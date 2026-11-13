# Lesson-curation HTTP canary

An intentionally vulnerable fixture for disposable, isolated reproduction labs.
It uses Python's standard library, with no package installation or external service.
Never deploy it as a production application or supply real credentials/data.

Build the Dockerfile in this directory. Generate two different temporary bearer
tokens in `CANARY_CONTROL_TOKEN` and `CANARY_ATTACKER_TOKEN`. Mount a readable file
at `/data/protected.txt`, or set `CANARY_PROTECTED_VALUE_FILE` to its path. The file
holds only a synthetic per-run protected value; the reproduction worker can plant
its own read-proof canary there. The container runs as UID/GID 65532.

- `GET /health` is unauthenticated and returns `{"status":"ok"}`. It deliberately
  does not prove that the protected note has been seeded.
- `GET /api/me` reports `owner/admin` for the control token and `reader/user` for
  the attacker token. Missing/invalid credentials get 401.
- `GET /api/notes/owner-note` returns the protected value and the literal record
  marker `bb8-lesson-canary-record-v1`. An absent seed file returns 500 even though
  `/health` still returns 200.
- The default configuration intentionally omits ownership enforcement: a reader
  can fetch the owner's note. `CANARY_ENFORCE_OWNER=1` provides the fixed control;
  it refuses the reader with 403 while the owner still succeeds.
- `CANARY_METHOD=POST` exposes the same read operation through POST only, with an
  accurate OPTIONS/Allow response. This checks that an OPTIONS-only probe remains
  unknown for lesson retention rather than being credited as a verified fixture.
- `CANARY_FORCE_FAILURE=1` makes the note operation return 500 for a controlled
  negative check. Use it only in a dedicated disposable canary lab.

Qualify the actual HTTP contract locally with `python3 qualify.py`. Credentials
and protected values are generated in memory and are never printed or committed.
