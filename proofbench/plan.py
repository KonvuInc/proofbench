"""plan.json contract. Written by the planning agent, validated here before anything runs.

Minimal example:
{
  "claim": "Stored XSS in the Graphite function description tooltip",
  "target": {"image": "grafana/grafana:9.3.8", "patched_image": "grafana/grafana:9.3.11",
             "service": "grafana", "base_url": "http://grafana:3000"},
  "prerequisites": ["attacker controls the Graphite /functions response"],
  "readiness": [{"name": "health", "url": "http://grafana:3000/api/health", "status": 200}],
  "victim": {"steps": [{"goto": "/login"}]},
  "observations": [{"id": "users", "service": "db", "cmd": "psql -tAc 'select count(*) from users'"}],
  "assertions": [{"id": "xss", "claim": "...", "primary": true, "oracle": {"type": "canary"}}]
}
"""

import re
from enum import Enum


class OracleType(str, Enum):
    CANARY = "canary"          # script ran in the victim's page
    STATE_DIFF = "state_diff"  # target state changed, read-only before/after
    LEAK = "leak"              # per-run lab secret reached the attacker


ORACLES = {oracle.value for oracle in OracleType}
STEP_KINDS = {"goto", "fill", "click", "hover", "press", "type", "wait_for", "wait_ms", "screenshot"}
# Readiness must leave the target as the exploit will find it: no writes, no deletes.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# Pinned tag or digest; rolling tags (latest, main, ...) make the experiment unrepeatable.
ROLLING_TAG = re.compile(r":(latest|main|master|nightly|dev)$")


def validate(plan: dict) -> list[str]:
    """Return human-readable errors. Empty list = valid."""
    errors = []
    target = plan.get("target", {})

    for key in ("claim", "target", "readiness", "assertions"):
        if not plan.get(key):
            errors.append(f"missing '{key}'")

    for key in ("image", "service", "base_url"):
        if not target.get(key):
            errors.append(f"missing 'target.{key}'")

    image = target.get("image", "")
    if ":" not in image or ROLLING_TAG.search(image):
        errors.append(f"target.image must be pinned to a version, got '{image}'")

    for probe in plan.get("readiness", []):
        if not probe.get("name") or not probe.get("url"):
            errors.append(f"readiness probe needs 'name' and 'url': {probe}")
        if probe.get("method", "GET").upper() not in SAFE_METHODS:
            errors.append(f"readiness probe '{probe.get('name')}' must not change the target: "
                          f"method {probe.get('method')}, allowed {sorted(SAFE_METHODS)}")

    # Planned roles: each account the exploit uses, with an identity check proving its role.
    for role in plan.get("roles", []):
        if not all(role.get(field) for field in ("account", "role", "url", "contains")):
            errors.append(f"role needs 'account', 'role', 'url' and 'contains': {role}")

    steps = plan.get("victim", {}).get("steps", [])
    for step in steps:
        if len(step) != 1 or next(iter(step)) not in STEP_KINDS:
            errors.append(f"victim step must be one of {sorted(STEP_KINDS)}: {step}")

    # Seed inventory: read-only commands that list what the lab seeded. Shown, never judged.
    for item in plan.get("seed", []):
        if not item.get("id") or not item.get("service") or not item.get("cmd"):
            errors.append(f"seed entry needs 'id', 'service' and 'cmd': {item}")

    observation_ids = {observation.get("id") for observation in plan.get("observations", [])}
    for assertion in plan.get("assertions", []):
        errors += _check_assertion(assertion, observation_ids, steps)

    return errors


def _check_assertion(assertion: dict, observation_ids: set, victim_steps: list) -> list[str]:
    errors = []
    oracle = assertion.get("oracle", {})

    if not assertion.get("id") or not assertion.get("claim"):
        errors.append(f"assertion needs 'id' and 'claim': {assertion}")

    if oracle.get("type") not in ORACLES:
        errors.append(f"assertion '{assertion.get('id')}': oracle.type must be one of {sorted(ORACLES)}")
        return errors

    if oracle["type"] == OracleType.CANARY and not victim_steps:
        errors.append(f"assertion '{assertion.get('id')}': canary oracle needs victim.steps")

    if oracle["type"] == OracleType.STATE_DIFF and oracle.get("observation") not in observation_ids:
        errors.append(f"assertion '{assertion.get('id')}': unknown observation '{oracle.get('observation')}'")

    return errors
