"""Verdict: computed in code from controller-owned observations, never from agent claims.

    plan.json assertions ──┐
    victim traces (before/after) ──┼──> per-assertion status ──> rollup ──> outcome
    observations (before/after) ──┘

Statuses: proven | not_observed | inconclusive (inconclusive always carries a reason).
Rollup: over primary assertions, any inconclusive → None,
≥1 proven and the rest not_observed → True, all not_observed → False.
"""

from enum import Enum

from proofbench.plan import OracleType


class Status(str, Enum):
    PROVEN = "proven"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"


class Outcome(str, Enum):
    REPRODUCED = "reproduced"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    STOPPED = "stopped"




def judge_canary(before: dict | None, after: dict | None) -> tuple[Status, str]:
    """XSS-style oracle: nonce canary absent before the attack, present after the victim's steps."""
    if before is None or after is None:
        return Status.INCONCLUSIVE, "missing victim baseline or after-attack run"

    if not before["all_steps_ok"]:
        return Status.INCONCLUSIVE, "baseline victim run did not complete its steps"

    if before["canary_matched"]:
        return Status.INCONCLUSIVE, "canary already present before the attack (dirty baseline)"

    if after["canary_matched"]:
        return Status.PROVEN, "nonce canary called from the victim's page after the attack"

    if not after["all_steps_ok"]:
        failed = next((step for step in after["steps"] if not step["ok"]), {})
        return Status.INCONCLUSIVE, f"victim path not reached: {failed.get('step')} failed"

    return Status.NOT_OBSERVED, "victim completed every step; canary not observed"


def judge_state_diff(before: dict | None, after: dict | None, expect: dict) -> tuple[Status, str]:
    """State oracle: a read-only probe on the target, run by the controller before and after."""
    if before is None or after is None:
        return Status.INCONCLUSIVE, "missing before or after observation"

    if before["exit"] != 0 or after["exit"] != 0:
        return Status.INCONCLUSIVE, "observation command failed"

    if contains := expect.get("after_contains"):
        if contains in before["stdout"]:
            return Status.INCONCLUSIVE, f"'{contains}' already present before the attack"
        if contains in after["stdout"]:
            return Status.PROVEN, f"'{contains}' appeared after the attack"
        return Status.NOT_OBSERVED, f"'{contains}' not present after the attack"

    if before["stdout"] != after["stdout"]:
        return Status.PROVEN, "target state changed"
    return Status.NOT_OBSERVED, "target state unchanged"


def judge_leak(seeded: bool, log: list[dict]) -> tuple[Status, str]:
    """Disclosure oracle: the per-run secret, seeded only inside the lab, shows up in attacker output."""
    if not seeded:
        return Status.INCONCLUSIVE, "secret not seeded in the lab (use ${PROOFBENCH_SECRET} in compose.yml)"

    if any(entry.get("secret_seen") for entry in log):
        return Status.PROVEN, "lab secret appeared in the attacker's captured output"
    return Status.NOT_OBSERVED, "lab secret never appeared in the attacker's output"


def attack_completed(log: list[dict]) -> str | None:
    """Why "not observed" cannot be trusted, or None: it needs an exploit that ran to completion.

    A crashed or missing attack cannot tell "the fix blocked it" from "the exploit never
    reached the target". An effect the attack did cause still counts as proof.
    """
    if not log:
        return "no attack command ran"
    if not any(entry.get("exit") == 0 for entry in log):
        return "every attack command failed; the exploit may not have reached the target"
    return None


def judge(assertion: dict, state: dict, evidence: dict) -> tuple[Status, str]:
    status, reason = _judge_oracle(assertion, state, evidence)
    if status == Status.NOT_OBSERVED and (incomplete := attack_completed(evidence.get("attack_log", []))):
        return Status.INCONCLUSIVE, incomplete
    return status, reason


def _judge_oracle(assertion: dict, state: dict, evidence: dict) -> tuple[Status, str]:
    oracle = assertion["oracle"]

    if oracle["type"] == OracleType.CANARY:
        return judge_canary(evidence.get("victim_before"), evidence.get("victim_after"))

    if oracle["type"] == OracleType.LEAK:
        return judge_leak(state.get("secret_in_lab", False), evidence.get("attack_log", []))

    obs_id = oracle["observation"]
    before = evidence.get("observations_before", {}).get(obs_id)
    after = evidence.get("observations_after", {}).get(obs_id)
    return judge_state_diff(before, after, oracle)


def rollup(statuses: list[tuple[bool, Status]]) -> bool | None:
    """statuses = [(primary, status)]. See module docstring."""
    if not statuses:
        return None

    primaries = [status for primary, status in statuses if primary]
    pool = primaries or [status for _, status in statuses]
    if Status.INCONCLUSIVE in pool:
        return None
    return Status.PROVEN in pool


def decide(plan: dict, state: dict, evidence: dict) -> dict:
    """Build result.json content. `evidence` holds parsed traces/observations keyed by label."""
    if stopped := state.get("stopped"):
        return {"outcome": Outcome.STOPPED.value, "category": stopped["category"],
                "reason": stopped["reason"], "assertions": []}

    blocker = None
    if not state.get("readiness", {}).get("ok"):
        blocker = "target never passed readiness"
    elif state.get("attack", {}).get("plan_sha256") not in (None, state.get("plan_sha256_now")):
        blocker = "plan.json changed after the attack started"

    results = []
    for assertion in plan["assertions"]:
        status, reason = (Status.INCONCLUSIVE, blocker) if blocker else judge(assertion, state, evidence)
        results.append({"id": assertion["id"], "claim": assertion["claim"], "primary": assertion.get("primary", True),
                        "status": status.value, "reason": reason})

    success = rollup([(result["primary"], Status(result["status"])) for result in results])
    outcome = {True: Outcome.REPRODUCED, False: Outcome.NOT_OBSERVED, None: Outcome.INCONCLUSIVE}[success]
    return {"outcome": outcome.value, "assertions": results}
