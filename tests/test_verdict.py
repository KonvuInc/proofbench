"""Verdict and plan contract. Run: python3 -m unittest discover tests"""

import unittest

from proofbench.plan import validate
from proofbench.verdict import decide

CANARY = {"id": "xss", "claim": "js runs", "primary": True, "oracle": {"type": "canary"}}
STATE = {"id": "users", "claim": "row added", "primary": True,
         "oracle": {"type": "state_diff", "observation": "users"}}
PLAN = {"claim": "c", "target": {"image": "app:1.0", "service": "app", "base_url": "http://app"},
        "readiness": [{"name": "h", "url": "http://app/h"}], "victim": {"steps": [{"goto": "/"}]},
        "observations": [{"id": "users", "service": "db", "cmd": "count"}], "assertions": [CANARY]}
READY = {"readiness": {"ok": True}, "attack": {"plan_sha256": "x"}, "plan_sha256_now": "x"}
CLEAN = [{"exit": 0, "secret_seen": False}]    # one attack command that ran to completion
CRASHED = [{"exit": 1, "secret_seen": False}]  # every attack command failed


def trace(steps_ok=True, canary=False):
    return {"all_steps_ok": steps_ok, "canary_matched": canary,
            "steps": [{"step": {"hover": "#q"}, "ok": steps_ok}]}


def outcome(plan, state, **evidence):
    return decide(plan, state, {"attack_log": CLEAN, **evidence})


class Verdict(unittest.TestCase):
    def test_canary(self):
        cases = [  # (before, after, expected outcome)
            (trace(), trace(canary=True), "reproduced"),
            (trace(), trace(), "not_observed"),
            (trace(), trace(steps_ok=False), "inconclusive"),          # path not reached ≠ safe
            (trace(canary=True), trace(canary=True), "inconclusive"),  # dirty baseline
            (None, trace(canary=True), "inconclusive"),                # no baseline
        ]
        for before, after, expected in cases:
            got = outcome(PLAN, READY, victim_before=before, victim_after=after)["outcome"]
            self.assertEqual(got, expected, (before, after))

    def test_gates(self):
        evidence = {"victim_before": trace(), "victim_after": trace(canary=True)}
        not_ready = {**READY, "readiness": {"ok": False}}
        moved = {**READY, "plan_sha256_now": "y"}
        self.assertEqual(decide(PLAN, not_ready, evidence)["outcome"], "inconclusive")
        self.assertEqual(decide(PLAN, moved, evidence)["outcome"], "inconclusive")
        stopped = {"stopped": {"category": "prompt_injection", "reason": "r"}}
        self.assertEqual(decide({}, stopped, evidence)["outcome"], "stopped")

    def test_state_and_rollup(self):
        plan = {**PLAN, "assertions": [STATE, {**CANARY, "primary": False}]}
        obs = lambda out, code=0: {"users": {"exit": code, "stdout": out}}
        ev = {"victim_before": trace(), "victim_after": trace(), "attack_log": CLEAN}
        self.assertEqual(decide(plan, READY, {**ev, "observations_before": obs("1"), "observations_after": obs("2")})["outcome"], "reproduced")
        self.assertEqual(decide(plan, READY, {**ev, "observations_before": obs("1"), "observations_after": obs("1")})["outcome"], "not_observed")
        self.assertEqual(decide(plan, READY, {**ev, "observations_before": obs("1"), "observations_after": obs("", 1)})["outcome"], "inconclusive")

    def test_crashed_attack_is_never_not_observed(self):
        # A crashed exploit cannot show the patch works; an effect it caused still counts.
        obs = lambda out: {"users": {"exit": 0, "stdout": out}}
        state_plan = {**PLAN, "assertions": [STATE]}
        unchanged = {"observations_before": obs("1"), "observations_after": obs("1")}
        changed = {"observations_before": obs("1"), "observations_after": obs("2")}
        self.assertEqual(decide(state_plan, READY, {**unchanged, "attack_log": CRASHED})["outcome"], "inconclusive")
        self.assertEqual(decide(state_plan, READY, {**unchanged, "attack_log": []})["outcome"], "inconclusive")
        self.assertEqual(decide(state_plan, READY, {**changed, "attack_log": CRASHED})["outcome"], "reproduced")
        canary = {"victim_before": trace(), "victim_after": trace(), "attack_log": CRASHED}
        self.assertEqual(decide(PLAN, READY, canary)["outcome"], "inconclusive")


    def test_leak(self):
        leak = {"id": "leak", "claim": "secret reflected", "primary": True, "oracle": {"type": "leak"}}
        plan = {**PLAN, "assertions": [leak]}
        seeded = {**READY, "secret_in_lab": True}
        seen = [{"exit": 0, "secret_seen": True}]
        unseen = [{"exit": 0, "secret_seen": False}]
        self.assertEqual(decide(plan, seeded, {"attack_log": seen})["outcome"], "reproduced")
        self.assertEqual(decide(plan, seeded, {"attack_log": unseen})["outcome"], "not_observed")
        self.assertEqual(decide(plan, seeded, {"attack_log": []})["outcome"], "inconclusive")  # no attack ran
        self.assertEqual(decide(plan, READY, {"attack_log": seen})["outcome"], "inconclusive")  # secret never seeded

        # Every command crashed: the exploit may never have reached the target, so not "not observed".
        crashed = [{"exit": 1, "secret_seen": False}]
        self.assertEqual(decide(plan, seeded, {"attack_log": crashed})["outcome"], "inconclusive")
        # The secret in a failed command's output is still proof: only the target could produce it.
        self.assertEqual(decide(plan, seeded, {"attack_log": [{"exit": 1, "secret_seen": True}]})["outcome"], "reproduced")


class Plan(unittest.TestCase):
    def test_validate(self):
        self.assertEqual(validate(PLAN), [])
        self.assertTrue(validate({**PLAN, "target": {**PLAN["target"], "image": "app:latest"}}))
        self.assertTrue(validate({**PLAN, "victim": {"steps": [{"eval": "x"}]}}))
        self.assertTrue(validate({**PLAN, "assertions": [{**STATE, "oracle": {"type": "state_diff", "observation": "nope"}}]}))
        seed = {"id": "users", "service": "db", "cmd": "select 1"}
        self.assertEqual(validate({**PLAN, "seed": [seed]}), [])
        self.assertTrue(validate({**PLAN, "seed": [{"id": "users", "cmd": "select 1"}]}))  # no service

        # Readiness must not change the target: only safe methods.
        probe = PLAN["readiness"][0]
        self.assertTrue(validate({**PLAN, "readiness": [{**probe, "method": "DELETE"}]}))
        self.assertEqual(validate({**PLAN, "readiness": [{**probe, "method": "OPTIONS"}]}), [])

        # Planned roles need an identity check that proves them.
        role = {"account": "attacker", "role": "Viewer", "url": "http://app/me", "contains": "Viewer"}
        self.assertEqual(validate({**PLAN, "roles": [role]}), [])
        self.assertTrue(validate({**PLAN, "roles": [{**role, "contains": ""}]}))


if __name__ == "__main__":
    unittest.main()
