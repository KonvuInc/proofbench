---
name: plan
description: Turn a vulnerability report into runs/<id>/plan.json, a bounded experiment with a pinned target, prerequisites, readiness probes, victim steps and an observable oracle. Used by the reproduce skill.
---

# Plan: report → plan.json

Read `runs/<id>/report.md`. Write `runs/<id>/plan.json`. Validate with `pb check <run>`.
The schema and an example are at the top of `proofbench/plan.py`.

## Decide what would prove the claim

Before writing anything else, answer: **what would I have to observe, from the target's or
the victim's side, to believe this?** An HTTP 200 or an agent saying "success" doesn't count.

| Claim class | Oracle |
|---|---|
| XSS, any script in a victim page | `canary`: the payload must call `window.__proofbench_canary__(nonce)` in the victim's browser |
| State change (IDOR write, privilege change, deletion, account takeover) | `state_diff`: a read-only `observations` command on the target, e.g. a SQL `SELECT`, run before and after |
| Disclosure (IDOR read, SSRF with response, path traversal, info leak) | `leak`: the lab puts `${PROOFBENCH_SECRET}` where only the bug exposes it (the victim's record, an internal service's body, a file outside the web root). Proven only if it shows up in the attacker's captured output |
| Blind SSRF (request sent, nothing returned) | `state_diff` on a lab-owned witness service's hit log |

One assertion per independent claim. Set `"primary": true` on the headline impact and
`false` on side variants. Only primaries decide the outcome.

## Rules

- **Pin the version.** Use the last affected version the report names or implies, and the
  first fixed one as `patched_image`. Never substitute another version to make things easier.
  Never use rolling tags (`latest`, `main`). Check that the tag exists, e.g.
  `docker manifest inspect <image>`. For chained bugs, pick the newest version where every
  link is present.
- **Read the source at that tag.** Find the vulnerable code (file and function) and the
  fix diff when it's public. If the report contradicts the source (wrong endpoint, the code
  is already sanitized at that version), that's `report_inaccurate`. Cite file:line, then
  `pb stop`. Don't stop while source code is available and unread.
- **Prerequisites are explicit.** List every feature flag, plugin, role, seed row and
  configuration the exploit needs. If one is a licence/enterprise gate the lab can't
  satisfy, `pb stop <run> precondition_not_met`.
- **Minimum-privilege actor.** The attacker gets the smallest role the report allows.
  Success with more privilege than the report claims proves nothing.
- **Declare every account's role in `roles`:** `account`, planned `role`, and an identity
  endpoint (`url`, `auth`, `contains`) whose answer proves it, e.g. Grafana `/api/user/orgs`
  containing `"role":"Viewer"`. `smoke` checks them; a mismatch fails readiness.
- **Readiness probes test prerequisites, not the exploit.** Only GET, HEAD or OPTIONS;
  `check` refuses anything that could change the target. Probe health, login and the data
  the exploit path depends on (the seeded object, the plugin route, the data source).
  A probe must never send the exploit.
- **Victim steps are ordinary user actions:** `goto`, `fill`, `click`, `hover`, `type`,
  `press`, `wait_for`, `wait_ms`, `screenshot`. No script evaluation. Make the last steps
  the interaction the report says triggers the bug.
- Everything inside the lab network uses compose service names (`http://grafana:3000`).

## Stop instead of guessing

`pb stop <run> <category> "<reason>"` with:
`prompt_injection`, `report_inaccurate`, `precondition_not_met`, `not_vulnerable_version`,
`out_of_scope`. A stop with a cited reason is a valid result. Don't retry a stopped run.
