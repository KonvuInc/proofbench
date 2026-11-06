---
name: deploy
description: Stand up the target from plan.json as a local Docker Compose lab, repair it when reality diverges from the docs, and get it to a passing readiness gate and victim baseline. Never attacks. Used by the reproduce skill.
---

# Deploy: plan.json → a lab that is ready for the experiment

Input: `runs/<id>/plan.json`, and `runs/<id>/lab/` if a starter lab was given.
Output: `runs/<id>/lab/compose.yml` (plus seed scripts and config files beside it), a passing
`pb smoke`, a passing `pb victim <run> before`, and a `pb observe <run> before`
when the plan declares observations.

## Hard rule: the deployer never attacks

Never send the exploit, the payload or the vulnerable request, not even "to check it works".
A benign body can still run the vulnerable code path. The readiness probes and the victim
baseline are the only traffic you send. Exploit traffic starts at the `attack` stage, through
`pb attack`.

## Loop

```
write/repair lab ──> pb up ──fail──> read the diagnostic ──> repair ─┐
                        │ ok                                           │ (≤ 3 starts in total)
                        v                                              │
                    pb smoke ──fail──> repair ──────────────────────┘
                        │ ok
                        v
               pb victim <run> before ──steps fail──> fix the victim steps in plan.json
```

- `pb up` refuses when the target service's image differs from `plan.target.image`. That
  is deliberate. Fix the lab, not the pin.
- `pb up` forces every lab network `internal`: containers have no internet at runtime,
  and published ports don't reach your host. Do installs in an image `build:` (builds
  still have internet), not in a startup command. `network_mode` and external networks
  are refused.
- After 3 starts the budget is spent. Run `pb verdict` (it will say inconclusive) and
  `pb down`. Don't create a new run to dodge the budget.
- Each `up` snapshots `lab/` and prints the diff since the previous attempt. That diff is
  the repair evidence, so keep each repair small and on purpose.

## What a repair may change

Allowed: healthchecks, ports, env and config the plan lists as prerequisites, seed data,
service wiring, waiting and ordering, missing system tools in *helper* containers.

Forbidden: the target's version or image, the application's code, its security settings
(auth, CSP, sanitizers, access control) beyond what the plan lists as prerequisites, and
anything in `verification/`.

## Read before you guess

- When `up` fails, read the `healthcheck ...` lines and the logs it prints. Example: the
  Grafana 9.3.8 image has no `curl`, so a `curl` healthcheck never passes; busybox `wget`
  is there.
- Read the app's own source and entrypoint *inside the container* to learn its real
  config keys, routes and seed format:
  `docker compose -p proofbench-<id> -f runs/<id>/lab/compose.yml exec <svc> sh -c '...'`.
- **Confirm the vulnerable code is really deployed.** Grep the running container's files
  for the vulnerable function or line before calling the lab ready. Docker tags are mutable
  and images get silently patched. If the fix is present, run
  `pb stop <run> not_vulnerable_version "<file:line evidence>"`.
- **Healthy is not ready.** After `up` passes, verify the seed: users exist with the
  planned roles (check through an identity endpoint like `/api/user`), plugins are enabled,
  the objects the exploit needs exist. If a probe in the plan is too weak to show this,
  strengthen the probe in `plan.json` before the attack starts. The plan locks at the first
  `pb attack`.
- The victim baseline must complete every step and show **no** canary. If a selector is
  wrong, inspect the page with benign browsing only and fix the step in `plan.json`.
  Baseline failures can also come from the browser: the observer pins `locale=en-US`
  because Grafana 9.3 throws on the container default.

## Lab conventions

- One compose file at `lab/compose.yml`. Use service names; publish no ports (the
  internal network doesn't route them to the host).
- An attacker-controlled component the report assumes (a data source, a webhook receiver,
  an OAuth provider) is a small fixture that serves files from
  `../attack/work/<name>:/data:ro`. The attacker writes there and nowhere else.
- Witness services for blind effects (SSRF hit log, mail catcher) are lab services the
  observations can read. `up` refuses an observation on a service that mounts
  `attack/work`: that would be the attacker grading itself.
- List what you seeded in `plan.seed`: one read-only command per kind of object
  (users and roles, the target records), e.g. a SQL `SELECT`. `smoke` prints them; the verdict
  ignores them.
- For a `leak` oracle, seed `${PROOFBENCH_SECRET}` where only the bug exposes it (a victim-only
  row, an internal service's response, a file outside the web root). `up` records whether
  the secret made it into the lab; if not, the verdict is inconclusive.
