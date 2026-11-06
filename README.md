# proofbench

A tool for your agent to reproduce vulnerabilities. Hand your coding agent a report: it
plans the experiment, builds a local Docker lab, attacks it, and comes back with a verdict
decided by what the target and a simulated victim showed, not by what the agent says.

```
Report ──────> Sandbox ─────────────────────────> Attack ─────────────────> Recap
plan.json      compose lab, up, readiness,        pb attack -- ...          verdict (code)
(agent)        roles, seed, repair (≤3 starts),   (scoped container)        cleanup receipt
               baselines                          victim/observe after
```

## What it enforces

The patterns from the OWASP Global AppSec San Francisco 2026 talk *Reproducing the exploit,
not the report*, enforced in code rather than asked of the agent:

1. **Check the target, not the agent.** The verdict comes from read-only target state, a
   canary in a simulated victim's browser, or a planted secret reaching the attacker, never
   from what the agent reports.
2. **Healthy is not ready.** Read-only readiness probes and a check of each declared
   account's role must pass before any attack.
3. **Repair within a budget.** Three lab starts, each one diffed against the last.
4. **Keep building and attacking apart.** The attacker runs in a container with no
   capabilities, on a lab network with no internet, and the plan locks at the first exploit.
5. **An inconclusive result says why.** It is never reported as "not vulnerable", and a
   patched-version control replays the same exploit.

## How it works

It ships as a Claude Code plugin. Four skills (`reproduce`, `plan`, `deploy`, `attack`) teach
the agent the method; the agent runs every lab step through a stdlib-only Python CLI. The
agent writes the plan, the lab and the payloads. The CLI owns everything that decides the outcome:

| Owned by the CLI | How |
|---|---|
| Version pin | `up` refuses a lab whose target image differs from `plan.json` |
| Containment | every lab network is forced `internal` (no internet); host networks, external networks, privileged mode, added capabilities, host namespaces and Docker-socket or host-root mounts are refused; the attacker container drops all capabilities |
| Readiness | probes from inside the lab network, GET/HEAD/OPTIONS only, so they cannot fire the exploit |
| Roles | each account's planned role is checked against an identity endpoint; a mismatch fails readiness and blocks the attack |
| Seed inventory | read-only queries list the seeded users and records before the attack |
| Repair evidence | every `up` snapshots the lab and diffs it against the previous attempt |
| Victim browser | headless Chromium performing only the plan's declared steps, recorded |
| Oracles | `canary` (script ran in the victim's page), `state_diff` (read-only target state before/after), `leak` (a per-run lab secret reached the attacker's captured output) |
| Plan lock | the plan is hashed at the first attack; changing it afterwards makes the result inconclusive |
| Verdict | per-assertion proven / not observed / inconclusive, rolled up in code |
| Cleanup | `down -v`, then lists anything still labelled with the run's project |

Outcomes: **reproduced**, **not observed** (in this checked configuration), **inconclusive**
(with the reason), **stopped** (prompt injection, report inaccurate, missing prerequisite…).

## Getting started

You need Docker (running), Python 3.11 or newer (macOS ships 3.9: install a newer one, e.g.
`brew install python`), and [Claude Code](https://claude.com/claude-code). No cloud account.

```bash
git clone https://github.com/KonvuInc/proofbench.git
cd proofbench
python3 -m pip install .            # optional: `pb` on your PATH (else bin/pb)
```

Check your setup with a lab that needs no agent (about 2 minutes; the first run also builds
the ~2 GB browser image used for the simulated victim, once):

```bash
labs/grafana-cve-2024-1313/demo.sh      # Grafana 10.2.5: REPRODUCED
labs/grafana-cve-2024-1313/control.sh   # Grafana 10.2.6: NOT OBSERVED
```

Runs are written to `runs/<id>/` under the directory you run from; each holds the full
evidence for one experiment. Optional: `pip install anthropic` and an `ANTHROPIC_API_KEY` give
one-line summaries of attacker output in the terminal.

## Reproduce a report with Claude Code

```bash
claude --plugin-dir /path/to/proofbench
> /proofbench:reproduce path/to/report.md
```

Claude plans the experiment, writes the lab, attacks through `pb attack`, and reports
what `pb verdict` printed. Pass `--lab <dir>` to start from an existing lab. Run it
on disclosed vulnerabilities only; see the trust model below.

## Labs

| Lab | Class | Oracle | Demo |
|---|---|---|---|
| [grafana-cve-2023-1410](labs/grafana-cve-2023-1410) | stored XSS | browser canary | `demo.sh`: vulnerable, patched, missing prerequisite |
| [grafana-cve-2024-1313](labs/grafana-cve-2024-1313) | BOLA (cross-org delete) | database count | `demo.sh` (10.2.5), then `control.sh` (10.2.6) |

Each demo replays one agent run's decisions (plan, repairs, exploit) from `reference/`
and runs everything else live.

To add a lab for a known CVE, use this layout:

```
labs/<product>-<cve>/
  report.md         the claim: affected and fixed versions, preconditions
  lab/compose.yml   target and supporting services (seed scripts beside it)
  reference/        plan.json and exploit from a verified run, for demo.sh
  demo.sh           optional: replays reference/ through the CLI
```

A lab is ready when a blind run (`scripts/blind-test.sh labs/<lab>`) reaches the claimed
verdict without reading `reference/`, the patched control comes out **not observed** with
every probe and victim step passing, and `pb down` reports clean for both runs. The lab
rules themselves (pinned versions, no published ports, read-only probes, roles, seed) are
in the `plan` and `deploy` skills, and `pb` enforces most of them.

## CLI

The agent drives every step; you mostly need these:

```
pb new <report.md> [--lab dir]     create runs/<id>
pb check <run>                     show the plan and validate it
pb verdict <run>                   compute and show the verdict
pb down <run>                      tear down, write the cleanup receipt
pb -v <command> ...                raw output instead of summaries
```

`pb --help` lists the rest (`up`, `smoke`, `observe`, `victim`, `attack`, `control`,
`replay`, `stop`, `status`). Each run keeps its evidence in `runs/<id>/`: `deployment/`,
`verification/` (observations, victim traces, screenshots, video), `attack/log.jsonl`,
`result.json`, `cleanup.json`. Tests: `python3 -m unittest discover tests`.

## Layout

```
skills/      reproduce · plan · deploy · attack       the agent's instructions
proofbench/cli.py          arguments and terminal rendering
proofbench/controller.py   lifecycle steps, gates, evidence (service)
proofbench/run.py          run folder, state, plan, control (domain)
proofbench/docker.py       the only module that calls docker (driver)
proofbench/plan.py, verdict.py   plan contract, verdict rollup
proofbench/observer/       probe + victim browser image, owned by the controller
```

## Trust model and limits

- **Docker is not a VM.** These are disposable labs for disclosed CVEs. Don't run untrusted
  binaries from a report in them.
- **The agent has a shell on your machine.** The CLI separates roles (the attacker runs in
  a container that can only reach the lab network and its own work dir; the verdict reads
  only controller-written files), but nothing stops a misbehaving agent from editing
  `runs/<id>/verification/` directly. The guarantee is that the verdict is computed from
  observations, not that those observations are tamper-proof. Review the evidence.
- **One oracle per effect.** The canary proves script execution in that page, not account
  takeover. A stronger claim needs its own observation.
- **Model traffic is not offline.** Labs can't make outbound calls (images still pull and
  build at `up`), but Claude needs its API.

## Origin

proofbench is a lightweight, open-source take on the approach behind
[Konvu](https://konvu.com)'s [reproduction engine](https://konvu.com/blog/from-vulnerability-finding-to-exploit-proof):
plan the experiment, rebuild the target, attack it, and let only observations decide
the verdict, all on one laptop. Konvu's product applies the same approach at scale, with
report intake and deduplication, isolated cloud labs and a review dashboard.

## License

MIT. See [LICENSE](LICENSE).
