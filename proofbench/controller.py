"""Lab service: the lifecycle steps, their gates and their evidence. No terminal output.

    cli.py ──> controller.py ──> docker.py        (each layer talks only to the one below)
                 │
                 └──> run.py               (run folder, state, plan, evidence)

Every step checks its gate first (order, budget, containment), raises Refused when it
does not hold, runs the controller-owned action, then records what happened.
"""

import json
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from proofbench import docker
from proofbench.run import Label, Run, StopCategory, create_control, lab_diff, new_run, render_replay, require
from proofbench.verdict import decide

MAX_DEPLOY_ATTEMPTS = 3  # first start + 2 repairs
MAX_ATTACK_COMMANDS = 60
ATTACK_CMD_TIMEOUT_S = 180
LOG_EXCERPT = 4000
STDERR_EXCERPT = 500


@dataclass
class Deployment:
    attempt: int
    ok: bool
    diff: str
    log: str
    digest: str


@dataclass
class Readiness:
    ok: bool
    results: list[dict]


@dataclass
class AttackResult:
    ok: bool
    exit: int
    output: str


# ── runs ───────────────────────────────────────────────────────────────────


def create_run(report: Path, starter_lab: Path | None) -> Run:
    """A new run for a report, optionally starting from an existing lab."""
    return new_run(report, starter_lab)


def create_control_run(src: Run) -> Run:
    """The negative control of a finished run: patched image, same locked exploit."""
    return create_control(src)


# ── sandbox ────────────────────────────────────────────────────────────────


def start_lab(run: Run, plan: dict) -> Deployment:
    """Start or restart the lab. Pins the image, contains the network, snapshots the lab."""
    attempt = len(run.state["deploys"]) + 1
    require(not run.state.get("stopped"), "run is stopped")
    require(not run.attacked, "attack already started: a redeployed lab would not match the baseline")
    require(attempt <= MAX_DEPLOY_ATTEMPTS, f"deploy budget spent ({MAX_DEPLOY_ATTEMPTS} attempts); write the verdict")
    require(run.compose_file.exists(), "lab/compose.yml missing (deploy skill)")

    # Version pin: the target service must run exactly the planned image.
    docker.isolation_path(run.compose_file).unlink(missing_ok=True)  # resolve the agent's lab alone
    config = docker.compose_config(run.id, run.compose_file)
    require(config is not None, "lab/compose.yml is not valid compose")
    service = config["services"].get(plan["target"]["service"], {})
    require(service.get("image") == plan["target"]["image"],
            f"service '{plan['target']['service']}' runs '{service.get('image')}', plan pins '{plan['target']['image']}'")

    # Containment: no route out of the lab network, and no way around it.
    violations = docker.network_escapes(config)
    require(not violations, "lab escapes its network: " + "; ".join(violations))
    docker.write_isolation(run.compose_file, config)

    # Observations must read the target, never files the attacker can write.
    tainted = docker.services_mounting(config, run.attack_work_dir)
    tainted &= {observation["service"] for observation in plan.get("observations", [])}
    require(not tainted, f"observations run on attacker-writable services {sorted(tainted)}; observe the target")
    run.state["secret_in_lab"] = run.state["secret"] in json.dumps(config)

    # The repair evidence: what changed in the lab since the previous attempt.
    snapshot = run.deployment_dir / f"attempt-{attempt}"
    shutil.rmtree(snapshot, ignore_errors=True)  # left behind by an interrupted start
    shutil.copytree(run.dir / "lab", snapshot)
    diff = lab_diff(run.deployment_dir / f"attempt-{attempt - 1}", snapshot) if attempt > 1 else ""
    (run.deployment_dir / f"attempt-{attempt}.diff").write_text(diff)

    proc = docker.compose_up(run.id, run.compose_file)
    log = proc.stdout + proc.stderr
    if proc.returncode != 0:
        log += "\n" + docker.compose_diagnostics(run.id, run.compose_file)
    (run.deployment_dir / f"attempt-{attempt}.log").write_text(log)

    ok = proc.returncode == 0
    digest = docker.image_digest(plan["target"]["image"])
    run.state["deploys"].append({"n": attempt, "ok": ok, "ts": time.time(), "image": plan["target"]["image"], "digest": digest})
    run.state.pop("readiness", None)
    run.save()
    return Deployment(attempt=attempt, ok=ok, diff=diff, log=log, digest=digest)


def readiness_probes(plan: dict) -> list[dict]:
    """Readiness probes plus one identity check per planned role.

    A deployed role that differs from the plan (Admin where the report says Viewer) fails
    readiness, so the attacker never runs with the wrong privilege. Example:
      {"account": "attacker", "role": "Viewer", "url": ".../api/user/orgs",
       "auth": ["attacker", "pw"], "contains": "\\"role\\":\\"Viewer\\""}
    """
    roles = [{"name": f"role {role['account']} = {role['role']}", "url": role["url"],
              **({"auth": role["auth"]} if role.get("auth") else {}), "contains": role["contains"]}
             for role in plan.get("roles", [])]
    return plan["readiness"] + roles


def check_readiness(run: Run, plan: dict) -> Readiness:
    """Readiness gate: deterministic, read-only probes from inside the lab network."""
    require(run.state["deploys"] and run.state["deploys"][-1]["ok"], "lab is not up")
    attempt = run.state["deploys"][-1]["n"]
    out_dir = run.deployment_dir.resolve()

    (out_dir / "probes.json").write_text(json.dumps(readiness_probes(plan)))
    proc = docker.run_observer(run.id, out_dir, out_dir, "python", "/obs/probe.py", "/in/probes.json")
    require(proc.returncode == 0, f"prober failed: {proc.stderr[-LOG_EXCERPT:]}")

    results = json.loads(proc.stdout)
    ok = all(result["ok"] for result in results)
    (out_dir / f"readiness-{attempt}.json").write_text(json.dumps(results, indent=2))
    run.state["readiness"] = {"ok": ok, "attempt": attempt, "ts": time.time()}
    run.save()
    return Readiness(ok=ok, results=results)


def _run_read_only(run: Run, items: list[dict]) -> dict:
    """Run read-only commands on lab services; keyed by id with exit, stdout, stderr."""
    out = {}
    for item in items:
        proc = docker.compose_exec(run.id, run.compose_file, item["service"], item["cmd"])
        out[item["id"]] = {"exit": proc.returncode, "stdout": proc.stdout.strip(), "stderr": proc.stderr[-STDERR_EXCERPT:]}
    return out


def read_seed(run: Run, plan: dict) -> dict:
    """What the lab seeded (users, records), read-only. Shown, never judged."""
    require(run.ready, "target has not passed readiness")
    inventory = _run_read_only(run, plan.get("seed", []))
    if inventory:
        (run.deployment_dir / f"seed-{run.state['readiness']['attempt']}.json").write_text(json.dumps(inventory, indent=2))
    return inventory


# ── observation ────────────────────────────────────────────────────────────


def run_victim(run: Run, plan: dict, label: Label) -> tuple[dict, Path]:
    """The declared victim steps in a fresh browser, with the canary observer attached."""
    require(run.ready, "target has not passed readiness")
    run.require_phase(label)

    out = run.victim_dir(label)
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    spec = {"label": label.value, "nonce": run.state["nonce"], "base_url": plan["target"]["base_url"],
            "steps": plan["victim"]["steps"]}
    (out / "spec.json").write_text(json.dumps(spec))

    proc = docker.run_observer(run.id, out, out, "python", "/obs/victim.py", "/in/spec.json", "/out")
    require(proc.returncode == 0, f"victim run crashed: {proc.stderr[-LOG_EXCERPT:]}")
    return json.loads((out / "trace.json").read_text()), out


def read_target_state(run: Run, plan: dict, label: Label) -> dict:
    """The plan's read-only target observations, run by the controller."""
    require(run.ready, "target has not passed readiness")
    run.require_phase(label)

    results = _run_read_only(run, plan.get("observations", []))
    run.observations_path(label).parent.mkdir(exist_ok=True)
    run.observations_path(label).write_text(json.dumps(results, indent=2))
    return results


# ── attack ─────────────────────────────────────────────────────────────────


def _begin_attack(run: Run, plan: dict, commands: int) -> None:
    """Gates before exploit traffic, then lock the plan so oracles cannot move."""
    require(not run.state.get("stopped"), "run is stopped")
    require(run.ready, "target has not passed readiness")
    run.require_baselines(plan)

    attack = run.state.setdefault("attack", {"plan_sha256": run.plan_sha(), "commands": 0, "started": time.time()})
    require(attack["commands"] + commands <= MAX_ATTACK_COMMANDS, f"attack budget spent ({MAX_ATTACK_COMMANDS} commands)")
    attack["commands"] += commands
    run.save()


def _run_attacker_command(run: Run, plan: dict, cmd: str) -> AttackResult:
    """One command in the attacker container; logged by the controller, not the attacker."""
    nonce = run.state["nonce"]
    env = {"PROOFBENCH_TARGET": plan["target"]["base_url"], "PROOFBENCH_NONCE": nonce,
           "PROOFBENCH_CANARY": f"window.__proofbench_canary__('{nonce}')"}
    proc = docker.run_attacker(run.id, run.attack_work_dir, env, cmd, ATTACK_CMD_TIMEOUT_S)

    # Leak oracle input: checked on the full output, before the excerpt truncates it.
    entry = {"ts": time.time(), "cmd": cmd, "exit": proc.returncode,
             "secret_seen": run.state["secret"] in proc.stdout + proc.stderr,
             "stdout": proc.stdout[-LOG_EXCERPT:], "stderr": proc.stderr[-LOG_EXCERPT:]}
    with open(run.attack_log_path, "a") as log_file:
        log_file.write(json.dumps(entry) + "\n")
    return AttackResult(ok=proc.returncode == 0, exit=proc.returncode,
                   output=proc.stdout[-LOG_EXCERPT:] + proc.stderr[-LOG_EXCERPT:])


def attack(run: Run, plan: dict, cmd: str) -> AttackResult:
    """The attacker's only tool: one command, counted against the budget."""
    _begin_attack(run, plan, commands=1)
    return _run_attacker_command(run, plan, cmd)


def prepare_replay(run: Run, plan: dict) -> list[str]:
    """Prepare a control run's locked exploit: gates, files rendered, commands returned."""
    require((run.dir / "attack" / "replay.json").exists(), "not a control run (pb control <run>)")
    require(not run.attacked, "already replayed")
    commands = render_replay(run)
    require(bool(commands), "nothing to replay: the source run has no attack command that completed")
    _begin_attack(run, plan, commands=len(commands))
    return commands


def replay_command(run: Run, plan: dict, cmd: str) -> AttackResult:
    return _run_attacker_command(run, plan, cmd)


def stop(run: Run, category: StopCategory, reason: str) -> None:
    """End without a verdict from observations. After exploit traffic only an injection may."""
    require(not run.attacked or category == StopCategory.PROMPT_INJECTION,
            "attack already started: run the verdict instead")
    run.state["stopped"] = {"category": category.value, "reason": reason, "ts": time.time()}
    run.save()


# ── recap ──────────────────────────────────────────────────────────────────


def decide_verdict(run: Run) -> tuple[dict, dict, dict]:
    """Compute result.json from controller-written evidence. Returns (plan, result, evidence)."""
    plan = run.plan() if not run.state.get("stopped") else {}
    run.state["plan_sha256_now"] = run.plan_sha() if plan else None

    evidence = run.evidence()
    result = decide(plan, run.state, evidence)
    result.update({"run": run.id, "nonce": run.state["nonce"], "decided": time.time()})
    (run.dir / "result.json").write_text(json.dumps(result, indent=2))
    return plan, result, evidence


def teardown(run: Run) -> dict:
    """Tear down and prove it: list anything still labelled with this run's project."""
    log = ""
    down_ok = True
    if run.compose_file.exists():  # a run stopped at plan stage never had a lab
        proc = docker.compose_down(run.id, run.compose_file)
        down_ok, log = proc.returncode == 0, proc.stdout + proc.stderr

    left = docker.leftovers(run.id)
    clean = down_ok and not any(left.values())
    receipt = {"clean": clean, "leftovers": left, "ts": time.time(), "log": log[-LOG_EXCERPT:]}
    (run.dir / "cleanup.json").write_text(json.dumps(receipt, indent=2))
    run.state["cleanup"] = {"clean": clean}
    run.save()
    return receipt
