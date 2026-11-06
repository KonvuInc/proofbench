"""Run domain: one experiment's folder, state, plan and evidence. No Docker, no terminal.

    runs/<id>/
      report.md  plan.json  lab/            written by the agent
      run.json                              state, owned by this module
      deployment/  verification/            written by the controller
      attack/work/  attack/log.jsonl        attacker files / controller log
      result.json  cleanup.json             verdict and receipt

Gates raise Refused; the CLI turns that into a `refused: <reason>` exit.
"""

import difflib
import hashlib
import json
import os
import secrets
import shutil
import time
from enum import Enum
from pathlib import Path

from proofbench.plan import validate

RUNS_DIR = Path("runs")
NONCE_PLACEHOLDER = "{{NONCE}}"
SECRET_ENV = "PROOFBENCH_SECRET"  # labs seed it with ${PROOFBENCH_SECRET}; the attacker never gets it
NONCE_BYTES = 8
SECRET_BYTES = 16
RUN_ID_SUFFIX_BYTES = 2


class Refused(Exception):
    """A gate said no: wrong order, spent budget, unsafe lab. The message says why."""


class Label(str, Enum):
    BEFORE = "before"
    AFTER = "after"


class StopCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    REPORT_INACCURATE = "report_inaccurate"
    PRECONDITION_NOT_MET = "precondition_not_met"
    NOT_VULNERABLE_VERSION = "not_vulnerable_version"
    DEPLOYMENT_ISSUE = "deployment_issue"
    OUT_OF_SCOPE = "out_of_scope"


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise Refused(msg)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Run:
    """One experiment. State lives in runs/<id>/run.json; artifacts beside it."""

    def __init__(self, ref: str):
        # A bare id ("20261102-…") lives under runs/; anything with a folder is a path.
        path = Path(ref)
        self.dir = path if path.is_dir() or len(path.parts) > 1 else RUNS_DIR / ref
        require((self.dir / "run.json").exists(), f"no run at {self.dir}")
        self.id = self.dir.name
        self.state = json.loads((self.dir / "run.json").read_text())

        # Compose interpolates ${PROOFBENCH_SECRET} from this process's env. The attacker
        # container gets an explicit env list, so it never inherits the secret.
        if secret := self.state.get("secret"):
            os.environ[SECRET_ENV] = secret

    # ── paths ──────────────────────────────────────────────────────────────

    @property
    def compose_file(self) -> Path:
        return (self.dir / "lab" / "compose.yml").resolve()

    @property
    def deployment_dir(self) -> Path:
        return self.dir / "deployment"

    @property
    def attack_work_dir(self) -> Path:
        return (self.dir / "attack" / "work").resolve()

    @property
    def attack_log_path(self) -> Path:
        return self.dir / "attack" / "log.jsonl"

    def victim_dir(self, label: Label) -> Path:
        return (self.dir / "verification" / f"victim-{label.value}").resolve()

    def observations_path(self, label: Label) -> Path:
        return self.dir / "verification" / f"observations-{label.value}.json"

    # ── state ──────────────────────────────────────────────────────────────

    def save(self) -> None:
        (self.dir / "run.json").write_text(json.dumps(self.state, indent=2))

    def plan(self) -> dict:
        path = self.dir / "plan.json"
        require(path.exists(), "plan.json missing: write it first (plan skill)")
        plan = json.loads(path.read_text())
        errors = validate(plan)
        require(not errors, "plan.json invalid:\n  " + "\n  ".join(errors))
        return plan

    def plan_sha(self) -> str:
        return sha256((self.dir / "plan.json").read_bytes())

    def read_json(self, path: Path) -> dict | None:
        return json.loads(path.read_text()) if path.exists() else None

    @property
    def ready(self) -> bool:
        return self.state.get("readiness", {}).get("ok", False)

    @property
    def attacked(self) -> bool:
        return bool(self.state.get("attack"))

    def attack_log(self) -> list[dict]:
        if not self.attack_log_path.exists():
            return []
        return [json.loads(line) for line in self.attack_log_path.read_text().splitlines()]

    def evidence(self) -> dict:
        """Everything the verdict may read, all of it controller-written."""
        return {
            "victim_before": self.read_json(self.victim_dir(Label.BEFORE) / "trace.json"),
            "victim_after": self.read_json(self.victim_dir(Label.AFTER) / "trace.json"),
            "observations_before": self.read_json(self.observations_path(Label.BEFORE)) or {},
            "observations_after": self.read_json(self.observations_path(Label.AFTER)) or {},
            "attack_log": self.attack_log(),
        }

    def require_baselines(self, plan: dict) -> None:
        """Before any exploit traffic, every declared oracle needs its baseline."""
        require(not plan.get("victim") or (self.victim_dir(Label.BEFORE) / "trace.json").exists(),
                "run the victim baseline first (pb victim <run> before)")
        require(not plan.get("observations") or self.observations_path(Label.BEFORE).exists(),
                "run the baseline observations first (pb observe <run> before)")

    def require_phase(self, label: Label) -> None:
        """`before` steps run only before the attack, `after` steps only after it."""
        if label == Label.BEFORE:
            require(not self.attacked, "baseline must run before the attack")
            return
        require(self.attacked, "the after-run needs an attack first")


def new_run(report: Path, lab: Path | None) -> Run:
    """Create runs/<id> with the report, a fresh nonce and secret and, optionally, a starter lab."""
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(RUN_ID_SUFFIX_BYTES)
    run_dir = RUNS_DIR / run_id
    (run_dir / "attack" / "work").mkdir(parents=True)
    shutil.copy(report, run_dir / "report.md")

    if lab:
        shutil.copytree(lab, run_dir / "lab")

    state = {"id": run_id, "created": time.time(), "report_sha256": sha256(report.read_bytes()),
             "nonce": secrets.token_hex(NONCE_BYTES), "secret": secrets.token_hex(SECRET_BYTES),
             "lab_source": str(lab) if lab else None, "deploys": []}
    (run_dir / "run.json").write_text(json.dumps(state, indent=2))
    return Run(str(run_dir))


def lab_diff(old: Path, new: Path) -> str:
    """Unified diff of every text file across two lab snapshots: the repair evidence."""
    out = []
    files = sorted({path.relative_to(old) for path in old.rglob("*") if path.is_file()} |
                   {path.relative_to(new) for path in new.rglob("*") if path.is_file()})
    for rel in files:
        before = (old / rel).read_text(errors="replace").splitlines(keepends=True) if (old / rel).exists() else []
        after = (new / rel).read_text(errors="replace").splitlines(keepends=True) if (new / rel).exists() else []
        out += difflib.unified_diff(before, after, f"a/{rel}", f"b/{rel}")
    return "".join(out)


def create_control(src: Run) -> Run:
    """Negative control: same report, plan, lab and locked exploit, on the patched image.

    The attacker's files and commands are replayed, not re-invented. Files are copied byte
    for byte with the source nonce masked; the template hash proves it is the same attempt.
    """
    plan = src.plan()
    patched = plan["target"].get("patched_image")
    require(bool(patched), "plan.target.patched_image is not set")
    require(src.attacked, "source run has no attack to replay")
    commands = [entry["cmd"] for entry in src.attack_log() if entry["exit"] == 0]
    require(bool(commands), "nothing to replay: the source run has no attack command that completed")

    run = new_run(src.dir / "report.md", None)
    old_nonce = src.state["nonce"].encode()
    vulnerable_image = plan["target"]["image"]

    # Plan and lab: only the image changes.
    plan["target"]["image"] = patched
    plan["control_of"] = src.id
    (run.dir / "plan.json").write_text(json.dumps(plan, indent=2))
    shutil.copytree(src.dir / "lab", run.dir / "lab")
    compose = run.dir / "lab" / "compose.yml"
    compose.write_text(compose.read_text().replace(vulnerable_image, patched))

    # Exploit template, kept out of work/ until `replay` so the baseline sees the benign lab.
    template = run.dir / "attack" / "template"
    shutil.copytree(src.dir / "attack" / "work", template)
    template_hash = hashlib.sha256()
    for file in sorted(template.rglob("*")):
        if not file.is_file():
            continue
        masked = file.read_bytes().replace(old_nonce, NONCE_PLACEHOLDER.encode())
        template_hash.update(str(file.relative_to(template)).encode() + masked)
        file.write_bytes(masked)

    replay = [command.replace(src.state["nonce"], NONCE_PLACEHOLDER) for command in commands]
    template_hash.update(json.dumps(replay).encode())
    (run.dir / "attack" / "replay.json").write_text(json.dumps(replay, indent=2))

    run.state.update({"control_of": src.id, "template_sha256": template_hash.hexdigest()})
    run.save()
    return run


def render_replay(run: Run) -> list[str]:
    """Write a control's exploit files into attack/work with this run's nonce; return its commands."""
    nonce = run.state["nonce"]
    template = run.dir / "attack" / "template"
    for file in template.rglob("*"):
        if not file.is_file():
            continue
        dest = run.attack_work_dir / file.relative_to(template)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(file.read_bytes().replace(NONCE_PLACEHOLDER.encode(), nonce.encode()))

    replay = json.loads((run.dir / "attack" / "replay.json").read_text())
    return [cmd.replace(NONCE_PLACEHOLDER, nonce) for cmd in replay]
