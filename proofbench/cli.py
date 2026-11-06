"""proofbench: turn a vulnerability report into a bounded, locally reproducible experiment.

    report.md ─> plan.json ─> lab/compose.yml ─> up ─> smoke ─┐  (repair loop, bounded)
                 (agent)      (agent)                        │
          observe/victim before ─> attack ─> victim/observe after
                                                              │
                                     verdict (code) ─> down (cleanup receipt)

The agent writes plan.json, the lab and the attack payloads. This controller owns
everything that decides the outcome: lab lifecycle, version pin, readiness, the
victim browser, observations, the verdict and cleanup.

This module only parses arguments and renders; controller.py does the work.
"""

import argparse
import functools
import json
import shlex
import sys
from pathlib import Path

from proofbench import controller, ui
from proofbench.plan import OracleType
from proofbench.run import Label, Refused, Run, StopCategory
from proofbench.summary import OutputKind, summarize

DIGEST_CHARS_SHOWN = 12  # hash characters shown on screen
STAGE_FILE = ".stage"  # last stage shown for this run, so repeated commands group under one panel
REPORT_FILE = ".report"  # the REPORT show_stage shows once per run, on its first displayed command
STATUS_KEYS = ("id", "deploys", "readiness", "attack", "stopped", "cleanup", "control_of")


def exit_on_refusal(fn):
    """A gate that says no ends the command with `refused: <reason>` and a non-zero exit."""
    @functools.wraps(fn)
    def wrapper(args):
        try:
            return fn(args)
        except Refused as refusal:
            sys.exit(f"refused: {refusal}")
    return wrapper


# ── display helpers ────────────────────────────────────────────────────────


def show_stage(run: Run, name: str, what: str) -> None:
    """New stage: a panel. Same stage as the previous command: an indented subparsers-step line."""
    marker = run.dir / STAGE_FILE
    if marker.exists() and marker.read_text() == name:
        ui.substep(what)
        return

    ui.stage(name, what)
    marker.write_text(name)


def show_report(run: Run, plan: dict) -> None:
    """REPORT show_stage, once per run: the claim and the experiment as planned, raw."""
    marker = run.dir / REPORT_FILE
    if marker.exists():
        return

    show_stage(run, "REPORT", run.id)
    ui.evidence_box("claim", [plan["claim"]])
    ui.evidence_box("target", [f"image    {plan['target']['image']}", f"service  {plan['target']['service']}"])
    if prereqs := plan.get("prerequisites"):
        ui.evidence_box("prerequisites", [f"{number}. {item}" for number, item in enumerate(prereqs, 1)])

    # The assertion's own text is left out: it can describe the patched result.
    for assertion in plan["assertions"]:
        oracle = assertion["oracle"]
        on = f" on {oracle['observation']}" if oracle.get("observation") else ""
        ui.evidence_box(f"assertion · {assertion['id']}", [f"oracle   {oracle['type']}{on}",
                                                f"primary  {'yes' if assertion.get('primary', True) else 'no'}"])
    marker.touch()


def output_detail(args) -> ui.Detail:
    """Summaries for a human at a terminal; raw output for agents, pipes and --verbose."""
    if getattr(args, "verbose", False) or not sys.stdout.isatty():
        return ui.Detail.RAW
    return ui.Detail.SUMMARY


def show_output(args, kind: OutputKind, text: str) -> None:
    """AttackResult output as a Haiku summary when wanted and available, else verbatim."""
    if not text.strip():
        return

    summary = None
    if output_detail(args) == ui.Detail.SUMMARY:
        with ui.spinner("summarizing"):
            summary = summarize(kind, text)
    ui.indented(summary or text)


def shell_cmd(argv: list[str]) -> str:
    """One quoted string stays as written (`-- "a && b"`); argv words are re-quoted (`-- python -c 'x y'`)."""
    if len(argv) == 1:
        return argv[0]
    return shlex.join(argv)


def stage_name(label: Label) -> str:
    return "SANDBOX" if label == Label.BEFORE else "RECAP"


def show_attack_result(args, result: controller.AttackResult) -> None:
    show_output(args, OutputKind.ATTACK, result.output)
    if not result.ok:
        sys.exit(result.exit)


# ── commands ───────────────────────────────────────────────────────────────


@exit_on_refusal
def cmd_new(args) -> None:
    run = controller.create_run(Path(args.report), Path(args.lab) if args.lab else None)
    print(run.dir)


@exit_on_refusal
def cmd_check(args) -> None:
    run = Run(args.run)
    show_report(run, run.plan())
    ui.check(True, "plan.json valid")


@exit_on_refusal
def cmd_up(args) -> None:
    run = Run(args.run)
    plan = run.plan()
    show_report(run, plan)
    show_stage(run, "SANDBOX", f"lab · attempt {len(run.state['deploys']) + 1}/{controller.MAX_DEPLOY_ATTEMPTS}")

    with ui.spinner("starting the lab"):
        deploy = controller.start_lab(run, plan)

    if deploy.diff:
        ui.info(f"repair since attempt {deploy.attempt - 1}")
        show_output(args, OutputKind.REPAIR, deploy.diff)
        ui.evidence_link("repair diff", run.deployment_dir / f"attempt-{deploy.attempt}.diff")
    ui.check(deploy.ok, "healthy" if deploy.ok else "failed to start")
    if not deploy.ok:
        ui.indented(deploy.log[-controller.LOG_EXCERPT:])
        sys.exit(1)

    digest = deploy.digest.rpartition(":")[2][:DIGEST_CHARS_SHOWN]
    ui.evidence_box("pinned image", [plan["target"]["image"], f"sha256:{digest}" if digest else "local build"])
    ui.evidence_box("containment", ["network  internal", "attacker --cap-drop ALL --pids-limit --memory"])


@exit_on_refusal
def cmd_smoke(args) -> None:
    run = Run(args.run)
    plan = run.plan()
    show_stage(run, "SANDBOX", "readiness")

    with ui.spinner("probing readiness"):
        readiness = controller.check_readiness(run, plan)
    for probe in readiness.results:
        ui.check(probe["ok"], f"{probe['name']}  {probe.get('status', probe.get('error'))}")
    ui.check(readiness.ok, "ready" if readiness.ok else "not ready")
    if not readiness.ok:
        sys.exit(1)

    with ui.spinner("reading seeded data"):
        inventory = controller.read_seed(run, plan)
    for name, output in inventory.items():
        if output["exit"] != 0:
            ui.check(False, f"seeded {name}: exit {output['exit']} {output['stderr'][:200]}")
            continue
        ui.evidence_box(f"seeded · {name}", output["stdout"].splitlines())


@exit_on_refusal
def cmd_victim(args) -> None:
    run = Run(args.run)
    plan = run.plan()
    label = Label(args.label)
    show_stage(run, stage_name(label), f"victim browser · {label.value}")

    with ui.spinner("victim browser running its steps"):
        trace, out = controller.run_victim(run, plan, label)

    for step in trace["steps"]:
        if output_detail(args) == ui.Detail.RAW or not step["ok"]:
            ui.check(step["ok"], f"{json.dumps(step['step'])}  {step.get('error', '')[:200]}")
    done = sum(step["ok"] for step in trace["steps"])
    ui.check(trace["all_steps_ok"], f"{done}/{len(plan['victim']['steps'])} steps")
    if any(assertion["oracle"]["type"] == OracleType.CANARY for assertion in plan["assertions"]):
        ui.info(f"canary {'OBSERVED' if trace['canary_matched'] else 'not observed'}")

    # Evidence a human opens: the declared screenshots (else the final frame), the video.
    shots = sorted(shot for shot in out.glob("*.png") if shot.name != "final.png") or [out / "final.png"]
    for shot in shots:
        ui.evidence_link("screenshot", shot)
    for video in sorted(out.glob("video/*.webm")):
        ui.evidence_link("video", video)


@exit_on_refusal
def cmd_observe(args) -> None:
    run = Run(args.run)
    plan = run.plan()
    label = Label(args.label)
    show_stage(run, stage_name(label), f"target state · {label.value}")

    with ui.spinner("reading target state"):
        results = controller.read_target_state(run, plan, label)
    for observation in plan.get("observations", []):
        output = results[observation["id"]]
        if output["exit"] != 0:
            ui.check(False, f"{observation['id']}: exit {output['exit']} {output['stderr'][:200]}")
            continue
        ui.evidence_box(f"{observation['service']} · read-only",
                        [f"$ {observation['cmd']}", f"= {output['stdout'][:200]}"])


@exit_on_refusal
def cmd_attack(args) -> None:
    """The attacker's only tool: one command in a throwaway container on the lab network.

    /work (= runs/<id>/attack/work) is the attacker's writable area. Env: PROOFBENCH_TARGET,
    PROOFBENCH_NONCE, PROOFBENCH_CANARY (a JS snippet that proves execution when the victim runs it).
    """
    run = Run(args.run)
    plan = run.plan()
    cmd = shell_cmd(args.cmd)
    show_stage(run, "ATTACK", cmd[:120])

    with ui.spinner("attacker command running"):
        result = controller.attack(run, plan, cmd)
    show_attack_result(args, result)


@exit_on_refusal
def cmd_replay(args) -> None:
    run = Run(args.run)
    plan = run.plan()
    # Every command of the locked exploit runs, even after a failure: skipping one would
    # test a different exploit. The exit code reports failures at the end.
    commands = controller.prepare_replay(run, plan)
    failed = 0
    for cmd in commands:
        show_stage(run, "ATTACK", cmd[:120])
        with ui.spinner("attacker command running"):
            result = controller.replay_command(run, plan, cmd)
        show_output(args, OutputKind.ATTACK, result.output)
        failed += not result.ok

    if failed:
        sys.exit(f"{failed} of {len(commands)} replayed commands failed")


@exit_on_refusal
def cmd_stop(args) -> None:
    run = Run(args.run)
    controller.stop(run, StopCategory(args.category), args.reason)
    ui.check(False, f"stopped: {args.category}")


@exit_on_refusal
def cmd_verdict(args) -> None:
    run = Run(args.run)
    plan, result, evidence = controller.decide_verdict(run)
    show_stage(run, "RECAP", "verdict")

    if not run.ready:
        ui.check(False, "target never passed readiness")
    after = evidence["victim_after"]
    if after and not after["all_steps_ok"]:
        ui.check(False, "victim steps incomplete")

    reasons = [f"{assertion['id']}  {assertion['status']}" for assertion in result["assertions"]]
    if result.get("category"):
        reasons.append(f"{result['category']}: {result['reason']}")
    ui.verdict_card(result["outcome"], reasons)

    # The observed values themselves, not only the status they produced.
    for observation in plan.get("observations", []):
        before = evidence["observations_before"].get(observation["id"], {}).get("stdout", "?")
        after_value = evidence["observations_after"].get(observation["id"], {}).get("stdout", "?")
        ui.evidence_box(observation["id"], [f"before  {before}", f"after   {after_value}"])

    ui.evidence_link("result", run.dir / "result.json")
    if commands := len(evidence["attack_log"]):
        ui.evidence_link(f"attack log ({commands} command{'s' if commands > 1 else ''})", run.attack_log_path)


@exit_on_refusal
def cmd_down(args) -> None:
    run = Run(args.run)
    with ui.spinner("tearing down"):
        receipt = controller.teardown(run)

    ui.check(receipt["clean"], f"cleanup {'clean' if receipt['clean'] else 'INCOMPLETE'}")
    ui.evidence_box("cleanup", [f"{kind:<11}{len(names)} left" for kind, names in receipt["leftovers"].items()])
    ui.evidence_link("evidence", run.dir)
    if not receipt["clean"]:
        sys.exit(1)


@exit_on_refusal
def cmd_control(args) -> None:
    print(controller.create_control_run(Run(args.run)).dir)


@exit_on_refusal
def cmd_status(args) -> None:
    run = Run(args.run)
    print(json.dumps({key: run.state.get(key) for key in STATUS_KEYS}, indent=2))


# ── entry point ────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(prog="pb", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-v", "--verbose", action="store_true", help="raw command output instead of summaries")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add(name, fn, help_):
        subparser = subparsers.add_parser(name, help=help_)
        subparser.set_defaults(fn=fn)
        return subparser

    subparser = add("new", cmd_new, "create a run from a report")
    subparser.add_argument("report")
    subparser.add_argument("--lab", help="starter lab dir to copy into runs/<id>/lab")

    for name, fn, help_ in (("check", cmd_check, "validate plan.json"),
                            ("up", cmd_up, "start the lab (counts against the deploy budget)"),
                            ("smoke", cmd_smoke, "run readiness probes and list seeded data"),
                            ("verdict", cmd_verdict, "compute result.json from observations"),
                            ("down", cmd_down, "tear down and write the cleanup receipt"),
                            ("control", cmd_control, "create the patched-image negative control run"),
                            ("replay", cmd_replay, "replay the locked attack in a control run"),
                            ("status", cmd_status, "print run state")):
        add(name, fn, help_).add_argument("run")

    labels = [label.value for label in Label]
    for name, fn in (("victim", cmd_victim), ("observe", cmd_observe)):
        subparser = add(name, fn, f"run {name} {'/'.join(labels)} the attack")
        subparser.add_argument("run")
        subparser.add_argument("label", choices=labels)

    subparser = add("attack", cmd_attack, "run one attacker command: pb attack <run> -- <cmd>")
    subparser.add_argument("run")
    subparser.add_argument("cmd", nargs=argparse.REMAINDER)

    subparser = add("stop", cmd_stop, "stop the run with a category and reason")
    subparser.add_argument("run")
    subparser.add_argument("category", choices=[c.value for c in StopCategory])
    subparser.add_argument("reason")

    args = parser.parse_args()
    if getattr(args, "cmd", None) and args.cmd[:1] == ["--"]:
        args.cmd = args.cmd[1:]
    args.fn(args)


if __name__ == "__main__":
    main()
