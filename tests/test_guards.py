"""Controller guards: lab isolation, run-order gates, lifecycle bugs, timeouts. Run: python3 -m unittest discover tests"""

import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from proofbench import cli, controller, docker, ui
from proofbench.run import Refused, Run

PLAN = {"claim": "c", "target": {"image": "app:1.0", "service": "app", "base_url": "http://app"},
        "readiness": [{"name": "h", "url": "http://app/h", "contains": "ok"}],
        "observations": [{"id": "rows", "service": "db", "cmd": "count"}],
        "assertions": [{"id": "rows", "claim": "row added", "oracle": {"type": "state_diff", "observation": "rows"}}]}
ROOT = Path("/runs/20260101-000000-abcd")


def bind(source: str) -> dict:
    return {"volumes": [{"type": "bind", "source": source, "target": "/mnt"}]}


ATTACKED = {"readiness": {"ok": True}, "attack": {"plan_sha256": "x", "commands": 1}}


def make_run(state: dict) -> Path:
    """A run dir on disk with a valid plan and the given state."""
    run_dir = Path(tempfile.mkdtemp()) / "20260101-000000-abcd"
    (run_dir / "attack" / "work").mkdir(parents=True)
    (run_dir / "plan.json").write_text(json.dumps(PLAN))
    (run_dir / "run.json").write_text(json.dumps({"nonce": "n", "secret": "s", "deploys": [], **state}))
    return run_dir


class Isolation(unittest.TestCase):
    def test_every_lab_network_is_internal(self):
        config = {"networks": {"default": {"name": "p_default"}, "back": {"name": "p_back"}}}
        override = docker.isolation_override(config)
        self.assertEqual(override, {"networks": {"default": {"internal": True}, "back": {"internal": True}}})

    def test_refuses_escapes_from_lab_network(self):
        config = {"services": {"app": {"network_mode": "host"}},
                  "networks": {"ext": {"external": True}, "default": {}}}
        self.assertEqual(len(docker.network_escapes(config, ROOT)), 2)
        self.assertEqual(docker.network_escapes({"services": {"app": {}}, "networks": {"default": {}}}, ROOT), [])

    def test_refuses_escapes_from_the_container(self):
        # Each of these gives a lab service the host, and with it the internet.
        escapes = [{"privileged": True}, {"cap_add": ["NET_ADMIN"]}, {"pid": "host"}, {"ipc": "host"},
                   {"uts": "host"}, {"cgroup": "host"}, {"userns_mode": "host"}, {"devices": ["/dev/kmsg"]},
                   {"volumes_from": ["container:other"]},
                   bind("/var/run/docker.sock"), bind("/"), bind("/var/run"), bind("/etc"),
                   bind(str(Path.home() / ".docker/run/docker.sock")), bind(str(Path.home() / ".ssh")),
                   bind(f"{ROOT}/../other-run"), {"build": {"context": "/"}},
                   {"build": {"context": f"{ROOT}/lab", "additional_contexts": {"h": str(Path.home())}}}]
        for svc in escapes:
            self.assertTrue(docker.network_escapes({"services": {"app": svc}}, ROOT), svc)

    def test_refuses_host_files_outside_the_service(self):
        # Top-level objects can bind host paths too, e.g. a named volume backed by /var/run.
        for config in ({"volumes": {"v": {"driver_opts": {"type": "none", "o": "bind", "device": "/var/run"}}}},
                       {"volumes": {"v": {"external": True}}}, {"volumes": {"v": {"driver": "nfs"}}},
                       {"secrets": {"s": {"file": str(Path.home() / ".ssh/id_rsa")}}},
                       {"configs": {"c": {"file": "/etc/passwd"}}}):
            self.assertTrue(docker.network_escapes(config, ROOT), config)

    def test_symlink_out_of_the_run_folder_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "lab").mkdir()
            (root / "lab" / "sock").symlink_to("/var/run")
            self.assertTrue(docker.network_escapes({"services": {"app": bind(f"{root}/lab/sock")}}, root))

    def test_shipped_lab_layouts_pass(self):
        # Lab files, attacker fixtures under attack/work, plain named volumes, remote build contexts.
        config = {"services": {"app": {**bind(f"{ROOT}/lab/seed.py"), "build": {"context": f"{ROOT}/lab"}},
                               "fixture": bind(f"{ROOT}/lab/../attack/work/graphite"),
                               "db": {"volumes": [{"type": "volume", "source": "pg", "target": "/var/lib/pg"}],
                                      "build": {"context": "https://github.com/org/repo.git"}}},
                  "volumes": {"pg": {"name": "p_pg"}}, "configs": {"c": {"file": f"{ROOT}/lab/app.ini"}}}
        self.assertEqual(docker.network_escapes(config, ROOT), [])

    def test_observation_cannot_read_attacker_files(self):
        # A witness that cats what the attacker wrote is the attacker grading itself.
        work = "/runs/r/attack/work"
        config = {"services": {"hint": {"volumes": [{"source": work, "target": "/work"}]}, "db": {}}}
        self.assertEqual(docker.services_mounting(config, Path(work)), {"hint"})

    def test_timed_out_container_is_removed(self):
        # Killing the docker client leaves the container running; remove it by name.
        timeout = subprocess.CompletedProcess([], docker.TIMEOUT_EXIT, "", "")
        with mock.patch.object(docker, "run_command", return_value=timeout) as run_command:
            docker.run_attacker("r", Path("/w"), {}, "sleep 999", 1)
        started, removed = (call[0][0] for call in run_command.call_args_list)
        name = started[started.index("--name") + 1]
        self.assertIn("com.docker.compose.project=proofbench-r", started)
        self.assertEqual(removed, ["docker", "rm", "-f", name])

    def test_attacker_container_is_hardened(self):
        with mock.patch.object(docker, "run_command") as run_command:
            docker.run_attacker("r", Path("/w"), {}, "id", 5)
        args = run_command.call_args[0][0]
        for flag in ("--cap-drop", "--pids-limit", "--memory"):
            self.assertIn(flag, args)
        self.assertIn("no-new-privileges", " ".join(args))


class Gates(unittest.TestCase):
    def test_baseline_observation_refused_after_attack(self):
        run = make_run(ATTACKED)
        with self.assertRaises(SystemExit):
            cli.cmd_observe(Namespace(run=str(run), label="before"))

    def test_stop_refused_after_attack_except_injection(self):
        run = make_run(ATTACKED)
        with self.assertRaises(SystemExit):
            cli.cmd_stop(Namespace(run=str(run), category="report_inaccurate", reason="r"))

        cli.cmd_stop(Namespace(run=str(run), category="prompt_injection", reason="r"))
        self.assertEqual(json.loads((run / "run.json").read_text())["stopped"]["category"], "prompt_injection")

    def test_attack_refused_on_stopped_run(self):
        run = make_run({"readiness": {"ok": True}, "stopped": {"category": "out_of_scope"}})
        (run / "verification").mkdir()
        (run / "verification" / "observations-before.json").write_text("{}")  # only the stop should refuse

        with self.assertRaises(SystemExit) as refused:
            cli.cmd_attack(Namespace(run=str(run), cmd=["id"]))
        self.assertIn("stopped", str(refused.exception))

    def test_attack_budget(self):
        run = make_run({"readiness": {"ok": True},
                        "attack": {"plan_sha256": "x", "commands": controller.MAX_ATTACK_COMMANDS - 1}})
        (run / "verification").mkdir()
        (run / "verification" / "observations-before.json").write_text("{}")
        done = subprocess.CompletedProcess([], 0, "", "")

        with mock.patch.object(docker, "run_attacker", return_value=done):
            controller.attack(Run(str(run)), PLAN, "last")
            with self.assertRaises(Refused):
                controller.attack(Run(str(run)), PLAN, "one more")

    def test_attack_is_logged_by_the_controller(self):
        # The leak oracle reads secret_seen from this log; the attacker never writes it.
        run = make_run({"readiness": {"ok": True}, "secret": "s3cr3t"})
        (run / "verification").mkdir()
        (run / "verification" / "observations-before.json").write_text("{}")
        leaked = subprocess.CompletedProcess([], 1, "token=s3cr3t", "")

        with mock.patch.object(docker, "run_attacker", return_value=leaked):
            result = controller.attack(Run(str(run)), PLAN, "curl app")

        entry = json.loads((run / "attack" / "log.jsonl").read_text())
        self.assertFalse(result.ok)
        self.assertEqual((entry["exit"], entry["secret_seen"]), (1, True))
        self.assertEqual(json.loads((run / "run.json").read_text())["attack"]["commands"], 1)

    def test_attack_command_keeps_quoting(self):
        self.assertEqual(cli.shell_cmd(["python", "-c", "print(1)"]), "python -c 'print(1)'")
        self.assertEqual(cli.shell_cmd(["python a.py && cat out"]), "python a.py && cat out")


class Lifecycle(unittest.TestCase):
    def test_replay_needs_the_observation_baseline(self):
        # Without `observe before`, a state_diff control can only end inconclusive.
        run = make_run({"readiness": {"ok": True}})
        (run / "attack" / "replay.json").write_text(json.dumps(["true"]))

        with mock.patch.object(docker, "run_attacker") as attacker, self.assertRaises(SystemExit):
            cli.cmd_replay(Namespace(run=str(run), verbose=False))
        attacker.assert_not_called()

    def test_lab_cannot_restart_after_the_attack(self):
        # A redeployed lab would be compared against the old baseline.
        run = make_run(ATTACKED)
        (run / "lab").mkdir()
        (run / "lab" / "compose.yml").write_text("services: {}")
        config = {"services": {"app": {"image": "app:1.0"}}, "networks": {"default": {}}}
        with mock.patch.object(docker, "compose_config", return_value=config), \
                mock.patch.object(docker, "compose_up") as up, self.assertRaises(SystemExit) as refused:
            cli.cmd_up(Namespace(run=str(run), verbose=False))
        up.assert_not_called()
        self.assertIn("attack", str(refused.exception))

    def test_interrupted_start_does_not_block_the_next(self):
        # Ctrl-C mid `up` leaves deployment/attempt-1 behind; the next start must still work.
        run = make_run({})
        (run / "lab").mkdir()
        (run / "lab" / "compose.yml").write_text("services: {}")
        (run / "deployment" / "attempt-1").mkdir(parents=True)
        config = {"services": {"app": {"image": "app:1.0"}}, "networks": {"default": {}}}
        ok = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(docker, "compose_config", return_value=config), \
                mock.patch.object(docker, "compose_up", return_value=ok), \
                mock.patch.object(docker, "image_digest", return_value=""):
            deployment = controller.start_lab(Run(str(run)), PLAN)
        self.assertTrue(deployment.ok)
        self.assertEqual(deployment.diff, "")  # a first attempt has nothing to diff against

    def test_last_lab_start_records_failure(self):
        # The final allowed start: a failed compose keeps its diagnostics, then the budget refuses.
        run = make_run({"secret": "s3cr3t", "deploys": [{}] * (controller.MAX_DEPLOY_ATTEMPTS - 1)})
        (run / "lab").mkdir()
        (run / "lab" / "compose.yml").write_text("services: {}")
        previous = run / "deployment" / f"attempt-{controller.MAX_DEPLOY_ATTEMPTS - 1}"
        previous.mkdir(parents=True)
        (previous / "compose.yml").write_text("services: {app: {}}")
        config = {"services": {"app": {"image": "app:1.0", "environment": {"TOKEN": "s3cr3t"}}},
                  "networks": {"default": {}}}
        failed = subprocess.CompletedProcess([], 1, "", "boom")

        lab_run = Run(str(run))
        with mock.patch.object(docker, "compose_config", return_value=config), \
                mock.patch.object(docker, "compose_up", return_value=failed), \
                mock.patch.object(docker, "compose_diagnostics", return_value="diagnostics"), \
                mock.patch.object(docker, "image_digest", return_value=""):
            deployment = controller.start_lab(lab_run, PLAN)
            with self.assertRaises(Refused):
                controller.start_lab(Run(str(run)), PLAN)

        self.assertEqual((deployment.attempt, deployment.ok), (controller.MAX_DEPLOY_ATTEMPTS, False))
        self.assertIn("diagnostics", deployment.log)
        self.assertIn("-services: {app: {}}", deployment.diff)  # the repair since the previous attempt
        self.assertTrue(lab_run.state["secret_in_lab"])

    def test_cleanup_receipt_reports_what_is_left(self):
        run = make_run({})
        (run / "lab").mkdir()
        (run / "lab" / "compose.yml").write_text("services: {}")
        empty = {"containers": [], "volumes": [], "networks": []}
        cases = [(0, empty, True), (1, empty, False), (0, {**empty, "containers": ["app"]}, False)]

        for down_exit, left, clean in cases:
            down = subprocess.CompletedProcess([], down_exit, "", "")
            with mock.patch.object(docker, "compose_down", return_value=down), \
                    mock.patch.object(docker, "leftovers", return_value=left):
                self.assertEqual(controller.teardown(Run(str(run)))["clean"], clean, (down_exit, left))

    def test_replay_runs_every_command_then_fails(self):
        # One failing command must not skip the rest of the locked exploit.
        run = make_run({"readiness": {"ok": True}})
        (run / "verification").mkdir()
        (run / "verification" / "observations-before.json").write_text("{}")
        (run / "attack" / "template").mkdir()
        (run / "attack" / "replay.json").write_text(json.dumps(["first", "second"]))
        failed, passed = (subprocess.CompletedProcess([], code, "", "") for code in (1, 0))
        with mock.patch.object(docker, "run_attacker", side_effect=[failed, passed]) as attacker, \
                self.assertRaises(SystemExit):
            cli.cmd_replay(Namespace(run=str(run), verbose=False))
        self.assertEqual(attacker.call_count, 2)

    def test_control_needs_a_command_to_replay(self):
        # With no command that ran cleanly, a control would test nothing.
        src = make_run({"attack": {"plan_sha256": "x", "commands": 1}})
        (src / "plan.json").write_text(json.dumps({**PLAN, "target": {**PLAN["target"], "patched_image": "app:1.1"}}))
        (src / "attack" / "log.jsonl").write_text(json.dumps({"cmd": "x", "exit": 1}) + "\n")
        with self.assertRaises(SystemExit):
            cli.cmd_control(Namespace(run=str(src)))

    def test_missing_run_names_the_path_given(self):
        from proofbench.run import Refused, Run
        with self.assertRaises(Refused) as missing:
            Run("runs/does-not-exist")
        self.assertEqual(str(missing.exception), "no run at runs/does-not-exist")

    def test_down_without_a_lab_is_clean(self):
        # A run stopped at plan stage never had a lab: nothing to tear down, still a receipt.
        run = make_run({"stopped": {"category": "out_of_scope"}})
        empty = {"containers": [], "volumes": [], "networks": []}

        with mock.patch.object(docker, "compose_down") as down, \
                mock.patch.object(docker, "leftovers", return_value=empty):
            cli.cmd_down(Namespace(run=str(run)))

        down.assert_not_called()
        self.assertTrue(json.loads((run / "cleanup.json").read_text())["clean"])

    def test_control_keeps_binary_payloads_intact(self):
        # The control replays attacker files byte for byte; only the nonce is masked.
        src = make_run({"readiness": {"ok": True}, "attack": {"plan_sha256": "x", "commands": 1}, "nonce": "abc123"})
        plan = {**PLAN, "target": {**PLAN["target"], "patched_image": "app:1.1"}}
        (src / "plan.json").write_text(json.dumps(plan))
        (src / "report.md").write_text("r")
        (src / "lab").mkdir()
        (src / "lab" / "compose.yml").write_text("services: {app: {image: 'app:1.0'}}")
        (src / "attack" / "work" / "blob.bin").write_bytes(b"\xff\xfe" + b"abc123")
        (src / "attack" / "work" / "passwd").symlink_to("/etc/passwd")  # attacker-made, points at the host
        (src / "attack" / "log.jsonl").write_text(json.dumps({"cmd": "python x", "exit": 0}) + "\n")

        cwd = Path.cwd()
        self.addCleanup(lambda: __import__("os").chdir(cwd))
        __import__("os").chdir(tempfile.mkdtemp())
        with mock.patch("builtins.print") as out:
            cli.cmd_control(Namespace(run=str(src)))

        control = Path(out.call_args[0][0])
        self.assertEqual((control / "attack" / "template" / "blob.bin").read_bytes(), b"\xff\xfe{{NONCE}}")
        self.assertEqual([file.name for file in (control / "attack" / "template").iterdir()], ["blob.bin"])


class Packaging(unittest.TestCase):
    def test_observer_tag_ignores_subfolders(self):
        # An installed package gets observer/__pycache__/; the image tag must still compute.
        observer = Path(tempfile.mkdtemp())
        (observer / "victim.py").write_text("x")
        (observer / "__pycache__").mkdir()
        with mock.patch.object(docker, "OBSERVER_DIR", observer):
            self.assertTrue(docker.observer_image().startswith("proofbench-observer:"))


class Roles(unittest.TestCase):
    def test_planned_roles_become_readiness_probes(self):
        # A wrong deployed role fails readiness, and attack refuses until readiness passes.
        role = {"account": "attacker", "role": "Viewer", "url": "http://app/me",
                "auth": ["attacker", "pw"], "contains": '"role":"Viewer"'}
        probes = controller.readiness_probes({**PLAN, "roles": [role]})
        self.assertEqual(probes[:1], PLAN["readiness"])
        self.assertEqual(probes[1], {"name": "role attacker = Viewer", "url": "http://app/me",
                                     "auth": ["attacker", "pw"], "contains": '"role":"Viewer"'})


class Display(unittest.TestCase):
    def test_agents_get_raw_output(self):
        # Agents run proofbench without a terminal and need the real output to iterate on payloads.
        with mock.patch("sys.stdout.isatty", return_value=False):
            self.assertEqual(cli.output_detail(Namespace(verbose=False)), ui.Detail.RAW)
        with mock.patch("sys.stdout.isatty", return_value=True):
            self.assertEqual(cli.output_detail(Namespace(verbose=False)), ui.Detail.SUMMARY)
            self.assertEqual(cli.output_detail(Namespace(verbose=True)), ui.Detail.RAW)

    def test_evidence_link_is_absolute(self):
        with mock.patch("builtins.print") as out:
            ui.evidence_link("screenshot", Path("runs/x/final.png"))
        self.assertIn(str(Path("runs/x/final.png").resolve()), out.call_args[0][0])


class Timeouts(unittest.TestCase):
    def test_timeout_is_an_exit_code_not_a_crash(self):
        res = docker.run_command(["sleep", "5"], timeout=1)
        self.assertEqual(res.returncode, docker.TIMEOUT_EXIT)


if __name__ == "__main__":
    unittest.main()
