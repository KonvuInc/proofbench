"""Docker driver. The only module that shells out to `docker`.

Every lab is one compose project, `proofbench-<run id>`, on its own default network.
Controller-owned containers (prober, victim) and the attacker join that network.
Every lab network is forced `internal` (no route out), through a controller-written
override file the agent's compose.yml cannot remove.
"""

import hashlib
import json
import secrets
import subprocess
from pathlib import Path

ATTACKER_IMAGE = "python:3.12-slim"
OBSERVER_DIR = Path(__file__).resolve().parent / "observer"
UP_TIMEOUT_S = 300
TIMEOUT_EXIT = 124  # same code as coreutils `timeout`
PROJECT_LABEL = "com.docker.compose.project"  # compose labels every lab resource with it
CONTAINER_SUFFIX_BYTES = 3
ISOLATION_FILE = "isolation.yml"  # in runs/<id>/, beside lab/, outside the agent's lab dir

# Attacker container limits: no capabilities, no privilege gain, bounded fork/memory.
ATTACKER_LIMITS = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--pids-limit", "256", "--memory", "1g"]


def observer_image() -> str:
    """Tag = hash of the observer sources, so an edited probe/victim script is always rebuilt."""
    digest = hashlib.sha256()
    for file in sorted(OBSERVER_DIR.iterdir()):
        if not file.is_file():  # e.g. __pycache__ in an installed package
            continue
        digest.update(file.name.encode() + file.read_bytes())
    return f"proofbench-observer:{digest.hexdigest()[:12]}"


def project(run_id: str) -> str:
    return f"proofbench-{run_id}"


def network(run_id: str) -> str:
    return f"{project(run_id)}_default"


def run_command(args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
    """Run a command, capture output, never raise: a non-zero exit or a timeout is a return code."""
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as timeout_error:
        out = timeout_error.stdout.decode(errors="replace") if isinstance(timeout_error.stdout, bytes) else (timeout_error.stdout or "")
        err = timeout_error.stderr.decode(errors="replace") if isinstance(timeout_error.stderr, bytes) else (timeout_error.stderr or "")
        return subprocess.CompletedProcess(args, TIMEOUT_EXIT, out, err + f"\ntimed out after {timeout}s")


def isolation_path(compose_file: Path) -> Path:
    return compose_file.parent.parent / ISOLATION_FILE


def compose(run_id: str, compose_file: Path, *args: str, timeout: int | None = None) -> subprocess.CompletedProcess:
    """docker compose on the agent's lab, plus the isolation override once `up` has written it."""
    files = ["-f", str(compose_file)]
    if isolation_path(compose_file).exists():
        files += ["-f", str(isolation_path(compose_file))]
    return run_command(["docker", "compose", "-p", project(run_id), *files, *args], timeout=timeout)


def compose_config(run_id: str, compose_file: Path) -> dict | None:
    """Resolved compose model, or None if the file is invalid."""
    proc = compose(run_id, compose_file, "config", "--format", "json")
    if proc.returncode != 0:
        return None
    return json.loads(proc.stdout)


# Service settings that hand a lab container the host (and so the internet).
HOST_ACCESS_KEYS = ("network_mode", "privileged", "cap_add", "devices")
HOST_NAMESPACES = ("pid", "ipc", "uts", "cgroup", "userns_mode")


def _outside(path: str | None, root: Path) -> bool:
    """A host path outside the run folder, symlinks resolved. Remote build contexts are not host paths."""
    return bool(path) and Path(path).is_absolute() and not Path(path).resolve().is_relative_to(root)


def network_escapes(config: dict, root: Path) -> list[str]:
    """Ways a lab could leave its sandbox: host namespaces, privileges, pre-existing networks, and
    any host file outside the run folder `root` (the Docker socket, the host filesystem). `up`
    refuses all of them."""
    errors = []
    for name, svc in config.get("services", {}).items():
        errors += [f"service '{name}' sets {key}" for key in HOST_ACCESS_KEYS if svc.get(key)]
        errors += [f"service '{name}' shares the host {key} namespace" for key in HOST_NAMESPACES
                   if svc.get(key) == "host"]
        errors += [f"service '{name}' mounts {vol['source']}, outside the run folder" for vol in svc.get("volumes", [])
                   if vol.get("type") == "bind" and _outside(vol.get("source"), root)]
        errors += [f"service '{name}' mounts volumes from {src}" for src in svc.get("volumes_from", [])
                   if src.startswith("container:")]
        build = svc.get("build") or {}
        errors += [f"service '{name}' builds from {ctx}, outside the run folder"
                   for ctx in [build.get("context"), *(build.get("additional_contexts") or {}).values()]
                   if _outside(ctx, root)]

    # A named volume with driver options can bind any host path (driver_opts: {o: bind, device: /}).
    errors += [f"volume '{name}' is external or driver-backed" for name, vol in config.get("volumes", {}).items()
               if vol.get("external") or vol.get("driver_opts") or vol.get("driver", "local") != "local"]
    errors += [f"{kind[:-1]} '{name}' reads {item['file']}, outside the run folder"
               for kind in ("configs", "secrets") for name, item in config.get(kind, {}).items()
               if _outside(item.get("file"), root)]
    errors += [f"network '{name}' is external" for name, net in config.get("networks", {}).items()
               if net.get("external")]
    return errors


def services_mounting(config: dict, work_dir: Path) -> set[str]:
    """Services that bind-mount the attacker's work dir (or a subdir), e.g. a fake data source."""
    work = work_dir.resolve()
    return {name for name, svc in config.get("services", {}).items()
            for vol in svc.get("volumes", [])
            if vol.get("source") and Path(vol["source"]).resolve().is_relative_to(work)}


def isolation_override(config: dict) -> dict:
    """Compose override marking every lab network internal: services reach each other, not the internet."""
    return {"networks": {name: {"internal": True} for name in config.get("networks", {})}}


def write_isolation(compose_file: Path, config: dict) -> None:
    """Write the override (JSON is valid YAML) that every later compose call includes."""
    isolation_path(compose_file).write_text(json.dumps(isolation_override(config), indent=2))


def compose_up(run_id: str, compose_file: Path) -> subprocess.CompletedProcess:
    """Start the lab and wait for every healthcheck. A failing healthcheck fails this call."""
    return compose(run_id, compose_file, "up", "-d", "--wait", "--wait-timeout", str(UP_TIMEOUT_S), timeout=UP_TIMEOUT_S + 60)


def compose_diagnostics(run_id: str, compose_file: Path) -> str:
    """What the deployer needs to repair a failed start: service states and recent logs."""
    ps = compose(run_id, compose_file, "ps", "-a").stdout
    logs = compose(run_id, compose_file, "logs", "--tail", "40", "--no-color").stdout
    return f"$ docker compose ps -a\n{ps}\n{health_logs(run_id, compose_file)}\n$ docker compose logs --tail 40\n{logs}"


def health_logs(run_id: str, compose_file: Path) -> str:
    """Last healthcheck output per container: the line that explains an 'unhealthy'."""
    out = []
    for cid in compose(run_id, compose_file, "ps", "-aq").stdout.split():
        proc = run_command(["docker", "inspect", "--format", "{{.Name}} {{json .State.Health}}", cid])
        name, _, health = proc.stdout.strip().partition(" ")
        if health in ("", "null"):
            continue
        last = (json.loads(health).get("Log") or [{}])[-1]
        out.append(f"healthcheck {name}: exit {last.get('ExitCode')} {last.get('Output', '').strip()[:300]}")
    return "\n".join(out)


def compose_exec(run_id: str, compose_file: Path, service: str, cmd: str) -> subprocess.CompletedProcess:
    return compose(run_id, compose_file, "exec", "-T", service, "sh", "-c", cmd, timeout=60)


def compose_down(run_id: str, compose_file: Path) -> subprocess.CompletedProcess:
    return compose(run_id, compose_file, "down", "-v", "--remove-orphans", timeout=180)


def image_digest(image: str) -> str:
    proc = run_command(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image])
    if proc.returncode != 0:
        return ""
    digests = json.loads(proc.stdout or "[]")
    return digests[0] if digests else ""


def leftovers(run_id: str) -> dict:
    """Containers, volumes and networks still labelled with this run's project."""
    label = f"label={PROJECT_LABEL}={project(run_id)}"
    found = {}
    for kind, cmd in (("containers", ["ps", "-aq"]), ("volumes", ["volume", "ls", "-q"]), ("networks", ["network", "ls", "-q"])):
        out = run_command(["docker", *cmd, "--filter", label]).stdout.split()
        found[kind] = out
    return found


def ensure_observer() -> str:
    """Build the controller's browser image when its sources changed. Returns the tag."""
    image = observer_image()
    if run_command(["docker", "image", "inspect", image]).returncode == 0:
        return image
    proc = run_command(["docker", "build", "-t", image, str(OBSERVER_DIR)])
    if proc.returncode != 0:
        raise RuntimeError(f"observer image build failed:\n{proc.stderr[-2000:]}")
    return image


def _run_container(run_id: str, role: str, args: list[str], timeout: int) -> subprocess.CompletedProcess:
    """`docker run --rm` a one-shot container on the lab network, named and labelled with the run.

    A timeout kills the docker client, not the container: remove it by name so it never
    keeps running on the lab network. The project label lets `leftovers` find it otherwise.
    """
    name = f"{project(run_id)}-{role}-{secrets.token_hex(CONTAINER_SUFFIX_BYTES)}"
    proc = run_command(["docker", "run", "--rm", "--name", name,
                        "--label", f"{PROJECT_LABEL}={project(run_id)}",
                        "--network", network(run_id), *args], timeout=timeout)
    if proc.returncode == TIMEOUT_EXIT:
        run_command(["docker", "rm", "-f", name])
    return proc


def run_observer(run_id: str, in_dir: Path, out_dir: Path, *cmd: str, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a controller-owned script on the lab network. Input mounted read-only."""
    image = ensure_observer()
    return _run_container(run_id, "observer", ["-v", f"{in_dir}:/in:ro", "-v", f"{out_dir}:/out", image, *cmd],
                          timeout)


def run_attacker(run_id: str, work_dir: Path, env: dict, cmd: str, timeout: int) -> subprocess.CompletedProcess:
    """Run one attacker command in a throwaway container: lab network + its own work dir only."""
    env_args = [arg for name, value in env.items() for arg in ("-e", f"{name}={value}")]
    return _run_container(run_id, "attacker", ["-v", f"{work_dir}:/work", "-w", "/work", *env_args,
                                               *ATTACKER_LIMITS, ATTACKER_IMAGE, "sh", "-c", cmd], timeout)
