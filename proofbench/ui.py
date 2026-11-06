"""Terminal presentation: boxed stage panels, a pipeline bar, spinners, a verdict card.

    ╭──────────────────────────────────────────────────────────────╮
    │ ✓ REPORT ━━ ● SANDBOX ━━ ○ ATTACK ━━ ○ RECAP                  │   pipeline bar
    │ readiness probes (prerequisites, never the exploit)          │   what this step does
    ╰──────────────────────────────────────────────────────────────╯
      ✓ passed    ✗ failed    · info    ↗ evidence (cmd-click)        one line per check

Plain text when stdout is not a terminal or NO_COLOR is set, so logs, pipes and agents
get clean output.
"""

import os
import re
import shutil
import sys
import textwrap
import threading
import time
from contextlib import contextmanager
from enum import Enum
from pathlib import Path


class Detail(str, Enum):
    SUMMARY = "summary"  # default: Haiku summaries of command output when available
    RAW = "raw"          # --verbose: the output itself


class Tone(str, Enum):
    OK = "32"       # green
    FAIL = "31"     # red
    WARN = "33"     # yellow
    STAGE = "1;36"  # bold cyan
    BOLD = "1"
    DIM = "2"
    GREY = "90"


STAGES = ["REPORT", "SANDBOX", "ATTACK", "RECAP"]
MAX_WIDTH = 78
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPIN_INTERVAL_S = 0.1
ANSI = re.compile(r"\033\[[0-9;]*m")


def _is_styled() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _panel_width() -> int:
    return min(shutil.get_terminal_size((MAX_WIDTH, 24)).columns, MAX_WIDTH)


def paint(text: str, tone: Tone) -> str:
    return f"\033[{tone.value}m{text}\033[0m" if _is_styled() else text


def _panel(lines: list[str], tone: Tone) -> None:
    """Rounded panel around already-painted lines; pads by visible width, not byte length."""
    inner = _panel_width() - 4
    print(paint("╭" + "─" * (inner + 2) + "╮", tone))

    # Wrap plain lines that overflow; painted lines (titles) are short by construction.
    rows = []
    for line in lines:
        plain = ANSI.sub("", line) == line
        rows += textwrap.wrap(line, inner) or [""] if plain and len(line) > inner else [line]

    for line in rows:
        pad = max(inner - len(ANSI.sub("", line)), 0)
        print(f"{paint('│', tone)} {line}{' ' * pad} {paint('│', tone)}")
    print(paint("╰" + "─" * (inner + 2) + "╯", tone))


def _pipeline_bar(current: str) -> str:
    """`✓ REPORT ━━ ● SANDBOX ━━ ○ ATTACK ━━ ○ RECAP`; a stage outside the four marks none."""
    at = STAGES.index(current) if current in STAGES else -1
    parts = []
    for i, name in enumerate(STAGES):
        if i < at:
            parts.append(paint(f"✓ {name}", Tone.OK))
        elif i == at:
            parts.append(paint(f"● {name}", Tone.STAGE))
        else:
            parts.append(paint(f"○ {name}", Tone.DIM))
    return paint(" ━━ ", Tone.DIM).join(parts)


def stage(name: str, what: str) -> None:
    """Step header. Terminal: a panel with the pipeline bar. Plain: `== SANDBOX  what`."""
    if not _is_styled():
        print(f"\n== {name}  {what}")
        return

    print()
    title = _pipeline_bar(name) if name in STAGES else paint(f"◆ {name}", Tone.WARN)
    _panel([title, what], Tone.STAGE if name in STAGES else Tone.WARN)


def substep(what: str) -> None:
    """A further step inside the current stage panel, e.g. `  ▸ readiness probes`."""
    print(f"\n  {paint('▸', Tone.STAGE)} {paint(what, Tone.BOLD)}")


HANGING = re.compile(r"^(\d+\. |\S+ {2,})")  # "3. text" or "key   value": wrap under the text


def _wrap(line: str, width: int) -> list[str]:
    """Wrap with a hanging indent, so continuation lines align after a number or a key."""
    lead = HANGING.match(line)
    return textwrap.wrap(line, width, subsequent_indent=" " * len(lead.group(1)) if lead else "")


def evidence_box(title: str, lines: list[str]) -> None:
    """Raw proof in a small grey box, title on the top border. Plain: `[title]` + lines.

      ┌─ pinned image ─────────────┐
      │ grafana/grafana:10.2.5     │
      │ sha256:33df8202cfe4        │
      └────────────────────────────┘
    """
    if not _is_styled():
        print(f"  [{title}]")
        for line in lines:
            print(f"    {line}")
        return

    # Fit the content, capped by the terminal; wrap anything wider.
    cap = _panel_width() - 6
    rows = [part for line in lines for part in (_wrap(line, cap) or [""])]
    inner = min(max([len(title) + 3, *map(len, rows)]), cap)

    top = f"┌─ {title} " + "─" * (inner - len(title) - 1) + "┐"
    print("  " + paint(top, Tone.GREY))
    for row in rows:
        print(f"  {paint('│', Tone.GREY)} {row.ljust(inner)} {paint('│', Tone.GREY)}")
    print("  " + paint("└" + "─" * (inner + 2) + "┘", Tone.GREY))


def check(ok: bool, text: str) -> None:
    mark = paint("✓", Tone.OK) if ok else paint("✗", Tone.FAIL)
    print(f"  {mark} {text}")


def info(text: str) -> None:
    print(f"  {paint('·', Tone.DIM)} {text}")


def indented(text: str) -> None:
    """Indented multi-line text: summaries, diffs, raw output."""
    for line in text.rstrip().splitlines():
        print(f"    {line}")


def evidence_link(label: str, path: Path) -> None:
    """Evidence file, cmd-click to open: a short path linking to the absolute file (OSC 8).

    Not a terminal: the absolute path, so logs and agents can still locate it.
    """
    target = path.resolve()
    shown = os.path.relpath(target) if _is_styled() else str(target)
    if _is_styled():
        shown = f"\033]8;;file://{target}\033\\{shown}\033]8;;\033\\"
    print(f"  {paint('↗', Tone.DIM)} {label}: {shown}")


# Red = the exploit worked (vulnerable), green = it did not (safe here), yellow = undecided.
OUTCOME_TONES = {"reproduced": Tone.FAIL, "not_observed": Tone.OK}


def outcome(name: str) -> str:
    return paint(name.replace("_", " ").upper(), OUTCOME_TONES.get(name, Tone.WARN))


def verdict_card(name: str, lines: list[str]) -> None:
    """Verdict card: border and headline in the outcome's color, reasons below."""
    tone = OUTCOME_TONES.get(name, Tone.WARN)
    text = f"■ {name.replace('_', ' ').upper()}"
    headline = f"\033[1;{tone.value}m{text}\033[0m"  # bold + outcome color
    if not _is_styled():
        print(f"\nRESULT   {name.replace('_', ' ').upper()}")
        for line in lines:
            print(f"  {line}")
        return

    print()
    _panel([headline, *lines], tone)



@contextmanager
def spinner(label: str):
    """Spinner with elapsed seconds while a slow step runs; silent when not a terminal."""
    if not _is_styled():
        yield
        return

    done = threading.Event()
    start = time.time()

    def spin() -> None:
        tick = 0
        while not done.wait(SPIN_INTERVAL_S):
            frame = paint(SPINNER[tick % len(SPINNER)], Tone.STAGE)
            elapsed = paint(f"{time.time() - start:.0f}s", Tone.DIM)
            sys.stdout.write(f"\r  {frame} {label}  {elapsed}\033[K")
            sys.stdout.flush()
            tick += 1

    thread = threading.Thread(target=spin, daemon=True)
    thread.start()
    try:
        yield
    finally:
        done.set()
        thread.join()
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
