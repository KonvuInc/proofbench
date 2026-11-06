"""Simulated victim + independent canary observer (Playwright, headless Chromium).

Usage: python victim.py <spec.json> <out_dir>

spec.json = {"label": "after", "nonce": "...", "base_url": "http://grafana:3000",
             "steps": [{"goto": "/login"}, {"fill": ["input[name=user]", "admin"]}, {"hover": "..."}]}

The victim performs only the declared, ordinary UI steps. It never evaluates attacker
payloads. Execution is proven only when page JavaScript calls
window.__proofbench_canary__(nonce): the call lands in this Python process, which the
attacker cannot write to. An alert() or a console line is recorded but is not proof.
"""

import json
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

CANARY_FN = "__proofbench_canary__"
STEP_TIMEOUT_MS = 15_000
SETTLE_MS = 2_000
VIEWPORT = {"width": 1440, "height": 900}
LOCALE = "en-US"


def run_step(page, base_url: str, step: dict, out: Path, idx: int) -> None:
    """Execute one declared step. Raises on failure so the trace marks the path as not reached."""
    (kind, arg), = step.items()

    if kind == "goto":
        page.goto(base_url + arg, wait_until="networkidle")
        return
    if kind == "fill":
        page.fill(arg[0], arg[1])
        return
    if kind == "click":
        page.click(arg)
        return
    if kind == "hover":
        page.hover(arg)
        return
    if kind == "press":
        page.keyboard.press(arg)
        return
    if kind == "type":
        page.keyboard.type(arg)
        return
    if kind == "wait_for":
        page.wait_for_selector(arg, state="visible")
        return
    if kind == "wait_ms":
        page.wait_for_timeout(arg)
        return
    if kind == "screenshot":
        page.screenshot(path=out / f"{idx:02d}-{arg}.png")
        return

    raise ValueError(f"unknown step kind: {kind}")


def main(spec_path: str, out_dir: str) -> None:
    spec = json.loads(Path(spec_path).read_text())
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    trace = {"label": spec["label"], "nonce": spec["nonce"], "started": time.time(),
             "steps": [], "canary_calls": [], "dialogs": [], "page_errors": []}

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        # Explicit locale: the container default makes some SPAs throw in Intl (Grafana 9.3 does).
        ctx = browser.new_context(viewport=VIEWPORT, locale=LOCALE, record_video_dir=str(out / "video"))
        page = ctx.new_page()
        page.set_default_timeout(STEP_TIMEOUT_MS)

        # Observer hooks, attached before the first navigation.
        def on_canary(nonce):
            trace["canary_calls"].append({"nonce": str(nonce), "url": page.url, "ts": time.time()})

        page.expose_function(CANARY_FN, on_canary)
        page.on("dialog", lambda d: (trace["dialogs"].append(d.message), d.dismiss()))
        page.on("pageerror", lambda e: trace["page_errors"].append(str(e)[:300]))

        # Declared victim actions. Stop at the first failure: later steps would be meaningless.
        for idx, step in enumerate(spec["steps"]):
            try:
                run_step(page, spec["base_url"], step, out, idx)
                trace["steps"].append({"step": step, "ok": True})
            except Exception as e:  # noqa: BLE001 - any step failure means path not reached
                trace["steps"].append({"step": step, "ok": False, "error": str(e)[:500]})
                break

        page.wait_for_timeout(SETTLE_MS)
        page.screenshot(path=out / "final.png")
        trace["final_url"] = page.url
        ctx.close()
        browser.close()

    trace["all_steps_ok"] = len(trace["steps"]) == len(spec["steps"]) and all(s["ok"] for s in trace["steps"])
    trace["canary_matched"] = any(c["nonce"] == spec["nonce"] for c in trace["canary_calls"])
    trace["finished"] = time.time()
    (out / "trace.json").write_text(json.dumps(trace, indent=2))
    print(json.dumps({k: trace[k] for k in ("label", "all_steps_ok", "canary_matched")}))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
