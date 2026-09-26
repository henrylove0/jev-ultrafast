"""QA harness: drive a real browser with Jev (via jev-ultrafast) and report PASS/FAIL.

Usage:
    uv run --env-file .env python qa_run.py --url http://localhost:3000 \
        --goal "Verify the login page shows the Exe logo and a Sign in button."

Exit codes: 0 = agent reached DONE, 1 = BLOCKED/failed or harness error.
Prints: status, actions taken, final URL, elapsed ms.

Notes:
    * Goals should describe an observable assertion about the page ("verify X is visible").
    * TYPE_TEXT goals additionally need TEXT_MODEL_API_KEY in .env (typing uses a text model).
    * Launches a dedicated Chrome (profile ~/.jev-chrome-profile, CDP port 9333) if not already up;
      your main Chrome is never touched.
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request

CDP_PORT = 9333
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
PROFILE = "~/.jev-chrome-profile"


def cdp_ws() -> str | None:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json/version", timeout=3) as r:
            return json.load(r)["webSocketDebuggerUrl"]
    except Exception:
        return None


def ensure_chrome() -> str:
    ws = cdp_ws()
    if ws:
        return ws
    subprocess.Popen(
        [
            CHROME,
            f"--remote-debugging-port={CDP_PORT}",
            f"--user-data-dir={PROFILE.replace('~', __import__('os').path.expanduser('~'))}",
            "--no-first-run",
            "--no-default-browser-check",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(30):
        ws = cdp_ws()
        if ws:
            return ws
        time.sleep(0.5)
    raise SystemExit("Could not start dedicated Chrome with CDP on port 9333")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="page under test (our own app)")
    ap.add_argument("--goal", required=True, action="append", help="QA assertion; repeat for an ordered list")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument(
        "--settle-ms", type=int, default=0, help="wait for client-side app rendering before first assertion"
    )
    ap.add_argument(
        "--redact",
        action="append",
        default=[],
        help="literal value to remove from model-visible page text (repeatable)",
    )
    a = ap.parse_args()

    import os

    os.environ["BU_CDP_WS"] = ensure_chrome()

    from jev_ultrafast import Agent
    from jev_ultrafast.agent import sanitize_url

    started = time.perf_counter()
    with Agent(a.url, a.goal, redact_values=a.redact, initial_wait_ms=a.settle_ms) as agent:
        last = None
        for state in agent.run():
            last = state
            print(f"{state['elapsed_ms']:>6} ms  {len(state['history'])} actions  {state['status']}")
        verdict = last["status"]
        final_url = sanitize_url(last["page"]["url"])
        n_actions = len(last["history"])

    print(
        json.dumps(
            {
                "verdict": "PASS" if verdict == "done" else "FAIL",
                "agent_status": verdict,
                "actions": n_actions,
                "final_url": final_url,
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
            }
        )
    )
    sys.exit(0 if verdict == "done" else 1)


if __name__ == "__main__":
    main()
