"""Authenticate the dedicated QA Chrome without exposing credentials to a model or argv."""

import subprocess
import time

from jev_ultrafast.browser import Browser


def keychain_password(service: str, account: str) -> str:
    result = subprocess.run(
        ["security", "find-generic-password", "-w", "-s", service, "-a", account],
        check=True,
        capture_output=True,
        text=True,
    )
    password = result.stdout.rstrip("\n")
    if not password:
        raise RuntimeError("Keychain credential is empty")
    return password


def _find(actions: list[dict], kind: str, words: tuple[str, ...]) -> dict | None:
    return next(
        (
            action
            for action in actions
            if action.get("kind") == kind and any(word in str(action.get("label", "")).lower() for word in words)
        ),
        None,
    )


def login(auth_url: str, service: str, account: str, timeout: int = 45) -> dict:
    password = keychain_password(service, account)
    browser = Browser(auth_url)
    actions_taken = 0
    started = time.perf_counter()
    try:
        deadline = time.monotonic() + timeout
        supplied: set[str] = set()
        executed: set[tuple[str, str]] = set()
        while time.monotonic() < deadline and actions_taken < 6:
            page = browser.observe(screenshot=False)
            actions = page["actions"]
            email = _find(actions, "fill", ("email", "username"))
            secret = _find(actions, "fill", ("password",))
            if email and "email" not in supplied and ("fill", str(email["node"])) not in executed:
                browser.act(email, page, text=account)
                executed.add(("fill", str(email["node"])))
                supplied.add("email")
                actions_taken += 1
                continue
            if secret and "password" not in supplied and ("fill", str(secret["node"])) not in executed:
                browser.act(secret, page, text=password)
                executed.add(("fill", str(secret["node"])))
                supplied.add("password")
                actions_taken += 1
                continue
            reveal = _find(actions, "click", ("show password",))
            if reveal and ("click", str(reveal["node"])) not in executed:
                browser.act(reveal, page)
                executed.add(("click", str(reveal["node"])))
                actions_taken += 1
                continue
            submit = _find(actions, "click", ("sign in", "log in", "continue"))
            if submit and {"email", "password"}.issubset(supplied) and ("click", str(submit["node"])) not in executed:
                browser.act(submit, page)
                executed.add(("click", str(submit["node"])))
                actions_taken += 1
                continue
            if not page["url"].startswith(auth_url.rstrip("/")):
                return {
                    "verdict": "PASS",
                    "actions": actions_taken,
                    "final_url": page["url"],
                    "elapsed_ms": round((time.perf_counter() - started) * 1000),
                }
            time.sleep(0.2)
        return {
            "verdict": "BLOCKED",
            "actions": actions_taken,
            "final_url": browser.observe(screenshot=False)["url"],
            "elapsed_ms": round((time.perf_counter() - started) * 1000),
        }
    finally:
        password = ""
        browser.close()
