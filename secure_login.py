"""Authenticate the dedicated QA Chrome without exposing credentials to a model or argv."""

import subprocess
import time
import urllib.parse

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


def _password_action(browser: Browser, page: dict, email: dict) -> dict | None:
    """Register one visible password input in the observed email form, without reading its value."""
    node = email.get("node")
    if type(node) is not int:
        return None
    observed = browser.evaluate(
        """(() => {
          const cache = window.__jevFast;
          const email = cache?.nodes.get(""" + str(node) + """);
          const form = email?.closest('form');
          if (!form) return null;
          const candidates = [...form.querySelectorAll('input[type="password"]')].filter(e => {
            const r = e.getBoundingClientRect();
            return !e.disabled && !e.readOnly && r.width > 0 && r.height > 0 &&
              r.x + r.width / 2 >= 0 && r.y + r.height / 2 >= 0 &&
              r.x + r.width / 2 < innerWidth && r.y + r.height / 2 < innerHeight &&
              e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}) &&
              e.contains(document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2));
          });
          if (candidates.length !== 1) return null;
          const input = candidates[0];
          if (!cache.ids.has(input)) cache.ids.set(input, cache.next++);
          const id = cache.ids.get(input);
          cache.nodes.set(id, input);
          return {node:id};
        })()"""
    )
    return {"id": "secure-password", "kind": "fill", "node": observed["node"]} if observed else None


def _submit_action(browser: Browser, email: dict) -> dict | None:
    """Select the submit control in the observed email form, never a matching tab."""
    node = email.get("node")
    if type(node) is not int:
        return None
    observed = browser.evaluate(
        """(() => {
          const cache = window.__jevFast;
          const email = cache?.nodes.get(""" + str(node) + """);
          const form = email?.closest('form');
          if (!form) return null;
          const candidates = [...form.querySelectorAll('button[type="submit"],input[type="submit"]')]
            .filter(e => !e.disabled && e.checkVisibility({checkOpacity:true,checkVisibilityCSS:true}));
          if (candidates.length !== 1) return null;
          const button = candidates[0];
          if (!cache.ids.has(button)) cache.ids.set(button, cache.next++);
          const id = cache.ids.get(button);
          cache.nodes.set(id, button);
          return {node:id};
        })()"""
    )
    return {"id": "secure-submit", "kind": "click", "node": observed["node"]} if observed else None


def login(auth_url: str, service: str, account: str, timeout: int = 45) -> dict:
    password = keychain_password(service, account)
    browser = Browser(auth_url)
    actions_taken = 0
    started = time.perf_counter()
    expected_url = urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query).get("redirect", [""])[0]
    expected_host = urllib.parse.urlparse(expected_url).hostname
    auth_host = urllib.parse.urlparse(auth_url).hostname
    try:
        deadline = time.monotonic() + timeout
        supplied: set[str] = set()
        executed: set[tuple[str, str]] = set()
        submitted = False
        while time.monotonic() < deadline and actions_taken < 6:
            page = browser.observe(screenshot=False)
            current_host = urllib.parse.urlparse(page["url"]).hostname
            if current_host == expected_host and submitted:
                return {
                    "verdict": "PASS",
                    "actions": actions_taken,
                    "final_url": page["url"],
                    "elapsed_ms": round((time.perf_counter() - started) * 1000),
                }
            if current_host not in {auth_host, expected_host}:
                return {
                    "verdict": "FAIL",
                    "reason": "unexpected_redirect",
                    "actions": actions_taken,
                    "final_url": page["url"],
                    "elapsed_ms": round((time.perf_counter() - started) * 1000),
                }
            if submitted:
                error = browser.evaluate("document.getElementById('login-error')?.textContent || ''")
                if error.strip():
                    lower = error.lower()
                    reason = (
                        "invalid_credentials" if "invalid" in lower or "credential" in lower
                        else "unconfirmed_account" if "confirm" in lower
                        else "auth_service_unavailable" if "unavailable" in lower
                        else "auth_rejected"
                    )
                    return {
                        "verdict": "FAIL",
                        "reason": reason,
                        "actions": actions_taken,
                        "final_url": page["url"],
                        "elapsed_ms": round((time.perf_counter() - started) * 1000),
                    }
            actions = page["actions"]
            email = _find(actions, "fill", ("email", "username"))
            secret = _password_action(browser, page, email) if email else None
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
            submit = _submit_action(browser, email) if email else None
            if submit and {"email", "password"}.issubset(supplied) and ("click", str(submit["node"])) not in executed:
                browser.act(submit, page)
                executed.add(("click", str(submit["node"])))
                submitted = True
                actions_taken += 1
                continue
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
