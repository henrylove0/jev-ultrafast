"""Bounded release QA for Exe: deterministic HTTP contracts plus Jev visibility checks."""

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from qa_run import ensure_chrome
from secure_login import login

HERE = Path(__file__).resolve().parent
RESULTS: list[dict] = []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def record(name: str, status: str, detail: str, **evidence) -> bool:
    row = {"check": name, "status": status, "detail": detail, **evidence}
    RESULTS.append(row)
    print(f"  [{status}] {name} — {detail}")
    return status == "PASS"


def request(url: str, host: str | None = None, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "exe-release-qa/1"})
    if host:
        req.add_header("Host", host)
    opener = urllib.request.build_opener(NoRedirect)
    try:
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    body = response.read(8192)
    return {
        "status": response.status,
        "content_type": response.headers.get("Content-Type", "").split(";", 1)[0].lower(),
        "location": response.headers.get("Location", ""),
        "body": body.decode("utf-8", "replace"),
    }


def assert_health(name: str, url: str, content_type: str, body_contains: str, host: str | None = None) -> bool:
    try:
        response = request(url, host=host)
    except Exception as error:
        return record(name, "FAIL", f"unreachable: {str(error)[:100]}")
    ok = response["status"] == 200 and response["content_type"] == content_type and body_contains in response["body"]
    return record(
        name,
        "PASS" if ok else "FAIL",
        f"HTTP {response['status']} {response['content_type']}; "
        f"expected 200 {content_type} containing {body_contains!r}",
        url=url,
    )


def assert_sso_redirect(name: str, app_url: str, auth_url: str, host: str | None = None) -> bool:
    try:
        response = request(app_url, host=host)
    except Exception as error:
        return record(name, "FAIL", f"unreachable: {str(error)[:100]}")
    location = response["location"]
    parsed = urllib.parse.urlparse(location)
    expected_host = urllib.parse.urlparse(auth_url).hostname
    query = urllib.parse.parse_qs(parsed.query)
    redirects = query.get("redirect", [])
    target_host = urllib.parse.urlparse(redirects[0]).hostname if redirects else None
    app_host = urllib.parse.urlparse(app_url).hostname
    ok = (
        response["status"] in {301, 302, 303, 307, 308} and parsed.hostname == expected_host and target_host == app_host
    )
    return record(
        name,
        "PASS" if ok else "FAIL",
        f"HTTP {response['status']} -> {parsed.hostname or '<none>'}; redirect target host={target_host or '<none>'}",
        url=app_url,
        final_url=location,
    )


def jev_check(name: str, url: str, goal: str, redact: list[str] | None = None, settle_ms: int = 0) -> bool:
    command = [sys.executable, str(HERE / "qa_run.py"), "--url", url, "--goal", goal]
    if settle_ms:
        command.extend(["--settle-ms", str(settle_ms)])
    for value in redact or []:
        command.extend(["--redact", value])
    try:
        proc = subprocess.run(command, cwd=HERE, capture_output=True, text=True, timeout=210, env={**os.environ})
    except subprocess.TimeoutExpired:
        return record(name, "BLOCKED", "Jev assertion exceeded 210 seconds")
    line = next((item for item in reversed(proc.stdout.splitlines()) if '"verdict"' in item), "")
    try:
        verdict = json.loads(line)
    except json.JSONDecodeError:
        return record(name, "FAIL", "Jev harness produced no structured verdict")
    status = "PASS" if proc.returncode == 0 and verdict.get("verdict") == "PASS" else "BLOCKED"
    return record(
        name,
        status,
        f"{verdict.get('agent_status')} · {verdict.get('actions')} actions · {verdict.get('elapsed_ms')} ms",
        final_url=verdict.get("final_url"),
        actions=verdict.get("actions"),
        elapsed_ms=verdict.get("elapsed_ms"),
    )


def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text())


def validate_live_evidence(evidence: dict, surfaces: dict) -> bool:
    observed = evidence.get("observedDeployed", {})
    missing = []
    for name in surfaces:
        item = observed.get(name, {})
        if not item.get("observedAt") or not any(item.get(key) for key in ("image", "source", "version")):
            missing.append(f"{name} (observedAt and one of image/source/version required)")
    return record(
        "deployment/evidence",
        "PASS" if not missing else "BLOCKED",
        "observed runtime identity supplied for every surface"
        if not missing
        else f"missing observed runtime evidence: {', '.join(missing)}",
        observed_deployed=observed,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default=str(HERE / "profiles" / "production.json"))
    parser.add_argument("--phase", choices=("artifact", "live"), default="live")
    parser.add_argument(
        "--deployment-evidence", help="required for live QA; observed runtime image/source/version JSON"
    )
    parser.add_argument("--skip-browser", action="store_true")
    parser.add_argument("--with-login", action="store_true")
    args = parser.parse_args()

    profile = load_json(args.profile)
    surfaces = profile["surfaces"]
    auth = surfaces["auth"]
    print(f"=== {profile['name']} · {args.phase} QA ===")

    if args.phase == "live":
        if not args.deployment_evidence:
            record("deployment/evidence", "BLOCKED", "--deployment-evidence is required for live QA")
            return finish()
        validate_live_evidence(load_json(args.deployment_evidence), surfaces)

    assert_health("health/crm", surfaces["crm"] + "/health", "application/json", '"status":"ok"')
    assert_health("health/wiki", surfaces["wiki"] + "/health", "application/json", '"online":true')
    assert_health(
        "health/dashboard", surfaces["dashboard"] + "/health", "application/json", '"service":"exe-dashboard"'
    )
    assert_health("render/auth-http", auth + "/", "text/html", "<title>Exe Auth</title>")

    for name in ("crm", "wiki", "erp", "dashboard"):
        host = profile["erpTenantHost"] if name == "erp" else None
        assert_sso_redirect(f"sso/{name}-redirect", surfaces[name] + "/", auth, host=host)

    if not args.skip_browser:
        ensure_chrome()
        jev_check(
            "render/auth-jev", auth, "Verify the Exe sign-in page visibly shows an Email field and a Sign In button."
        )
    else:
        record("render/auth-jev", "NOT_RUN", "browser checks disabled by --skip-browser")

    if args.with_login:
        credential = profile["credential"]
        login_url = auth + "/?product=Dashboard&redirect=" + urllib.parse.quote(surfaces["dashboard"] + "/", safe="")
        try:
            outcome = login(login_url, credential["service"], credential["account"])
            record(
                "login/central",
                outcome["verdict"],
                f"{outcome['actions']} actions · {outcome['elapsed_ms']} ms",
                final_url=outcome["final_url"],
                actions=outcome["actions"],
                elapsed_ms=outcome["elapsed_ms"],
            )
        except Exception as error:
            record("login/central", "FAIL", f"secure login helper: {type(error).__name__}")
        if RESULTS[-1]["status"] == "PASS":
            account = credential["account"]
            for name, goal in (
                ("dashboard", "Verify the authenticated Exe dashboard visibly shows its application navigation."),
                ("crm", "Verify the signed-in CRM visibly shows the Companies workspace."),
                ("wiki", "Verify the signed-in Wiki visibly shows the Company workspace and Welcome to Exe Wiki."),
                ("erp", "Verify the signed-in ERP Desktop visibly shows Accounting and Stock modules."),
            ):
                jev_check(f"login/{name}-session", surfaces[name], goal, redact=[account], settle_ms=4000)
    else:
        record("login/central", "NOT_RUN", "authenticated checks require --with-login")

    finish()


def finish() -> None:
    counts = {
        status: sum(row["status"] == status for row in RESULTS) for status in ("PASS", "FAIL", "BLOCKED", "NOT_RUN")
    }
    output = HERE / "qa_release_results.json"
    output.write_text(json.dumps({"results": RESULTS, "counts": counts}, indent=2) + "\n")
    print(
        f"=== PASS={counts['PASS']} FAIL={counts['FAIL']} BLOCKED={counts['BLOCKED']} NOT_RUN={counts['NOT_RUN']} ==="
    )
    print(f"results: {output}")
    raise SystemExit(0 if counts["FAIL"] == counts["BLOCKED"] == 0 else 1)


if __name__ == "__main__":
    main()
