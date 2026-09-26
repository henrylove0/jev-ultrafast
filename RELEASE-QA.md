# Release QA — Exe production

The harness separates artifact checks from live checks. An image publish is not a live deployment. Run `--phase live` only with evidence captured from the running containers; otherwise the runner reports `BLOCKED` instead of certifying an older release.

```bash
cd /Users/exeai/henrykun/tools/jev-ultrafast
uv run --env-file .env python qa_release.py \
  --profile profiles/production.json \
  --phase live \
  --deployment-evidence /path/to/observed-deployment.json
```

The evidence file is local and must describe each surface under `observedDeployed` with `observedAt` and at least one of `image`, `source`, or `version`. Capture it from the live runtime after deployment. Do not derive it from the desired manifest.

Use `--phase artifact` for a local preview or published artifact before deployment. That result must be labeled artifact QA and cannot close the live gate.

The production profile fixes the five public hosts and Frappe tenant host `erp.askexe.com`. The free HTTP phase asserts exact health response types and bodies, then asserts unauthenticated app roots redirect to `auth.askexe.com` with a return URL for the same app host. The auth SPA's `/health` fallback is deliberately not treated as GoTrue health.

Browser assertions use the dedicated Chrome profile and CDP port 9333. Each Jev run contains one visible assertion. A Jev `done` result proves only that visible assertion; HTTP routing and deployment evidence are separate gates.

For the approved cohort login flow:

```bash
uv run --env-file .env python qa_release.py \
  --phase live --deployment-evidence /path/to/observed-deployment.json --with-login
```

The helper reads `e2e@askexe.com` from macOS Keychain service `exe-e2e-credential`, fills observed browser fields directly, and never places the password in argv, logs, goals, screenshots, or model payloads. The account identifier is redacted from model-visible page state. One central login is reused across Dashboard, CRM, Wiki, and ERP.

Results distinguish `PASS`, `FAIL`, `BLOCKED`, and `NOT_RUN`, with actions, final URL, and elapsed time for each Jev run. Do not loop on a billable failure.
