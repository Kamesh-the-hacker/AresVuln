# AresVuln

**AresVuln — Mythic-themed web vulnerability scanner (GUI + CLI)**

AresVuln is a modular, GUI-first web vulnerability scanner built for security teams and developers who want fast discovery and clear results without wrestling with the command line. It bundles a user-friendly desktop/web GUI with the option to run scans from the CLI and in automated pipelines.

> ⚠️ **Important — Authorized testing only.** Always obtain explicit written permission before scanning systems you do not own. AresVuln includes non-destructive and simulated testing modes to reduce risk when assessing production systems.

---

## Overview

AresVuln performs automated discovery and verification of common web application weaknesses (OWASP Top 10 categories) while emphasizing safety, reproducibility, and extensibility. The GUI exposes scan configuration, live progress, evidence viewers, and reporting tools, so findings are easy to triage and export.

---

## Key Features (GUI-focused)

* **Graphical dashboard**: create and manage targets, scopes, and scan profiles.
* **One-click scan**: enter a target URL, choose a scan profile, and start.
* **Scan profiles**: choose from *Non-Destructive*, *Full Audit (with verification)*, and *Simulated* modes.
* **Authentication support**: store session cookies, use form-login flows, or upload session recordings (securely encrypted on disk).
* **Safe mode / Simulation**: run risk-free checks that emulate attacks without sending malicious payloads to production.
* **Live evidence viewer**: view request/response pairs, stack traces, screenshots, and reproduction steps in the UI.
* **Fine-grained controls**: concurrency, rate-limits, timeout, user-agent, and proxy settings.
* **Plugin integration**: enable/disable plugin checks from the GUI.
* **Export & sharing**: export JSON, CSV, PDF/HTML, and create ticket links for trackers.
* **Access control**: role-based access in multi-user deployments.
* **Audit logs & safe-guards**: scan approval workflows, pre-scan impact checks, and destructive-check confirmations.

---

## How to use (GUI)

1. **Open AresVuln** (desktop app or hosted web UI).
2. **Create a new target**: give it a name, base URL, and scope (allowed domains/paths).
3. **Set authentication (optional)**: add session cookies or configure a login flow.
4. **Choose a scan profile**:

   * **Non-Destructive** — discovery + passive checks (safe for production).
   * **Simulated** — emulates exploit attempts without sending real exploit payloads.
   * **Full Audit** — includes active verification checks. *Disabled by default for new targets; requires explicit confirmation.*
5. **Configure limits** (concurrency, rate limit, request timeout) and any proxy settings.
6. **Start scan** — watch live progress, findings stream in the UI, and evidence is recorded.
7. **Review & export** — use built-in filters to triage, add notes, and export reports.

---

## Safety and Ethics (must read)

* **Default scan mode is Non-Destructive.** Active destructive checks are opt-in per target and require a second confirmation.
* **Pre-scan Impact Checks**: AresVuln runs light checks to detect potentially high-impact endpoints (e.g., endpoints with destructive verbs, file uploads, or transaction endpoints) and will pause the scan for manual approval.
* **Legal & Consent**: store proof of authorization (signed scope documents) with each target. The UI prompts for upload of authorization when enabling Full Audit mode.
* **Logging & Data Handling**: scans produce sensitive artifacts (responses, cookies). Reports are encrypted at rest when stored in AresVuln’s workspace.

---

## Quickstart (CLI)

If you prefer the terminal or need to automate scans, the CLI remains available — but destructive checks are still gated behind explicit flags and require a valid authorization token.

```bash
# run a basic (non-destructive) scan from CLI
python aresvuln_cli.py --target https://example.com --profile non-destructive --output results.json

# run a full audit (requires --confirm-destructive and an authorization token)
python aresvuln_cli.py --target https://example.com --profile full-audit --confirm-destructive --auth-token /path/to/auth.json
```

---

## Configuration (config.yaml)

```yaml
ui:
  port: 8080
  workspace_path: ./workspaces/default

scan:
  concurrency: 10
  rate_limit: 20
  timeout: 10
  default_profile: non-destructive

security:
  encrypt_reports: true
  require_target_authorization: true
```

---

## Modules & Plugin System

AresVuln keeps the same modular architecture:

* **crawler/** — URL discovery, sitemap parsing, parameter extraction
* **scanner/** — modular checks; each check advertises whether it is *safe*, *active*, or *destructive*
* **auth/** — browser-driven login recorder, cookie store, OAuth flows
* **reporting/** — UI report renderer and file exporters
* **plugins/** — enable/disable from GUI; plugin manifest must declare safety level

Plugins that implement destructive interactions must declare that and will not be loadable unless the workspace admin enables them.

---

## Reports & Evidence

Reports include a clear severity, suggested remediation, and a reproducible evidence block (requests, responses, screenshots). Sensitive data redaction is supported when exporting.

---

## Best Practices for GUI Scanning

* Start with **Non-Destructive** on production.
* Use **Staging** environments for Full Audit runs.
* Limit concurrency and set rate-limits on live systems.
* Keep authorization documents attached to targets for auditability.

---

## Development & Testing (UI)

* UI is built with React/Electron (or your chosen stack). Follow the code style in `ui/README.md`.
* Run UI tests and end-to-end flows before releasing:

```bash
cd ui && npm install && npm run test
```

---

## Contribution

Contributions welcome. All PRs affecting checks must include tests and an explicit safety classification for the check (*safe*, *active*, *destructive*).

---

## License

MIT License — see `LICENSE` for details.

---

*Last updated: 2025-09-29*
