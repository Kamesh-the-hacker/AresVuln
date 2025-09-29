box it will perofrom the attacks and tell the attacks
ChatGPT said:
AresVuln — README

AresVuln — GUI-first web vulnerability scanner
Single-box URL scanner: enter a URL, run configured attacks, and get a clear list of findings with evidence.

⚠️ Legal & safety notice: Only scan systems you own or have explicit written permission to test. AresVuln includes simulated and non‑destructive modes — use them for production targets.

What this README describes

This README explains the one‑box GUI flow you asked for: a single input box where a user pastes a URL and clicks Scan. The app will run the selected scan profile (Non‑Destructive, Simulated, or Full Audit) against that URL, enumerate findings, and present attack details and evidence in the UI.

Quick features (single-box workflow)

Single URL input box on the main screen (required fields: Target URL, optional Scope/Allowed Domain).

Scan button (Start / Pause / Stop) beside the box.

Profile selector (Non‑Destructive / Simulated / Full Audit) — defaults to Non‑Destructive.

Live results panel: streaming findings with severity, affected path/parameter, and short remediation.

Evidence viewer: click a finding to open request/response pairs, reproduction steps, and optional screenshot.

Activity & safety checks: pre-scan impact assessment and confirmation dialog when Full Audit is selected.

Export: JSON, CSV, HTML/PDF for each scan.

How it works (user flow)

Open AresVuln GUI.

Paste the target URL into the single input box (e.g., https://app.example.com). Optionally set scope (domain/path regex).



Click Scan.

The scanner crawls the site within scope, extracts parameters, and runs the enabled checks. Findings stream into the results panel as they are discovered.

Click a finding to view detailed evidence and reproduction steps. Use the Export button to save the report.

Typical checks performed (configurable)

Input validation and reflected/stored XSS checks

SQL injection probing (safe vectors in Non‑Destructive; verified payloads only in Full Audit)

Insecure direct object references (IDOR) checks

CSRF presence checks and CSRF token validation

Server/config disclosure (headers, robots, sensitive files)

File upload handling and LFI/RFI probes (limited/disabled in Non‑Destructive)

Authentication flow testing (session fixation, password reset weaknesses)

Custom user rules (YAML/JSON) for app‑specific endpoints

Safety & Authorization

Default mode = Non‑Destructive. Full Audit is opt‑in and requires an uploaded authorization document.

Pre-scan impact check detects potentially destructive endpoints (payment, transaction, delete) and pauses for confirmation.

Rate-limits & concurrency are enforced and configurable to avoid DoS.

Audit logs maintain who ran what scan and when; stores proof of authorization with Full Audit runs.

Example GUI labels & layout (concept)

Top bar: AresVuln logo | Settings | Reports

Main panel (center):

Target URL: [ ____________________________ ] [Scan ▼] [Profile: Non-Destructive ▼]

Right panel: Live Findings (streamed)

Bottom panel: Evidence viewer / Request-Response / Export

Command-line (optional)

For automation, the same scan can be run from CLI:

# non-destructive scan
python aresvuln_cli.py --target https://example.com --profile non-destructive --out results.json

# full audit (requires auth token & confirmation)
python aresvuln_cli.py --target https://example.com --profile full-audit --confirm-destructive --auth /path/to/auth.json

Output formats

results.json — canonical findings with evidence blocks

report.html / report.pdf — human-readable report with remediation guidance

findings.csv — spreadsheet import for trackers



Best practices

Start with Non‑Destructive in production.

Run Full Audits only in staging or after obtaining written authorization.

Attach authorization docs to each target when using Full Audit.

Review rate limits to match target capacity.

Contributing & development

Contributions welcome. When adding checks, declare the safety level (safe/active/destructive) and include tests. Follow code style in ui/README.md and scanner/CONTRIBUTING.md.
