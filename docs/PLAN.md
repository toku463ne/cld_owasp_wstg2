# Implementation plan

Requirements: [`VISION.md`](../VISION.md). Working rules: [`CLAUDE.md`](../CLAUDE.md).

## Architecture

### Storage split
- **SQLite** (outside the repo): users, targets, scope records, per-step verdicts, findings, evidence index (relative path, SHA-256, collected date, version), jobs.
- **Evidence files** (outside the repo): `<evidence_dir>/<target>/<evidence_id>/<version>/...`
  - Each collection or edit creates a new version folder. Originals are never overwritten.
  - A version folder is written to a temp path and renamed when complete.
- **Catalog** (in the repo, YAML, English):
  - `catalog/evidence/*.yaml`: evidence definitions. ID, target type (`domain` / `fqdn`), `auto` / `manual`, level (`light` / `full`), command, output files, load note.
  - `catalog/wstg/WSTG-*.yaml`: per-WSTG scenario. Overview, pass/fail criteria, steps (summary, command or concrete operation, referenced evidence IDs).
  - Evidence is defined once and referenced by several WSTG scenarios. This replaces the predecessor's commands embedded in step text.

### WSTG status
- `-`: no step verdict and no evidence
- `started`: at least one step verdict or evidence
- `fail`: at least one step is `fail`
- `pass`: every step is `pass`

### Runtime
- Flask app on 127.0.0.1, behind nginx on **HTTP port 8083** with `allow 192.168.0.0/16; deny all;`.
  - Later, when the tool is opened to everyone: DNS name, TLS certificate, port 443.
- A separate worker process runs queued jobs (automatic evidence) from a SQLite table.
- Both run as systemd user services on Kali.

### Scope
- Each target has a **scope record**: allowed hosts and ports, authorization reference, validity period.
- Every command is checked against the scope before it runs. Out of scope or expired → refused.
- Domain targets run passive commands only (DNS, whois, CT logs, search engines).

### Traffic capture (replacing the Burp history checks)
- No Burp dependency. Use Python HTTP libraries and curl.
  - Unauthenticated crawl and per-request checks (headers, cookies, methods, redirects, error pages): Python HTTP client + curl.
  - Login flows and JavaScript-heavy pages: a headless browser driven from Python, recording a HAR.
  - Manual browsing by the tester: HAR exported from the browser and imported (manual evidence), parsed automatically.
- ngrep only sees plaintext HTTP, so it is not used for HTTPS targets.
- Details are settled in M9.

## Milestones

| # | Scope | Reuse from |
|---|---|---|
| **M0 Skeleton** | uv project (`src/` layout), Flask app factory, config file outside the repo (refuse to start if evidence/DB resolve inside the repo), SQLite schema with migrations, admin/guest login, CSRF, pytest, CLI (`uv run wstg ...`) | mine.wstg config/users |
| **M1 Catalog** | Import the WSTG v4.2 index (97 tests), catalog schema and validation, translate and split `criteria.yaml` into evidence definitions and scenarios. Start with INFO/CONF/CRYP; translate the rest alongside later milestones | cld_owasp_wstg matrix |
| **M2 Targets and main page** | Target selector with `+`, domain/FQDN parent link, scope records, four tabs, WSTG index (status, link to WSTG page, link to OWASP page) | mine.wstg projects |
| **M3 WSTG page** | Overview, criteria, per-step verdict / reset / command, evidence display and edit (new version, collected date), FQDN reads parent domain evidence | — |
| **M4 Manual evidence** | Fixed evidence ID with multiple images / files / text; paste and drop capture | mine.wstg capture.js, manual.py |
| **M5 Automatic evidence** | Collect button, full/light modes, skip completed evidence (resume), scope check, progress view, proxy setting, load notes | cld_owasp_wstg run_target, mine.wstg runner |
| **M6 Findings** | List, detail/create, status and dates, CVSS 3.1 calculation (severity computed, not stored) | cld_owasp_wstg cvss31.py, findings.py |
| **M7 AI prompt** | Copy criteria, step verdicts, and evidence excerpts to the clipboard | cld_owasp_wstg prompt |
| **M8 Deployment** | `setup-kali.sh`, nginx config (8083), systemd units, backup | mine.wstg setup-kali.sh |
| **M9 More automation** | Traffic capture (see above) to reduce manual evidence | — |

M0–M3 give a minimal tool where tests can be viewed and judged. M4–M6 make it usable for real tests.

## Decisions

| Topic | Decision |
|---|---|
| Web framework | Flask |
| Evidence location | Outside the repository |
| nginx | HTTP on 8083 for now; TLS on 443 when opened to everyone |
| Evidence edits | Keep the original; each edit is a new version |
| Burp history | Replace with Python HTTP client, curl, headless browser HAR, HAR import |
| Scope records | Required; every command is checked |
