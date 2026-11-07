# Implementation plan

Requirements: [`VISION.md`](../VISION.md). Working rules: [`CLAUDE.md`](../CLAUDE.md).

## Progress

Last updated: 2026-11-07

| # | Milestone | Status | Notes |
|---|---|---|---|
| M0 | Skeleton | **Done** (`5d9c082`) | 23 tests pass; CLI and waitress server checked by hand |
| M1 | Catalog | **In progress** | Index (97), schema and validator, INFO + CRYP scenarios; CONF pending |
| M2 | Targets and main page | **Done** | Targets, scope records and check, selector, tabs, WSTG index |
| M3 | WSTG page | **In progress** | Overview, criteria, steps, verdict/reset, rendered commands, AI prompt (basic); evidence view/edit with M4/M5 |
| M4 | Manual evidence | **Done** (browser paste to be checked on Kali) | Versioned store, capture box, upload, text, edit/remove as new versions |
| M5 | Automatic evidence | **Done** (real tools to be checked on Kali) | Jobs, worker, light/full, resume, scope check, cancel, proxy |
| M6 | Findings | Not started | |
| M7 | AI prompt | Not started | |
| M8 | Deployment | **Partly done** (setup script, checked on Kali) | `scripts/setup-kali.sh`, nginx :8083, `wstg2-web` user service; worker unit and backup pending |
| M9 | More automation | Not started | |

### M0 delivered
- uv project (`src/wstg/`), Python 3.12, Flask + waitress, pytest.
- Config from `WSTG_CONFIG` outside the repo; refuses config, evidence, or DB paths inside the repo (symlinks resolved).
- SQLite with numbered migrations (`src/wstg/migrations/`), backup before migrating an existing schema, rollback on failure.
- Users: admin / guest, 12+ character passwords, last active admin cannot be disabled, audit log.
- Web: login/logout, CSRF on every POST (login included), server-side role checks, client network allowlist (default 192.168.0.0/16 + loopback), security headers (CSP, X-Frame-Options), open-redirect guard.
- Main page shell (target selector + `+`, four tabs, all placeholders); admin user page.
- CLI: `check-config`, `migrate`, `user-add`, `user-passwd`, `user-disable`, `user-list`, `serve`.
- Fixed during smoke test: waitress dropped nginx's `X-Forwarded-For` by default, which would have made every client look like 127.0.0.1.

### M5 delivered
- Migration `0004_jobs`: `jobs` (queued / running / cancelling / done / cancelled / interrupted, heartbeat) and `job_items` (pending / running / skipped / complete / failed / refused / cancelled).
- `src/wstg/runner.py`: plan (automatic evidence of the target's type; light skips `level: full`; heavy last), one active job per target, worker that runs one job at a time. Per command: render placeholders (`{out}` = temp folder of the new version), refuse unfilled placeholders, `check_command` against the scope record, no shell, no stdin, own process group, timeout, 200 MB stdout cap, cancel while running (kills the process group). Complete only when the exit code is in `ok_exit_codes` and every declared output exists; otherwise a failed version is kept for review but never becomes `latest`, and is retried next time. Completed evidence is skipped (resume). On start the worker marks jobs of a dead worker as interrupted and removes temp folders.
- Commands get a clean environment (PATH, HOME, LANG, ...); `WSTG_HTTP_PROXY` sets http(s)_proxy for them; proxies from the worker's own environment are dropped.
- CLI: `wstg worker [--once]`, `wstg collect TARGET [--mode] [--run]`. Setup script installs `wstg2-worker` next to `wstg2-web`.
- Automatic evidence tab: light / full collect, job progress (refreshes every 5 s), cancel, per-evidence collected / failed state, worker hints (waiting, stalled). Evidence page shows the command that ran, exit code, duration, and failed versions.
- Editing a text item keeps its file name, so `{ev:ID}/stdout.txt` stays valid after an edit.
- Not yet checked: the real catalog tools against a lab target on Kali (tests use local harmless commands only).

### M4 delivered
- Migration `0003_evidence`: `evidence_versions` index (source manual / auto / edit, status complete / failed, item count).
- `src/wstg/evidence.py` store: `<root>/<target>/<evidence id>/v0001/` with `meta.json` and `items/`; every change (add images / file / text, edit caption or text, remove) writes a full new version; unchanged files are hard links; temp folder + fsync + rename under the DB write lock; `latest` symlink replaced atomically, only for complete versions; an indexing failure moves the folder back and removes it.
- Web (`src/wstg/web_evidence.py`): evidence page with version banner and history, capture box adapted from mine.wstg (`static/capture.js`: paste / drop / choose, several images with captions, one version per save), file upload, text, edit and remove. Domain evidence opened from an FQDN target redirects to the domain target; writes go to the owner only.
- Serving: only PNG/JPEG (checked by magic bytes on upload) and text are shown inline; everything else is a download (`application/octet-stream`, attachment) with a sandbox CSP, so uploaded HTML/SVG never runs in the tool's origin.
- The WSTG index counts collected evidence (status `started`); the WSTG page and the manual evidence tab show collected date, version, and item count.
- Not yet checked in a real browser: clipboard paste into the capture box (only the upload path was tested with curl).

### M2 delivered (and M3 so far)
- Migration `0002_targets`: `targets` (domain / FQDN, parent), `scopes` (allowed hosts and ports, base URL, authorization reference, validity period), `step_verdicts` (no row = `-`).
- `src/wstg/targets.py`: host name validation (FQDN must be under its parent), default scope (target host, ports 80/443, not usable until authorization and dates are set), `check_command` (extracts hosts and ports from the rendered argv; refuses unknown hosts, ports, expired or unauthorized scope; domain targets passive only), WSTG status, verdicts with audit log.
- Web (`src/wstg/web_targets.py`): `/t/<target>/...` pages, target selector with `+` (admin), WSTG index (tests for the target type, status, WSTG page link, OWASP link), settings and scope page, automatic evidence tab (definitions only), WSTG page (overview, pass/fail, notes, steps with verdict select and reset, commands with placeholders and `{ev:ID}` filled in, copy buttons, evidence list with sharing, AI prompt copy). Merged tests redirect to the test they were merged into.
- Clipboard copy falls back to `execCommand` because `navigator.clipboard` needs HTTPS and the tool runs on plain HTTP for now.
- Evidence folders: `<evidence root>/<target>/` created with the target; `{ev:ID}` points to `<evidence root>/<owner>/<ID>/latest` (owner = the target, or its parent domain for domain evidence). The `latest` link is created by M4/M5.
- Open: step verdicts are keyed by step position; reordering steps in a scenario later would move verdicts (add stable step keys if that becomes a problem). Deleting or renaming targets is not offered.

### M1 so far
- `catalog/wstg_index.yaml`: 97 WSTG v4.2 tests with one-line summary, target types (domain: INFO-01; both: INFO-04, CONF-10), OWASP page path checked against the OWASP/wstg v4.2 file list, merged tests (INFO-09, INPV-03, ERRH-02).
- `src/wstg/catalog.py` + `uv run wstg catalog-check [-v]`: loader and validator (unknown keys, duplicates, references, placeholders, domain = passive only, heavy = full + load_note, manual evidence has no command). Placeholders are replaced by name only, so curl globs and `%{http_code}` pass through.
- Evidence: 34 definitions (23 auto, 11 manual) in `catalog/evidence/{core,info,cryp}.yaml`; `ok_exit_codes` for tools that exit non-zero with usable output (wget 8).
- Scenarios: INFO-01 to 08 and 10, CRYP-01 to 04 (13).
- Open: CONF-01 to 11 (writing was interrupted; resume later, possibly alongside M3), the remaining categories, and checking tool options on Kali (e.g. katana `-ct`). Commands were not run against any host.

### M8 (pulled forward) delivered
- `scripts/setup-kali.sh`: apt base packages, uv, data dirs (`/srv/wstg2/{evidence,db}`), config file and secret key generated once, `uv sync`, `check-config`, `migrate`, first admin, systemd user service `wstg2-web` (restarted on every run, lingering), nginx site rendered from `deploy/nginx/wstg2.conf.template` (port and allow list from the config), `nginx -t` with rollback, smoke test. Options `--no-packages`, `--no-nginx`, `--no-systemd`, `--dry-run`. Rerun after `git pull` to update a Kali host.
- New config key `WSTG_WEB_PORT` (default 8083), read by the setup script only.
- `README.md` with setup, update, configuration, and uninstall steps.
- Checked on WSL: dry run, real run into a scratch directory (`--no-nginx --no-systemd`), rerun keeps config/secret/users, rendered nginx site passes `nginx -t`.
- Checked on Kali (2026-11-07): full run with nginx and the `wstg2-web` user service; smoke test returns 200 on 5083 and 8083.
- Fixed on Kali: smoke test hung (curl without timeout, through the user's proxy) → `--noproxy '*'` and timeouts, progress output, service log on failure; exit 143 on restart counted as normal (`SuccessExitStatus=143`).
- Config, data, service, and nginx names use the `wstg2` prefix so mine.wstg can run on the same host.

### Open items carried forward
- M8 remainder: worker unit (with M5), backup timer.
- Login rate limiting is not implemented yet (consider in M8, or rely on nginx `limit_req`).
- Session cookie is not `Secure` while the tool runs on plain HTTP (8083). Turn it on when moving to TLS on 443.
- UI title is provisional ("WSTG Runner").

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
| Catalog format | YAML (PyYAML, the only new dependency). Evidence commands are argv lists (no shell); analysis commands shown to the tester may use a shell and refer to collected evidence as `{ev:ID}` |
| Host names (config, data, service, nginx site) | `wstg2` prefix (`~/.config/wstg2/wstg2.env`, `/srv/wstg2`, `wstg2-web`, `wstg2.conf`) so the predecessor mine.wstg (`wstg`) can run on the same Kali host |
