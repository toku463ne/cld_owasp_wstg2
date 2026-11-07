# CLAUDE.md: OWASP WSTG test runner (web tool)

## Purpose

A web tool for running OWASP WSTG tests against a target.
Automate everything that can be automated. For what must stay manual, show concrete,
per-WSTG steps (exact commands or exact UI operations).

@VISION.md

`VISION.md` is the owner's requirements and the source of truth. **Do not edit it.**
When it is ambiguous or contradictory, ask the owner (or, for small things, pick the
simplest option and tell the owner what was assumed).

## Communication and language

- **Talk to the owner in Japanese.**
- Source code, comments, commit messages, documents, and all web page text are **in English**.

## Predecessor projects (read-only references)

Two earlier projects are linked into this repository as symlinks. Use them to speed up
development; do not modify them.

| Path | What to reuse |
|---|---|
| `cld_owasp_wstg/` | WSTG v4.2 index (`matrix/wstg_tests.yaml`), per-WSTG steps and pass/fail criteria (`matrix/criteria.yaml`), command lines for tools, load/rate-limit notes, CVSS 3.1 calculation (`scripts/cvss31.py`), findings model (`scripts/findings.py`), prompt for AI review, resume/skip logic of bulk runs (`scripts/run_target.py`, `scripts/run_activity.py`) |
| `mine.wstg/` | **Screenshot capture method** (`src/wstg/static/capture.js`, `src/wstg/manual.py`: paste / drop / choose files, multiple images with captions per capture), domain/site project model and evidence reuse, command catalog (`catalog/`), Kali setup script, nginx config |

Rules:
- Never read, copy, or summarize real evidence from them (`evidence/**`, `docs/owasp/evidence/**`, `*.xlsx`, any customer data).
- Adapt code to this project's design; where they conflict with `VISION.md`, `VISION.md` wins.
- Do not import from them at runtime. Copy and adapt what is needed.

## Design summary (from VISION.md)

### Targets
- Two target types: **domain** (e.g. `example.com`) and **FQDN** (e.g. `www.example.com`, a web server).
- An FQDN target normally has a parent domain target and can read the domain's evidence.
- A target selector (list) at the top left of the main page switches the whole UI; a `+` button next to it creates a target.

### Pages
- **Main page** with tabs: WSTG index / Findings / Manual evidence / Automatic evidence.
- **WSTG index**: every WSTG test with summary, link to its WSTG page, link to the official OWASP page, and status (`-`, `started`, `pass`, `fail`).
- **WSTG page**: overview, pass/fail criteria, "AI prompt" button (copies a prompt for an AI chat to judge the results), findings (create button + related findings), and steps. Each step has: summary, verdict select (`-`, `pass`, `fail`), reset button, command line or concrete operation, and evidence.
- **Findings list**: link to detail, link to source WSTG page, CVSS score, updated date.
- **Finding detail / create**: title, status (`open` / `in progress` / `closed`), created / closed dates, summary, impact, reproduction steps, CVSS rationale.
- **Manual evidence**: screenshots, uploaded files, editable text. One fixed evidence ID holds multiple items.
- **Automatic evidence**: a button to collect pre-test evidence. Modes: **full** and **light** (light skips slow or heavy tools such as nikto). An interrupted run resumes: already collected evidence is skipped.

### Evidence model
- Evidence has an **evidence ID** and can be shared by several WSTG tests. Which WSTG uses which evidence is defined per WSTG scenario (data, not ad-hoc code).
- Evidence is editable and shows its collection date. An edit creates a **new version**; the original is kept.
- Each target has a **scope record** (allowed hosts/ports, authorization reference, validity period). Every command is checked against it before running; domain targets run passive commands only.
- No Burp dependency: traffic-based checks use Python HTTP clients, curl, headless-browser HAR recording, and HAR import.

Implementation plan and milestones: [`docs/PLAN.md`](docs/PLAN.md).
- Prefer automation over manual evidence (e.g. extract what Burp history would show automatically when possible).
- Evidence lives **outside the repository** (path set by configuration, e.g. `/srv/wstg2/evidence`). The app refuses to start if the evidence directory resolves inside the repo.
- Folder layout, one folder per target:
  ```
  <evidence dir>/
    example.com/
    www.example.com/
  ```

### System
- Runs on **Kali Linux**. Main program is Python, managed with **uv**. Web framework: **Flask**.
- Served through **nginx on port 8083, plain HTTP** (the Python app listens on loopback only). TLS on 443 comes later, when the tool is opened to everyone.
- Users in **SQLite**, roles **admin** and **guest**.
- Access allowed only from **192.168.0.0/16** by default.

## Invariants (do not break)

- Real evidence and the SQLite database live outside the repository and are never committed.
- The repository never contains customer information: no real domains, host names, IPs, credentials. Use `example.com`, `.test`, and documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in code, tests, and docs.
- Every write endpoint checks the role (guest is read-only) and CSRF on the server side; hiding buttons is only a convenience.
- A missing or failed collection is never a `pass`.
- Automatic collection is resumable and idempotent: completed evidence is skipped, partial output is never treated as complete (write to a temp path, then rename).
- Heavy, noisy, or lockout-prone steps (scanners, brute force, rate-limit tests) are marked and excluded from light mode.
- Severity is computed from the CVSS vector; it is not stored or chosen by hand.

## Safety rules for development

- During development, run commands only against a local test target started on loopback. Do not run scanners (nikto, ffuf, sqlmap, nmap, etc.) against any external host.
- Tests use temporary directories and synthetic fixtures only.
- Never commit secrets.

## How to work

- Keep steps small; write a short plan before larger changes.
- When adding a dependency, prefer the standard library or small, common packages; record the choice.
- Keep the **Commands** section below up to date as the project takes shape.
- **Update `docs/PLAN.md` whenever progress is made**: the Progress table (status, commit), what was delivered, and open items carried forward. Commit it together with the work it describes.

## Commands

Settings come from a KEY=VALUE file outside the repo named by `WSTG_CONFIG`
(example: `docs/examples/wstg2.env.example`; keys are listed in `src/wstg/config.py`).

```bash
export WSTG_CONFIG=~/.config/wstg2/wstg2.env

scripts/setup-kali.sh [--no-packages] [--dry-run]   # set up / update a Kali host (see README.md)

uv sync                                   # install dependencies
uv run wstg check-config                  # show settings; fails if data paths are inside the repo
uv run wstg migrate                       # create data dirs, apply migrations (backs up the DB first)
uv run wstg user-add NAME --role admin    # admin|guest; password from WSTG_NEW_USER_PASSWORD or prompt
uv run wstg user-passwd NAME
uv run wstg user-disable NAME [--enable]
uv run wstg user-list
uv run wstg serve [--dev]                 # web app on 127.0.0.1:$WSTG_APP_PORT (default 5083), behind nginx :8083
uv run wstg catalog-check [-v]            # validate catalog/ (index, evidence, scenarios); needs no config
uv run wstg tools-check [--strict]        # which tools of catalog/tools.yaml are installed; needs no config
uv run wstg tools-check --remote          # tools on the jump host (WSTG_DIRECT_SSH)
uv run wstg worker [--once]               # run queued automatic evidence jobs
uv run wstg collect TARGET [--mode light|full] [--run]
uv run wstg backup [--dest DIR] [--keep 14]

uv run pytest -q                          # tests (temporary directories only)
```

Code layout: `src/wstg/` (`config.py`, `db.py` + `migrations/NNNN_*.sql`, `users.py`,
`web.py`, `web_targets.py`, `web_evidence.py` + `templates/` + `static/`, `cli.py`, `catalog.py`,
`targets.py` (targets, scope check, status), `evidence.py` (versioned store), `runner.py`
(jobs, worker)), catalog data in `catalog/`
(`wstg_index.yaml`, `evidence/*.yaml`, `wstg/WSTG-*.yaml`, `tools.yaml`; schema in `catalog/evidence/core.yaml`
and `src/wstg/catalog.py`), tests in `tests/`, setup in
`scripts/setup-kali.sh` + `deploy/nginx/wstg2.conf.template`.
Schema changes: add a new numbered migration; never edit an applied one.
