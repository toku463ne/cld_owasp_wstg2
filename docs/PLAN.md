# Implementation plan

Requirements: [`VISION.md`](../VISION.md). Working rules: [`CLAUDE.md`](../CLAUDE.md).

## Progress

Last updated: 2026-11-08

| # | Milestone | Status | Notes |
|---|---|---|---|
| M0 | Skeleton | **Done** (`5d9c082`) | 23 tests pass; CLI and waitress server checked by hand |
| M1 | Catalog | **Done** | All 94 WSTG v4.2 scenarios (97 tests, 3 merged); schema and validator; 121 evidence; catalog-check clean |
| M2 | Targets and main page | **Done** | Targets, scope records and check, selector, tabs, WSTG index |
| M3 | WSTG page | **Done** | Overview, criteria, steps, verdict/reset, commands, evidence (view, edit, collected date), findings, AI prompt |
| M4 | Manual evidence | **Done** (browser paste to be checked on Kali) | Versioned store, capture box, upload, text, edit/remove as new versions |
| M5 | Automatic evidence | **Done** (real tools to be checked on Kali) | Jobs, worker, light/full, resume, scope check, cancel, proxy |
| M6 | Findings | **Done** | List, create from WSTG page, detail/edit, status and dates, CVSS 3.1 |
| M7 | AI prompt | **Done** | Criteria, verdicts, commands, evidence excerpts, findings |
| M8 | Deployment | **Done** (checked on Kali) | `scripts/setup-kali.sh`, nginx :8083, user services, backup, test tools from `catalog/tools.yaml` |
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

### M7 delivered
- `src/wstg/prompt.py`: prompt with criteria, notes, steps with verdicts and rendered commands, every referenced evidence (collected date, version, command and exit code, text items and small text files cut at 6000 characters, 60000 in total; screenshots listed by caption; binary files listed), findings already recorded, and the requested answer format (verdicts, impact, reproduction, CVSS vector with rationale). Missing evidence is written as NOT COLLECTED.
- HAR files are never included (cookies and tokens). The button's tooltip reminds the tester to paste only into an AI chat the engagement allows.

### M6 delivered
- Migration `0005_findings`: title, status (open / in progress / closed), summary, impact, reproduction, CVSS vector and rationale, created / updated / closed dates. No severity column.
- `src/wstg/cvss.py`: CVSS v3.1 base score per the FIRST specification (Roundup from Appendix A), checked against calculator values; severity always computed from the vector. `/api/cvss` serves it to the page, so the formula exists once.
- `src/wstg/findings.py` + `web_findings.py`: findings tab (link, source WSTG, status, score and severity, updated; highest score first), create from a WSTG page, detail / edit (admin), closed date set on close and cleared on reopen, audit log with the previous values of changed fields. WSTG page lists the test's findings with a "Create finding" button. Metric selects build the vector and show the score live.

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
- Scope check also treats bare host-like arguments as contacted hosts (fail closed); a test runs every catalog command through a standard scope.
- Open: step verdicts are keyed by step position; reordering steps in a scenario later would move verdicts (add stable step keys if that becomes a problem). Deleting or renaming targets is not offered.

### M1 so far
- `catalog/wstg_index.yaml`: 97 WSTG v4.2 tests with one-line summary, target types (domain: INFO-01; both: INFO-04, CONF-10), OWASP page path checked against the OWASP/wstg v4.2 file list, merged tests (INFO-09, INPV-03, ERRH-02).
- `src/wstg/catalog.py` + `uv run wstg catalog-check [-v]`: loader and validator (unknown keys, duplicates, references, placeholders, domain = passive only, heavy = full + load_note, manual evidence has no command). Placeholders are replaced by name only, so curl globs and `%{http_code}` pass through.
- Evidence: 34 definitions (23 auto, 11 manual) in `catalog/evidence/{core,info,cryp}.yaml`; `ok_exit_codes` for tools that exit non-zero with usable output (wget 8).
- Scenarios: INFO-01 to 08 and 10, CONF-01 to 11, IDNT-01 to 05, CRYP-01 to 04 (29).
- CONF (from cld_owasp_wstg criteria, reworked for automatic evidence): new evidence in `catalog/evidence/conf.yaml`:
  - light: `default-content` (28 default, status, sample, console paths and asset folders, bodies kept), `admin-paths` (25 administrative paths), `backup-files` (30 backup, config, dump, repository names; bodies kept, prompts show file names only), `http-methods` (OPTIONS / and *, TRACE with a marker header, HEAD, unknown method WSTGX, empty POST with and without three method override headers; nothing that changes data).
  - full/heavy: `http-methods-write` (PUT, GET, DELETE, GET of /wstg-put-test.txt), `content-ffuf` and `backup-ffuf` (SecLists common.txt, the latter with 6 backup extensions; WSTG_PAUSE aware).
  - manual: `firewall-rules`, `file-permissions` (from the owner), `subdomain-cnames` (domain; tester's DNS loop).
  - 8 finding kinds (default-content, admin-interface-exposed, http-method-enabled, hsts-missing, cross-domain-policy-permissive, file-permission, subdomain-takeover, cloud-storage-public); `seclists-web-content` in tools.yaml.
  - Auto-run steps read every collected output (port lists, Nikto JSON, page markers, directory listings, repository markers, ffuf results, archived backup names, Allow headers, TRACE echo, HSTS max-age, CNAME chain, unclaimed-resource messages, storage URLs); AI tasks judge each test. Still manual: firewall rules and file permissions from the owner, extension variants and archived files (requests built from earlier results), default credentials, subdomain responses and cloud storage checks (hosts outside the target's scope), writes to storage.
  - curl arguments of the four light evidence and http-methods-write checked against a loopback server.
- IDNT (`catalog/evidence/idnt.yaml`): `auth-pages` (light; 20 login, registration, reset paths plus WordPress REST users and ?author=1, with redirect targets and bodies; ATHN will reuse it); manual `role-definitions`, `role-matrix` (input for ATHZ), `registration-tests`, `provisioning-process`, `enum-tests`. Auto-run: paths per role from the HAR captions (perl, ids normalized to :id, static files dropped; stays out of the prompt), registration and user management links in the crawl, form fields, public user lists, e-mail addresses and naming patterns in pages. AI tasks draft the role matrix and judge each test. 5 finding kinds. Manual on purpose: everything that needs logged-in accounts or the owner (role definitions, registration abuse, disabling an account, enumeration comparisons through forms with CSRF tokens; a curl comparison command is given for simple forms).
- Open: the remaining categories, and checking tool options on Kali (e.g. katana `-ct`). Commands were not run against any host.

### M1 ATHN delivered
- `catalog/evidence/athn.yaml`: two light auto evidence that send no credentials — `login-http` (one plain-HTTP GET per common login/reset/registration path, headers only, "code content-type URL -> redirect" per path, to tell an HTTPS redirect from a form served over HTTP) and `alt-auth-endpoints` (one GET per common API/mobile/legacy login endpoint, presence only, for the ATHN-10 channel comparison); nine manual evidence for the parts that need a test account and send login attempts (default credentials, lockout, bypass, remember-me, cache, password policy, security question, reset, alternative channels), each with the exact capture and the load note.
- Scenarios WSTG-ATHN-01 to 10 (`catalog/wstg/`): auto-run steps read only collected evidence (HTTP-login redirect and form-action scheme for ATHN-01; product fingerprints and installer paths for ATHN-02; CAPTCHA markers for ATHN-03; protected/role paths from the crawl for ATHN-04; autocomplete and password-field attributes for ATHN-05/07; security-question markers for ATHN-08; change/reset entry points for ATHN-09; answering endpoints for ATHN-10). Everything that submits credentials, locks accounts, or needs a logged-in session stays a manual step with a concrete curl/operation and a load note; each test ends with an `ai_task` verdict step.
- 10 finding kinds added to `catalog/finding_kinds.yaml` (credentials-over-http, default-credentials, weak-lockout, authentication-bypass, remember-password-weakness, sensitive-page-cached, weak-password-policy, weak-security-question, weak-password-reset, weaker-alternative-channel).
- `tests/test_athn.py`: ATHN-01 and ATHN-10 auto-run against synthetic evidence (HTTP form served without redirect flagged, dead endpoints dropped), every ATHN page renders. `catalog-check` clean (39 scenarios, 64 evidence); full suite 164 passed.
- Not run against any host; `login-http` and `alt-auth-endpoints` argv (curl `--next` chains) and the manual-step commands still to be checked against a lab target on Kali.

### M1 ATHZ delivered
- `catalog/evidence/athz.yaml`: four manual evidence (traversal-tests, authz-bypass-tests, privilege-escalation-tests, idor-tests). Authorization testing replays requests with each role's session and sends payloads that touch other test users' data, so it cannot be driven blindly by the tool; the role matrix (WSTG-IDNT-01) and the per-role HAR (har-browse) are the inputs, and every active step uses dedicated test accounts and test data with a load note.
- Scenarios WSTG-ATHZ-01 to 04 (`catalog/wstg/`): auto-run steps read only the crawl and collected pages to surface candidates — file-naming parameters for ATHZ-01, admin-like and UI-hidden endpoints for ATHZ-02, role-carrying fields for ATHZ-03, object-reference parameters and numeric path segments for ATHZ-04. The actual replays and payloads are manual steps with concrete curl examples; each test ends with an `ai_task` verdict (ATHZ-01 and ATHZ-03 report their two sub-kinds / directions separately).
- 5 finding kinds added (path-traversal, file-inclusion, authorization-bypass, privilege-escalation, insecure-direct-object-reference).
- `tests/test_athz.py`: ATHZ-01 and ATHZ-04 candidate extraction against synthetic crawl output (file params vs. id= distinguished; numeric references vs. static assets), every ATHZ page renders. `catalog-check` clean (43 scenarios, 68 evidence); full suite 170 passed.
- Not run against any host; the manual-step commands (traversal/IDOR curl, role replays) to be checked against a lab target on Kali.

### M1 SESS delivered
- `catalog/evidence/sess.yaml`: eight manual evidence for the logged-in behaviour that needs a test account (cookie-attr-tests, session-reissue-tests, session-exposure-tests, csrf-tests, logout-tests, timeout-tests, session-puzzling-tests, hijacking-tests), each keeping token values inside evidence. Anonymous cookies and their attributes are reused from `session-token-samples` (cryp.yaml); the login responses come from the per-role HAR (har-browse).
- Scenarios WSTG-SESS-01 to 09 (`catalog/wstg/`): auto-run steps read only collected evidence — anonymous Set-Cookie list with the value masked (SESS-01), a perl check of Secure/HttpOnly/SameSite per anonymous cookie (SESS-02), session id in URLs / client storage / error bodies (SESS-01/04), anti-CSRF token fields in forms (SESS-05), cookie Max-Age/Expires (SESS-07), and transport evidence (SESS-09). All token values are masked in the output. The active, logged-in checks (reissue, logout, timeout, puzzling, hijacking, CSRF replay) are manual steps with concrete curl/operations and load notes; each test ends with an `ai_task` verdict. Cross-links: SESS-01↔CRYP-04 (predictability), SESS-02 (Secure)↔SESS-09, ATHN-06 (back button)↔SESS-06.
- 10 finding kinds added (cookie-missing-httponly, cookie-weak-samesite, cookie-scope-broad, session-fixation, session-token-exposed, csrf, weak-logout, weak-session-timeout, session-puzzling, session-hijacking); SESS-01 reuses the existing predictable-token, SESS-02 reuses cookie-without-secure.
- `tests/test_sess.py`: SESS-01/02/04 auto-run against synthetic cookie and crawl evidence (value always masked, missing attributes flagged per cookie, token in URL and error body found), every SESS page renders. `catalog-check` clean (52 scenarios, 76 evidence); full suite 182 passed.
- Note: a step that references several evidence ids runs its auto-run command only when all are collected (analysis.run marks it "missing" otherwise); SESS reuses this as IDNT-04 does, relying on the light evidence being collected together.
- Not run against any host; the manual-step commands to be checked against a lab target on Kali.

### M1 INPV delivered
- 18 scenarios WSTG-INPV-01 to 19 (`catalog/wstg/`); INPV-03 (HTTP verb tampering) stays merged into CONF-06 and redirects there. Covers reflected/stored XSS, HPP, SQL/LDAP/XML(+XXE)/SSI/XPath/mail/code/command/format-string/template injection, incubated vulnerabilities, HTTP splitting/smuggling, raw-request handling, Host header injection, and SSRF.
- Injection is active and context-specific, so the actual payloads are manual steps with concrete curl/sqlmap/ncat examples against a scoped test target and test data; heavy or disruptive ones carry load notes (sqlmap, request smuggling, oversized raw requests). Auto-run steps read only the crawl to surface candidate inputs (parameter names, form fields, URL-taking/command-building/evaluation/mail/XML parameters, .shtml pages). Each test ends with an `ai_task` verdict; INPV-07 and INPV-15 report their two sub-kinds separately.
- One harmless light auto evidence added, `host-header-probe` (`catalog/evidence/inpv.yaml`): a single GET with a forged Host/X-Forwarded-Host marker; INPV-17 step 1 auto-run greps the saved headers/body for the marker to flag Host-header trust. Passes the standard scope check (the marker is a header value, not a contacted host). The 18 manual evidence are also in inpv.yaml, each keeping retrieved data to a summary and test data removable.
- 20 finding kinds added (reflected-xss, stored-xss, http-parameter-pollution, sql-injection, ldap-injection, xml-injection, xxe, ssi-injection, xpath-injection, mail-injection, code-injection, command-injection, format-string-injection, incubated-vulnerability, http-response-splitting, http-request-smuggling, request-parsing-weakness, host-header-injection, server-side-template-injection, ssrf); INPV-11 also reuses file-inclusion, INPV-16 reuses unprotected-path.
- `tests/test_inpv.py`: INPV-01/19 candidate extraction (parameter vs URL-taking parameter), INPV-17 probe reflection, every INPV page renders, INPV-03 redirects to CONF-06. `catalog-check` clean (70 scenarios, 95 evidence); full suite 204 passed.
- Not run against any host; all injection payloads/commands to be exercised against a lab target on Kali.

### M1 ERRH / BUSL / CLNT / APIT delivered (catalog complete)
- 24 scenarios finish the catalog: ERRH-01 (ERRH-02 merged here), BUSL-01 to 09, CLNT-01 to 13, APIT-01. All 94 WSTG v4.2 scenarios now exist (97 tests, 3 merged: INFO-09→INFO-08, INPV-03→CONF-06, ERRH-02→ERRH-01); `catalog-check` reports 0 tests without a scenario.
- Three new harmless light auto evidence (headers/bodies only, nothing changed): `error-probes` (a few error-triggering GETs; ERRH-01 auto-run greps the bodies for stack-trace/SQL/internal-path markers), `cors-probe` (GET with an untrusted Origin; CLNT-07 auto-run flags a reflected/wildcard/null Origin combined with credentials=true), `graphql-introspection` (a read-only `{__schema{types{name kind}}}` to common endpoints; APIT-01 auto-run reports which bodies expose `__schema`). The two-field innermost selection avoids `{name}` being read as a `{placeholder}`.
- Business logic (BUSL) depends on the application's rules and needs test accounts, so it is manual throughout; CLNT and APIT confirm in the browser/DevTools. Auto-run steps otherwise read only the crawl, `site-assets` (DOM sources/sinks, postMessage, storage, dynamic resource URLs, SWF), and `http-root-https` headers (clickjacking) to surface candidates. Each test ends with an `ai_task` verdict. Load notes on the disruptive ones (BUSL-05/07 repetition, BUSL-09 uploads, APIT-01 deep queries).
- ~44 finding kinds added across ERRH/BUSL/CLNT/APIT; CLNT-01/02 share dom-xss-tests, INPV-11 reuse noted. Per-test manual evidence added in `catalog/evidence/{errh,busl,clnt,apit}.yaml`, each keeping retrieved data to a summary.
- Scope-check refinement (`targets.contacted`): a URL or host inside a `-H`/`--header` value is request content, not a connection target, so it is no longer read as a contacted host (fixed a false positive on `cors-probe`'s untrusted Origin). New test `test_header_values_are_not_treated_as_contacted_hosts`; the connection URL is still checked.
- `tests/test_errh_busl_clnt_apit.py`: ERRH-01 marker scan, CLNT-07 danger/safe CORS branches, CLNT-09 missing frame headers, APIT-01 introspection detection, every page renders. Full suite 234 passed.
- Not run against any host; all probes and manual commands to be exercised against a lab target on Kali.

### Per-test tester annotations: manual status override and tester review (owner request)
- Migration `0010_test_reviews`: one row per (target, test) with `tester_review` (text) and (0010) a `no_need` flag; `0011_status_override` generalises the flag into `status_override` (`''`/started/pass/fail/`no need`) and backfills `no_need = 1` rows to `status_override = 'no need'`. A row with no override and an empty review is removed. Independent of step verdicts and AI reviews, so `Reset test` does not touch them.
- Manual status override (owner asked for the tester to change the status directly): the WSTG page head has a Status dropdown (admin) with `auto (<computed>)`, `started`, `pass`, `fail`, `no need`. `auto` (empty) uses the status computed from the step verdicts; any other value overrides it on the WSTG page and the index (and its count). Step verdicts are always kept, so clearing the override restores the computed status. `no need` is the motivating case (for example WSTG-APIT-01 GraphQL when no GraphQL is used). A fifth status `no need` was added to `tmod.STATUSES`; `tmod.STATUS_OVERRIDES` is the settable set. `targets.set_status_override` / `test_review` / `test_reviews`; invalid values are refused; `POST .../status` (admin).
- Tester review: an optional, editable free-text review per test, shown next to the AI review (`POST .../tester-review`, `targets.set_tester_review`). Admins edit it; guests see it read-only. Kept when the status override changes.
- UI: a `statusclass` Jinja filter maps a status to its CSS class (handles the space in "no need"); `.status.s-noneed` style added. Both new endpoints are admin-only and reject merged or unknown tests.
- Tests in `tests/test_web_targets.py` (override to any status on page and index, invalid refused, clear back to auto, tester review persistence and guest read-only, row removal, admin-only, merged/unknown rejected) and `test_header_values_...`; full suite 237 passed.
- Note: this extends the VISION status set (`-`, started, pass, fail) with `no need` and lets the tester override the computed status, at the owner's explicit request.

### M8 (pulled forward) delivered
- `scripts/setup-kali.sh`: apt base packages, uv, data dirs (`/srv/wstg2/{evidence,db}`), config file and secret key generated once, `uv sync`, `check-config`, `migrate`, first admin, systemd user service `wstg2-web` (restarted on every run, lingering), nginx site rendered from `deploy/nginx/wstg2.conf.template` (port and allow list from the config), `nginx -t` with rollback, smoke test. Options `--no-packages`, `--no-nginx`, `--no-systemd`, `--dry-run`. Rerun after `git pull` to update a Kali host.
- New config key `WSTG_WEB_PORT` (default 8083), read by the setup script only.
- `README.md` with setup, update, configuration, and uninstall steps.
- Checked on WSL: dry run, real run into a scratch directory (`--no-nginx --no-systemd`), rerun keeps config/secret/users, rendered nginx site passes `nginx -t`.
- Checked on Kali (2026-11-07): full run with nginx and the `wstg2-web` user service; smoke test returns 200 on 5083 and 8083.
- Fixed on Kali: smoke test hung (curl without timeout, through the user's proxy) → `--noproxy '*'` and timeouts, progress output, service log on failure; exit 143 on restart counted as normal (`SuccessExitStatus=143`).
- Config, data, service, and nginx names use the `wstg2` prefix so mine.wstg can run on the same host.
- Test tools: `catalog/tools.yaml` (command, apt or npm package); `catalog-check` fails when an automatic evidence command is not listed. `wstg tools-check [--packages apt|npm] [--strict]`. The setup script installs them (apt, retried one by one on failure; npm into `~/.local` through `WSTG_HTTP_PROXY`) and prints the check. User units put `~/.local/bin` on PATH.
- Proxy (from a Kali check: `openssl s_client` timed out behind the proxy): evidence `proxy_args` replace the argv element `{proxy_args}` only when `WSTG_HTTP_PROXY` is set (`{proxy_url}`, `{proxy_hostport}`); the scope check runs without them; credentials in the proxy URL are masked in the recorded command. `direct: true` marks tools that cannot use a proxy (whois, traceroute, nmap, sslscan); their failure message says so.
- Evidence page: a missing tool or refused command creates no version, so the page shows the last job attempt (status and message).
- AI review import (`src/wstg/ai_review.py`, migration 0006 `ai_reviews`): the AI prompt now ends with a `{"wstg_review": ...}` JSON template; the WSTG page has "Import an AI answer" (admin, CSRF). Rules: "-" leaves a step unchanged; a pass is refused when the step's evidence is missing or failed; tester verdicts are kept unless "Overwrite" is ticked; applied verdicts are recorded as `ai:<user>` (shown as an "AI" chip); each import is stored with per-step outcome and reason, shown under each step.
- Load control as in cld_owasp_wstg: `WSTG_PAUSE` (seconds, 0..60) adds `pause_args` (nikto `-Pause N`, ffuf `-p N -t 1`, katana `-delay N -c 1 -p 1`); without it nikto runs at full speed and ffuf at ffuf's default threads with `-rate 50`. nikto has `-maxtime 235m` and a 4-hour timeout; `incomplete_if` marks a run cut short by `-maxtime` as failed (cld_owasp_wstg used `-maxtime 30m` and kept partial results; here a partial result is never complete). Tools run one at a time.
- WSTG-INFO-05 reworked (9 steps): machines read every collected page and script and the AI review sorts the hits. katana-crawl keeps every response (`-sr -srd {out}/responses`, no extra requests); gitleaks (`detect --no-git --redact`, new in tools.yaml, allowed in auto-run as a file scanner only) finds secrets in the top page and scripts, in the crawl, and in the HAR response bodies (extracted with perl JSON::PP); grep keeps internal hosts, private addresses, and developer notes; a script endpoint list; AI tasks triage each output. HAR-derived output stays out of the AI prompt. The browser review is reduced to screens missing from the HAR and DOM built by JavaScript.
- Fixed: commands read manual evidence at `{ev:ID}/*.har`, but manual files are stored under `items/`; every HAR command (CRYP-02/03/04, INFO-05/06/07/08) now reads `{ev:har-browse}/items/*.har`, and catalog-check refuses manual evidence paths outside `items/`.
- Per-evidence collection: *Collect* / *Collect again* on each automatic evidence row and on the evidence page (`wstg collect --evidence ID [--force]`); migration 0009 adds `jobs.evidence_id` and `jobs.force`; the job's mode is the evidence's level; heavy evidence asks for confirmation.
- Failed collections: the evidence page shows the newest failed version right away (command, jump host, exit code, duration, message, last 200 lines of stdout/stderr, link to all files); the job table links failed and stopped items to their version ("log"), and the evidence list links "failed" to that block.
- WSTG index: evidence column per test (collected/total, complete / partial / none, missing IDs on hover, "prompt saved") and totals. *Save AI prompts* (and `wstg ai-prompts`) take `evidence` (complete = default, any, all) and `existing` (skip = default, overwrite).
- WSTG page *Reset test* (admin, confirm): removes the test's step verdicts and imported AI reviews (audit `test.reset` with counts); evidence, findings, and `_ai` files are kept.
- Duplicate findings: `catalog/finding_kinds.yaml` (27 kinds, each with a subject format); scenarios list theirs (`finding_kinds:`). Migration 0008 adds `findings.kind` / `subject` with a unique index per target (subject normalized: lower case, single spaces), so the same problem is one finding across tests; the finding form has kind and subject and links to the existing finding on a duplicate. AI answers give kind, subject, and `same_as` (an existing finding id); a proposal is not created when same_as, kind+subject, or (no kind) the title on the test matches. The AI chat prompt lists the test's findings (with #id, kind, subject); prompt files for an agent list all findings of the target.
- AI files and findings (`src/wstg/ai_files.py`): prompts saved to `<evidence>/<target>/_ai/prompts/WSTG-*.md` (WSTG page *Save AI prompt*, WSTG index *Save all AI prompts*, `wstg ai-prompts`), with the evidence folder paths and the answer path for an agent, and `_ai/README.md` with the agent's instructions. `_ai/answers/WSTG-*.json` are imported in bulk (WSTG index *Import AI answers*, `wstg ai-import`); an answer identical to the last import is skipped. The review JSON has `findings` (title, steps, summary, impact, reproduction, CVSS vector, rationale; an invalid vector is dropped with a note); the WSTG page lists them with *Create finding*, and import can create them all; created by `ai:<user>`, never twice per title and test. The step/prompt building moved from the WSTG page route to `ai_files.steps_for` / `build_prompt` so the CLI uses the same code.
- Manual work reduced (survey of all 13 scenarios):
  - `auto_run: true` (`src/wstg/analysis.py`): 36 analysis commands that only read collected evidence (grep, jq, sed, perl, `openssl x509`...) run by the tool when the WSTG page opens; the output is shown under the step and goes into the AI prompt. `catalog-check` refuses programs outside a local-only allowlist (no curl, dig, loops). Cached per target in `<evidence>/<target>/.analysis/`, keyed by the command and the evidence versions; 30 s timeout, 256 KB cap. Commands that wait for manual evidence (HAR) say so.
  - AI prompt: HAR files are summarized without values (method, URL with parameter names, status, type, body field names, cookie names, Set-Cookie flags); outputs of auto-run commands that read HAR files stay out of the prompt.
  - New automatic evidence: `tls-versions-curl` (CRYP-01 step 6, one curl with `--next` per TLS version, replaces the shell loop) and `session-token-samples` (ten anonymous responses; CRYP-04 step 2 predictability, judged by the AI).
  - CRYP-02 step 2 and CRYP-04 step 3: a perl decoder reports name, encoding, decoded length, block multiple, readable share, and repeated 16-byte blocks (ECB) of anonymous cookies and hidden fields, without values. Logged-in values from the HAR are still decoded by hand (operation).
  - AI tasks that draft what the tester used to write: INFO-04 step 6 (purpose of hosts and ports), INFO-06 step 7 (entry point inventory), INFO-07 step 5 (flow map), INFO-10 step 6 (architecture). The tester checks the draft and saves it as the manual evidence.
  - Still manual, on purpose: search engine dorks (INFO-01; scraping breaks the search engines' terms), browser walkthroughs and HAR capture, Wappalyzer, logged-in page source review, padding oracle probes and padbuster (CRYP-02, needs agreement on request counts), crypto design review (CRYP-04), external all-port scan, other TLS ports, and commands that chain results of earlier steps into requests to the target (robots/sitemap paths, hidden paths, source maps, vhost ports).
- Scenario steps can have `ai_task`: the step is judged by the AI review (the task goes into the AI prompt as "YOUR TASK for this step"; the page says so). WSTG-INFO-02 now judges version disclosure (steps 1 to 3) and known CVEs (step 4, AI task, replaces the NVD curl lookup) separately, with separate findings; WSTG-INFO-08 has an AI task step for framework/CMS CVEs.
- Stop on load: the running row of a job has **Stop** (migration 0007 `jobs.stop_seq`; the worker checks every 2 s, kills that command, local or on the jump host, records it as cancelled with a failed version, and goes on with the next item); the job-wide button is now **Stop job** (with a confirm). Stopped evidence is retried on the next Collect.
- CLI reads `~/.config/wstg2/wstg2.env` when `WSTG_CONFIG` is unset (found on Kali: `tools-check --remote` failed with "WSTG_EVIDENCE_ROOT is not set").
- Jump host (`WSTG_DIRECT_SSH`, key auth, `BatchMode`, strict host keys): `direct` evidence (whois, traceroute, nmap, sslscan) runs there over SSH in a `mktemp` folder with `timeout`; output files come back with tar (safe extraction), the folder is removed, cancel/timeout kill the remote process. `wstg tools-check --remote`. New `dns-rdap` evidence (RDAP over HTTPS through the proxy) in INFO-01 step 1.

### Open items carried forward
- Check on Kali: katana `-sr -srd` (store responses) and the responses folder layout; gitleaks package and `detect --no-git --redact --report-format json` output fields (RuleID, File, StartLine, Match); the jump host (Ubuntu 24.04) with real whois/traceroute/nmap/sslscan; RDAP for the target's TLD; the proxy options of each tool (openssl, testssl, whatweb, nikto, ffuf, katana, subfinder, wafw00f) behind the real proxy; Kali package names in `catalog/tools.yaml` (katana, padbuster, theharvester); browser clipboard paste into the capture box, the worker with real tools against a lab target (tool options such as katana `-ct`), backup.
- M1 is complete (all 94 scenarios). Remaining catalog work is refinement against real lab targets, not new categories.
- Check on Kali: the new light probes against a lab target — `error-probes` (does `%c0%ae%c0%ae/` reach the server cleanly), `cors-probe` (CORS headers on `/` and `/api`), `graphql-introspection` (endpoints and the introspection response), `host-header-probe` (reflection) — and the many manual injection/logic commands.
- Check on Kali: the ATHN `login-http` and `alt-auth-endpoints` curl `--next` chains against a lab target, and the manual-step commands (force browsing, cache-header loop, enumeration curl).
- Check on Kali: the CONF evidence against a lab target (content-ffuf and backup-ffuf run time, Nikto JSON layout read by `jq '.. | objects | select(has("msg"))'`).
- M9: headless-browser HAR recording (needs a decision on adding Playwright and a browser), HAR analysis (cookies, headers, parameters) to replace manual Burp checks.
- Backup frequency is the owner's decision; `--backup-timer` installs a daily one only when asked. Evidence is copied with rsync (versions never change).
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
