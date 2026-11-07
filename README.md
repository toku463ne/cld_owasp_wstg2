# WSTG Runner

A web tool for running [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/)
tests against a target. Everything that can be automated is automated; for what must stay
manual, each WSTG test shows concrete steps (exact commands or UI operations).

Status: early development. See [`docs/PLAN.md`](docs/PLAN.md) for milestones and progress.
Requirements: [`VISION.md`](VISION.md).

## Layout

```
Browser (192.168.0.0/16) --HTTP :8083--> nginx --> 127.0.0.1:5083 wstg serve (Flask + waitress)
                                                        |
                                 config  ~/.config/wstg2/wstg2.env, secret_key   (mode 600)
                                 data    /srv/wstg2/evidence/<target>/...
                                         /srv/wstg2/db/wstg2.sqlite3
```

The config file, evidence, and database live **outside the repository**. The app refuses
to start if any of them resolves inside it.

## Setup on Kali

Run as the normal user that will own the evidence (not root; `sudo` is used where needed).

```bash
git clone <this repository> ~/cld_owasp_wstg2 && cd ~/cld_owasp_wstg2
scripts/setup-kali.sh
```

The script is safe to run again. It:

1. installs base packages (`git curl openssl python3 pipx sqlite3 nginx`) and `uv`,
2. creates `/srv/wstg2/evidence` and `/srv/wstg2/db` (mode 700),
3. writes `~/.config/wstg2/wstg2.env` and a random `secret_key` if missing (existing ones are kept),
4. runs `uv sync`, then installs the test tools listed in `catalog/tools.yaml` (apt: nikto,
   nmap, sslscan, testssl.sh, whatweb, ffuf, katana, seclists, ...; npm into `~/.local`:
   retire) and prints `wstg tools-check`; then `wstg check-config`, `wstg migrate`,
5. asks for the first admin password if no user exists (12+ characters),
6. installs and restarts the systemd **user** services `wstg2-web` (web app) and `wstg2-worker`
   (automatic evidence jobs), with lingering,
7. renders `deploy/nginx/wstg2.conf.template` into `/etc/nginx/sites-available/wstg2.conf`
   (port and allowed networks from the config file), checks it with `nginx -t`, reloads nginx,
8. checks `http://127.0.0.1:5083/login` and `http://127.0.0.1:8083/login`.

Then open `http://<kali address>:8083/` from a PC in 192.168.0.0/16 and log in.

Options:

| Option | Effect |
|---|---|
| `--data-dir DIR` | data root (default `/srv/wstg2`) |
| `--config FILE` | config file (default `~/.config/wstg2/wstg2.env`) |
| `--admin NAME` | first admin user name (default `admin`) |
| `--no-packages` | skip apt and npm (base packages and test tools); `tools-check` still reports what is missing |
| `--no-nginx` | skip the nginx site |
| `--no-systemd` | skip the user services; run `uv run wstg serve` and `uv run wstg worker` yourself |
| `--backup-timer` | also install a daily database backup (`wstg backup`, keeps 14) |
| `--dry-run` | print what would be done, including the rendered nginx site |

Without a terminal (for example over a non-interactive SSH command), set
`WSTG_NEW_USER_PASSWORD` for the first admin, or add the user later.

## Updating a Kali host during development

```bash
cd ~/cld_owasp_wstg2
git pull
scripts/setup-kali.sh --no-packages     # sync deps, migrate, restart wstg2-web, re-render nginx
uv run wstg tools-check                 # which test tools are installed
```

When `catalog/tools.yaml` gains a tool, run `scripts/setup-kali.sh` without `--no-packages`.

Check it:

```bash
systemctl --user status wstg2-web wstg2-worker
journalctl --user -u wstg2-web -u wstg2-worker -f
curl -s --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8083/login   # expect 200
```

## Using it

1. **+** next to the target list: create a **domain** target (`example.com`), then **FQDN** targets
   (`www.example.com`) with the domain as parent.
2. **Settings and scope**: enter the authorization reference and the validity period, and check
   the allowed hosts and ports. Until then every command is refused.
3. **Automatic evidence** tab: *Collect* in light mode first, full mode when heavy tools are agreed.
   Collecting again skips what is already collected.
   Each row also has *Collect* (only that evidence) or *Collect again* (a new version; earlier ones
   are kept), as does the evidence page.
4. **WSTG index**: open a test, follow the steps, set each step's verdict, add screenshots and
   files on the evidence pages, and copy the AI prompt when you want a second opinion.
   *Reset test* clears every step verdict and the imported AI reviews of that test; evidence and
   findings are kept.
   Analysis commands that only read collected evidence run by themselves; their output is shown
   under the step. Steps marked *Judged by the AI review* (known CVEs, inventories, drafts) are
   answered by the AI prompt.
5. **AI review**: paste the AI chat's whole answer into *Import an AI answer* on the WSTG page. The
   JSON block at its end sets the step verdicts: a pass is refused when the step's evidence is
   missing or failed, "-" changes nothing, and verdicts you set yourself are kept unless
   *Overwrite verdicts set by a tester* is ticked. Each step shows the AI's verdict and reason.
   Findings the AI proposes are listed there with a *Create finding* button (or tick *Also create
   the findings the AI proposes*). Duplicates are not created: each finding has a **kind**
   (`catalog/finding_kinds.yaml`) and a **subject**, and a target has one finding per kind and
   subject across all tests; the AI can also point to an existing finding (`same_as`). Without a
   kind, the same title on the same test counts as a duplicate. The AI chat prompt lists the
   findings of that test; prompts saved for an AI agent list all findings of the target.
6. **AI review in bulk (AI agent)**: the WSTG index shows per test how much of its evidence is
   collected (`3/4`; hover for the missing IDs) and whether its prompt is saved. *Save AI prompts*
   there (or `uv run wstg ai-prompts TARGET [--evidence complete|any|all] [--existing skip|overwrite]`)
   writes `<evidence>/<target>/_ai/prompts/WSTG-*.md` and a README.md for the agent: by default only
   for tests whose evidence is complete, skipping prompt files that already exist. The agent, or you from an AI chat, writes each answer to
   `_ai/answers/WSTG-XXXX-NN.json`. *Import AI answers* (or `uv run wstg ai-import TARGET
   [--findings]`) imports them all; files already imported are skipped.

### Prompt for an AI agent (bulk review)

After *Save AI prompts* (or `uv run wstg ai-prompts TARGET`), start an AI agent that can read
and write local files (for example Claude Code on the Kali host) and give it the prompt below.
Replace `EVIDENCE_ROOT` with the value of `WSTG_EVIDENCE_ROOT` (for example `/srv/wstg2/evidence`)
and `TARGET` with the target name, or keep `*` to review every target that has saved prompts.
Use an AI service the engagement allows: the prompts and evidence hold customer data.

```text
You are reviewing the results of an authorized OWASP WSTG v4.2 web security test.

Folders: EVIDENCE_ROOT/TARGET/_ai/ (TARGET may be *: then do every folder
EVIDENCE_ROOT/*/_ai/ that has a prompts/ folder). Each has README.md, prompts/, answers/.

For every file prompts/WSTG-XXXX-NN.md in those folders:

1. Skip it when answers/WSTG-XXXX-NN.json already exists and is newer than the prompt.
2. Read the whole prompt and follow it. It holds the pass/fail criteria, the steps with
   the tester's verdicts, command outputs, evidence excerpts, and the JSON template.
3. Judge from the prompt and the evidence folders it lists at the end. You may open
   files there for detail. Never open *.har files (they hold cookies and tokens).
4. Do not send any request to the target or its hosts. Public references (NVD, vendor
   advisories) may be used if your tools allow it; cite them in the reason.
5. A missing or failed collection is never a pass: use "-" when the evidence is missing
   or not enough to decide. For steps with "YOUR TASK for this step", do that task.
6. Write answers/WSTG-XXXX-NN.json: only the filled-in JSON object of the template,
   {"wstg_review": {...}}, as valid UTF-8 JSON (no code fences, no comments, no other
   text). Keep "test" and "target" exactly as given and one entry per step. Put each
   distinct problem in "findings" with a full CVSS 3.1 vector; use [] when there is none.
   Give each finding a "kind" from the prompt's list and a "subject" written exactly as
   the kind describes. When a finding listed as already recorded (any test) is the
   same problem, set "same_as" to its number instead of describing it again.
   Within one run, use the same kind and subject when two tests show the same problem.
7. Write nothing else and change, move, or delete no other file.

At the end, print a table: target, test, overall verdict, number of findings, and the
prompts you skipped or could not answer, with the reason.
```

Then import the answers: *Import AI answers* on the WSTG index tab, or
`uv run wstg ai-import TARGET [--findings]`. Check the verdicts and the proposed findings on each
WSTG page; the AI's verdicts are marked "AI" and findings it created are by `ai:<user>`.

## Configuration

`WSTG_CONFIG` names a KEY=VALUE file outside the repository. Keys are documented in
[`src/wstg/config.py`](src/wstg/config.py); an example is in
[`docs/examples/wstg2.env.example`](docs/examples/wstg2.env.example).

| Key | Default | Meaning |
|---|---|---|
| `WSTG_EVIDENCE_ROOT` | (required) | evidence root, one folder per target |
| `WSTG_DB_PATH` | (required) | SQLite database |
| `WSTG_SECRET_KEY_FILE` / `WSTG_SECRET_KEY` | (required to serve) | Flask session key |
| `WSTG_APP_PORT` | `5083` | loopback port of the app |
| `WSTG_WEB_PORT` | `8083` | nginx port (used by the setup script) |
| `WSTG_HTTP_PROXY` | (empty) | proxy for collection commands, e.g. `http://127.0.0.1:8080`. Set as `http_proxy`/`https_proxy`; tools that ignore those get their own option (openssl `-proxy`, testssl `--proxy`, whatweb `--proxy`, nikto `-useproxy`, ffuf `-x`, katana/subfinder `-proxy`, wafw00f `-p`). whois, traceroute, nmap, and sslscan cannot use a proxy: set `WSTG_DIRECT_SSH` |
| `WSTG_DIRECT_SSH` | (empty) | jump host (`user@host` or a `Host` alias of `~/.ssh/config`) that runs the tools which cannot use a proxy; see [Jump host](#jump-host-for-tools-that-cannot-use-the-proxy) |
| `WSTG_PAUSE` | (empty = full speed) | seconds between requests for tools with a delay option: nikto `-Pause N`, ffuf `-p N -t 1`, katana `-delay N -c 1 -p 1`. Weak targets that reach CPU 100% or answer 502/503/504: start with `2`, raise to 3 to 5. nikto then runs for hours and stops at 235 minutes (recorded as incomplete) |
| `WSTG_JOB_STALE_SECONDS` | `120` | a running job without a worker heartbeat for this long is shown as stalled |
| `WSTG_ALLOWED_NETWORKS` | `192.168.0.0/16,127.0.0.0/8` | client networks; enforced by nginx and the app |

After changing `WSTG_WEB_PORT` or `WSTG_ALLOWED_NETWORKS`, run the setup script again
to re-render the nginx site. After changing `WSTG_HTTP_PROXY`, `WSTG_DIRECT_SSH`, or `WSTG_PAUSE`, restart
the worker: `systemctl --user restart wstg2-worker`.

When a collection puts too much load on the target, use **Stop** on the running row of the
Automatic evidence tab: it kills that command only (also on the jump host) and the job goes on
with the next item. **Stop job** stops the whole job. Stopped evidence is not complete; the next
Collect runs it again (set `WSTG_PAUSE` first, or collect in light mode).

### Jump host for tools that cannot use the proxy

whois, traceroute, nmap, and sslscan need direct connections (raw TCP, UDP, ICMP). Behind
a proxy-only network, give the worker a jump host with direct Internet access (for example
Ubuntu 24.04). Those four commands then run there over SSH: in a temporary folder under
`/tmp`, with `timeout`, stdout/stderr streamed back, output files copied back with tar, and
the folder removed afterwards. The scope check still runs on the Kali host first. Every other
tool keeps using `WSTG_HTTP_PROXY`. For domain registration data without the jump host, the
`dns-rdap` evidence (RDAP over HTTPS) works through the proxy.

On the jump host:

```bash
sudo apt install whois traceroute nmap sslscan
```

On the Kali host, as the user that runs the worker:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/wstg2_jump -N ''         # key without a passphrase (the worker cannot type one)
ssh-copy-id -i ~/.ssh/wstg2_jump.pub tester@jump.example.net
cat >> ~/.ssh/config <<'EOF'
Host wstg2-jump
    HostName jump.example.net
    User tester
    IdentityFile ~/.ssh/wstg2_jump
    IdentitiesOnly yes
EOF
ssh wstg2-jump true                                       # once by hand: accept the host key
echo 'WSTG_DIRECT_SSH=wstg2-jump' >> ~/.config/wstg2/wstg2.env
systemctl --user restart wstg2-worker
uv run wstg tools-check --remote                          # tools on the jump host
```

The worker connects with `BatchMode=yes` and `StrictHostKeyChecking=yes`: it never asks
for a password and refuses unknown host keys. If the jump host needs the proxy to be
reached, put a `ProxyCommand` or `ProxyJump` in that `Host` entry. The scan source
address is the jump host's; announce that address to the target's administrator.

## Commands

```bash
export WSTG_CONFIG=~/.config/wstg2/wstg2.env   # optional: this file is the default

uv run wstg check-config                  # show settings; fails if data paths are inside the repo
uv run wstg migrate                       # create data dirs, apply migrations (backs up the DB first)
uv run wstg user-add NAME --role admin    # admin|guest; password from WSTG_NEW_USER_PASSWORD or prompt
uv run wstg user-passwd NAME
uv run wstg user-disable NAME [--enable]
uv run wstg user-list
uv run wstg serve [--dev]                 # 127.0.0.1:$WSTG_APP_PORT
uv run wstg catalog-check [-v]            # validate the WSTG catalog (catalog/)
uv run wstg tools-check [--strict]        # which tools of catalog/tools.yaml are installed
uv run wstg tools-check --remote          # tools on the jump host of WSTG_DIRECT_SSH
uv run wstg worker [--once]               # run queued automatic evidence jobs (systemd: wstg2-worker)
uv run wstg collect TARGET [--mode light|full] [--evidence ID [--force]] [--run]   # queue (or with --run, run now) a collection
uv run wstg backup [--dest DIR] [--keep 14]              # copy the database; rsync the evidence folder yourself
```

## Development

```bash
uv sync
uv run pytest -q                          # temporary directories and synthetic fixtures only
```

Without nginx (for example on a workstation), point a config at a scratch directory and
open `http://127.0.0.1:5083/` directly:

```bash
scripts/setup-kali.sh --no-packages --no-nginx --no-systemd \
  --data-dir ~/wstg2-dev --config ~/.config/wstg2-dev/wstg2.env
WSTG_CONFIG=~/.config/wstg2-dev/wstg2.env uv run wstg serve --dev
```

Rules for contributors (and for Claude Code) are in [`CLAUDE.md`](CLAUDE.md). In short:
no customer data in the repository, run tools only against local test targets during
development, and use `example.com` / documentation IP ranges in code and tests.

## Uninstall

```bash
systemctl --user disable --now wstg2-web wstg2-worker
rm ~/.config/systemd/user/wstg2-web.service ~/.config/systemd/user/wstg2-worker.service
sudo rm /etc/nginx/sites-enabled/wstg2.conf /etc/nginx/sites-available/wstg2.conf && sudo systemctl reload nginx
# Data and config are kept: /srv/wstg2, ~/.config/wstg2
```
