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
4. runs `uv sync`, `wstg check-config`, `wstg migrate`,
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
| `--no-packages` | skip apt |
| `--no-nginx` | skip the nginx site |
| `--no-systemd` | skip the user service; run `uv run wstg serve` yourself |
| `--dry-run` | print what would be done, including the rendered nginx site |

Without a terminal (for example over a non-interactive SSH command), set
`WSTG_NEW_USER_PASSWORD` for the first admin, or add the user later.

## Updating a Kali host during development

```bash
cd ~/cld_owasp_wstg2
git pull
scripts/setup-kali.sh --no-packages     # sync deps, migrate, restart wstg2-web, re-render nginx
```

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
4. **WSTG index**: open a test, follow the steps, set each step's verdict, add screenshots and
   files on the evidence pages, and copy the AI prompt when you want a second opinion.

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
| `WSTG_HTTP_PROXY` | (empty) | proxy for collection commands, e.g. `http://127.0.0.1:8080` (some tools ignore it: nmap, ffuf) |
| `WSTG_JOB_STALE_SECONDS` | `120` | a running job without a worker heartbeat for this long is shown as stalled |
| `WSTG_ALLOWED_NETWORKS` | `192.168.0.0/16,127.0.0.0/8` | client networks; enforced by nginx and the app |

After changing `WSTG_WEB_PORT` or `WSTG_ALLOWED_NETWORKS`, run the setup script again
to re-render the nginx site.

## Commands

```bash
export WSTG_CONFIG=~/.config/wstg2/wstg2.env

uv run wstg check-config                  # show settings; fails if data paths are inside the repo
uv run wstg migrate                       # create data dirs, apply migrations (backs up the DB first)
uv run wstg user-add NAME --role admin    # admin|guest; password from WSTG_NEW_USER_PASSWORD or prompt
uv run wstg user-passwd NAME
uv run wstg user-disable NAME [--enable]
uv run wstg user-list
uv run wstg serve [--dev]                 # 127.0.0.1:$WSTG_APP_PORT
uv run wstg catalog-check [-v]            # validate the WSTG catalog (catalog/)
uv run wstg worker [--once]               # run queued automatic evidence jobs (systemd: wstg2-worker)
uv run wstg collect TARGET [--mode light|full] [--run]   # queue (or with --run, run now) a collection
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
