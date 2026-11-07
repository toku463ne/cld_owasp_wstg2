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
                                 config  ~/.config/wstg/wstg.env, secret_key   (mode 600)
                                 data    /srv/wstg/evidence/<target>/...
                                         /srv/wstg/db/wstg.sqlite3
```

The config file, evidence, and database live **outside the repository**. The app refuses
to start if any of them resolves inside it.

## Setup on Kali

Run as the normal user that will own the evidence (not root; `sudo` is used where needed).

```bash
git clone <this repository> ~/wstg && cd ~/wstg
scripts/setup-kali.sh
```

The script is safe to run again. It:

1. installs base packages (`git curl openssl python3 pipx sqlite3 nginx`) and `uv`,
2. creates `/srv/wstg/evidence` and `/srv/wstg/db` (mode 700),
3. writes `~/.config/wstg/wstg.env` and a random `secret_key` if missing (existing ones are kept),
4. runs `uv sync`, `wstg check-config`, `wstg migrate`,
5. asks for the first admin password if no user exists (12+ characters),
6. installs and restarts the systemd **user** service `wstg-web` (with lingering),
7. renders `deploy/nginx/wstg.conf.template` into `/etc/nginx/sites-available/wstg.conf`
   (port and allowed networks from the config file), checks it with `nginx -t`, reloads nginx,
8. checks `http://127.0.0.1:5083/login` and `http://127.0.0.1:8083/login`.

Then open `http://<kali address>:8083/` from a PC in 192.168.0.0/16 and log in.

Options:

| Option | Effect |
|---|---|
| `--data-dir DIR` | data root (default `/srv/wstg`) |
| `--config FILE` | config file (default `~/.config/wstg/wstg.env`) |
| `--admin NAME` | first admin user name (default `admin`) |
| `--no-packages` | skip apt |
| `--no-nginx` | skip the nginx site |
| `--no-systemd` | skip the user service; run `uv run wstg serve` yourself |
| `--dry-run` | print what would be done, including the rendered nginx site |

Without a terminal (for example over a non-interactive SSH command), set
`WSTG_NEW_USER_PASSWORD` for the first admin, or add the user later.

## Updating a Kali host during development

```bash
cd ~/wstg
git pull
scripts/setup-kali.sh --no-packages     # sync deps, migrate, restart wstg-web, re-render nginx
```

Check it:

```bash
systemctl --user status wstg-web
journalctl --user -u wstg-web -f
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8083/login   # expect 200
```

## Configuration

`WSTG_CONFIG` names a KEY=VALUE file outside the repository. Keys are documented in
[`src/wstg/config.py`](src/wstg/config.py); an example is in
[`docs/examples/wstg.env.example`](docs/examples/wstg.env.example).

| Key | Default | Meaning |
|---|---|---|
| `WSTG_EVIDENCE_ROOT` | (required) | evidence root, one folder per target |
| `WSTG_DB_PATH` | (required) | SQLite database |
| `WSTG_SECRET_KEY_FILE` / `WSTG_SECRET_KEY` | (required to serve) | Flask session key |
| `WSTG_APP_PORT` | `5083` | loopback port of the app |
| `WSTG_WEB_PORT` | `8083` | nginx port (used by the setup script) |
| `WSTG_ALLOWED_NETWORKS` | `192.168.0.0/16,127.0.0.0/8` | client networks; enforced by nginx and the app |

After changing `WSTG_WEB_PORT` or `WSTG_ALLOWED_NETWORKS`, run the setup script again
to re-render the nginx site.

## Commands

```bash
export WSTG_CONFIG=~/.config/wstg/wstg.env

uv run wstg check-config                  # show settings; fails if data paths are inside the repo
uv run wstg migrate                       # create data dirs, apply migrations (backs up the DB first)
uv run wstg user-add NAME --role admin    # admin|guest; password from WSTG_NEW_USER_PASSWORD or prompt
uv run wstg user-passwd NAME
uv run wstg user-disable NAME [--enable]
uv run wstg user-list
uv run wstg serve [--dev]                 # 127.0.0.1:$WSTG_APP_PORT
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
  --data-dir ~/wstg-dev --config ~/.config/wstg-dev/wstg.env
WSTG_CONFIG=~/.config/wstg-dev/wstg.env uv run wstg serve --dev
```

Rules for contributors (and for Claude Code) are in [`CLAUDE.md`](CLAUDE.md). In short:
no customer data in the repository, run tools only against local test targets during
development, and use `example.com` / documentation IP ranges in code and tests.

## Uninstall

```bash
systemctl --user disable --now wstg-web && rm ~/.config/systemd/user/wstg-web.service
sudo rm /etc/nginx/sites-enabled/wstg.conf /etc/nginx/sites-available/wstg.conf && sudo systemctl reload nginx
# Data and config are kept: /srv/wstg, ~/.config/wstg
```
