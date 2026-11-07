#!/bin/bash
# Set up (or update) WSTG Runner on a Kali host. Safe to run again: the
# existing config, secret key, database, evidence, and users are kept.
#
#   scripts/setup-kali.sh [options]
#
#   --data-dir DIR    data root outside the repo (default /srv/wstg2)
#                     -> DIR/evidence, DIR/db/wstg2.sqlite3
#   --config FILE     config file outside the repo (default ~/.config/wstg2/wstg2.env)
#   --admin NAME      first admin user, created only when no user exists (default admin)
#   --no-packages     skip apt
#   --no-nginx        skip the nginx site (port 8083)
#   --no-systemd      skip the systemd user services (run `uv run wstg serve` / `worker` yourself)
#   --backup-timer    also install a daily database backup (wstg backup, keeps 14)
#   --dry-run         print what would be done, change nothing
#   -h, --help        show this help
#
# Typical update after `git pull`:   scripts/setup-kali.sh --no-packages
#
# Run as the normal user that will own the evidence (not root). sudo is used
# for apt, the data directory under /srv, nginx, and lingering of user services.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR=/srv/wstg2
CONFIG="$HOME/.config/wstg2/wstg2.env"
ADMIN=admin
PACKAGES=1
NGINX=1
SYSTEMD=1
BACKUP_TIMER=0
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --data-dir) DATA_DIR="$2"; shift 2;;
    --config) CONFIG="$2"; shift 2;;
    --admin) ADMIN="$2"; shift 2;;
    --no-packages) PACKAGES=0; shift;;
    --no-nginx) NGINX=0; shift;;
    --no-systemd) SYSTEMD=0; shift;;
    --backup-timer) BACKUP_TIMER=1; shift;;
    --dry-run) DRY=1; shift;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2;;
  esac
done

step() { printf '\n== %s\n' "$*"; }
run()  { if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }
die()  { echo "error: $*" >&2; exit 1; }

inside_repo() {  # true if $1 (resolved, may not exist yet) is inside the repo
  local p; p="$(realpath -m "$1")"
  case "$p" in "$REPO"|"$REPO"/*) return 0;; *) return 1;; esac
}

env_get() {  # file key -> last value, quotes removed (same rules as config.py)
  [ -f "$1" ] || return 0
  sed -nE "s/^[[:space:]]*(export[[:space:]]+)?$2[[:space:]]*=[[:space:]]*(.*)$/\2/p" "$1" \
    | tail -n 1 | sed -E 's/[[:space:]]+$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/'
}

# --------------------------------------------------------------------------
step "Preflight"
# Settings come from the config file only. WSTG_* values left in the shell
# would silently win over the file (explicit environment wins in config.py).
stale=$(env | grep -o '^WSTG_[A-Z_]*' | grep -vxE 'WSTG_CONFIG|WSTG_NEW_USER_PASSWORD' || true)
if [ -n "$stale" ]; then
  echo "ignoring WSTG_* variables from the shell: $(echo $stale)"
  # shellcheck disable=SC2086
  unset $stale
fi
[ "$(id -u)" -ne 0 ] || die "run as the normal user that will own the evidence, not root"
# shellcheck disable=SC1091
. /etc/os-release
[ "${ID:-}" = kali ] || echo "warning: this is ${PRETTY_NAME:-unknown}, not Kali; continuing"
inside_repo "$DATA_DIR" && die "--data-dir $DATA_DIR is inside the repository"
inside_repo "$CONFIG"   && die "--config $CONFIG is inside the repository"
echo "repository  $REPO"
echo "data dir    $DATA_DIR"
echo "config      $CONFIG"

# --------------------------------------------------------------------------
if [ "$PACKAGES" = 1 ]; then
  step "Packages (apt)"
  # Base packages only. Test tools (nikto, nmap, ...) are added when the
  # automatic evidence catalog needs them; Kali ships most of them already.
  pkgs=(git curl openssl python3 pipx sqlite3)
  [ "$NGINX" = 0 ] || pkgs+=(nginx)
  run sudo apt-get update
  run sudo apt-get install -y "${pkgs[@]}"
fi

# --------------------------------------------------------------------------
step "uv"
export PATH="$HOME/.local/bin:$PATH"
if ! command -v uv >/dev/null 2>&1; then
  command -v pipx >/dev/null 2>&1 || die "pipx not found (run without --no-packages, or install uv yourself)"
  run pipx install uv
fi
[ "$DRY" = 1 ] || uv --version
UV_BIN="$(command -v uv || echo "$HOME/.local/bin/uv")"

# --------------------------------------------------------------------------
step "Data directories"
EVIDENCE_DIR="$DATA_DIR/evidence"
DB_DIR="$DATA_DIR/db"
SUDO=""
parent="$(realpath -m "$DATA_DIR")"
while [ ! -d "$parent" ]; do parent="$(dirname "$parent")"; done
[ -w "$parent" ] || SUDO=sudo   # for example /srv
for d in "$DATA_DIR" "$EVIDENCE_DIR" "$DB_DIR"; do
  [ -d "$d" ] || run $SUDO mkdir -p "$d"
done
if [ -n "$SUDO" ] && [ "$DRY" = 0 ] && [ "$(stat -c %u "$DATA_DIR")" != "$(id -u)" ]; then
  sudo chown "$(id -u):$(id -g)" "$DATA_DIR"
fi
[ -n "$SUDO" ] && run sudo chown "$(id -u):$(id -g)" "$EVIDENCE_DIR" "$DB_DIR"
run chmod 700 "$DATA_DIR" "$EVIDENCE_DIR" "$DB_DIR"

# --------------------------------------------------------------------------
step "Config file and secret key (outside the repo, mode 600)"
CONFIG_DIR="$(dirname "$CONFIG")"
run mkdir -p -m 700 "$CONFIG_DIR"
if [ -f "$CONFIG" ]; then
  echo "keeping existing $CONFIG"
else
  if [ "$DRY" = 1 ]; then echo "  [dry-run] would write $CONFIG"
  else
    (umask 077; cat > "$CONFIG" <<EOF
# WSTG Runner settings. Keep this file outside the repository (mode 600).
# Keys are documented in src/wstg/config.py.

# Data (must be outside the repository; the app refuses to start otherwise)
WSTG_EVIDENCE_ROOT=$EVIDENCE_DIR
WSTG_DB_PATH=$DB_DIR/wstg2.sqlite3

# Flask session key (generated by setup-kali.sh)
WSTG_SECRET_KEY_FILE=$CONFIG_DIR/secret_key

# Loopback port of the app; nginx listens on WSTG_WEB_PORT and proxies here
WSTG_APP_PORT=5083

# nginx port (read by setup-kali.sh only)
WSTG_WEB_PORT=8083

# Client networks allowed (nginx and the app both enforce this list)
WSTG_ALLOWED_NETWORKS=192.168.0.0/16,127.0.0.0/8
EOF
    )
    echo "wrote $CONFIG"
  fi
fi

SECRET_FILE="$(env_get "$CONFIG" WSTG_SECRET_KEY_FILE)"
SECRET_FILE="${SECRET_FILE:-$CONFIG_DIR/secret_key}"
SECRET_FILE="${SECRET_FILE/#\~/$HOME}"
if [ -n "$(env_get "$CONFIG" WSTG_SECRET_KEY)" ]; then
  echo "secret key set in the config file"
elif [ -s "$SECRET_FILE" ]; then
  echo "keeping existing $SECRET_FILE"
elif [ "$DRY" = 1 ]; then
  echo "  [dry-run] would generate $SECRET_FILE"
else
  inside_repo "$SECRET_FILE" && die "WSTG_SECRET_KEY_FILE $SECRET_FILE is inside the repository"
  mkdir -p -m 700 "$(dirname "$SECRET_FILE")"
  (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(48))' > "$SECRET_FILE")
  echo "generated $SECRET_FILE"
fi
[ "$DRY" = 1 ] || chmod 600 "$CONFIG"

APP_PORT="$(env_get "$CONFIG" WSTG_APP_PORT)"; APP_PORT="${APP_PORT:-5083}"
WEB_PORT="$(env_get "$CONFIG" WSTG_WEB_PORT)"; WEB_PORT="${WEB_PORT:-8083}"
NETWORKS="$(env_get "$CONFIG" WSTG_ALLOWED_NETWORKS)"; NETWORKS="${NETWORKS:-192.168.0.0/16,127.0.0.0/8}"
export WSTG_CONFIG="$CONFIG"

# --------------------------------------------------------------------------
step "Python environment"
run "$UV_BIN" --directory "$REPO" sync --frozen
wstg() { "$UV_BIN" --directory "$REPO" run --frozen wstg "$@"; }
[ "$DRY" = 1 ] || wstg check-config

step "Database migrations"
run wstg migrate

step "Admin user"
if [ "$DRY" = 1 ]; then
  echo "  [dry-run] would create admin '$ADMIN' if no user exists"
elif [ -n "$(wstg user-list)" ]; then
  echo "users exist; skipping"
elif [ -t 0 ] || [ -n "${WSTG_NEW_USER_PASSWORD:-}" ]; then
  echo "create the first admin user '$ADMIN' (password: at least 12 characters)"
  wstg user-add "$ADMIN" --role admin
else
  echo "warning: no user exists and no terminal; later run: uv run wstg user-add $ADMIN --role admin"
fi

# --------------------------------------------------------------------------
if [ "$SYSTEMD" = 1 ]; then
  step "systemd user services (wstg2-web, wstg2-worker)"
  UNIT_DIR="$HOME/.config/systemd/user"
  unit() {  # name description command
    if [ "$DRY" = 1 ]; then echo "  [dry-run] would write $UNIT_DIR/$1.service"; return; fi
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/$1.service" <<EOF
[Unit]
Description=$2

[Service]
Environment=WSTG_CONFIG=$CONFIG
WorkingDirectory=$REPO
ExecStart=$UV_BIN run --frozen wstg $3
Restart=on-failure
# uv exits with 143 when systemd stops it with SIGTERM; that is a normal stop.
SuccessExitStatus=143
RestartSec=5

[Install]
WantedBy=default.target
EOF
  }
  unit wstg2-web "WSTG Runner web app (127.0.0.1:$APP_PORT, behind nginx :$WEB_PORT)" serve
  unit wstg2-worker "WSTG Runner automatic evidence worker" worker
  if [ "$BACKUP_TIMER" = 1 ]; then
    if [ "$DRY" = 1 ]; then echo "  [dry-run] would write $UNIT_DIR/wstg2-backup.service/.timer"
    else
      cat > "$UNIT_DIR/wstg2-backup.service" <<EOF
[Unit]
Description=WSTG Runner database backup

[Service]
Type=oneshot
Environment=WSTG_CONFIG=$CONFIG
WorkingDirectory=$REPO
ExecStart=$UV_BIN run --frozen wstg backup
EOF
      cat > "$UNIT_DIR/wstg2-backup.timer" <<EOF
[Unit]
Description=Daily WSTG Runner database backup

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF
    fi
  fi
  run systemctl --user daemon-reload
  run systemctl --user enable wstg2-web.service wstg2-worker.service
  # Restart (not just start) so an update picks up the new code. A collection
  # that is running is marked interrupted; collecting again skips what is done.
  run systemctl --user restart wstg2-web.service wstg2-worker.service
  [ "$BACKUP_TIMER" = 0 ] || run systemctl --user enable --now wstg2-backup.timer
  # Keep the user service running without an open login session.
  if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null || true)" != yes ]; then
    run sudo loginctl enable-linger "$USER"
  fi
fi

# --------------------------------------------------------------------------
if [ "$NGINX" = 1 ]; then
  step "nginx site (HTTP :$WEB_PORT -> 127.0.0.1:$APP_PORT)"
  command -v nginx >/dev/null 2>&1 || [ -x /usr/sbin/nginx ] || [ "$DRY" = 1 ] \
    || die "nginx not found (run without --no-packages, or use --no-nginx)"
  allow=""
  IFS=',' read -ra nets <<< "$NETWORKS"
  for n in "${nets[@]}"; do
    n="$(echo "$n" | tr -d '[:space:]')"
    [ -z "$n" ] && continue
    [[ "$n" =~ ^[0-9A-Fa-f:./]+$ ]] || die "WSTG_ALLOWED_NETWORKS: bad entry '$n'"
    allow+="    allow $n;"$'\n'
  done
  # IPv6 loopback, so a local check through [::1] works too.
  [[ "$NETWORKS" == *127.0.0.0/8* ]] && allow+="    allow ::1;"$'\n'
  allow="${allow%$'\n'}"
  SITE=/etc/nginx/sites-available/wstg2.conf
  rendered="$(awk -v allow="$allow" -v web="$WEB_PORT" -v app="$APP_PORT" '
    { gsub(/@WEB_PORT@/, web); gsub(/@APP_PORT@/, app) }
    /^@ALLOW_RULES@$/ { print allow; next }
    { print }' "$REPO/deploy/nginx/wstg2.conf.template")"
  if [ "$DRY" = 1 ]; then
    echo "  [dry-run] would write $SITE:"; echo "$rendered" | sed 's/^/    /'
  else
    printf '%s\n' "$rendered" | sudo tee "$SITE.new" >/dev/null
    [ -f "$SITE" ] && sudo cp -p "$SITE" "$SITE.bak"
    sudo mv "$SITE.new" "$SITE"
    sudo ln -sf "$SITE" /etc/nginx/sites-enabled/wstg2.conf
    if ! sudo nginx -t; then
      if [ -f "$SITE.bak" ]; then sudo mv "$SITE.bak" "$SITE"; else sudo rm -f /etc/nginx/sites-enabled/wstg2.conf; fi
      die "nginx -t failed; previous site restored"
    fi
    sudo systemctl enable nginx
    if systemctl is-active --quiet nginx; then sudo systemctl reload nginx; else sudo systemctl start nginx; fi
  fi
fi

# --------------------------------------------------------------------------
step "Smoke test"
if [ "$DRY" = 0 ]; then
  if [ "$SYSTEMD" = 1 ]; then
    code=000
    printf 'waiting for the app on 127.0.0.1:%s ' "$APP_PORT"
    for _ in $(seq 1 10); do
      code=$(curl -s --noproxy '*' --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$APP_PORT/login" || true)
      [ "$code" = 200 ] && break
      # Stop waiting if the service already gave up.
      systemctl --user is-failed --quiet wstg2-web.service && break
      printf '.'
      sleep 1
    done
    echo
    echo "app   http://127.0.0.1:$APP_PORT/login -> HTTP $code"
    if [ "$code" != 200 ]; then
      echo "warning: app not answering (000 = nothing listening or no reply). Service state and log:"
      systemctl --user status wstg2-web.service --no-pager -n 0 2>&1 | sed 's/^/  /' || true
      journalctl --user -u wstg2-web.service -n 30 --no-pager 2>&1 | sed 's/^/  /' || true
    fi
  fi
  if [ "$NGINX" = 1 ]; then
    code=$(curl -s --noproxy '*' --connect-timeout 2 --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$WEB_PORT/login" || true)
    echo "nginx http://127.0.0.1:$WEB_PORT/login -> HTTP $code"
    [ "$code" = 200 ] || echo "warning: expected 200 (403 means 127.0.0.0/8 is not in WSTG_ALLOWED_NETWORKS; 502 means the app is down)"
  fi
fi

addr="$(hostname -I 2>/dev/null | awk '{print $1}')"
cat <<EOF

Done.
  export WSTG_CONFIG=$CONFIG
  Web UI:   http://${addr:-<this host>}:$WEB_PORT/   (allowed from: $NETWORKS)
  Services: systemctl --user status wstg2-web wstg2-worker
  Logs:     journalctl --user -u wstg2-web -u wstg2-worker -f
  Update:   git pull && scripts/setup-kali.sh --no-packages
EOF
