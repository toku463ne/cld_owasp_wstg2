"""Configuration and the "data lives outside the repository" startup check.

Settings come from environment variables, optionally pre-loaded from a
KEY=VALUE file named by WSTG_CONFIG. The file itself must be outside the
repository. Explicit environment variables win over the file.

    WSTG_CONFIG             path to a KEY=VALUE file (optional; default
                            ~/.config/wstg2/wstg2.env when that file exists)
    WSTG_EVIDENCE_ROOT      absolute path of the evidence root (required)
    WSTG_DB_PATH            absolute path of the SQLite database (required)
    WSTG_SECRET_KEY         Flask session key, or
    WSTG_SECRET_KEY_FILE    file holding it (one of the two is required to serve)
    WSTG_APP_PORT           loopback port of the app behind nginx (default 5083)
    WSTG_ALLOWED_NETWORKS   comma-separated client networks the app accepts
                            (default 192.168.0.0/16,127.0.0.0/8); nginx enforces
                            the same list, this is a second line of defense
    WSTG_HTTP_PROXY         proxy for collection commands (http_proxy/https_proxy of the
                            child processes, plus `proxy_args` of tools that ignore
                            those), e.g. http://127.0.0.1:8080; empty = none
    WSTG_DIRECT_SSH         jump host for tools that cannot use a proxy (whois,
                            traceroute, nmap, sslscan): user@host or a Host alias of
                            ~/.ssh/config; key authentication, host key in known_hosts
    WSTG_PAUSE              seconds between requests for tools with a delay option
                            (nikto -Pause, ffuf -p with one thread), 0..60; 0 or empty =
                            full speed. Use 2 for weak targets (3 to 5 if they still fail)
    WSTG_JOB_STALE_SECONDS  a running job without a heartbeat for this long is marked
                            interrupted (default 120)
    WSTG_WEB_PORT           nginx port (default 8083); read by scripts/setup-kali.sh,
                            not by the app
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_APP_PORT = 5083
DEFAULT_ALLOWED_NETWORKS = "192.168.0.0/16,127.0.0.0/8"


class ConfigError(Exception):
    pass


def repo_root() -> Path | None:
    """The working tree that contains this package, if any."""
    try:
        out = subprocess.run(
            ["git", "-C", str(PACKAGE_DIR), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if out:
            return Path(out).resolve()
    except (OSError, subprocess.CalledProcessError):
        pass
    for parent in [PACKAGE_DIR, *PACKAGE_DIR.parents]:
        if (parent / ".git").exists():
            return parent.resolve()
    return None


def is_inside(path: Path, root: Path) -> bool:
    path, root = path.resolve(), root.resolve()
    return path == root or root in path.parents


_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def load_env_file(path: Path) -> dict[str, str]:
    """Parse KEY=VALUE lines: comments at line start, optional `export `,
    one pair of matching quotes removed, no variable expansion."""
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.replace("\r", "").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if _KEY_RE.fullmatch(key):
            values[key] = value
    return values


@dataclass(frozen=True)
class Config:
    evidence_root: Path
    db_path: Path
    secret_key: str = ""
    app_port: int = DEFAULT_APP_PORT
    allowed_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = field(default_factory=tuple)
    http_proxy: str = ""
    direct_ssh: str = ""
    pause: int = 0
    job_stale_seconds: int = 120

    def guarded_paths(self) -> dict[str, Path]:
        return {"evidence root": self.evidence_root, "database": self.db_path}

    def client_allowed(self, addr: str | None) -> bool:
        if not addr:
            return False
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        return any(ip in net for net in self.allowed_networks)


def _parse_networks(value: str):
    nets = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError as e:
            raise ConfigError(f"WSTG_ALLOWED_NETWORKS: {e}") from None
    return tuple(nets)


def _ssh_dest(value: str) -> str:
    # user@host or a Host alias from ~/.ssh/config; never an ssh option.
    if value and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(@[A-Za-z0-9_.-]+)?", value):
        raise ConfigError(f"WSTG_DIRECT_SSH must be user@host or an ssh Host alias: {value!r}")
    return value


def _int(env: dict[str, str], name: str, default: int) -> int:
    try:
        return int(env.get(name) or default)
    except ValueError:
        raise ConfigError(f"{name} must be a number") from None


def default_config_file() -> Path:
    return Path.home() / ".config" / "wstg2" / "wstg2.env"


def load(env: dict[str, str] | None = None, check_repo: bool = True) -> Config:
    from_process = env is None
    env = dict(os.environ if env is None else env)
    cfg_file = env.get("WSTG_CONFIG")
    if not cfg_file and from_process and default_config_file().is_file():
        # The file setup-kali.sh writes, so commands work without exporting WSTG_CONFIG.
        cfg_file = str(default_config_file())
    if cfg_file:
        cfg_path = Path(cfg_file)
        root = repo_root()
        if root and is_inside(cfg_path, root):
            raise ConfigError(f"config file {cfg_path} is inside the repository {root}")
        if not cfg_path.is_file():
            raise ConfigError(f"config file not found: {cfg_path}")
        env = {**load_env_file(cfg_path), **env}

    def path(name: str) -> Path:
        value = env.get(name)
        if not value:
            raise ConfigError(f"{name} is not set")
        p = Path(value).expanduser()
        if not p.is_absolute():
            raise ConfigError(f"{name} must be an absolute path: {value}")
        return p

    secret = env.get("WSTG_SECRET_KEY", "")
    if not secret and env.get("WSTG_SECRET_KEY_FILE"):
        secret = Path(env["WSTG_SECRET_KEY_FILE"]).expanduser().read_text().strip()

    try:
        port = int(env.get("WSTG_APP_PORT", DEFAULT_APP_PORT))
    except ValueError:
        raise ConfigError("WSTG_APP_PORT must be a number") from None

    cfg = Config(
        evidence_root=path("WSTG_EVIDENCE_ROOT"),
        db_path=path("WSTG_DB_PATH"),
        secret_key=secret,
        app_port=port,
        allowed_networks=_parse_networks(env.get("WSTG_ALLOWED_NETWORKS", DEFAULT_ALLOWED_NETWORKS)),
        http_proxy=env.get("WSTG_HTTP_PROXY", "").strip(),
        direct_ssh=_ssh_dest(env.get("WSTG_DIRECT_SSH", "").strip()),
        pause=_int(env, "WSTG_PAUSE", 0),
        job_stale_seconds=_int(env, "WSTG_JOB_STALE_SECONDS", 120),
    )
    if not 0 <= cfg.pause <= 60:
        raise ConfigError("WSTG_PAUSE must be 0..60 seconds")
    if check_repo:
        check_outside_repo(cfg)
    return cfg


def check_outside_repo(cfg: Config, root: Path | None = None) -> None:
    """Refuse to run when any data path resolves inside the repository.

    Path.resolve() follows symlinks: a symlink outside pointing into the
    repository is rejected.
    """
    root = root or repo_root()
    if root is None:
        return
    for label, p in cfg.guarded_paths().items():
        if is_inside(p, root):
            raise ConfigError(f"{label} {p} resolves inside the repository {root}; refusing to start")


def ensure_dirs(cfg: Config) -> None:
    """Create the data directories, readable by the owner only."""
    for p in (cfg.evidence_root, cfg.db_path.parent):
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
