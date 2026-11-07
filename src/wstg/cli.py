"""Command line: `uv run wstg <command>`."""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from . import catalog, config, db as dbmod, users


def _cfg() -> config.Config:
    return config.load()


def _db(cfg: config.Config) -> dbmod.Database:
    return dbmod.Database(cfg.db_path)


def _new_password(args) -> str:
    pw = os.environ.get("WSTG_NEW_USER_PASSWORD")
    if pw:
        return pw
    if not sys.stdin.isatty():
        raise users.UserError("set WSTG_NEW_USER_PASSWORD or run in a terminal")
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Again: "):
        raise users.UserError("passwords do not match")
    return pw


def cmd_check_config(args) -> int:
    cfg = _cfg()
    print(f"evidence root : {cfg.evidence_root}")
    print(f"database      : {cfg.db_path}")
    print(f"app port      : 127.0.0.1:{cfg.app_port}")
    print(f"allowed nets  : {', '.join(str(n) for n in cfg.allowed_networks)}")
    print(f"secret key    : {'set' if cfg.secret_key else 'NOT SET'}")
    print("OK: data paths are outside the repository")
    return 0


def cmd_migrate(args) -> int:
    cfg = _cfg()
    config.ensure_dirs(cfg)
    applied = dbmod.migrate(_db(cfg))
    print("applied: " + ", ".join(applied) if applied else "up to date")
    return 0


def cmd_user_add(args) -> int:
    db = _db(_cfg())
    users.add(db, args.username, _new_password(args), args.role, actor="cli")
    print(f"added {args.username} ({args.role})")
    return 0


def cmd_user_passwd(args) -> int:
    db = _db(_cfg())
    users.set_password(db, args.username, _new_password(args), actor="cli")
    print(f"password changed: {args.username}")
    return 0


def cmd_user_disable(args) -> int:
    users.set_disabled(_db(_cfg()), args.username, not args.enable, actor="cli")
    print(f"{'enabled' if args.enable else 'disabled'} {args.username}")
    return 0


def cmd_user_list(args) -> int:
    for u in users.list_all(_db(_cfg())):
        state = "disabled" if u["disabled"] else "active"
        print(f"{u['username']:<24} {u['role']:<6} {state:<8} {u['created_at']}")
    return 0


def cmd_catalog_check(args) -> int:
    c = catalog.load()
    autos = [e for e in c.evidence.values() if e.kind == "auto"]
    print(f"WSTG {c.wstg_version}: {len(c.tests)} tests, {len(c.scenarios)} scenarios")
    print(f"evidence: {len(c.evidence)} ({len(autos)} auto, "
          f"{sum(e.level == 'light' for e in autos)} light, {len(c.evidence) - len(autos)} manual)")
    missing = [t.id for t in c.tests.values() if not t.merged_into and t.id not in c.scenarios]
    print(f"tests without a scenario: {len(missing)}")
    if args.verbose and missing:
        print("  " + " ".join(missing))
    unused = [e for e in c.evidence if not c.tests_using(e)]
    if unused:
        print("evidence not used by any scenario: " + ", ".join(unused))
    print("OK")
    return 0


def cmd_serve(args) -> int:
    from .web import create_app

    cfg = _cfg()
    app = create_app(cfg)
    if args.dev:
        app.run(host="127.0.0.1", port=cfg.app_port, debug=False)
        return 0
    from waitress import serve

    # Loopback only: nginx is the single way in from the network. The app
    # (ProxyFix) reads the client address from nginx's X-Forwarded-For.
    # waitress would otherwise drop X-Forwarded-For as untrusted, and every
    # client would look like 127.0.0.1.
    serve(app, host="127.0.0.1", port=cfg.app_port, threads=8, clear_untrusted_proxy_headers=False)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wstg", description="OWASP WSTG test runner")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check-config", help="show settings; fail if data paths are inside the repository"
                   ).set_defaults(func=cmd_check_config)
    sub.add_parser("migrate", help="create data directories and apply database migrations"
                   ).set_defaults(func=cmd_migrate)

    s = sub.add_parser("user-add", help="add a user (password from WSTG_NEW_USER_PASSWORD or prompt)")
    s.add_argument("username")
    s.add_argument("--role", choices=users.ROLES, default="guest")
    s.set_defaults(func=cmd_user_add)

    s = sub.add_parser("user-passwd", help="change a user's password")
    s.add_argument("username")
    s.set_defaults(func=cmd_user_passwd)

    s = sub.add_parser("user-disable", help="disable (or with --enable, re-enable) a user")
    s.add_argument("username")
    s.add_argument("--enable", action="store_true")
    s.set_defaults(func=cmd_user_disable)

    sub.add_parser("user-list", help="list users").set_defaults(func=cmd_user_list)

    s = sub.add_parser("catalog-check", help="load and validate the WSTG catalog (catalog/)")
    s.add_argument("-v", "--verbose", action="store_true", help="list tests without a scenario")
    s.set_defaults(func=cmd_catalog_check)

    s = sub.add_parser("serve", help="run the web app on 127.0.0.1:WSTG_APP_PORT (behind nginx)")
    s.add_argument("--dev", action="store_true", help="use the Flask development server")
    s.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (config.ConfigError, users.UserError, catalog.CatalogError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
