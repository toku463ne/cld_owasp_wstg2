"""Command line: `uv run wstg <command>`."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

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


def cmd_tools_check(args) -> int:
    import os
    import shutil
    c = catalog.load()
    tools = list(c.tools.values())
    if args.remote:
        return _tools_check_remote(c)
    if args.packages:
        for t in tools:
            if t.install == args.packages:
                print(t.package)
        return 0
    used = {}
    for e in c.evidence.values():
        if e.kind == "auto":
            used.setdefault(e.argv[0], []).append(e.id)
    path = os.environ.get("PATH", "/usr/bin:/bin") + os.pathsep + os.path.expanduser("~/.local/bin")
    missing = []
    for t in tools:
        found = (t.path if os.path.exists(t.path) else None) if t.path else shutil.which(t.name, path=path)
        if not found:
            missing.append(t)
        how = "base system" if t.install == "none" else f"{t.install} {t.package}"
        line = f"{'ok     ' if found else 'MISSING'} {t.name:<14} {found or '(' + how + ')'}"
        if t.name in used and not found:
            line += "  needed by " + ", ".join(used[t.name])
        if t.note and not found:
            line += f"  [{t.note}]"
        print(line)
    if missing:
        print(f"{len(missing)} missing; install with scripts/setup-kali.sh (without --no-packages)")
        return 1 if args.strict else 0
    print("OK")
    return 0


def _tools_check_remote(c) -> int:
    """Check the tools of `direct` evidence on the jump host (WSTG_DIRECT_SSH)."""
    import shlex
    from . import runner as rmod
    cfg = config.load()
    if not cfg.direct_ssh:
        print("WSTG_DIRECT_SSH is not set; direct tools (whois, traceroute, nmap, sslscan) run on this host")
        return 0
    names = sorted({e.argv[0] for e in c.evidence.values() if e.kind == "auto" and e.direct})
    names += ["tar", "timeout", "mktemp"]
    script = "; ".join(f"printf '%s %s\\n' {shlex.quote(n)} \"$(command -v {shlex.quote(n)} || echo -)\""
                       for n in names)
    try:
        r = rmod.Remote(cfg.direct_ssh, dict(os.environ)).run(script, 60)
    except rmod.RunError as e:
        print(f"error: {e}")
        return 1
    if r.returncode != 0:
        print(f"error: ssh to {cfg.direct_ssh} failed (exit {r.returncode}): "
              f"{r.stderr.decode(errors='replace').strip()}")
        print("  check: key authentication works and the host key is in ~/.ssh/known_hosts"
              f" (run `ssh {cfg.direct_ssh} true` once by hand)")
        return 1
    missing = []
    for line in r.stdout.decode(errors="replace").splitlines():
        name, _, where = line.partition(" ")
        ok = where != "-"
        if not ok:
            missing.append(c.tools[name].package if name in c.tools else name)
        print(f"{'ok     ' if ok else 'MISSING'} {name:<14} on {cfg.direct_ssh}  {where if ok else ''}")
    if missing:
        print(f"install on the jump host: sudo apt install {' '.join(missing)}")
        return 1
    print("OK")
    return 0


def _runner(cfg):
    from . import evidence as evmod, runner as rmod
    db = _db(cfg)
    if dbmod.pending_migrations(db):
        raise config.ConfigError("database has pending migrations; run `wstg migrate`")
    return rmod.Runner(cfg, db, catalog.load(), evmod.Store(cfg, db))


def cmd_worker(args) -> int:
    r = _runner(_cfg())
    print(f"worker {r.worker} polling for jobs", flush=True)
    r.serve(once=args.once)
    return 0


def cmd_collect(args) -> int:
    from . import runner as rmod, targets as tmod
    r = _runner(_cfg())
    t = tmod.get(r.db, args.target)
    if not t:
        raise config.ConfigError(f"no such target: {args.target}")
    try:
        job = rmod.enqueue(r.db, r.cat, t, args.mode, actor="cli", evidence_id=args.evidence or "",
                           force=args.force)
    except rmod.RunError as e:
        raise config.ConfigError(str(e)) from None
    print(f"queued job {job} ({args.evidence or args.mode}) for {t.name}")
    if args.run:
        r.recover()
        r.run_job(r.claim())
        for it in rmod.job_items(r.db, job):
            print(f"  {it['status']:<9} {it['evidence_id']:<24} {it['message']}")
    return 0


def cmd_capture(args) -> int:
    from . import capture as capmod, targets as tmod
    r = _runner(_cfg())
    t = _target(r, args.target)
    try:
        res = capmod.record_session(r.cfg, r.db, r.store, t, role=args.role or "", actor="cli",
                                    headless=args.headless, start_url=args.url)
    except (capmod.CaptureError, tmod.TargetError) as e:
        raise config.ConfigError(str(e)) from None
    print(f"saved HAR {res['har_file']} as {capmod.EVIDENCE_ID} v{res['har_version']} for {t.name}")
    if res["state_file"]:
        print(f"saved storage state {res['state_file']} (v{res['version']})")
    if res["out_of_scope_hosts"]:
        print(f"  WARNING: contacted {len(res['out_of_scope_hosts'])} host(s) outside the scope: "
              + ", ".join(res["out_of_scope_hosts"]))
    print(f"  analyse it with the WSTG pages, or: uv run wstg-har cookies "
          f"{tmod.evidence_dir(r.cfg, t) / capmod.EVIDENCE_ID / 'latest' / 'items'}/*.har")
    return 0


def _target(r, name):
    from . import targets as tmod
    t = tmod.get(r.db, name)
    if not t:
        raise config.ConfigError(f"no such target: {name}")
    return t


def cmd_ai_prompts(args) -> int:
    from . import ai_files
    r = _runner(_cfg())
    t = _target(r, args.target)
    for tid in args.test or []:
        if tid not in ai_files.tests_with_scenarios(r.cat, t):
            raise config.ConfigError(f"{tid} has no scenario for {t.type} targets")
    res = ai_files.save_prompts(r.cfg, r.db, r.cat, r.store, t, args.test or None,
                                evidence=args.evidence, existing=args.existing)
    for p in res["saved"]:
        print(f"  saved    {p}")
    for tid in res["skipped_existing"]:
        print(f"  skipped  {tid} (prompt file exists; --existing overwrite to rewrite)")
    for tid in res["skipped_evidence"]:
        print(f"  skipped  {tid} (evidence not collected; --evidence all to save anyway)")
    print(f"{ai_files.summary(res)}; instructions for an AI agent: {ai_files.folder(r.cfg, t) / 'README.md'}")
    return 0


def cmd_ai_import(args) -> int:
    from . import ai_files
    r = _runner(_cfg())
    t = _target(r, args.target)
    results = ai_files.import_answers(r.cfg, r.db, r.cat, r.store, t, args.actor,
                                      overwrite=args.overwrite, create_findings=args.findings)
    if not results:
        print(f"no answer files in {ai_files.folder(r.cfg, t) / 'answers'}")
    for x in results:
        print(f"  {x['status']:<8} {x['file']:<24} {x['message']}")
    return 1 if any(x["status"] == "error" for x in results) else 0


def cmd_backup(args) -> int:
    """Consistent copy of the database (SQLite online backup), keeping the newest N.
    Evidence folders are append-only versions: copy them with rsync."""
    from datetime import datetime, timezone
    cfg = _cfg()
    dest = Path(args.dest).expanduser() if args.dest else cfg.db_path.parent.parent / "backup"
    root = config.repo_root()
    if root and config.is_inside(dest, root):
        raise config.ConfigError(f"backup folder {dest} is inside the repository")
    dest.mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = dbmod.backup(_db(cfg), dest / f"{cfg.db_path.stem}-{stamp}.sqlite3")
    out.chmod(0o600)
    old = sorted(dest.glob(f"{cfg.db_path.stem}-*.sqlite3"))[:-args.keep] if args.keep > 0 else []
    for p in old:
        p.unlink()
    print(f"database backup: {out}" + (f" (removed {len(old)} old)" if old else ""))
    print(f"evidence: rsync -a {cfg.evidence_root}/ <backup host or disk>/  (versions are never changed)")
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

    s = sub.add_parser("tools-check", help="show which tools of catalog/tools.yaml are installed; needs no config")
    s.add_argument("--packages", choices=catalog.TOOL_INSTALLS[:2],
                   help="only print the package names installed with apt or npm (for setup-kali.sh)")
    s.add_argument("--strict", action="store_true", help="exit 1 when a tool is missing")
    s.add_argument("--remote", action="store_true",
                   help="check the jump host of WSTG_DIRECT_SSH instead (needs the config)")
    s.set_defaults(func=cmd_tools_check)

    s = sub.add_parser("worker", help="run queued automatic evidence jobs (one at a time)")
    s.add_argument("--once", action="store_true", help="run what is queued, then exit")
    s.set_defaults(func=cmd_worker)

    s = sub.add_parser("collect", help="queue automatic evidence collection for a target")
    s.add_argument("target")
    s.add_argument("--mode", choices=("light", "full"), default="light")
    s.add_argument("--run", action="store_true", help="run it now in this process (no worker needed)")
    s.add_argument("--evidence", help="collect only this evidence ID")
    s.add_argument("--force", action="store_true", help="with --evidence: collect again even if collected")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("capture", help="record a browsing session as a HAR with a headful browser (M9)")
    s.add_argument("target")
    s.add_argument("--role", default="", help="a label for this session (for example anon, user, admin)")
    s.add_argument("--url", default=None, help="start URL (default: the scope base URL)")
    s.add_argument("--headless", action="store_true", help="run the browser headless (for automation/testing)")
    s.set_defaults(func=cmd_capture)

    s = sub.add_parser("ai-prompts", help="save AI prompts to <evidence>/<target>/_ai/prompts for an AI agent")
    s.add_argument("target")
    s.add_argument("--test", action="append", help="only this test (repeatable); default: every test with a scenario")
    s.add_argument("--evidence", choices=("complete", "any", "all"), default="complete",
                   help="complete: only tests whose evidence is all collected (default); any: at least one; all: every test")
    s.add_argument("--existing", choices=("skip", "overwrite"), default="skip",
                   help="what to do when a prompt file exists (default: skip)")
    s.set_defaults(func=cmd_ai_prompts)

    s = sub.add_parser("ai-import", help="import AI answers from <evidence>/<target>/_ai/answers/WSTG-*.json")
    s.add_argument("target")
    s.add_argument("--overwrite", action="store_true", help="also replace verdicts a tester set")
    s.add_argument("--findings", action="store_true", help="create the findings the AI proposes")
    s.add_argument("--actor", default="cli", help="recorded as ai:<actor> (default: cli)")
    s.set_defaults(func=cmd_ai_import)

    s = sub.add_parser("backup", help="copy the database to a backup folder (keeps the newest N)")
    s.add_argument("--dest", help="backup folder (default: <data dir>/backup)")
    s.add_argument("--keep", type=int, default=14)
    s.set_defaults(func=cmd_backup)

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
