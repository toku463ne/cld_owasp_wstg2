from datetime import date

import pytest

from wstg import targets as tm


def make_scope(db, t, **kw):
    args = dict(allowed_hosts=t.name, allowed_ports="80,443", base_url=f"https://{t.name}",
                authorization_ref="Contract 2026-001", valid_from="2026-01-01", valid_until="2026-12-31",
                actor="test")
    if t.type == "domain":
        args.update(allowed_ports="", base_url="")
    args.update(kw)
    tm.update_scope(db, t, **args)
    return tm.get_scope(db, t)


@pytest.mark.parametrize("bad", ["", "localhost", "-a.example.com", "a..example.com", "192.0.2.1",
                                 "a_b.example.com", "x" * 64 + ".example.com"])
def test_bad_names(bad):
    with pytest.raises(tm.TargetError):
        tm.normalize_name(bad)


def test_name_is_normalized():
    assert tm.normalize_name(" WWW.Example.COM. ") == "www.example.com"


def test_create_domain_and_fqdn(db, cfg):
    d = tm.create(db, cfg, "example.com", "domain", actor="test")
    f = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com", actor="test")
    assert f.parent_name == "example.com" and f.domain == "example.com"
    assert [t.name for t in tm.list_all(db)] == ["example.com", "www.example.com"]
    assert tm.evidence_dir(cfg, f).is_dir() and tm.evidence_dir(cfg, d).is_dir()
    s = tm.get_scope(db, f)
    assert s.allowed_hosts == ("www.example.com",) and s.allowed_ports == (80, 443)
    assert tm.scope_problems(s)  # no authorization yet


def test_fqdn_must_be_under_parent(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    with pytest.raises(tm.TargetError, match="not under"):
        tm.create(db, cfg, "www.example.org", "fqdn", parent="example.com")
    with pytest.raises(tm.TargetError, match="only an FQDN"):
        tm.create(db, cfg, "sub.example.com", "domain", parent="example.com")
    with pytest.raises(tm.TargetError, match="already exists"):
        tm.create(db, cfg, "Example.com", "domain")


def test_scope_validation(db, cfg):
    f = tm.create(db, cfg, "www.example.com", "fqdn")
    for kw, msg in [({"allowed_ports": "80,99999"}, "bad port"),
                    ({"base_url": "https://other.example.com"}, "must be www.example.com"),
                    ({"base_url": "ftp://www.example.com"}, "base URL"),
                    ({"valid_from": "2026-13-01"}, "not a valid date"),
                    ({"valid_from": "2026-12-31", "valid_until": "2026-01-01"}, "after")]:
        with pytest.raises(tm.TargetError, match=msg):
            make_scope(db, f, **kw)


def test_scope_period(db, cfg):
    f = tm.create(db, cfg, "www.example.com", "fqdn")
    s = make_scope(db, f)
    assert tm.scope_problems(s, date(2026, 6, 1)) == []
    assert "expired" in tm.scope_problems(s, date(2027, 1, 1))[0]
    assert "not valid before" in tm.scope_problems(s, date(2025, 12, 31))[0]
    s2 = make_scope(db, f, authorization_ref="")
    assert "no authorization reference" in tm.scope_problems(s2, date(2026, 6, 1))


def test_check_command(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    f = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    s = make_scope(db, f, allowed_hosts="www.example.com\n*.cdn.example.com", base_url="https://www.example.com:8443",
                   allowed_ports="80,443,8443")
    today = date(2026, 6, 1)
    ok = [["curl", "-sS", "https://www.example.com:8443/"], ["curl", "http://www.example.com/"],
          ["testssl", "www.example.com:443"], ["nmap", "www.example.com"],
          ["curl", "https://a.cdn.example.com/x.js"]]
    for argv in ok:
        tm.check_command(f, s, argv, passive=False, today=today)
    bad = [(["curl", "https://evil.example.org/"], "not in the scope"),
           (["curl", "https://www.example.com:9000/"], "port 9000"),
           (["curl", "https://cdn.example.com/"], "not in the scope"),
           (["echo", "hello"], "cannot tell")]
    for argv, msg in bad:
        with pytest.raises(tm.ScopeError, match=msg):
            tm.check_command(f, s, argv, passive=False, today=today)
    with pytest.raises(tm.ScopeError, match="expired"):
        tm.check_command(f, s, ok[0], passive=False, today=date(2027, 1, 1))


def test_domain_targets_run_passive_only(db, cfg):
    d = tm.create(db, cfg, "example.com", "domain")
    s = make_scope(db, d)
    today = date(2026, 6, 1)
    tm.check_command(d, s, ["whois", "example.com"], passive=True, today=today)
    with pytest.raises(tm.ScopeError, match="passive commands only"):
        tm.check_command(d, s, ["curl", "https://example.com/"], passive=False, today=today)
    with pytest.raises(tm.ScopeError, match="no authorization"):
        tm.check_command(d, make_scope(db, d, authorization_ref=""), ["whois", "example.com"],
                         passive=True, today=today)


def test_status():
    assert tm.status(3, {}) == "-"
    assert tm.status(3, {}, has_evidence=True) == "started"
    assert tm.status(3, {1: "pass"}) == "started"
    assert tm.status(3, {1: "pass", 2: "pass", 3: "pass"}) == "pass"
    assert tm.status(3, {1: "pass", 2: "fail"}) == "fail"
    assert tm.status(0, {}) == "-"
    assert tm.status(2, {1: "pass", 2: "pass", 5: "pass"}) == "pass"
    assert tm.status(2, {1: "pass", 7: "pass"}) == "started"  # stale step numbers are ignored


def test_verdicts(db, cfg):
    f = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.set_verdict(db, f, "WSTG-INFO-02", 1, "pass", "test")
    tm.set_verdict(db, f, "WSTG-INFO-02", 1, "fail", "test")
    tm.set_verdict(db, f, "WSTG-INFO-02", 2, "pass", "test")
    assert tm.verdicts(db, f) == {"WSTG-INFO-02": {1: "fail", 2: "pass"}}
    tm.set_verdict(db, f, "WSTG-INFO-02", 1, "-", "test")
    assert tm.verdicts(db, f, "WSTG-INFO-02") == {"WSTG-INFO-02": {2: "pass"}}
    with pytest.raises(tm.TargetError):
        tm.set_verdict(db, f, "WSTG-INFO-02", 1, "maybe", "test")


def test_bare_host_arguments_are_checked(db, cfg):
    f = tm.create(db, cfg, "www.example.com", "fqdn")
    s = make_scope(db, f)
    with pytest.raises(tm.ScopeError, match="other.example.org"):
        tm.check_command(f, s, ["nmap", "www.example.com", "other.example.org"], passive=False,
                         today=date(2026, 6, 1))


def test_every_catalog_command_passes_a_standard_scope(db, cfg, tmp_path):
    """The real catalog's active commands only contact the target on 80/443."""
    from wstg import catalog as catmod
    from wstg import runner as rmod
    cat = catmod.load()
    tm.create(db, cfg, "example.com", "domain")
    f = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    s = make_scope(db, f)
    values = dict(tm.placeholder_values(cfg, f, s), out=str(tmp_path))
    for e in cat.evidence.values():
        if e.kind != "auto" or e.target_type != "fqdn":
            continue
        for proxy in ("", "http://proxy.example.net:3128"):
            argv, run_argv, _ = rmod.build_argv(e, values, proxy)
            assert not any(catmod.PLACEHOLDER_RE.search(a) for a in run_argv), e.id
            tm.check_command(f, s, argv, passive=e.passive, today=date(2026, 6, 1))
            assert ("proxy.example.net:3128" in " ".join(run_argv)) == bool(proxy and e.proxy_args), e.id
