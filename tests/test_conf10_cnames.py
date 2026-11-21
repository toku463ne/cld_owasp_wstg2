"""WSTG-CONF-10 automation: evidence inputs (ordering, rendering, re-collect),
the `wstg-dns cnames` lookup (with a fake dig), and the in-scope takeover probe.
No real DNS query or HTTP request is made."""

import json
import os
import sys

import pytest

from wstg import catalog as catmod
from wstg import dnscheck
from wstg import evidence as evmod
from wstg import runner as rmod
from wstg import takeover
from wstg import targets as tm

PY = sys.executable

# ---- fake dig -----------------------------------------------------------------
# Answers from a JSON table {"name TYPE": {"status": .., "answers": [[owner, type, rdata]]}};
# a query missing from the table gets no block (like a timeout).
FAKE_DIG = r'''#!PYTHON
import json, sys
table = json.load(open(sys.argv[0] + ".json"))
batch = sys.argv[sys.argv.index("-f") + 1]
for line in open(batch):
    name, rtype = line.split()[:2]
    r = table.get(f"{name} {rtype}")
    if r is None:
        print(";; communications error: timed out")
        continue
    print(";; Got answer:")
    print(f";; ->>HEADER<<- opcode: QUERY, status: {r['status']}, id: 1")
    print(";; QUESTION SECTION:")
    print(f";{name}.\t\t\tIN\t{rtype}")
    print()
    for owner, t, rdata in r.get("answers", []):
        print(f"{owner}.\t300\tIN\t{t}\t{rdata}.")
    print()
'''


@pytest.fixture
def fake_dig(tmp_path):
    p = tmp_path / "dig"
    p.write_text(FAKE_DIG.replace("PYTHON", PY))
    p.chmod(0o755)

    def set_table(table):
        (tmp_path / "dig.json").write_text(json.dumps(table))
    return str(p), set_table


def _ok(*answers, status="NOERROR"):
    return {"status": status, "answers": [list(a) for a in answers]}


def test_cnames_merges_sources_and_flags_dangling(tmp_path, fake_dig, capsys):
    dig, set_table = fake_dig
    crt = tmp_path / "crtsh.json"
    crt.write_text(json.dumps([{"name_value": "*.example.com\nshop.example.com"},
                               {"name_value": "WWW.example.com\nother.example.net"}]))
    sub = tmp_path / "subfinder.txt"
    sub.write_text("old.example.com\nwww.example.com\n")
    set_table({
        "example.com CNAME": _ok(),
        "www.example.com CNAME": _ok(),
        "shop.example.com CNAME": _ok(("shop.example.com", "CNAME", "shops.myshopify.com")),
        "old.example.com CNAME": _ok(("old.example.com", "CNAME", "gone-bucket.s3.amazonaws.com")),
        "shops.myshopify.com A": _ok(("shops.myshopify.com", "A", "192.0.2.10")),
        "shops.myshopify.com AAAA": _ok(),
        "gone-bucket.s3.amazonaws.com A": _ok(status="NXDOMAIN"),
        "gone-bucket.s3.amazonaws.com AAAA": _ok(status="NXDOMAIN"),
    })
    out = tmp_path / "cname-check.txt"
    rc = dnscheck.main(["cnames", "--domain", "example.com", "--crtsh", str(crt), "--subfinder", str(sub),
                        "-o", str(out), "--dig", dig])
    assert rc == 0
    text = out.read_text()
    assert "# ct-crtsh: 3 names" in text and "# subdomains-subfinder: 2 names" in text
    assert "other.example.net" not in text and "*." not in text
    assert "shop.example.com -> shops.myshopify.com\n" in text
    assert "old.example.com -> gone-bucket.s3.amazonaws.com [no address]" in text
    assert "www.example.com -> \n" in text and "example.com -> \n" in text


def test_cnames_missing_source_is_noted_and_no_source_fails(tmp_path, fake_dig):
    dig, set_table = fake_dig
    set_table({"a.example.com CNAME": _ok()})
    sub = tmp_path / "subfinder.txt"
    sub.write_text("a.example.com\n")
    out = tmp_path / "o.txt"
    assert dnscheck.main(["cnames", "--domain", "example.com", "--crtsh", str(tmp_path / "nope/crtsh.json"),
                          "--subfinder", str(sub), "-o", str(out), "--dig", dig]) == 0
    assert "# ct-crtsh: not collected (skipped)" in out.read_text()
    bad = tmp_path / "crtsh.json"
    bad.write_text("<html>503 Service Unavailable</html>")
    with pytest.raises(SystemExit) as e:
        dnscheck.main(["cnames", "--domain", "example.com", "--crtsh", str(bad),
                       "--subfinder", str(tmp_path / "nope.txt"), "--dig", dig])
    assert "ct-crtsh UNAVAILABLE" in str(e.value.code) and "nothing looked up" in str(e.value.code)


def test_cnames_lookup_failure_is_not_complete(tmp_path, fake_dig):
    dig, set_table = fake_dig
    set_table({"a.example.com CNAME": _ok()})          # b.example.com: no answer (timeout)
    sub = tmp_path / "subfinder.txt"
    sub.write_text("a.example.com\nb.example.com\n")
    out = tmp_path / "o.txt"
    assert dnscheck.main(["cnames", "--domain", "example.com", "--subfinder", str(sub),
                          "-o", str(out), "--dig", dig]) == 3
    assert not out.exists()                             # no output file: the collection fails


# ---- catalog: inputs ------------------------------------------------------------

def _ev(eid, argv=("true",), inputs=(), level="light", target_type="domain", kind="auto", **kw):
    return catmod.Evidence(id=eid, title=eid, target_type=target_type, kind=kind, level=level, passive=True,
                           argv=tuple(argv), inputs=tuple(inputs), **kw)


def test_inputs_are_validated():
    evs = {e.id: e for e in [
        _ev("a", ["x", "{ev:b}/f", "{ev:zzz}/f"], inputs=["b"]),
        _ev("b", inputs=["c"]), _ev("c", inputs=["b"]),
        _ev("d", inputs=["m", "f", "nope"]),
        catmod.Evidence(id="m", title="m", target_type="domain", kind="manual", description="x"),
        _ev("f", target_type="fqdn"),
        _ev("g", inputs=["a"], direct=True),
    ]}
    problems = []
    catmod._check_inputs(evs, problems)
    text = "\n".join(problems)
    assert "evidence a: argv reads {ev:zzz} but 'zzz' is not listed in inputs" in text
    assert "cycle" in text
    assert "input 'm' is not automatic evidence" in text
    assert "input 'f' is fqdn evidence, not readable from domain targets" in text
    assert "unknown input 'nope'" in text
    assert "evidence g: evidence with inputs cannot be direct" in text


def test_real_catalog_orders_cnames_after_subfinder():
    cat = catmod.load()
    ev = cat.evidence["subdomain-cnames"]
    assert ev.inputs == ("ct-crtsh", "subdomains-subfinder")
    t = tm.Target(id=1, name="example.com", type="domain", parent_id=None, parent_name=None,
                  description="", created_at="")
    for mode in ("light", "full"):
        ids = [e.id for e in rmod.plan(cat, t, mode)]
        assert ids.index("ct-crtsh") < ids.index("subdomain-cnames")
        if mode == "full":
            assert ids.index("subdomains-subfinder") < ids.index("subdomain-cnames")
        else:
            assert "subdomains-subfinder" not in ids


# ---- runner: inputs ---------------------------------------------------------------

@pytest.fixture
def domain(db, cfg):
    t = tm.create(db, cfg, "example.com", "domain")
    tm.update_scope(db, t, allowed_hosts="example.com", allowed_ports="443", base_url="",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    return t


READER = ("import os, sys\n"
          "p = sys.argv[1]\n"
          "print(open(p).read().strip() if os.path.exists(p) else 'missing ' + os.path.basename(os.path.dirname(p)))")


def test_job_collects_inputs_first_and_recollects_when_an_input_changes(cfg, db, domain):
    src_light = _ev("src-light", [PY, "-c", "print('L')"])
    src_full = _ev("src-full", [PY, "-c", "print('F')"], level="full")
    reader = _ev("reader", [PY, "-c", READER + "\nprint(open(sys.argv[2]).read().strip() if os.path.exists(sys.argv[2]) else 'missing full')",
                            "{ev:src-light}/stdout.txt", "{ev:src-full}/stdout.txt"],
                 inputs=["src-light", "src-full"])
    # catalog order puts the reader first; the job must still run it last
    cat = catmod.Catalog(wstg_version="4.2", tests={}, evidence={e.id: e for e in (reader, src_light, src_full)})
    store = evmod.Store(cfg, db)
    r = rmod.Runner(cfg, db, cat, store)

    def run(mode):
        job = rmod.enqueue(db, cat, domain, mode, "test")
        assert r.claim() == job
        r.run_job(job)
        return rmod.job_items(db, job)

    items = run("light")
    assert [i["evidence_id"] for i in items] == ["src-light", "reader"]
    v = store.load(domain.name, "reader")
    assert (v.path / "stdout.txt").read_text() == "L\nmissing full\n"
    assert "/src-light/v0001/stdout.txt" in " ".join(v.meta["argv"])       # the version actually read
    # full: src-full is new in this job, so the reader is collected again with it
    items = {i["evidence_id"]: i for i in run("full")}
    assert items["src-light"]["status"] == "skipped"
    assert items["reader"]["status"] == "complete" and "input src-full was updated" in items["reader"]["message"]
    assert (store.load(domain.name, "reader").path / "stdout.txt").read_text() == "L\nF\n"
    # nothing new: everything is skipped
    assert {i["status"] for i in run("full")} == {"skipped"}


# ---- takeover probe ------------------------------------------------------------------

def _cnames(store, target, text):
    tmp = store.begin(target, "subdomain-cnames")
    (tmp / "stdout.txt").write_text(text)
    (tmp / "cname-check.txt").write_text(text)
    store.commit(target, "subdomain-cnames", tmp, source="auto", actor="test", status="complete",
                 summary="collected", items=[evmod.Item("text", "stdout.txt", "", 0),
                                             evmod.Item("file", "cname-check.txt", "", 0)])


def test_takeover_probe_contacts_only_in_scope_hosts(cfg, db, domain):
    store = evmod.Store(cfg, db)
    shop = tm.create(db, cfg, "shop.example.com", "fqdn", parent="example.com")
    tm.update_scope(db, shop, allowed_hosts="shop.example.com", allowed_ports="443,80",
                    base_url="https://shop.example.com", authorization_ref="Contract 2026-001",
                    valid_from="2000-01-01", valid_until="2099-12-31", actor="test")
    expired = tm.create(db, cfg, "blog.example.com", "fqdn", parent="example.com")
    tm.update_scope(db, expired, allowed_hosts="blog.example.com", allowed_ports="443",
                    base_url="https://blog.example.com", authorization_ref="Contract 2020-001",
                    valid_from="2000-01-01", valid_until="2001-01-01", actor="test")
    _cnames(store, domain, "# ct-crtsh: 4 names\n"
                           "shop.example.com -> shops.myshopify.com\n"
                           "blog.example.com -> blog.ghost.io\n"
                           "old.example.com -> gone.s3.amazonaws.com [no address]\n"
                           "www.example.com -> \n"
                           "docs.example.com -> docs.github.io\n")
    calls = []

    def fetcher(url, proxy):
        calls.append(url)
        if url.startswith("https://"):
            raise OSError("connection refused")
        return "status 404; server -\nUNCLAIMED-RESOURCE MESSAGE: Sorry, this shop is currently unavailable\nbody: ..."

    text, plan, _ = takeover.probe(cfg, db, store, domain, actor="test", dry_run=True, fetcher=fetcher)
    assert calls == [] and "would fetch shop.example.com" in text
    text, plan, saved = takeover.probe(cfg, db, store, domain, actor="test", fetcher=fetcher)
    assert calls == ["https://shop.example.com/", "http://shop.example.com/"]      # http fallback, in scope
    assert "[https] no answer: connection refused" in text and "UNCLAIMED-RESOURCE MESSAGE" in text
    assert "blog.example.com -> blog.ghost.io\nskipped: out of scope" in text     # expired scope
    assert "docs.example.com -> docs.github.io\nskipped: out of scope" in text
    assert "old.example.com" in text and "not fetched" in text
    assert "www.example.com" not in text                                          # no CNAME
    v = store.load(domain.name, "takeover-responses")
    assert v.version == saved.version and v.items[0].file.endswith(".txt")


def test_takeover_probe_needs_a_domain_and_the_cnames(cfg, db, domain):
    store = evmod.Store(cfg, db)
    with pytest.raises(takeover.ProbeError, match="not collected"):
        takeover.probe(cfg, db, store, domain, actor="test")
    fq = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    with pytest.raises(takeover.ProbeError, match="not a domain target"):
        takeover.probe(cfg, db, store, fq, actor="test")


# ---- automatic takeover probe of an FQDN target (cname-takeover) ----------------------

def _cname_dir(tmp_path, text):
    d = tmp_path / "subdomain-cnames" / "v0001"
    d.mkdir(parents=True)
    (d / "cname-check.txt").write_text(text)
    return d


def test_takeover_fetches_only_the_target_url_when_it_has_a_live_cname(tmp_path, fake_dig, monkeypatch, capsys):
    dig, set_table = fake_dig
    set_table({})
    calls = []
    monkeypatch.setattr(takeover, "fetch", lambda url, proxy: calls.append(url) or
                        "status 404; server -\nUNCLAIMED-RESOURCE MESSAGE: NoSuchBucket\nbody: ...")
    d = _cname_dir(tmp_path, "www.example.com -> www-bucket.s3.amazonaws.com\nshop.example.com -> \n"
                             "old.example.com -> gone.s3.amazonaws.com [no address]\n")
    args = ["takeover", "--cnames", str(d), "--dig", dig]
    assert dnscheck.main(args + ["--host", "www.example.com", "--url", "https://www.example.com/"]) == 0
    out = capsys.readouterr().out
    assert calls == ["https://www.example.com/"] and "UNCLAIMED-RESOURCE MESSAGE: NoSuchBucket" in out
    assert "from subdomain-cnames: www-bucket.s3.amazonaws.com" in out
    assert dnscheck.main(args + ["--host", "shop.example.com", "--url", "https://shop.example.com/"]) == 0
    assert "has no CNAME" in capsys.readouterr().out
    assert dnscheck.main(args + ["--host", "old.example.com", "--url", "https://old.example.com/"]) == 0
    assert "DANGLING CNAME" in capsys.readouterr().out
    assert calls == ["https://www.example.com/"]                      # no request for the other two


def test_takeover_looks_up_the_cname_when_not_listed_and_fails_on_no_answer(tmp_path, fake_dig, monkeypatch, capsys):
    dig, set_table = fake_dig
    set_table({"app.example.com CNAME": _ok(("app.example.com", "CNAME", "app.herokuapp.com")),
               "app.herokuapp.com A": _ok(("app.herokuapp.com", "A", "192.0.2.20")),
               "app.herokuapp.com AAAA": _ok()})

    def refused(url, proxy):
        raise OSError("connection refused")
    monkeypatch.setattr(takeover, "fetch", refused)
    rc = dnscheck.main(["takeover", "--host", "app.example.com", "--cnames", str(tmp_path / "missing"),
                        "--url", "https://app.example.com/", "--dig", dig])
    out = capsys.readouterr().out
    assert "subdomain-cnames not collected; looked up: app.example.com -> app.herokuapp.com" in out
    assert rc == 4 and "no answer: connection refused" in out          # failed collection, retried


def test_cname_takeover_evidence_contacts_only_the_target(cfg, db):
    cat = catmod.load()
    ev = cat.evidence["cname-takeover"]
    dom = tm.create(db, cfg, "example.com", "domain")
    site = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    tm.update_scope(db, site, allowed_hosts="www.example.com", allowed_ports="443", base_url="https://www.example.com",
                    authorization_ref="Contract 2026-001", valid_from="2000-01-01", valid_until="2099-12-31",
                    actor="test")
    scope = tm.get_scope(db, site)
    values = tm.placeholder_values(cfg, site, scope) | {"out": "/tmp/x"}
    paths = rmod.input_paths(cfg, site, ev, cat)
    assert paths["subdomain-cnames"].endswith("/example.com/subdomain-cnames/latest")   # the parent's folder
    argv, _, _ = rmod.build_argv(ev, values, "", 0, paths)
    assert tm.contacted(argv, site) == [("www.example.com", None), ("www.example.com", 443)]
    tm.check_command(site, scope, argv, passive=ev.passive)             # in scope: no error
    assert ev.target_type == "fqdn" and not ev.passive and dom.type == "domain"
