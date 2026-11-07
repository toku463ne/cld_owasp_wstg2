"""ERRH / BUSL / CLNT / APIT scenarios: auto-run and probe-reading steps."""
import pytest

from wstg import evidence as evmod
from wstg import targets as tm

from test_conf import BASE, page, put


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    return tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")


@pytest.fixture
def store(cfg, db):
    return evmod.Store(cfg, db)


def test_errh01_flags_stack_trace_in_probe_body(admin_client, store, site):
    put(store, site, "error-probes", {
        "stdout.txt": f"500 text/html {BASE}/api/wstg-no-such-endpoint\n",
        "bodies/api.html": "Traceback (most recent call last):\n  at com.app.Foo(Foo.java:42)\n"})
    s1 = page(admin_client, "WSTG-ERRH-01").split("Step 1")[1].split("Step 2")[0]
    assert "Traceback" in s1 or "Foo.java" in s1


# "DANGER" also appears in the command text shown on the page, so the danger branch
# firing means it appears twice (command + output), the safe case only once (command).
def test_clnt07_cors_danger_combination(admin_client, store, site):
    put(store, site, "cors-probe", {
        "stdout.txt": "HTTP/1.1 200 OK\r\n"
                      "Access-Control-Allow-Origin: https://wstg-cors-marker.example\r\n"
                      "Access-Control-Allow-Credentials: true\r\n"})
    s1 = page(admin_client, "WSTG-CLNT-07").split("Step 1")[1].split("Step 2")[0]
    assert s1.count("DANGER:") >= 2


def test_clnt07_cors_safe_when_no_credentials(admin_client, store, site):
    put(store, site, "cors-probe", {
        "stdout.txt": "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://trusted.example\r\n"})
    s1 = page(admin_client, "WSTG-CLNT-07").split("Step 1")[1].split("Step 2")[0]
    assert s1.count("DANGER:") == 1       # only in the command text, not the output


def test_clnt09_reports_missing_frame_headers(admin_client, store, site):
    put(store, site, "http-root-https", {"stdout.txt": "HTTP/1.1 200 OK\r\nServer: x\r\n", "body.html": "<html></html>"})
    s1 = page(admin_client, "WSTG-CLNT-09").split("Step 1")[1].split("Step 2")[0]
    assert "no X-Frame-Options" in s1


def test_apit01_detects_introspection(admin_client, store, site):
    put(store, site, "graphql-introspection", {
        "stdout.txt": f"200 application/json {BASE}/graphql\n404 text/html {BASE}/api/graphql\n",
        "bodies/graphql.json": '{"data":{"__schema":{"types":[{"name":"Query","kind":"OBJECT"}]}}}',
        "bodies/api-graphql.json": "not found"})
    s1 = page(admin_client, "WSTG-APIT-01").split("Step 1")[1].split("Step 2")[0]
    assert "graphql.json" in s1            # the file whose body exposed __schema


IDS = (["WSTG-ERRH-01"]
       + [f"WSTG-BUSL-{n:02d}" for n in range(1, 10)]
       + [f"WSTG-CLNT-{n:02d}" for n in range(1, 14)]
       + ["WSTG-APIT-01"])


@pytest.mark.parametrize("tid", IDS)
def test_every_page_renders(admin_client, site, tid):
    assert page(admin_client, tid).count("Step 1") >= 1
