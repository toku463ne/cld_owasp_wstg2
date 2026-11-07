"""CONF scenarios: auto-run steps read synthetic evidence and show what they should."""
import shutil

import pytest

from wstg import evidence as evmod
from wstg import targets as tm


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    return tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")


def put(store, site, eid, files: dict[str, bytes | str]):
    tmp = store.begin(site, eid)
    items = []
    for name, data in files.items():
        p = tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        items.append(evmod.Item("file", name, "", 0, name=p.name))
    return store.commit(site, eid, tmp, source="auto", actor="test", summary="collected", items=items)


def page(client, test_id):
    return client.get(f"/t/www.example.com/wstg/{test_id}").get_data(as_text=True)


NOT_FOUND = "<html>Not here</html>"
BASE = "https://www.example.com"


@pytest.fixture
def common(cfg, db, site):
    store = evmod.Store(cfg, db)
    put(store, site, "http-404", {"stdout.txt": "HTTP/1.1 404 Not Found\r\n", "body.html": NOT_FOUND})
    return store


def test_conf02_finds_default_pages_and_listings(admin_client, common, site):
    put(common, site, "default-content", {
        "stdout.txt": f"200 900 text/html {BASE}/server-status\n404 21 text/html {BASE}/info.php\n200 300 text/html {BASE}/images/\n",
        "paths/server-status.html": "<h1>Apache Server Status for www.example.com</h1>Apache Status",
        "paths/images.html": "<html><title>Index of /images</title></html>",
        "paths/info.php.html": NOT_FOUND})
    p = page(admin_client, "WSTG-CONF-02")
    assert "default 404: HTTP/1.1 404 Not Found, 21 bytes" in p
    assert "server-status.html:Apache Status" in p                  # step 2
    assert "images.html" in p.split("Step 3")[1].split("Step 4")[0]  # step 3


def test_conf03_04_report_source_and_repository_files_by_name_only(admin_client, common, site):
    put(common, site, "backup-files", {
        "stdout.txt": f"200 23 text/plain {BASE}/.git/HEAD\n200 40 text/plain {BASE}/.env\n404 21 text/html {BASE}/dump.sql\n",
        "files/git-HEAD": "ref: refs/heads/main\n",
        "files/env": "DB_PASSWORD=SECRET-VALUE-1\n",
        "files/dump.sql": NOT_FOUND})
    for tid in ("WSTG-CONF-03", "WSTG-CONF-04"):
        p = page(admin_client, tid)
        assert f"200 23 text/plain {BASE}/.git/HEAD" in p and "dump.sql\n" not in p.split("Step 2")[1].split("Step 3")[0]
        assert "git-HEAD" in p
        assert "SECRET-VALUE-1" not in p
    step3 = page(admin_client, "WSTG-CONF-03").split("Step 3")[1].split("Step 4")[0]
    assert "<pre>env\ngit-HEAD\n" in step3          # file names, not content


def test_conf06_reads_methods_trace_and_override(admin_client, common, site):
    put(common, site, "http-methods", {
        "stdout.txt": (f"OPTIONS 200 {BASE}/\nOPTIONS * 400 {BASE}/\nTRACE 200 {BASE}/\nHEAD 200 {BASE}/\nWSTGX 501 {BASE}/\n"
                       f"POST (no override) 200 {BASE}/\nPOST X-HTTP-Method-Override=WSTGX 501 {BASE}/\n"),
        "options.txt": "HTTP/1.1 200 OK\r\nAllow: GET, POST, TRACE, PUT\r\n",
        "options-star.txt": "HTTP/1.1 400 Bad Request\r\n",
        "trace.txt": "HTTP/1.1 200 OK\r\n",
        "trace-body.txt": "TRACE / HTTP/1.1\r\nX-WSTG-Trace: wstg-xst-marker\r\n",
        "unknown-method.txt": "HTTP/1.1 501\r\n"})
    p = page(admin_client, "WSTG-CONF-06")
    assert "Allow: GET, POST, TRACE, PUT" in p
    assert "TRACE echoed the marker header: TRACE is on" in p
    assert "POST X-HTTP-Method-Override=WSTGX 501" in p.split("Step 3")[1].split("Step 4")[0]


def test_conf07_reads_hsts(admin_client, common, site):
    put(common, site, "http-root-https", {"stdout.txt": "HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=86400; includeSubDomains\r\n",
                                          "body.html": "<html></html>"})
    put(common, site, "http-root-http", {"stdout.txt": "HTTP/1.1 301 Moved\r\nLocation: https://www.example.com/\r\n",
                                         "body.html": ""})
    p = page(admin_client, "WSTG-CONF-07")
    assert "max-age=86400 (1 days) includeSubDomains" in p
    assert "Location: https://www.example.com/" in p and "none on plain HTTP" in p


def test_conf10_fqdn_steps_and_conf11_storage_urls(admin_client, common, site):
    put(common, site, "dns-fqdn", {"stdout.txt": "www.example.com. 300 IN CNAME example-site.s3-website-us-east-1.amazonaws.com.\n"})
    put(common, site, "http-root-https", {"stdout.txt": "HTTP/1.1 404\r\n",
                                          "body.html": "<Error><Code>NoSuchBucket</Code></Error>"})
    put(common, site, "site-assets", {"site/js/app.js": 'var u="https://example-assets.s3.amazonaws.com/img/a.png?X-Amz-Signature=abc";'})
    p = page(admin_client, "WSTG-CONF-10")
    assert "s3-website-us-east-1.amazonaws.com" in p and "NoSuchBucket" in p
    p = page(admin_client, "WSTG-CONF-11")
    assert "https://example-assets.s3.amazonaws.com/img/a.png" in p and "X-Amz-Signature=abc" not in p.split("Step 1")[1].split("Step 2")[0]


@pytest.mark.skipif(not shutil.which("jq"), reason="jq not installed")
def test_conf04_05_read_ffuf_and_admin_titles(admin_client, common, site):
    import json
    put(common, site, "content-ffuf", {"ffuf-content.json": json.dumps({"results": [
        {"status": 200, "length": 512, "url": f"{BASE}/old/"}, {"status": 302, "length": 0, "url": f"{BASE}/admin"}]})})
    put(common, site, "ports-web-common", {"nmap-web.txt": "443/tcp open https\n8443/tcp open https-alt\n"})
    put(common, site, "admin-paths", {"stdout.txt": f"200 800 text/html {BASE}/phpmyadmin/\n",
                                      "paths/phpmyadmin.html": '<title>phpMyAdmin</title><input type="password" name="pma_password">'})
    p = page(admin_client, "WSTG-CONF-04")
    assert f"200\t512\t{BASE}/old/" in p
    p = page(admin_client, "WSTG-CONF-05")
    assert "phpmyadmin.html:&lt;title&gt;phpMyAdmin" in p
    assert f"302\t0\t{BASE}/admin" in p and "8443/tcp open" in p

