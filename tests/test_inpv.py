"""INPV scenarios: auto-run steps surface injection candidates and the Host-header probe."""
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


def test_inpv01_lists_parameters_from_the_crawl(admin_client, store, site):
    put(store, site, "katana-crawl", {"katana.txt": f"{BASE}/search?q=a&page=2\n{BASE}/view?q=b\n"})
    s1 = page(admin_client, "WSTG-INPV-01").split("Step 1")[1].split("Step 2")[0]
    assert "q" in s1 and "page" in s1          # parameter names surfaced


def test_inpv19_lists_url_taking_params_only(admin_client, store, site):
    put(store, site, "katana-crawl", {"katana.txt": f"{BASE}/fetch?url=http://x&id=1\n{BASE}/p?image=a.png\n"})
    s1 = page(admin_client, "WSTG-INPV-19").split("Step 1")[1].split("Step 2")[0]
    assert "url=" in s1 and "image=" in s1
    assert "&amp;id=1" not in s1 and "id=1" not in s1   # id is not URL-taking


def test_inpv17_host_header_probe_reflection(admin_client, store, site):
    put(store, site, "host-header-probe", {
        "stdout.txt": "HTTP/1.1 302 Found\r\nLocation: http://wstg-host-marker.example/login\r\n",
        "body.html": "<a href='http://example.com/'>home</a>"})
    s1 = page(admin_client, "WSTG-INPV-17").split("Step 1")[1].split("Step 2")[0]
    assert "wstg-host-marker" in s1            # the forged Host was reflected into Location


IDS = [f"WSTG-INPV-{n:02d}" for n in range(1, 20) if n != 3]


@pytest.mark.parametrize("tid", IDS)
def test_every_inpv_page_renders(admin_client, site, tid):
    assert page(admin_client, tid).count("Step 1") >= 1


def test_inpv03_is_merged(admin_client, site):
    # INPV-03 (HTTP verb tampering) is merged into CONF-06 in WSTG v4.2
    r = admin_client.get("/t/www.example.com/wstg/WSTG-INPV-03", follow_redirects=False)
    assert r.status_code in (301, 302) and "WSTG-CONF-06" in r.headers.get("Location", "")
