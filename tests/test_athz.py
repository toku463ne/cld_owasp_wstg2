"""ATHZ scenarios: auto-run steps surface candidate parameters from collected evidence."""
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


def test_athz01_lists_file_naming_parameters_from_the_crawl(admin_client, store, site):
    put(store, site, "katana-crawl", {
        "katana.txt": f"{BASE}/view?file=report.pdf\n{BASE}/page?id=7\n{BASE}/doc?template=home\n"})
    s1 = page(admin_client, "WSTG-ATHZ-01").split("Step 1")[1].split("Step 2")[0]
    assert "file=report.pdf" in s1 and "template=home" in s1
    assert "id=7" not in s1                      # id= is not a file-naming parameter


def test_athz04_lists_object_reference_params_and_numeric_paths(admin_client, store, site):
    put(store, site, "katana-crawl", {
        "katana.txt": f"{BASE}/orders/1001\n{BASE}/account?id=42\n{BASE}/assets/logo\n"})
    s1 = page(admin_client, "WSTG-ATHZ-04").split("Step 1")[1].split("Step 2")[0]
    assert "id=42" in s1 and "/orders/1001" in s1
    assert "/assets/logo" not in s1              # not a numeric reference


@pytest.mark.parametrize("tid", [f"WSTG-ATHZ-{n:02d}" for n in range(1, 5)])
def test_every_athz_page_renders(admin_client, site, tid):
    assert page(admin_client, tid).count("Step 1") >= 1
