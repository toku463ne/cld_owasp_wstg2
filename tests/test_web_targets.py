from conftest import csrf_of

from wstg import targets as tm


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data)


def test_guest_cannot_create_or_judge(guest_client, db, cfg):
    assert guest_client.get("/targets/new").status_code == 403
    assert post(guest_client, "/targets/new", name="example.com", type="domain").status_code == 403
    tm.create(db, cfg, "www.example.com", "fqdn")
    assert guest_client.get("/t/www.example.com/").status_code == 200
    r = post(guest_client, "/t/www.example.com/wstg/WSTG-INFO-02/steps/1", verdict="pass")
    assert r.status_code == 403
    r = post(guest_client, "/t/www.example.com/settings", authorization_ref="x")
    assert r.status_code == 403
    assert tm.verdicts(db, tm.get(db, "www.example.com")) == {}


def test_create_and_browse(admin_client, db):
    r = post(admin_client, "/targets/new", name="example.com", type="domain")
    assert r.status_code == 302
    r = post(admin_client, "/targets/new", name="www.example.com", type="fqdn", parent="example.com")
    assert r.headers["Location"].endswith("/t/www.example.com/settings")
    assert admin_client.get("/").headers["Location"].endswith("/t/www.example.com/")

    page = admin_client.get("/t/www.example.com/").get_data(as_text=True)
    assert "WSTG-INFO-02" in page and "Fingerprint Web Server" in page
    assert "WSTG-INFO-01" not in page          # domain-only test
    assert "owasp.org/www-project-web-security-testing-guide/v42/" in page
    assert "scope record does not allow commands" in page

    domain_page = admin_client.get("/t/example.com/").get_data(as_text=True)
    assert "WSTG-INFO-01" in domain_page and "WSTG-INFO-02" not in domain_page

    for tab in ("findings", "manual", "auto", "settings"):
        assert admin_client.get(f"/t/www.example.com/{tab}").status_code == 200


def test_wstg_page_and_verdicts(admin_client, db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    page = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-03").get_data(as_text=True)
    assert "Step 1" in page and "Copy AI prompt" in page
    assert "https://www.example.com" in page                     # {base_url} rendered
    assert str(cfg.evidence_root / "www.example.com" / "metafiles" / "latest") in page   # {ev:ID}

    r = post(admin_client, "/t/www.example.com/wstg/WSTG-INFO-03/steps/1", verdict="fail")
    assert r.status_code == 302 and r.headers["Location"].endswith("#step-1")
    idx = admin_client.get("/t/www.example.com/").get_data(as_text=True)
    assert 'status s-fail">fail' in idx
    post(admin_client, "/t/www.example.com/wstg/WSTG-INFO-03/steps/1", verdict="pass", reset="1")
    assert tm.verdicts(db, tm.get(db, "www.example.com")) == {}
    assert post(admin_client, "/t/www.example.com/wstg/WSTG-INFO-03/steps/99", verdict="pass").status_code == 404


def test_merged_test_redirects(admin_client, db, cfg):
    tm.create(db, cfg, "www.example.com", "fqdn")
    r = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-09")
    assert r.headers["Location"].endswith("/wstg/WSTG-INFO-08")
    assert admin_client.get("/t/www.example.com/wstg/WSTG-NOPE-01").status_code == 404
    assert admin_client.get("/t/nope.example.com/").status_code == 404


def test_scope_settings(admin_client, db, cfg):
    tm.create(db, cfg, "www.example.com", "fqdn")
    r = post(admin_client, "/t/www.example.com/settings", description="Main site",
             authorization_ref="Contract 2026-001", valid_from="2026-01-01", valid_until="2099-12-31",
             base_url="https://www.example.com", allowed_hosts="www.example.com", allowed_ports="443")
    assert r.status_code == 302
    s = tm.get_scope(db, tm.get(db, "www.example.com"))
    assert s.allowed_ports == (443,) and s.authorization_ref == "Contract 2026-001"
    page = admin_client.get("/t/www.example.com/settings").get_data(as_text=True)
    assert "allows commands today" in page
    r = post(admin_client, "/t/www.example.com/settings", base_url="https://evil.example.org",
             allowed_hosts="www.example.com", allowed_ports="443")
    assert r.status_code == 200 and "base URL host must be" in r.get_data(as_text=True)
    assert tm.get_scope(db, tm.get(db, "www.example.com")).base_url == "https://www.example.com"


def test_auto_collect_queue_and_cancel(admin_client, guest_client, db, cfg):
    from wstg import runner as rmod
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    # no scope yet: the button is disabled and the server refuses to queue
    page = admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    assert "Collect is disabled until the scope record is complete" in page
    post(admin_client, "/t/www.example.com/auto/collect", mode="light")
    assert rmod.last_job(db, t) is None
    assert "set the scope record" in admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="80,443",
                    base_url="https://www.example.com", authorization_ref="Contract 2026-001",
                    valid_from="2000-01-01", valid_until="2099-12-31", actor="test")
    assert post(guest_client, "/t/www.example.com/auto/collect", mode="light").status_code == 403
    r = post(admin_client, "/t/www.example.com/auto/collect", mode="light")
    assert r.status_code == 302
    job = rmod.last_job(db, tm.get(db, "www.example.com"))
    assert job["status"] == "queued" and job["mode"] == "light"
    page = admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    assert f"Job {job['id']}" in page and "Waiting for the worker" in page and 'http-equiv="refresh"' in page
    assert "nikto" not in [i["evidence_id"] for i in rmod.job_items(db, job["id"])]
    post(admin_client, f"/t/www.example.com/auto/jobs/{job['id']}/cancel")
    assert rmod.last_job(db, tm.get(db, "www.example.com"))["status"] == "cancelled"
