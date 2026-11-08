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
    # a running item shows a Stop button; stopping it sets stop_seq for the worker
    with db.tx() as conn:
        conn.execute("UPDATE jobs SET status = 'running' WHERE id = ?", (job["id"],))
        conn.execute("UPDATE job_items SET status = 'running' WHERE job_id = ? AND seq = 1", (job["id"],))
    page = admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    stop_url = f"/t/www.example.com/auto/jobs/{job['id']}/items/1/stop"
    assert stop_url in page and "Stop job" in page
    assert stop_url not in guest_client.get("/t/www.example.com/auto").get_data(as_text=True)
    assert post(guest_client, stop_url).status_code == 403
    post(admin_client, f"/t/www.example.com/auto/jobs/{job['id']}/items/2/stop")   # not running: no-op
    assert rmod.last_job(db, t)["stop_seq"] is None
    post(admin_client, stop_url)
    assert rmod.last_job(db, t)["stop_seq"] == 1
    assert "stopping…" in admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    post(admin_client, f"/t/www.example.com/auto/jobs/{job['id']}/cancel")
    assert rmod.last_job(db, tm.get(db, "www.example.com"))["status"] == "cancelling"


def test_evidence_page_shows_proxy_args_and_last_failure(admin_client, db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    page = admin_client.get("/t/www.example.com/evidence/tls-cert-chain").get_data(as_text=True)
    assert "{proxy_args}" not in page and "With WSTG_HTTP_PROXY set, adds <code>-proxy {proxy_hostport}</code>" in page
    assert "cannot use WSTG_HTTP_PROXY" in admin_client.get("/t/www.example.com/evidence/tls-sslscan").get_data(as_text=True)
    with db.tx() as conn:
        conn.execute("INSERT INTO jobs (id, target_id, mode, status, created_at, created_by, finished_at)"
                     " VALUES (7, ?, 'light', 'done', 'x', 'test', '2026-06-01T00:00:00Z')", (t.id,))
        conn.execute("INSERT INTO job_items (job_id, seq, evidence_id, status, message)"
                     " VALUES (7, 0, 'tls-sslscan', 'failed', 'tool not installed: sslscan')")
    page = admin_client.get("/t/www.example.com/evidence/tls-sslscan").get_data(as_text=True)
    assert "Last attempt (job 7" in page and "tool not installed: sslscan" in page


def test_failed_collection_shows_command_and_output(admin_client, db, cfg):
    from wstg import evidence as evmod
    t = tm.create(db, cfg, "example.com", "domain")
    store = evmod.Store(cfg, db)
    tmp = store.begin(t, "dns-whois")
    (tmp / "stdout.txt").write_text("\n".join(f"line {i}" for i in range(300)))
    (tmp / "stderr.txt").write_text("whois: connect: Connection refused\n")
    items = [evmod.Item("text", "stdout.txt", "", 0, caption="stdout", mime="text/plain"),
             evmod.Item("text", "stderr.txt", "", 0, caption="stderr", mime="text/plain")]
    store.commit(t, "dns-whois", tmp, source="auto", actor="worker", status="failed", summary="failed: exit code 2",
                 items=items, extra_meta={"argv": ["whois", "example.com"], "exit_code": 2, "duration_s": 1.5,
                                          "via": "jump.example.net", "message": "exit code 2"})
    page = admin_client.get("/t/example.com/evidence/dns-whois").get_data(as_text=True)
    assert "Last failed collection: v1" in page and "whois example.com" in page and "jump.example.net" in page
    assert "exit code <b>2</b>" in page and "whois: connect: Connection refused" in page
    assert "line 299" in page and "line 50\n" not in page and "100 earlier lines" in page
    assert 'href="/t/example.com/evidence/dns-whois?v=1"' in page
    # an explicit version view does not repeat the block
    assert "Last failed collection" not in admin_client.get("/t/example.com/evidence/dns-whois?v=1").get_data(as_text=True)
    assert "#failed-log" in admin_client.get("/t/example.com/auto").get_data(as_text=True)


def test_collect_one_evidence_buttons(admin_client, guest_client, db, cfg):
    from wstg import runner as rmod
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    tm.update_scope(db, t, allowed_hosts="www.example.com", allowed_ports="80,443",
                    base_url="https://www.example.com", authorization_ref="Contract 2026-001",
                    valid_from="2000-01-01", valid_until="2099-12-31", actor="test")
    page = admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    assert "/t/www.example.com/auto/collect/http-404" in page and "is heavy" in page
    assert "/auto/collect/http-404" not in guest_client.get("/t/www.example.com/auto").get_data(as_text=True)
    assert post(guest_client, "/t/www.example.com/auto/collect/http-404").status_code == 403
    r = post(admin_client, "/t/www.example.com/auto/collect/http-404", back="evidence")
    assert r.headers["Location"].endswith("/t/www.example.com/evidence/http-404")
    job = rmod.last_job(db, t)
    assert (job["evidence_id"], job["force"], job["status"]) == ("http-404", 0, "queued")
    assert [i["evidence_id"] for i in rmod.job_items(db, job["id"])] == ["http-404"]
    page = admin_client.get("/t/www.example.com/evidence/http-404").get_data(as_text=True)
    assert "A job is running for this target" in page
    assert f"Job {job['id']} · http-404" in admin_client.get("/t/www.example.com/auto").get_data(as_text=True)
    post(admin_client, f"/t/www.example.com/auto/jobs/{job['id']}/cancel")
    post(admin_client, "/t/www.example.com/auto/collect/dns-whois")       # domain evidence on an FQDN: refused
    assert rmod.last_job(db, t)["evidence_id"] == "http-404"


def test_status_override_and_tester_review(admin_client, guest_client, db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    f = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")

    # tester sets APIT-01 (GraphQL) to "no need"
    r = post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="no need")
    assert r.status_code == 302
    assert tm.test_review(db, f, "WSTG-APIT-01")["override"] == "no need"
    page = admin_client.get("/t/www.example.com/wstg/WSTG-APIT-01").get_data(as_text=True)
    assert 'status s-noneed">no need' in page
    idx = admin_client.get("/t/www.example.com/").get_data(as_text=True)
    assert 'status s-noneed">no need' in idx

    # tester can set any status directly; it overrides the computed one
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="pass")
    assert tm.test_review(db, f, "WSTG-APIT-01")["override"] == "pass"
    assert 'status s-pass">pass' in admin_client.get("/t/www.example.com/").get_data(as_text=True)

    # an invalid status is refused (not stored)
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="bogus")
    assert tm.test_review(db, f, "WSTG-APIT-01")["override"] == "pass"

    # 'auto' (empty) clears the override, back to computed
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="")
    assert tm.test_review(db, f, "WSTG-APIT-01")["override"] == ""

    # tester review: save, keep across a status change, show to guest read-only
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/tester-review",
         review="We do not use GraphQL; confirmed with the owner.")
    assert tm.test_review(db, f, "WSTG-APIT-01")["review"].startswith("We do not use GraphQL")
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="no need")
    assert tm.test_review(db, f, "WSTG-APIT-01")["review"].startswith("We do not use GraphQL")   # kept
    gpage = guest_client.get("/t/www.example.com/wstg/WSTG-APIT-01").get_data(as_text=True)
    assert "We do not use GraphQL" in gpage and "Save tester review" not in gpage   # read-only for guest

    # clearing both removes the row
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="")
    post(admin_client, "/t/www.example.com/wstg/WSTG-APIT-01/tester-review", review="")
    assert db.one("SELECT 1 FROM test_reviews WHERE target_id = ?", (f.id,)) is None


def test_guest_cannot_set_status_or_tester_review(guest_client, db, cfg):
    tm.create(db, cfg, "www.example.com", "fqdn")
    assert post(guest_client, "/t/www.example.com/wstg/WSTG-APIT-01/status", status="no need").status_code == 403
    assert post(guest_client, "/t/www.example.com/wstg/WSTG-APIT-01/tester-review", review="x").status_code == 403


def test_status_override_rejects_merged_and_unknown_tests(admin_client, db, cfg):
    tm.create(db, cfg, "www.example.com", "fqdn")
    assert post(admin_client, "/t/www.example.com/wstg/WSTG-INPV-03/status", status="pass").status_code == 404
    assert post(admin_client, "/t/www.example.com/wstg/WSTG-NOPE-01/status", status="pass").status_code == 404
