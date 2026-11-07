from conftest import csrf_of

from wstg import findings as fm
from wstg import targets as tm

VEC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data)


def test_model_dates_and_validation(db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    fid = fm.create(db, t, "WSTG-INFO-02", {"title": "Server version disclosed", "cvss_vector": VEC.replace("CVSS:3.1/", "")}, "a")
    f = fm.get(db, t, fid)
    assert f["cvss_vector"] == VEC and f["cvss"]["score"] == 5.3 and f["closed_at"] is None
    fm.update(db, t, fid, dict(f, status="closed"), "a")
    closed = fm.get(db, t, fid)["closed_at"]
    assert closed
    fm.update(db, t, fid, dict(f, status="in progress"), "a")
    assert fm.get(db, t, fid)["closed_at"] is None
    for bad, msg in [({"title": ""}, "needs a title"), ({"title": "x", "status": "done"}, "status"),
                     ({"title": "x", "cvss_vector": "AV:Q"}, "CVSS vector")]:
        try:
            fm.create(db, t, "WSTG-INFO-02", bad, "a")
            raise AssertionError("expected an error")
        except fm.FindingError as e:
            assert msg in str(e)
    assert "severity" not in db.one("SELECT * FROM findings")  # never stored


def test_web_create_list_edit(admin_client, guest_client, db, cfg):
    tm.create(db, cfg, "www.example.com", "fqdn")
    base = "/t/www.example.com"
    assert guest_client.get(base + "/findings/new?test=WSTG-INFO-02").status_code == 403
    r = post(admin_client, base + "/findings/new?test=WSTG-INFO-02", title="Server version disclosed",
             status="open", summary="Server: Apache/2.4.49", cvss_vector=VEC)
    assert r.status_code == 302
    fid = int(r.headers["Location"].rsplit("/", 1)[1])
    lst = admin_client.get(base + "/findings").get_data(as_text=True)
    assert "Server version disclosed" in lst and "5.3 Medium" in lst and "WSTG-INFO-02" in lst
    page = admin_client.get(base + "/wstg/WSTG-INFO-02").get_data(as_text=True)
    assert "Server version disclosed" in page and "Create finding" in page
    assert post(guest_client, f"{base}/findings/{fid}", title="x").status_code == 403
    assert guest_client.get(f"{base}/findings/{fid}").status_code == 200
    post(admin_client, f"{base}/findings/{fid}", title="Server version disclosed", status="closed", cvss_vector=VEC)
    assert "closed " in admin_client.get(f"{base}/findings/{fid}").get_data(as_text=True)
    j = admin_client.get("/api/cvss?vector=" + VEC).json
    assert j["score"] == 5.3 and j["severity"] == "Medium"
    assert admin_client.get("/api/cvss?vector=bad").status_code == 400
