import io
import os

import pytest
from conftest import csrf_of

from wstg import evidence as evmod
from wstg import targets as tm

PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 32
JPG = b"\xff\xd8\xff\xe0" + b"\0" * 32


@pytest.fixture
def store(cfg, db):
    return evmod.Store(cfg, db)


@pytest.fixture
def site(db, cfg):
    tm.create(db, cfg, "example.com", "domain")
    return tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")


def test_versions_are_snapshots_and_kept(store, site):
    v1 = store.add_images(site, "har-browse", [(PNG, "login"), (JPG, "menu")], "admin")
    assert v1.version == 1 and [i.type for i in v1.items] == ["image", "image"]
    v2 = store.add_text(site, "har-browse", "flows: login, search", "notes", "admin")
    v3 = store.edit_item(site, "har-browse", 2, text="flows: login, search, logout", actor="admin")
    v4 = store.remove_item(site, "har-browse", 0, "admin")
    assert [v.version for v in (v2, v3, v4)] == [2, 3, 4]
    assert len(v4.items) == 2 and v4.items[0].caption == "menu"
    # older versions are unchanged
    old = store.load(site.name, "har-browse", 2)
    assert (old.path / old.items[2].file).read_text() == "flows: login, search"
    assert (v3.path / v3.items[2].file).read_text() == "flows: login, search, logout"
    assert len(store.load(site.name, "har-browse", 1).items) == 2
    # unchanged files are shared (hard links), latest points to v4
    assert os.path.samefile(v1.path / v1.items[1].file, v4.path / v4.items[0].file)
    assert os.readlink(store.folder(site.name, "har-browse") / "latest") == "v0004"
    assert store.load(site.name, "har-browse").version == 4
    assert [h["version"] for h in store.history(site, "har-browse")] == [4, 3, 2, 1]


def test_rejects_bad_input(store, site):
    with pytest.raises(evmod.EvidenceError, match="PNG and JPEG"):
        store.add_images(site, "har-browse", [(b"<svg onload=alert(1)>", "x")], "admin")
    with pytest.raises(evmod.EvidenceError, match="empty"):
        store.add_text(site, "har-browse", "  \n", "", "admin")
    with pytest.raises(evmod.EvidenceError, match="no such item"):
        store.remove_item(site, "har-browse", 0, "admin")
    assert store.load(site.name, "har-browse") is None
    assert not store.folder(site.name, "har-browse").exists()


def test_failed_index_leaves_no_version(store, site, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("disk full")
    monkeypatch.setattr(store.db, "audit", boom)
    with pytest.raises(RuntimeError):
        store.add_text(site, "har-browse", "x", "", "admin")
    folder = store.folder(site.name, "har-browse")
    assert sorted(p.name for p in folder.iterdir()) == []
    assert store.history(site, "har-browse") == []


def test_file_names_are_safe(store, site):
    v = store.add_file(site, "har-browse", b"data", "../../etc/passwd", "", "admin")
    assert v.items[0].file == "items/001-passwd" and v.items[0].name == "passwd"
    with pytest.raises(evmod.EvidenceError):
        store.file_path(v, "../meta.json")


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data, content_type="multipart/form-data")


def test_web_capture_upload_and_serve(admin_client, guest_client, site, cfg):
    url = "/t/www.example.com/evidence/har-browse"
    r = post(admin_client, url + "/images", image=[(io.BytesIO(PNG), "a.png"), (io.BytesIO(JPG), "b.jpg")],
             caption=["first", "second"])
    assert r.status_code == 200 and r.json["version"] == 1
    r = post(admin_client, url + "/file", file=(io.BytesIO(b"<script>alert(1)</script>"), "x.html"), caption="har")
    assert r.status_code == 302
    page = admin_client.get(url).get_data(as_text=True)
    assert "first" in page and "x.html" in page and "Version 2" in page

    img = admin_client.get(url + "/v/2/items/001.png")
    assert img.status_code == 200 and img.mimetype == "image/png"
    f = admin_client.get(url + "/v/2/items/003-x.html")
    assert f.mimetype == "application/octet-stream" and "attachment" in f.headers["Content-Disposition"]
    assert "sandbox" in f.headers["Content-Security-Policy"]
    assert admin_client.get(url + "/v/2/meta.json").status_code == 404

    # guests can read but not write
    assert guest_client.get(url).status_code == 200
    r = post(guest_client, url + "/text", text="x")
    assert r.status_code == 403

    # the index shows the test as started, the WSTG page shows the collection
    idx = admin_client.get("/t/www.example.com/").get_data(as_text=True)
    assert 'href="/t/www.example.com/wstg/WSTG-INFO-06"' in idx
    assert 'status s-started">started' in idx
    wp = admin_client.get("/t/www.example.com/wstg/WSTG-CRYP-03").get_data(as_text=True)
    assert "v2 · 3 item(s)" in wp


def test_domain_evidence_is_owned_by_the_domain(admin_client, site):
    r = admin_client.get("/t/www.example.com/evidence/search-dorks")
    assert r.status_code == 302 and r.headers["Location"].endswith("/t/example.com/evidence/search-dorks")
    r = post(admin_client, "/t/www.example.com/evidence/search-dorks/text", text="x")
    assert r.status_code == 400
    assert post(admin_client, "/t/example.com/evidence/search-dorks/text", text="no results").status_code == 302
    page = admin_client.get("/t/www.example.com/manual").get_data(as_text=True)
    assert "from example.com" in page and "v1 · 1 item(s)" in page
    assert admin_client.get("/t/example.com/evidence/har-browse").status_code == 404


def test_ai_prompt_includes_evidence_excerpts(admin_client, store, site):
    store.add_text(site, "har-browse", "flows: login, search", "flows covered", "admin")
    store.add_file(site, "har-browse", b'{"log": {"entries": []}}', "walk.har", "", "admin")
    page = admin_client.get("/t/www.example.com/wstg/WSTG-CRYP-03").get_data(as_text=True)
    prompt = page[page.index('id="ai-prompt"'):]
    assert "flows: login, search" in prompt
    assert "HAR file walk.har: summary without values" in prompt and "&#34;entries&#34;: []" not in prompt
    assert "NOT COLLECTED" in prompt


def test_ai_task_step_goes_into_the_prompt(admin_client, site):
    page = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-02").get_data(as_text=True)
    assert "Judged by the AI review." in page
    prompt = page[page.index('id="ai-prompt"'):]
    assert "YOUR TASK for this step: From the evidence of steps 1 to 3" in prompt
