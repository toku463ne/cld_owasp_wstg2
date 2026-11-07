import json

import pytest
from conftest import csrf_of

from wstg import ai_files
from wstg import ai_review as ar
from wstg import catalog as catmod
from wstg import evidence as evmod
from wstg import findings as fmod
from wstg import targets as tm

FINDINGS = [
    {"title": "Server version disclosed", "steps": [1, 3, 99], "summary": "Server: Apache/2.4.49",
     "impact": "helps attackers", "reproduction": "curl -I", "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "cvss_rationale": "AV:N network"},
    {"title": "Known CVE", "steps": "4", "cvss_vector": "not a vector"},
]


def review(test="WSTG-INFO-02", target="www.example.com", verdicts=("fail", "-", "-", "fail", "-"), findings=None):
    return {"wstg_review": {"test": test, "target": target, "overall": "fail", "summary": "s",
                            "steps": [{"step": i, "verdict": v, "reason": "r"} for i, v in enumerate(verdicts, 1)],
                            "findings": FINDINGS if findings is None else findings}}


@pytest.fixture
def env(cfg, db):
    tm.create(db, cfg, "example.com", "domain")
    t = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    return t, catmod.load(), evmod.Store(cfg, db)


def test_parse_findings_validates_vectors_and_steps():
    r = ar.parse(json.dumps(review()), test_id="WSTG-INFO-02", target_name="www.example.com", step_count=5)
    a, b = r.findings
    assert a["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" and a["steps"] == [1, 3]
    assert b["cvss_vector"] == "" and "CVSS vector dropped" in b["note"] and b["steps"] == [4]
    with pytest.raises(ar.ReviewError, match="no title"):
        ar.parse(json.dumps(review(findings=[{"summary": "x"}])), test_id="WSTG-INFO-02",
                 target_name="www.example.com", step_count=5)


def test_save_prompts_for_an_agent(cfg, db, env):
    t, cat, store = env
    paths = ai_files.save_prompts(cfg, db, cat, store, t)
    names = {p.name for p in paths}
    assert "WSTG-INFO-02.md" in names and "WSTG-INFO-01.md" not in names     # INFO-01 is for domains
    base = cfg.evidence_root / "www.example.com" / "_ai"
    text = (base / "prompts" / "WSTG-INFO-02.md").read_text()
    assert f"Write the JSON object above, filled in, to {base}/answers/WSTG-INFO-02.json" in text
    assert "- http-404: not collected" in text and '"findings"' in text
    assert "answers/WSTG-XXXX-NN.json" in (base / "README.md").read_text()
    assert (base / "answers").is_dir()


def test_import_answers_in_bulk(cfg, db, env):
    t, cat, store = env
    d = cfg.evidence_root / "www.example.com" / "_ai" / "answers"
    d.mkdir(parents=True)
    (d / "WSTG-INFO-02.json").write_text(json.dumps(review()))
    (d / "WSTG-INFO-03.json").write_text("I could not decide.")
    (d / "WSTG-INFO-01.json").write_text(json.dumps(review(test="WSTG-INFO-01")))
    (d / "notes.json").write_text("{}")                                   # ignored: not a test name
    res = {r["file"]: r for r in ai_files.import_answers(cfg, db, cat, store, t, "admin", create_findings=True)}
    assert set(res) == {"WSTG-INFO-01.json", "WSTG-INFO-02.json", "WSTG-INFO-03.json"}
    assert res["WSTG-INFO-02.json"]["status"] == "imported" and "2 created" in res["WSTG-INFO-02.json"]["message"]
    assert res["WSTG-INFO-03.json"]["status"] == "error" and "no review JSON" in res["WSTG-INFO-03.json"]["message"]
    assert "no scenario for fqdn" in res["WSTG-INFO-01.json"]["message"]
    assert tm.verdicts(db, t, "WSTG-INFO-02")["WSTG-INFO-02"] == {1: "fail", 4: "fail"}
    fs = fmod.list_for(db, t, "WSTG-INFO-02")
    assert sorted(f["title"] for f in fs) == ["Known CVE", "Server version disclosed"]
    assert {f["created_by"] for f in fs} == {"ai:admin"}
    assert "CVSS vector dropped" in next(f for f in fs if f["title"] == "Known CVE")["cvss_rationale"]
    # the same file again is skipped; a new answer with the same finding titles creates none
    again = {r["file"]: r for r in ai_files.import_answers(cfg, db, cat, store, t, "admin", create_findings=True)}
    assert again["WSTG-INFO-02.json"]["status"] == "skipped"
    (d / "WSTG-INFO-02.json").write_text(json.dumps(review(verdicts=("fail", "-", "-", "pass", "-"))))
    again = {r["file"]: r for r in ai_files.import_answers(cfg, db, cat, store, t, "admin", create_findings=True)}
    assert "0 created" in again["WSTG-INFO-02.json"]["message"]
    assert len(fmod.list_for(db, t, "WSTG-INFO-02")) == 2


def test_web_bulk_and_create_finding(admin_client, guest_client, cfg, db, env):
    t, cat, store = env
    tok = csrf_of(admin_client)
    page = admin_client.get("/t/www.example.com/").get_data(as_text=True)
    assert "Save all AI prompts" in page and "Import AI answers (0 files)" in page
    assert "Save all AI prompts" not in guest_client.get("/t/www.example.com/").get_data(as_text=True)
    assert guest_client.post("/t/www.example.com/ai/prompts", data={"csrf": csrf_of(guest_client)}).status_code == 403
    assert admin_client.post("/t/www.example.com/ai/prompts", data={"csrf": tok}).status_code == 302
    assert (cfg.evidence_root / "www.example.com" / "_ai" / "prompts" / "WSTG-INFO-02.md").is_file()
    r = admin_client.post("/t/www.example.com/wstg/WSTG-INFO-02/ai-prompt/save", data={"csrf": tok})
    assert r.status_code == 302
    (cfg.evidence_root / "www.example.com" / "_ai" / "answers" / "WSTG-INFO-02.json").write_text(json.dumps(review()))
    assert "Import AI answers (1 file)" in admin_client.get("/t/www.example.com/").get_data(as_text=True)
    admin_client.post("/t/www.example.com/ai/answers", data={"csrf": tok})   # findings not ticked
    assert fmod.list_for(db, t, "WSTG-INFO-02") == []
    page = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-02").get_data(as_text=True)
    assert "Findings proposed by the AI" in page and "Server version disclosed" in page and "Save AI prompt" in page
    rid = ar.latest(db, t, "WSTG-INFO-02")["id"]
    url = f"/t/www.example.com/wstg/WSTG-INFO-02/ai-review/{rid}/findings/0"
    assert guest_client.post(url, data={"csrf": csrf_of(guest_client)}).status_code == 403
    r = admin_client.post(url, data={"csrf": tok})
    assert r.status_code == 302 and "/findings/" in r.headers["Location"]
    admin_client.post(url, data={"csrf": tok})                          # twice: still one finding
    fs = fmod.list_for(db, t, "WSTG-INFO-02")
    assert [f["title"] for f in fs] == ["Server version disclosed"] and fs[0]["cvss"]["severity"]
    page = admin_client.get("/t/www.example.com/wstg/WSTG-INFO-02").get_data(as_text=True)
    assert f'/findings/{fs[0]["id"]}">created</a>' in page
    assert admin_client.post(f"/t/www.example.com/wstg/WSTG-INFO-02/ai-review/{rid}/findings/9",
                             data={"csrf": tok}).status_code == 302          # flashes "no such"


def test_cli_ai_prompts_and_import(cfg, db, env, monkeypatch, capsys):
    from wstg import cli
    t, cat, store = env
    monkeypatch.setattr(cli, "_cfg", lambda: cfg)
    assert cli.main(["ai-prompts", "www.example.com", "--test", "WSTG-INFO-02"]) == 0
    assert "WSTG-INFO-02.md" in capsys.readouterr().out
    d = cfg.evidence_root / "www.example.com" / "_ai" / "answers"
    (d / "WSTG-INFO-02.json").write_text(json.dumps(review()))
    assert cli.main(["ai-import", "www.example.com", "--findings"]) == 0
    assert "imported" in capsys.readouterr().out
    assert len(fmod.list_for(db, t, "WSTG-INFO-02")) == 2
