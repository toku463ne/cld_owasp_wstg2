import json

import pytest
from conftest import csrf_of

from wstg import ai_files
from wstg import ai_review as ar
from wstg import catalog as catmod
from wstg import evidence as evmod
from wstg import findings as fmod
from wstg import targets as tm


@pytest.fixture
def env(cfg, db):
    tm.create(db, cfg, "example.com", "domain")
    t = tm.create(db, cfg, "www.example.com", "fqdn", parent="example.com")
    return t, catmod.load(), evmod.Store(cfg, db)


def test_normalize_subject():
    assert fmod.normalize_subject("  `Apache  HTTP_Server` ") == "apache http_server"
    assert fmod.normalize_subject("https://www.example.com/Uploads/.") == "https://www.example.com/uploads"


def test_one_finding_per_kind_and_subject_across_tests(db, env):
    t, cat, _ = env
    a = fmod.create(db, t, "WSTG-INFO-02", {"title": "Apache version shown", "kind": "version-disclosure",
                                            "subject": "Apache http_server"}, "admin", kinds=cat.finding_kinds)
    with pytest.raises(fmod.FindingError) as ei:
        fmod.create(db, t, "WSTG-INFO-08", {"title": "Server banner", "kind": "version-disclosure",
                                            "subject": "apache  HTTP_SERVER"}, "admin", kinds=cat.finding_kinds)
    assert ei.value.existing == a
    b = fmod.create(db, t, "WSTG-INFO-08", {"title": "PHP version", "kind": "version-disclosure",
                                            "subject": "php php"}, "admin")
    with pytest.raises(fmod.FindingError, match=f"finding {a} already covers"):
        fmod.update(db, t, b, {"title": "PHP version", "kind": "version-disclosure", "subject": "apache http_server"}, "admin")
    with pytest.raises(fmod.FindingError, match="unknown finding kind"):
        fmod.create(db, t, "WSTG-INFO-02", {"title": "x", "kind": "nope", "subject": "y"}, "admin", kinds=cat.finding_kinds)
    with pytest.raises(fmod.FindingError, match="needs a subject"):
        fmod.create(db, t, "WSTG-INFO-02", {"title": "x", "kind": "version-disclosure"}, "admin")
    # no kind: any number of findings (checked by title in AI imports only)
    fmod.create(db, t, "WSTG-INFO-02", {"title": "x", "kind": "other", "subject": "ignored"}, "admin")
    fmod.create(db, t, "WSTG-INFO-02", {"title": "x"}, "admin")


def answer(findings, test="WSTG-INFO-02"):
    return json.dumps({"wstg_review": {"test": test, "target": "www.example.com", "overall": "fail",
                                       "steps": [{"step": 1, "verdict": "-"}], "findings": findings}})


def test_ai_proposals_match_existing_findings(db, env):
    t, cat, store = env
    old = fmod.create(db, t, "WSTG-INFO-08", {"title": "Apache banner", "kind": "version-disclosure",
                                              "subject": "apache http_server"}, "admin")
    other = fmod.create(db, t, "WSTG-CRYP-01", {"title": "TLS 1.0 enabled"}, "admin")
    sc = cat.scenarios["WSTG-INFO-02"]
    review = ar.parse(answer([
        {"title": "Server header reveals Apache version", "kind": "version-disclosure", "subject": "`Apache HTTP_Server`"},
        {"title": "Same as TLS one", "kind": "other", "same_as": f"#{other}"},
        {"title": "Weird kind", "kind": "tls-weak-cipher", "subject": "x"},
        {"title": "CVE-2021-41773 in Apache", "kind": "vulnerable-component", "subject": "apache http_server 2.4.49"},
    ]), test_id=sc.id, target_name=t.name, step_count=len(sc.steps), kinds=sc.finding_kinds)
    assert review.findings[2]["kind"] == "" and "not one of this test's kinds" in review.findings[2]["note"]
    out = ar.apply(db, store, cat, t, review, "a", "admin", create_findings=True)
    assert len(out["findings_created"]) == 2          # the weird kind (title only) and the CVE
    shown = {p["title"]: p for p in ar.latest(db, t, "WSTG-INFO-02")["findings"]}
    assert (shown["Server header reveals Apache version"]["finding"], shown["Server header reveals Apache version"]["match"]) \
        == (old, "kind and subject")
    assert (shown["Same as TLS one"]["finding"], shown["Same as TLS one"]["match"]) == (other, "same_as")
    cve = fmod.get(db, t, shown["CVE-2021-41773 in Apache"]["finding"])
    assert (cve["kind"], cve["subject"], cve["created_by"]) == ("vulnerable-component", "apache http_server 2.4.49", "ai:admin")
    # importing a reworded answer again creates nothing new
    again = ar.parse(answer([{"title": "Outdated Apache with CVEs", "kind": "vulnerable-component",
                              "subject": "Apache HTTP_Server 2.4.49"}]),
                     test_id=sc.id, target_name=t.name, step_count=len(sc.steps), kinds=sc.finding_kinds)
    assert ar.apply(db, store, cat, t, again, "b", "admin", create_findings=True)["findings_created"] == []


def test_chat_prompt_shows_this_tests_findings_and_agent_prompt_all(cfg, db, env):
    t, cat, store = env
    a = fmod.create(db, t, "WSTG-INFO-02", {"title": "Apache banner", "kind": "version-disclosure",
                                            "subject": "apache http_server"}, "admin")
    b = fmod.create(db, t, "WSTG-CRYP-01", {"title": "TLS 1.0 enabled", "kind": "tls-weak-protocol",
                                            "subject": "www.example.com:443 tlsv1.0"}, "admin")
    chat = ai_files.build_prompt(cfg, db, cat, store, t, "WSTG-INFO-02")
    assert f"#{a} [WSTG-INFO-02] Apache banner" in chat and "TLS 1.0 enabled" not in chat
    assert "Findings already recorded for this test:" in chat
    assert "- vulnerable-component: Component with known vulnerabilities. Subject:" in chat
    assert '"same_as": null' in chat and '"kind": "version-disclosure"' in chat
    agent = ai_files.build_prompt(cfg, db, cat, store, t, "WSTG-INFO-02", for_file=True)
    assert "on this target (all tests):" in agent
    assert f"#{b} [WSTG-CRYP-01] TLS 1.0 enabled" in agent and "subject='www.example.com:443 tlsv1.0'" in agent


def test_finding_form_refuses_duplicates(admin_client, db, env):
    t, cat, _ = env
    a = fmod.create(db, t, "WSTG-INFO-02", {"title": "Apache banner", "kind": "version-disclosure",
                                            "subject": "apache http_server"}, "admin")
    page = admin_client.get("/t/www.example.com/findings/new?test=WSTG-INFO-08").get_data(as_text=True)
    assert 'value="version-disclosure"' in page and 'name="subject"' in page
    r = admin_client.post("/t/www.example.com/findings/new", data={
        "csrf": csrf_of(admin_client), "test": "WSTG-INFO-08", "title": "Banner", "status": "open",
        "kind": "version-disclosure", "subject": "Apache HTTP_Server"})
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and f"/t/www.example.com/findings/{a}" in page and "Duplicate" in page
    assert len(fmod.list_for(db, t)) == 1
    assert "version-disclosure: apache http_server" in admin_client.get("/t/www.example.com/findings").get_data(as_text=True)
