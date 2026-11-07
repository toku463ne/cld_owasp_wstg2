import json

import pytest
from conftest import csrf_of

from wstg import ai_review as ar
from wstg import catalog as catmod
from wstg import evidence as evmod
from wstg import targets as tm


def answer(steps, test="WSTG-INFO-02", target="www.example.com", overall="fail", wrap=True):
    body = {"test": test, "target": target, "overall": overall, "summary": "s",
            "steps": [{"step": n, "verdict": v, "reason": f"r{n}"} for n, v in steps]}
    js = json.dumps({"wstg_review": body} if wrap else body, indent=2)
    return f"Here is my review.\n\n```json\n{{\"example\": 1}}\n```\n\nFinal:\n```json\n{js}\n```\n"


def test_parse_finds_the_last_review_block():
    r = ar.parse(answer([(1, "PASS"), (2, None)]), test_id="WSTG-INFO-02", target_name="www.example.com",
                 step_count=3)
    assert [(s["step"], s["verdict"]) for s in r.steps] == [(1, "pass"), (2, "-")] and r.overall == "fail"
    raw = json.dumps({"steps": [{"step": 1, "verdict": "fail"}]})
    assert ar.parse(raw, test_id="WSTG-INFO-02", target_name="x", step_count=1).steps[0]["verdict"] == "fail"


@pytest.mark.parametrize("text, msg", [
    ("no json here", "no review JSON"),
    (answer([(1, "pass")], test="WSTG-INFO-03"), "for WSTG-INFO-03"),
    (answer([(1, "pass")], target="other.example.com"), "target other.example.com"),
    (answer([(4, "pass")]), "step 4 does not exist"),
    (answer([(1, "pass"), (1, "fail")]), "appears twice"),
    (answer([(1, "maybe")]), "verdict must be"),
])
def test_parse_rejects(text, msg):
    with pytest.raises(ar.ReviewError, match=msg):
        ar.parse(text, test_id="WSTG-INFO-02", target_name="www.example.com", step_count=3)


@pytest.fixture
def setup(cfg, db):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    evs = {e.id: e for e in [
        catmod.Evidence(id="note-a", title="a", target_type="fqdn", kind="manual", description="d"),
        catmod.Evidence(id="note-b", title="b", target_type="fqdn", kind="manual", description="d"),
    ]}
    sc = catmod.Scenario(id="WSTG-INFO-02", overview="o", pass_criteria="p", fail_criteria="f", steps=(
        catmod.Step(summary="one", evidence=("note-a",)),
        catmod.Step(summary="two", evidence=("note-b",)),
        catmod.Step(summary="three"),
        catmod.Step(summary="four"),
    ))
    cat = catmod.Catalog(wstg_version="4.2", tests={}, evidence=evs, scenarios={sc.id: sc})
    store = evmod.Store(cfg, db)
    store.add_text(t, "note-a", "collected", "", "admin")      # note-b stays missing
    return t, cat, store


def test_apply_rules(db, setup):
    t, cat, store = setup
    tm.set_verdict(db, t, "WSTG-INFO-02", 3, "pass", "alice")      # a tester's verdict
    text = answer([(1, "pass"), (2, "pass"), (3, "fail"), (4, "-")])
    rv = ar.parse(text, test_id="WSTG-INFO-02", target_name=t.name, step_count=4)
    out = {r["step"]: r for r in ar.apply(db, store, cat, t, rv, text, "admin")["results"]}
    assert out[1]["outcome"] == "applied"
    assert out[2]["outcome"] == "refused" and "note-b" in out[2]["note"]
    assert out[3]["outcome"] == "kept" and "alice" in out[3]["note"]
    assert out[4]["outcome"] == "no decision"
    assert tm.verdicts(db, t, "WSTG-INFO-02")["WSTG-INFO-02"] == {1: "pass", 3: "pass"}
    assert ar.setters(db, t, "WSTG-INFO-02")[1] == "ai:admin"
    # overwrite replaces the tester's verdict; a fail never needs evidence
    text = answer([(2, "fail"), (3, "fail")])
    rv = ar.parse(text, test_id="WSTG-INFO-02", target_name=t.name, step_count=4)
    ar.apply(db, store, cat, t, rv, text, "admin", overwrite=True)
    assert tm.verdicts(db, t, "WSTG-INFO-02")["WSTG-INFO-02"] == {1: "pass", 2: "fail", 3: "fail"}
    last = ar.latest(db, t, "WSTG-INFO-02")
    assert last["steps"][3]["outcome"] == "applied" and last["steps"][3]["reason"] == "r3"


def post(client, url, **data):
    data["csrf"] = csrf_of(client)
    return client.post(url, data=data)


def test_web_import(admin_client, guest_client, db, cfg):
    t = tm.create(db, cfg, "www.example.com", "fqdn")
    url = "/t/www.example.com/wstg/WSTG-INFO-02"
    page = admin_client.get(url).get_data(as_text=True)
    assert "Import an AI answer" in page and '&#34;wstg_review&#34;' in page      # the prompt asks for the block
    n = len(catmod.load().scenarios["WSTG-INFO-02"].steps)
    text = answer([(1, "fail")] + [(i, "-") for i in range(2, n + 1)])
    assert post(guest_client, url + "/ai-review", answer=text).status_code == 403
    assert admin_client.post(url + "/ai-review", data={"answer": text}).status_code in (400, 403)
    r = post(admin_client, url + "/ai-review", answer=text)
    assert r.status_code == 302
    assert tm.verdicts(db, t, "WSTG-INFO-02")["WSTG-INFO-02"] == {1: "fail"}
    page = admin_client.get(url).get_data(as_text=True)
    assert "AI review imported: 1 applied" in page and "AI: fail" in page and "r1" in page
    r = post(admin_client, url + "/ai-review", answer="nothing")
    assert "AI answer not imported" in admin_client.get(url).get_data(as_text=True)
