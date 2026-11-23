"""wstg-har source (WSTG-INFO-05 step 9): comments, secrets, internal hosts in the captures."""
from __future__ import annotations

import json

from wstg import capture as cap
from wstg import har
from wstg import prompt

SID = "s3cr3tSessionValue123"
KEY = "AKIAABCDEFGHIJKLMNOP"


def entry(url, body, ctype="text/html", cookie=True):
    return {"request": {"method": "GET", "url": url, "headers": [],
                        "cookies": [{"name": "SESSIONID", "value": SID}] if cookie else []},
            "response": {"status": 200, "headers": [{"name": "Content-Type", "value": ctype}],
                         "content": {"mimeType": ctype, "text": body}}}


def files(tmp_path):
    h = tmp_path / "001-user-20261122-101010.har"
    h.write_text(json.dumps({"log": {"entries": [
        entry("https://www.example.com/account",
              f"<html><!-- TODO remove test account before release --><!--[if IE]>x<![endif]-->"
              f"<p>hi</p><!-- session {SID} --></html>"),
        entry("https://www.example.com/app.js",
              f'var cfg = {{apiKey: "{KEY}", api: "https://api-staging.example.net/v1/", '
              f'password: "hunter2hunter2", lib: "latest.min.js"}}; // 10.1.2.3',
              "application/javascript"),
        entry("https://cdn.example.org/lib.js", "<!-- TODO third party -->", "application/javascript", cookie=False),
        entry("https://www.example.com/logo.png", "binary", "image/png"),
    ]}}))
    d = tmp_path / "002-dom-user-20261122-101010.jsonl"
    d.write_text(json.dumps({"url": "https://www.example.com/account#x",
                             "html": "<html><!-- TODO remove test account before release -->"
                                     "<!-- built by app.js: debug panel at http://intranet.corp/admin --></html>"}) + "\n")
    return h, d


def test_source_finds_hits_and_masks_values(tmp_path, capsys):
    h, d = files(tmp_path)
    assert har.main(["source", str(h), str(d), str(tmp_path / "*.jsonl")]) == 0
    out = capsys.readouterr().out
    assert SID not in out and KEY not in out and "hunter2hunter2" not in out
    assert "scanned: 2 response bodies" in out and "1 DOM snapshots" in out and "1 third-party" in out
    assert "aws-access-key:" in out and "assigned-secret:" in out
    assert "api-staging.example.net (dev/staging/test host)  @ /app.js" in out
    assert "10.1.2.3  @ /app.js" in out and "intranet.corp" in out
    assert "latest.min.js" not in out.split("## Internal")[1].split("##")[0]
    assert "TODO remove test account before release  @ /account, /account (DOM)" in out
    assert "debug panel" in out and "[only in the DOM: added by JavaScript]" in out
    assert "[if IE]" not in out and "third party" not in out
    assert "# verdict:" in out


def test_source_notes_gaps(tmp_path, capsys):
    h = tmp_path / "anon.har"
    h.write_text(json.dumps({"log": {"entries": [entry("https://www.example.com/x.png", "b", "image/png")]}}))
    har.main(["source", str(h), str(tmp_path / "*.jsonl")])
    out = capsys.readouterr().out
    assert "NOTE: the HAR holds no response bodies" in out and "NOTE: no DOM snapshots" in out


def test_source_output_may_go_to_the_prompt():
    assert prompt.masked_har_view("wstg-har source /e/har-browse/v0001/items/*.har /e/har-browse/v0001/items/*.jsonl")


def test_dom_recorder_keeps_target_pages_newest_per_url(tmp_path):
    r = cap.DomRecorder("https://www.example.com")
    r.add("https://www.example.com/a#top", "<p>1</p>")
    r.add("https://www.example.com/a", "<p>2</p>")
    r.add("https://cdn.example.org/x", "<p>other</p>")
    r.add("about:blank", "")
    p = tmp_path / "dom.jsonl"
    assert r.write(p)
    rows = [json.loads(ln) for ln in p.read_text().splitlines()]
    assert rows == [{"url": "https://www.example.com/a", "html": "<p>2</p>"}]
    assert not cap.DomRecorder("https://www.example.com").write(tmp_path / "none.jsonl")
    assert cap.dom_path_for(tmp_path / "user-1.har").name == "dom-user-1.jsonl"


def test_code_comments_skip_strings():
    js = 'var u = "https://x.example.com/a"; // TODO drop the test server\n' \
         "var t = `line // not a comment`; /* FIXME: hard-coded key */ x = 'it''s'; //plain note"
    assert [c.strip() for c in har._code_comments(js)] == [
        "TODO drop the test server", "FIXME: hard-coded key", "plain note"]
    assert [c.strip() for c in har._code_comments('a { b: url("//cdn/x"); } /* temp fix */', css=True)] == ["temp fix"]


def test_script_and_style_comments_listed_when_they_read_like_notes(tmp_path, capsys):
    h = tmp_path / "user.har"
    h.write_text(json.dumps({"log": {"entries": [
        entry("https://www.example.com/js/app.js",
              "/*! app v1 | (c) 2026 */\n// TODO remove the debug login bypass\n"
              "function f() { return 1; } // returns one\n/* @license MIT TODO */",
              "application/javascript"),
        entry("https://www.example.com/js/vendor/jquery.min.js", "// TODO in a library", "application/javascript"),
        entry("https://www.example.com/css/site.css", "/* temporary: staging banner */ a { color: red }", "text/css"),
        entry("https://www.example.com/page",
              "<html><script>var x = 1; // FIXME password check disabled</script>"
              "<script type='text/template'>// TODO template</script></html>"),
    ]}}))
    har.main(["source", str(h)])
    out = capsys.readouterr().out
    sec = out.split("## Script and style comments")[1].split("\n## ")[0]
    assert "TODO remove the debug login bypass  @ /js/app.js" in sec
    assert "temporary: staging banner  @ /css/site.css" in sec
    assert "FIXME password check disabled  @ /page" in sec
    assert "returns one" not in sec and "library" not in sec.split("(")[0] and "@license" not in sec
    assert "TODO template" not in sec
    assert "library files skipped: 1" in sec
    assert "3 script-comment" in out
