"""Unit tests for the value-free HAR analyser (src/wstg/har.py).

The HAR fixtures carry made-up secret values; every test asserts the output
names the cookie/field/flag but never prints the value, so the rule that keeps
HAR values out of the AI prompt holds for this tool too.
"""
import json

import pytest

from wstg import har

SECRETS = ["s3cr3t-session-abc123", "hunter2", "Bearer-token-xyz789", "deadbeefcsrf"]


def _har(entries):
    return {"log": {"version": "1.2", "entries": entries}}


def _entry(method, url, *, req_cookies=None, set_cookie=None, post=None, headers=None):
    return {
        "request": {
            "method": method,
            "url": url,
            "cookies": [{"name": n, "value": "v"} for n in (req_cookies or [])],
            "headers": headers or [],
            "postData": post or {},
        },
        "response": {
            "headers": [{"name": "Set-Cookie", "value": v} for v in (set_cookie or [])],
        },
    }


def _write(tmp_path, name, doc):
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def _run(capsys, view, *files):
    rc = har.main([view, *[str(f) for f in files]])
    out = capsys.readouterr().out
    for s in SECRETS:
        assert s not in out, f"value leaked in {view}: {s!r}"
    return rc, out


def test_cookies_flags_missing_secure_and_samesite(tmp_path, capsys):
    doc = _har([
        _entry("GET", "https://example.com/", set_cookie=[
            "SID=s3cr3t-session-abc123; Path=/; HttpOnly",
        ]),
    ])
    f = _write(tmp_path, "a.har", doc)
    rc, out = _run(capsys, "cookies", f)
    assert rc == 0
    assert "SID:" in out
    assert "MISSING" in out and "secure" in out and "samesite" in out
    assert "httponly" not in out.split("MISSING", 1)[1].split("\n", 1)[0]  # httponly is present


def test_cookies_flag_present_only_if_on_every_occurrence(tmp_path, capsys):
    # SID set twice; Secure only on one occurrence -> counts as missing.
    doc = _har([
        _entry("GET", "https://example.com/a", set_cookie=["SID=x; Secure; HttpOnly; SameSite=Lax"]),
        _entry("GET", "https://example.com/b", set_cookie=["SID=y; HttpOnly; SameSite=Lax"]),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "cookies", f)
    assert "MISSING secure" in out


def test_urls_flags_credential_and_token_in_query(tmp_path, capsys):
    doc = _har([
        _entry("GET", "https://example.com/login?username=bob&password=hunter2"),
        _entry("GET", "https://example.com/p?sessionid=s3cr3t-session-abc123"),
        _entry("GET", "https://example.com/clean?page=2"),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "urls", f)
    assert "CREDENTIAL-IN-URL" in out
    assert "TOKEN-IN-URL" in out
    # parameter names shown, values masked
    assert "username=…" in out or "username=…" in out
    assert "page=2" not in out  # values dropped even for benign params


def test_cleartext_reports_http_requests_with_credentials(tmp_path, capsys):
    doc = _har([
        _entry("POST", "http://example.com/login",
                post={"mimeType": "application/x-www-form-urlencoded",
                      "params": [{"name": "user", "value": "bob"}, {"name": "pass", "value": "hunter2"}]}),
        _entry("GET", "http://example.com/dash", req_cookies=["SID"]),
        _entry("GET", "https://example.com/ok", req_cookies=["SID"]),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "cleartext", f)
    assert "CLEARTEXT POST http://example.com/login" in out
    assert "user" in out and "pass" in out
    assert "cookies: SID" in out
    assert "https://example.com/ok" not in out  # https not reported


def test_cleartext_none_message(tmp_path, capsys):
    doc = _har([_entry("GET", "https://example.com/ok", req_cookies=["SID"])])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "cleartext", f)
    assert "no plain-HTTP request" in out


def test_forms_flags_state_change_without_csrf(tmp_path, capsys):
    doc = _har([
        _entry("POST", "https://example.com/transfer",
                post={"mimeType": "application/x-www-form-urlencoded",
                      "params": [{"name": "amount", "value": "100"}]}),
        _entry("POST", "https://example.com/settings",
                post={"mimeType": "application/x-www-form-urlencoded",
                      "params": [{"name": "csrf_token", "value": "deadbeefcsrf"}, {"name": "x", "value": "1"}]}),
        _entry("GET", "https://example.com/view"),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "forms", f)
    assert "POST /transfer" in out and "NO CSRF TOKEN" in out
    assert "POST /settings" in out and "has CSRF token" in out
    assert "/view" not in out  # GET is not state-changing


def test_forms_csrf_via_header(tmp_path, capsys):
    doc = _har([
        _entry("POST", "https://example.com/api/x",
                headers=[{"name": "X-CSRF-Token", "value": "deadbeefcsrf"}],
                post={"mimeType": "application/json", "text": json.dumps({"a": 1})}),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "forms", f)
    assert "has CSRF token" in out


def test_json_body_field_names_read(tmp_path, capsys):
    doc = _har([
        _entry("POST", "http://example.com/api/login",
                post={"mimeType": "application/json",
                      "text": json.dumps({"username": "bob", "password": "hunter2"})}),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "cleartext", f)
    assert "username" in out and "password" in out


def test_unreadable_file_noted_not_fatal(tmp_path, capsys):
    bad = tmp_path / "bad.har"
    bad.write_text("not json")
    good = _write(tmp_path, "good.har", _har([_entry("GET", "https://example.com/")]))
    rc, out = _run(capsys, "cookies", bad, good)
    assert rc == 0
    assert "not a readable HAR file" in out


def test_usage_on_bad_view(capsys):
    rc = har.main(["bogus", "x.har"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "usage: wstg-har" in err


def test_usage_on_too_few_args(capsys):
    assert har.main(["cookies"]) == 2


@pytest.mark.parametrize("view", list(har._VIEWS))
def test_empty_har_does_not_crash(tmp_path, capsys, view):
    f = _write(tmp_path, "e.har", _har([]))
    rc, _ = _run(capsys, view, f)
    assert rc == 0


def _resp(url, ct, body, *, nosniff=False, encoding=None):
    headers = [{"name": "Content-Type", "value": ct}]
    if nosniff:
        headers.append({"name": "X-Content-Type-Options", "value": "nosniff"})
    content = {"mimeType": ct, "text": body}
    if encoding:
        content["encoding"] = encoding
    return {"request": {"method": "GET", "url": url, "cookies": [], "headers": [], "postData": {}},
            "response": {"headers": headers, "content": content}}


def test_xssi_flags_array_literal_without_nosniff(tmp_path, capsys):
    doc = _har([_resp("https://example.com/data.json", "application/json",
                      '["hunter2","deadbeefcsrf"]')])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "/data.json" in out and "array literal (includable)" in out
    assert "XSSI CANDIDATE" in out            # json type but no nosniff
    assert "hunter2" not in out               # no data values printed


def test_xssi_jsonp_callback_is_flagged(tmp_path, capsys):
    doc = _har([_resp("https://example.com/api?callback=cb", "application/javascript",
                      'cb({"x":"s3cr3t-session-abc123"})', nosniff=True)])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "JSONP / function call (includable)" in out and "[JSONP callback param]" in out


def test_xssi_object_literal_not_a_candidate(tmp_path, capsys):
    doc = _har([_resp("https://example.com/x.json", "application/json",
                      '{"a":1}', nosniff=True)])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "object literal" in out and "XSSI CANDIDATE" not in out


def test_xssi_guard_prefix_is_safe(tmp_path, capsys):
    doc = _har([_resp("https://example.com/feed.json", "application/json",
                      ')]}\'\n["hunter2"]', nosniff=True)])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "guarded (anti-XSSI prefix)" in out and "XSSI CANDIDATE" not in out


def test_xssi_none_message(tmp_path, capsys):
    doc = _har([_resp("https://example.com/", "text/html", "<html></html>")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "no JS/JSON response" in out
