"""Unit tests for the value-free HAR analyser (src/wstg/har.py).

The HAR fixtures carry made-up secret values; every test asserts the output
names the cookie/field/flag but never prints the value, so the rule that keeps
HAR values out of the AI prompt holds for this tool too.
"""
import json

import pytest

from wstg import har

SECRETS = ["s3cr3t-session-abc123", "hunter2", "Bearer-token-xyz789", "deadbeefcsrf",
           "abc123secretXYZ", "eyJhbGci.payloadpart.sigsig"]


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


def test_cookies_session_auth_verdict_section(tmp_path, capsys):
    doc = _har([
        _entry("GET", "https://example.com/a", set_cookie=[
            "SID=x; HttpOnly; Path=/",                              # no Secure, no SameSite, site-wide
            "AUTH=z; Secure; HttpOnly; SameSite=None; Domain=.example.com",  # SameSite=None + Domain
            "theme=dark; Secure; SameSite=Lax; Path=/app",          # not a session cookie
        ]),
    ])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "cookies", f)
    verdict = out.split("attribute verdict", 1)[1]
    assert "SID: WEAK" in verdict and "no Secure" in verdict and "no SameSite" in verdict
    assert "AUTH: WEAK" in verdict and "SameSite=None" in verdict and "Domain set" in verdict
    assert "theme" not in verdict                                   # a non-session cookie is not judged here


def test_cookies_verdict_notes_when_no_session_cookie(tmp_path, capsys):
    doc = _har([_entry("GET", "https://example.com/a", set_cookie=["theme=dark; Secure; SameSite=Lax; Path=/app"])])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "cookies", f)
    assert "no session/authentication cookie seen" in out


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


def _resp(url, ct, body, *, nosniff=False, encoding=None, req_cookies=(), set_cookie=None):
    headers = [{"name": "Content-Type", "value": ct}]
    if nosniff:
        headers.append({"name": "X-Content-Type-Options", "value": "nosniff"})
    if set_cookie:
        headers.append({"name": "Set-Cookie", "value": set_cookie})
    content = {"mimeType": ct, "text": body}
    if encoding:
        content["encoding"] = encoding
    return {"request": {"method": "GET", "url": url,
                        "cookies": [{"name": n, "value": "v"} for n in req_cookies],
                        "headers": [], "postData": {}},
            "response": {"headers": headers, "content": content}}


def test_xssi_exploitable_when_auth_cookie_samesite_none(tmp_path, capsys):
    doc = _har([_resp("https://example.com/data.json", "application/json",
                      '["hunter2","deadbeefcsrf"]',
                      req_cookies=("SID",), set_cookie="SID=x; Secure; SameSite=None")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "/data.json" in out and "array literal (includable)" in out
    assert "cross-site-auth=exploitable" in out and "XSSI EXPLOITABLE" in out
    assert "hunter2" not in out               # no data values printed


def test_xssi_not_exploitable_when_auth_cookie_samesite_lax(tmp_path, capsys):
    doc = _har([_resp("https://example.com/data.json", "application/json",
                      '["x"]', req_cookies=("SID",), set_cookie="SID=x; SameSite=Lax")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "cross-site-auth=protected" in out
    assert "XSSI EXPLOITABLE" not in out and "XSSI CANDIDATE" not in out


def test_xssi_legacy_when_auth_cookie_has_no_samesite(tmp_path, capsys):
    doc = _har([_resp("https://example.com/data.json", "application/json",
                      '["x"]', req_cookies=("SID",), set_cookie="SID=x; Path=/")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "cross-site-auth=legacy" in out and "XSSI CANDIDATE" in out


def test_xssi_jsonp_callback_is_flagged(tmp_path, capsys):
    doc = _har([_resp("https://example.com/api?callback=cb", "application/javascript",
                      'cb({"x":"s3cr3t-session-abc123"})', nosniff=True,
                      req_cookies=("SID",), set_cookie="SID=x; SameSite=None")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "JSONP / function call (includable)" in out and "[JSONP callback param]" in out


def test_xssi_object_literal_not_a_candidate(tmp_path, capsys):
    doc = _har([_resp("https://example.com/x.json", "application/json",
                      '{"a":1}', nosniff=True, req_cookies=("SID",), set_cookie="SID=x; SameSite=None")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "object literal" in out and "XSSI EXPLOITABLE" not in out


def test_xssi_guard_prefix_is_safe(tmp_path, capsys):
    doc = _har([_resp("https://example.com/feed.json", "application/json",
                      ')]}\'\n["hunter2"]', nosniff=True,
                      req_cookies=("SID",), set_cookie="SID=x; SameSite=None")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "guarded (anti-XSSI prefix)" in out and "XSSI EXPLOITABLE" not in out


def test_xssi_none_message(tmp_path, capsys):
    doc = _har([_resp("https://example.com/", "text/html", "<html></html>")])
    f = _write(tmp_path, "a.har", doc)
    _, out = _run(capsys, "xssi", f)
    assert "no JS/JSON response" in out


def _ep_entry(method, url, *, cookies=(), headers=(), post=None, status=200):
    e = _entry(method, url, req_cookies=list(cookies), post=post,
               headers=[{"name": n, "value": "Bearer-token-xyz789"} for n in headers])
    e["response"]["status"] = status
    return e


def test_entry_points_inventory_groups_params_and_guesses_login(tmp_path, capsys):
    anon = _write(tmp_path, "anon-20261121-010203.har", _har([
        _ep_entry("GET", "https://www.example.com/search?q=hunter2&page=2"),
        _ep_entry("GET", "https://www.example.com/static/app.js"),
        _ep_entry("GET", "https://cdn.example.net/lib.js"),
    ]))
    user = _write(tmp_path, "user-20261121-010304.har", _har([
        _ep_entry("GET", "https://www.example.com/user/123/orders", cookies=["SID"]),
        _ep_entry("GET", "https://www.example.com/user/456/orders", cookies=["SID"]),
        _ep_entry("POST", "https://www.example.com/api/orders", cookies=["SID"], headers=["X-CSRF-Token"],
                  post={"mimeType": "application/json",
                        "text": json.dumps({"items": [{"id": 1, "qty": 2}], "note": "s3cr3t-session-abc123"})}),
        _ep_entry("POST", "https://www.example.com/profile/avatar", cookies=["SID"],
                  post={"mimeType": "multipart/form-data",
                        "params": [{"name": "file", "fileName": "a.png"}, {"name": "csrf", "value": "deadbeefcsrf"}]}),
        _ep_entry("GET", "https://www.example.com/logout", cookies=["SID"], status=302),
        _ep_entry("GET", "https://www.example.com/news/latest"),
        _ep_entry("GET", "https://www.example.com/reset/a1B2c3D4e5F6g7H8i9J0k1"),
    ]))
    rc, out = _run(capsys, "entry-points", "--host", "www.example.com", anon, user)
    assert rc == 0
    assert "user-20261121-010304.har -> user" in out and "-> anon (anonymous)" in out
    assert "GET     /search\n          login: no (anonymous HAR)\n          params: query: q, page" in out
    # /user/123 and /user/456 are one entry point; seen only with a cookie
    assert out.count("/user/<id>/orders") == 1
    assert "/user/<id>/orders\n          login: likely (seen only logged in)" in out
    assert "json: items[].id, items[].qty, note" in out and "header: x-csrf-token" in out
    assert "STATE-CHANGING" in out and "FILE UPLOAD" in out and "file: file; multipart: csrf" in out
    assert "/logout" in out and "STATE-CHANGING GET?" in out and "status 302" in out
    assert "/news/latest\n          login: no (sent without cookies)" in out
    assert "/reset/<token>" in out and "a1B2c3D4" not in out
    assert "/static/app.js" not in out and "1 static requests skipped" in out
    assert "other hosts skipped (host: requests): cdn.example.net: 1" in out
    assert "cookies sent (name: requests): SID: 5" in out


def test_entry_points_without_anonymous_har_warns(tmp_path, capsys):
    f = _write(tmp_path, "walk.har", _har([_ep_entry("GET", "https://www.example.com/a", cookies=["SID"])]))
    _, out = _run(capsys, "entry-points", f)
    assert "no anonymous HAR" in out
    assert "GET     www.example.com/a" in out      # no --host: the host is shown


def test_entry_points_host_option_needs_files(capsys):
    assert har.main(["entry-points", "--host", "www.example.com"]) == 2


def test_entry_points_role_ignores_the_store_item_number(tmp_path, capsys):
    f = _write(tmp_path, "001-anon-20261108-052427.har", _har([_ep_entry("GET", "https://www.example.com/a")]))
    _, out = _run(capsys, "entry-points", "--host", "www.example.com", f)
    assert "-> anon (anonymous)" in out and "no anonymous HAR" not in out
    assert "login: no (anonymous HAR)" in out


# -- expose view (WSTG-SESS-04 step 4): token exposure from the HAR + storage state --

def _exp_entry(method, url, *, req_cookies=(), referer=None, status=200, body=""):
    headers = [{"name": "Referer", "value": referer}] if referer else []
    return {
        "request": {"method": method, "url": url, "headers": headers,
                    "cookies": [{"name": n, "value": v} for n, v in req_cookies]},
        "response": {"status": status, "headers": [], "content": {"text": body}},
    }


def _storage(origin, items):
    return {"cookies": [], "origins": [
        {"origin": origin, "localStorage": [{"name": n, "value": v} for n, v in items]}]}


def test_expose_flags_referer_storage_and_error_echo(tmp_path, capsys):
    sid = "abc123secretXYZ"
    har_doc = _har([
        _exp_entry("GET", "https://app.example.com/dash", req_cookies=[("SESSIONID", sid)]),
        _exp_entry("GET", "https://cdn.thirdparty.test/a.js",
                   referer=f"https://app.example.com/p?sid={sid}"),
        _exp_entry("GET", "https://app.example.com/boom", status=500,
                   body=f"error: session {sid} is not valid"),
    ])
    hf = _write(tmp_path, "001-user.har", har_doc)
    sf = _write(tmp_path, "002-storage-state.json",
                _storage("https://app.example.com",
                         [("auth_token", "eyJhbGci.payloadpart.sigsig"), ("theme", "dark")]))
    rc, out = _run(capsys, "expose", hf, sf)
    assert rc == 0
    assert "base host: app.example.com" in out
    assert "REFERER-LEAK" in out and "cdn.thirdparty.test" in out
    assert "STORAGE-TOKEN localStorage[auth_token]" in out
    assert "theme" not in out                       # a non-token key is not flagged
    assert "ERROR-ECHO HTTP 500 /boom" in out
    assert "chars)" in out                           # values are masked by length


def test_expose_clean_capture_reports_no_exposure(tmp_path, capsys):
    sid = "abc123secretXYZ"
    hf = _write(tmp_path, "001-user.har", _har([
        _exp_entry("GET", "https://app.example.com/dash", req_cookies=[("SESSIONID", sid)],
                   body="ok"),
    ]))
    sf = _write(tmp_path, "002-storage-state.json",
                _storage("https://app.example.com", [("theme", "dark")]))
    rc, out = _run(capsys, "expose", hf, sf)
    assert rc == 0
    assert "no session-token exposure seen" in out
    assert "REFERER-LEAK" not in out and "STORAGE-TOKEN" not in out and "ERROR-ECHO" not in out


def test_expose_does_not_flag_same_site_referer(tmp_path, capsys):
    sid = "abc123secretXYZ"
    hf = _write(tmp_path, "001-user.har", _har([
        _exp_entry("GET", "https://app.example.com/dash", req_cookies=[("SESSIONID", sid)]),
        _exp_entry("GET", "https://static.example.com/a.js",      # same-site subdomain
                   referer=f"https://app.example.com/p?sid={sid}"),
    ]))
    rc, out = _run(capsys, "expose", "--host", "example.com", hf)
    assert rc == 0
    assert "REFERER-LEAK" not in out


def test_expose_ignores_unreadable_file(tmp_path, capsys):
    junk = tmp_path / "x.txt"
    junk.write_text("not json or har")
    rc, out = _run(capsys, "expose", junk)
    assert rc == 0
    assert "not a readable HAR or storage-state file" in out


# -- cache / frame / storage views (ATHN-06, CLNT-09, CLNT-12) --

def _page(url, *, authed=False, status=200, ctype="text/html", resp_headers=()):
    sid = [("SESSIONID", "abc123secretXYZ")] if authed else []
    headers = [{"name": "Content-Type", "value": ctype}] + [{"name": n, "value": v} for n, v in resp_headers]
    return {
        "request": {"method": "GET", "url": url, "headers": [],
                    "cookies": [{"name": n, "value": v} for n, v in sid]},
        "response": {"status": status, "headers": headers, "content": {"text": ""}},
    }


def test_cache_flags_cacheable_authenticated_pages(tmp_path, capsys):
    f = _write(tmp_path, "001-user.har", _har([
        _page("https://app.example.com/account", authed=True,
              resp_headers=[("Cache-Control", "private, max-age=600")]),
        _page("https://app.example.com/settings", authed=True,
              resp_headers=[("Cache-Control", "no-store")]),
        _page("https://app.example.com/login"),            # anonymous: not judged
    ]))
    rc, out = _run(capsys, "cache", f)
    assert rc == 0
    assert "/account: CACHEABLE" in out and "max-age" in out
    assert "/settings: no-store" in out
    assert "/login" not in out                              # only authenticated pages


def test_cache_notes_when_no_authenticated_page(tmp_path, capsys):
    f = _write(tmp_path, "a.har", _har([_page("https://app.example.com/")]))
    rc, out = _run(capsys, "cache", f)
    assert "no authenticated HTML page" in out


def test_frame_flags_frameable_pages_including_authenticated(tmp_path, capsys):
    f = _write(tmp_path, "001-user.har", _har([
        _page("https://app.example.com/pay", authed=True),                     # no header
        _page("https://app.example.com/safe", resp_headers=[("X-Frame-Options", "DENY")]),
        _page("https://app.example.com/csp",
              resp_headers=[("Content-Security-Policy", "frame-ancestors 'none'")]),
    ]))
    rc, out = _run(capsys, "frame", f)
    assert rc == 0
    assert "/pay (authenticated): FRAMEABLE" in out
    assert "/safe: framing denied - X-Frame-Options: DENY" in out
    assert "/csp: framing denied - CSP frame-ancestors" in out


def test_storage_inventories_localstorage_and_flags_tokens(tmp_path, capsys):
    sf = _write(tmp_path, "002-storage-state.json",
                _storage("https://app.example.com",
                         [("auth_token", "eyJhbGci.payloadpart.sigsig"), ("theme", "dark")]))
    har_file = _write(tmp_path, "001-user.har", _har([_page("https://app.example.com/")]))
    rc, out = _run(capsys, "storage", har_file, sf)   # HAR in the glob is skipped silently
    assert rc == 0
    assert "https://app.example.com: 2 localStorage key(s)" in out
    assert "auth_token =" in out and "SENSITIVE" in out
    assert "theme =" in out
    assert "not a readable HAR" not in out
    assert "001-user.har" not in out


def test_storage_notes_when_no_storage_state(tmp_path, capsys):
    f = _write(tmp_path, "a.har", _har([_page("https://app.example.com/")]))
    rc, out = _run(capsys, "storage", f)
    assert "no storage-state file" in out


# -- csrf view (WSTG-SESS-05): CSRF posture from the capture, no request sent --

def _csrf_entry(method, path, *, ctype=None, fields=(), headers=(), cookies=("SESSIONID",),
                set_cookie=None, resp_headers=()):
    req = {"method": method, "url": f"https://app.example.com{path}",
           "headers": [{"name": n, "value": v} for n, v in headers],
           "cookies": [{"name": n, "value": "secretVALUE123"} for n in cookies]}
    if ctype:
        req["postData"] = {"mimeType": ctype, "params": [{"name": f, "value": "v"} for f in fields],
                           "text": '{"a": 1}' if "json" in ctype else ""}
    rh = [{"name": n, "value": v} for n, v in resp_headers]
    if set_cookie:
        rh.append({"name": "Set-Cookie", "value": set_cookie})
    return {"request": req, "response": {"status": 200, "headers": rh, "content": {"text": ""}}}


def test_csrf_view_judges_each_state_changing_request(tmp_path, capsys):
    hf = _write(tmp_path, "001-user.har", _har([
        _csrf_entry("GET", "/home", set_cookie="SESSIONID=secretVALUE123; Path=/; HttpOnly"),
        _csrf_entry("POST", "/profile", ctype="application/x-www-form-urlencoded", fields=["name"]),
        _csrf_entry("POST", "/settings", ctype="application/x-www-form-urlencoded",
                    fields=["csrf_token", "mail"]),
        _csrf_entry("POST", "/api/save", ctype="application/json"),
        _csrf_entry("DELETE", "/api/item/42"),
        _csrf_entry("GET", "/item/42/delete"),
        _csrf_entry("POST", "/api/bearer", ctype="application/x-www-form-urlencoded", cookies=(),
                    headers=[("Authorization", "Bearer x")]),
    ]))
    rc, out = _run(capsys, "csrf", hf)
    assert rc == 0
    lines = {ln.split()[1] + " " + ln.split()[2]: ln.split()[0] for ln in out.splitlines()
             if ln.startswith("  ") and not ln.startswith("      ") and ln.strip()}
    assert lines["POST /profile"] == "CSRF-LIKELY"          # no token, form, no SameSite
    assert lines["POST /settings"] == "TOKEN"
    assert lines["POST /api/save"] == "PREFLIGHT"           # JSON body needs a preflight
    assert lines["DELETE /api/item/<id>"] == "PREFLIGHT"
    assert lines["GET /item/<id>/delete"] == "CSRF-LIKELY"
    assert lines["POST /api/bearer"] == "NOT-APPLICABLE"
    assert "secretVALUE123" not in out
    assert "no request sent" in out


def test_csrf_view_samesite_lax_mitigates_post_and_cors_reopens(tmp_path, capsys):
    hf = _write(tmp_path, "001-user.har", _har([
        _csrf_entry("GET", "/home", set_cookie="SESSIONID=secretVALUE123; Path=/; SameSite=Lax"),
        _csrf_entry("POST", "/profile", ctype="application/x-www-form-urlencoded", fields=["name"]),
        _csrf_entry("POST", "/api/save", ctype="application/json",
                    resp_headers=[("Access-Control-Allow-Origin", "https://evil.test"),
                                  ("Access-Control-Allow-Credentials", "true")]),
    ]))
    rc, out = _run(capsys, "csrf", hf)
    assert "MITIGATED      POST /profile" in out
    assert "SameSite=Lax" in out
    assert "POST /api/save" in out and "CORS allows a credentialed cross-site request" in out


def test_csrf_view_uses_storage_state_samesite_and_reports_empty(tmp_path, capsys):
    hf = _write(tmp_path, "001-user.har", _har([
        _csrf_entry("POST", "/profile", ctype="application/x-www-form-urlencoded", fields=["name"])]))
    sf = _write(tmp_path, "002-storage-state.json", {"cookies": [
        {"name": "SESSIONID", "value": "secretVALUE123", "sameSite": "None"}], "origins": []})
    rc, out = _run(capsys, "csrf", hf, sf)
    assert "CSRF-LIKELY" in out and "SameSite=None" in out
    hf2 = _write(tmp_path, "003-anon.har", _har([_csrf_entry("GET", "/home")]))
    rc, out = _run(capsys, "csrf", hf2)
    assert "no state-changing request" in out
