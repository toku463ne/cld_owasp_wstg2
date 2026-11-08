"""Value-free analysis of imported HAR files, to replace manual Burp-history checks.

`har-browse` is a HAR the tester exports from the browser while walking the
application (one anonymous, one per logged-in role). This module reads those files
and prints facts a tester used to read out of Burp by hand: cookie attributes, which
requests carry a session token in the URL, what is sent over plain HTTP, and whether
state-changing requests carry an anti-CSRF token.

It never prints a value. Cookie values, token values, header values that may hold
secrets, and body field values are dropped; only names, flags, methods, paths, and
parameter names are shown. So the same rule that keeps HAR values out of the AI prompt
holds here, and auto-run steps that call this tool are still excluded from the prompt
(their command names a `.har` file).

Run as `wstg-har <view> FILE...` where view is cookies | urls | cleartext | forms | xssi.
Exit code is always 0 (a WSTG step reads the text output); unreadable files are noted.
"""
import json
import re
import sys
from pathlib import Path

# Parameter / field names that suggest a credential or a session token when seen in a
# URL query. Names only are matched; values are never read.
_CREDENTIAL_RE = re.compile(r"^(user|username|login|email|mail|pass|passwd|password|pwd)$", re.I)
_TOKEN_RE = re.compile(r"(sid|sessionid|session_id|phpsessid|jsessionid|aspsessionid|cfid|cftoken|"
                       r"token|auth|access_token|jwt|apikey|api_key|secret)", re.I)
_CSRF_RE = re.compile(r"(csrf|xsrf|_token|authenticity_token|requestverificationtoken|anticsrf|nonce)", re.I)
_COOKIE_FLAGS = ("secure", "httponly", "samesite", "path", "domain", "max-age", "expires")
_STATE_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


def _load(path: Path) -> list | None:
    try:
        return json.loads(path.read_text(errors="replace"))["log"]["entries"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _url_parts(url: str) -> tuple[str, str, str, list[str]]:
    """(scheme, host, path, query-parameter-names) for a URL, values dropped."""
    m = re.match(r"(?i)^([a-z][a-z0-9+.-]*)://([^/?#]*)([^?#]*)", url or "")
    scheme, host, path = (m.group(1).lower(), m.group(2).lower(), m.group(3)) if m else ("", "", url or "")
    _, _, query = (url or "").partition("?")
    names = [p.split("=", 1)[0] for p in query.split("&") if p] if query else []
    return scheme, host, path, names


def _set_cookies(entry: dict) -> list[tuple[str, list[str]]]:
    """[(cookie name, [present flags])] from the response Set-Cookie headers."""
    out = []
    for h in (entry.get("response") or {}).get("headers") or []:
        if str(h.get("name", "")).lower() != "set-cookie":
            continue
        parts = [x.strip() for x in str(h.get("value", "")).split(";")]
        if not parts:
            continue
        name = parts[0].split("=", 1)[0]
        flags = [x.split("=", 1)[0].lower() for x in parts[1:] if x.split("=", 1)[0].lower() in _COOKIE_FLAGS]
        out.append((name, flags))
    return out


def _body_field_names(req: dict) -> list[str]:
    post = req.get("postData") or {}
    names = [p.get("name", "") for p in post.get("params") or []]
    if not names and "json" in (post.get("mimeType") or ""):
        try:
            body = json.loads(post.get("text") or "")
            if isinstance(body, dict):
                names = list(body)
        except ValueError:
            pass
    return [n for n in names if n]


def _iter(files: list[Path]):
    """Yield (label, entries) per readable file; print a note for unreadable ones."""
    for p in files:
        entries = _load(p)
        if entries is None:
            print(f"== {p.name}: not a readable HAR file")
            continue
        yield p.name, entries


def view_cookies(files: list[Path]) -> None:
    """Set-Cookie attributes per cookie name (values dropped). Missing Secure/HttpOnly/
    SameSite on a cookie are flagged. A cookie whose set of flags differs between files
    (for example before vs. after login) is noted as a reissue/attribute-change hint."""
    seen: dict[str, set] = {}
    any_cookie = False
    for label, entries in _iter(files):
        print(f"== {label}")
        occ: dict[str, list[set]] = {}       # cookie name -> flag set per Set-Cookie seen
        for e in entries:
            for name, flags in _set_cookies(e):
                any_cookie = True
                occ.setdefault(name, []).append(set(flags))
        for name in sorted(occ):
            sets = occ[name]
            always = set.intersection(*sets)   # a flag counts as present only on every occurrence
            ever = set.union(*sets)
            # missing if the flag is absent from any occurrence of this cookie
            missing = [f for f in ("secure", "httponly", "samesite") if f not in always]
            note = "MISSING " + ",".join(missing) if missing else "secure,httponly,samesite present"
            scope = [f for f in ("domain", "path", "max-age", "expires") if f in ever]
            print(f"  {name}: {note}" + (f"; {','.join(scope)}" if scope else ""))
            seen.setdefault(name, set()).add(frozenset(always))
        if not occ:
            print("  (no Set-Cookie in this file)")
    for name, flagsets in sorted(seen.items()):
        if len(flagsets) > 1:
            print(f"! {name}: cookie attributes differ between files (reissue / attribute change — check login)")
    if not any_cookie:
        print("(no Set-Cookie header in any file)")


def view_urls(files: list[Path]) -> None:
    """One line per distinct request: method scheme host path and query parameter names.
    A query parameter that looks like a credential or a session token is flagged, since
    such a value then sits in URLs, history, and logs (WSTG-SESS-04, ATHN-01)."""
    seen = set()
    for label, entries in _iter(files):
        print(f"== {label}")
        for e in entries:
            req = e.get("request") or {}
            scheme, host, path, names = _url_parts(str(req.get("url", "")))
            line = f"{req.get('method', '?')} {scheme}://{host}{path}"
            if names:
                line += " ?" + "&".join(n + "=…" for n in names)
            flags = []
            if any(_CREDENTIAL_RE.match(n) for n in names):
                flags.append("CREDENTIAL-IN-URL")
            if any(_TOKEN_RE.search(n) for n in names):
                flags.append("TOKEN-IN-URL")
            if flags:
                line += "   <= " + " ".join(flags)
            if line not in seen:
                seen.add(line)
                print("  " + line)


def view_cleartext(files: list[Path]) -> None:
    """Requests sent over plain HTTP that carry a cookie or a credential/token field
    (names only), which means credentials or a session are exposed in the clear
    (WSTG-ATHN-01, CRYP-03). Mixed references (http:// resources) are listed too."""
    found = False
    for label, entries in _iter(files):
        print(f"== {label}")
        for e in entries:
            req = e.get("request") or {}
            scheme, host, path, names = _url_parts(str(req.get("url", "")))
            if scheme != "http":
                continue
            cookies = [c.get("name", "") for c in req.get("cookies") or []]
            fields = _body_field_names(req)
            cred = [n for n in names + fields if _CREDENTIAL_RE.match(n) or _TOKEN_RE.search(n)]
            if cookies or cred:
                found = True
                bits = []
                if cred:
                    bits.append("credential/token fields: " + ", ".join(sorted(set(cred))))
                if cookies:
                    bits.append("cookies: " + ", ".join(cookies))
                print(f"  CLEARTEXT {req.get('method', '?')} http://{host}{path}   <= " + "; ".join(bits))
    if not found:
        print("(no plain-HTTP request carrying a cookie or credential/token field)")


def view_forms(files: list[Path]) -> None:
    """State-changing requests (POST/PUT/DELETE/PATCH) and whether they carry an
    anti-CSRF token field (by name). A state-changing request with no such field is a
    CSRF candidate to check by hand (WSTG-SESS-05)."""
    seen = set()
    any_state = False
    for label, entries in _iter(files):
        print(f"== {label}")
        for e in entries:
            req = e.get("request") or {}
            method = str(req.get("method", "?")).upper()
            if method not in _STATE_METHODS:
                continue
            any_state = True
            _, host, path, qnames = _url_parts(str(req.get("url", "")))
            fields = _body_field_names(req)
            has_csrf = any(_CSRF_RE.search(n) for n in fields + qnames) or any(
                str(h.get("name", "")).lower() in ("x-csrf-token", "x-xsrf-token", "x-csrftoken")
                for h in req.get("headers") or [])
            line = f"{method} {path}   {'has CSRF token' if has_csrf else 'NO CSRF TOKEN (check)'}"
            if line not in seen:
                seen.add(line)
                print("  " + line)
    if not any_state:
        print("(no state-changing request in the HAR)")


def _header(headers: list, name: str) -> str:
    for h in headers or []:
        if str(h.get("name", "")).lower() == name:
            return str(h.get("value", ""))
    return ""


def _body_text(resp: dict) -> str:
    content = resp.get("content") or {}
    text = content.get("text") or ""
    if text and "base64" in str(content.get("encoding") or "").lower():
        import base64
        try:
            text = base64.b64decode(text).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""
    return text


def _xssi_shape(body: str) -> str:
    """Classify a response body as a cross-site <script> include would see it,
    from its leading bytes only (no data values are returned)."""
    s = body.lstrip()[:64]
    if not s:
        return "empty"
    for guard in (")]}'", "while(1)", "while (1)", "for(;;)", "for (;;)", "&&&START&&&"):
        if s.startswith(guard):
            return "guarded (anti-XSSI prefix)"
    if s[0] == "[":
        return "array literal (includable)"
    if re.match(r"[A-Za-z_$][\w$]*\s*\(", s):
        return "JSONP / function call (includable)"
    if s[0] == "{":
        return "object literal (not a bare script statement)"
    if s[:1] == "<":
        return "HTML (not script/JSON)"
    return "other"


_INCLUDABLE = ("array literal (includable)", "JSONP / function call (includable)")


def view_xssi(files: list[Path]) -> None:
    """For each JS/JSON response in the HAR (by Content-Type, URL extension, or a
    JSONP callback parameter), report the Content-Type, whether nosniff is set,
    and the include shape — so a response that a cross-site <script src> could
    read is flagged (WSTG-CLNT-13). Values are never printed, only the shape."""
    seen, found = set(), False
    for label, entries in _iter(files):
        print(f"== {label}")
        for e in entries:
            req, resp = e.get("request") or {}, e.get("response") or {}
            _, host, path, names = _url_parts(str(req.get("url", "")))
            ct = _header(resp.get("headers"), "content-type").split(";")[0].strip().lower()
            is_jsonp = any(n.lower() in ("callback", "jsonp", "cb") for n in names)
            if not (("json" in ct or "javascript" in ct or "ecmascript" in ct)
                    or path.lower().endswith((".json", ".js")) or is_jsonp):
                continue
            found = True
            nosniff = "nosniff" in _header(resp.get("headers"), "x-content-type-options").lower()
            shape = _xssi_shape(_body_text(resp))
            line = f"{req.get('method', '?')} {path}   ct={ct or '(none)'}  nosniff={'yes' if nosniff else 'NO'}  shape={shape}"
            # A candidate: includable shape served without nosniff or without a JS/JSON type.
            if shape in _INCLUDABLE and (not nosniff or "json" not in ct and "javascript" not in ct and "ecmascript" not in ct):
                line += "   <= XSSI CANDIDATE (confirm cross-site read)"
            if is_jsonp:
                line += "   [JSONP callback param]"
            if line not in seen:
                seen.add(line)
                print("  " + line)
    if not found:
        print("(no JS/JSON response in the HAR; browse the authenticated JS/JSON endpoints and recapture)")


_VIEWS = {"cookies": view_cookies, "urls": view_urls, "cleartext": view_cleartext,
          "forms": view_forms, "xssi": view_xssi}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2 or args[0] not in _VIEWS:
        print(f"usage: wstg-har {{{'|'.join(_VIEWS)}}} FILE.har ...", file=sys.stderr)
        return 2
    view, files = args[0], [Path(a) for a in args[1:]]
    _VIEWS[view](files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
