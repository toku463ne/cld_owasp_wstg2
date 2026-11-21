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

Run as `wstg-har <view> [--host HOST] FILE...` where view is cookies | urls | cleartext |
forms | xssi | entry-points (`--host` is used by entry-points only).
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
_SAMESITE_RE = re.compile(r";\s*samesite\s*=\s*([a-z]+)", re.I)


def _samesite_map(all_entries: list) -> dict[str, str]:
    """cookie name -> weakest SameSite seen in its Set-Cookie headers ('none',
    'lax', 'strict', or '' when the attribute is absent). 'none' and '' win,
    since those are what let a cookie ride a cross-site request."""
    order = {"none": 0, "": 1, "lax": 2, "strict": 3}
    out: dict[str, str] = {}
    for e in all_entries:
        for h in (e.get("response") or {}).get("headers") or []:
            if str(h.get("name", "")).lower() != "set-cookie":
                continue
            value = str(h.get("value", ""))
            name = value.split("=", 1)[0].strip()
            m = _SAMESITE_RE.search(value)
            ss = m.group(1).lower() if m else ""
            if name and (name not in out or order[ss] < order[out[name]]):
                out[name] = ss
    return out


def _xssi_posture(req: dict, samesite: dict[str, str]) -> tuple[str, str]:
    """From the cookies the request carried and their SameSite, decide whether a
    cross-site <script src> would carry authentication. Returns (code, note)."""
    cookies = [str(c.get("name", "")) for c in req.get("cookies") or [] if c.get("name")]
    if not cookies:
        return "no-auth", "no cookie sent to this response (data may be public)"
    states = {samesite.get(c, "?") for c in cookies}
    if "none" in states:
        return "exploitable", "an auth cookie is SameSite=None: sent on a cross-site <script> request"
    if "" in states or "?" in states:
        return "legacy", ("an auth cookie has no SameSite: modern browsers default to Lax and block it, "
                          "legacy browsers send it")
    return "protected", "auth cookies are SameSite=Lax/Strict: not sent on a cross-site <script> request"


def view_xssi(files: list[Path]) -> None:
    """For each JS/JSON response in the HAR (by Content-Type, URL extension, or a
    JSONP callback parameter), report the Content-Type, whether nosniff is set,
    the include shape, and whether the request's auth cookies would ride a
    cross-site <script src> (SameSite). A cross-site <script> is a subresource
    request, so only SameSite=None cookies are sent; Lax/Strict are not. This
    lets the step decide exploitability without a new request (WSTG-CLNT-13).
    Values are never printed, only shapes, header flags, and cookie names."""
    loaded = list(_iter(files))
    samesite = _samesite_map([e for _, entries in loaded for e in entries])
    seen, found = set(), False
    for label, entries in loaded:
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
            typed = "json" in ct or "javascript" in ct or "ecmascript" in ct
            code, note = _xssi_posture(req, samesite)
            line = (f"{req.get('method', '?')} {path}   ct={ct or '(none)'}  "
                    f"nosniff={'yes' if nosniff else 'NO'}  shape={shape}  cross-site-auth={code}")
            # Includable shape, not protected by nosniff+type, and auth rides cross-site.
            if shape in _INCLUDABLE and not (nosniff and typed):
                if code == "exploitable":
                    line += f"   <= XSSI EXPLOITABLE ({note})"
                elif code == "legacy":
                    line += f"   <= XSSI CANDIDATE ({note})"
                elif code == "no-auth":
                    line += "   <= includable, but no auth cookie (confirm the data is sensitive)"
                else:
                    line += f"   -- includable, but {note}"
            if is_jsonp:
                line += "   [JSONP callback param]"
            if line not in seen:
                seen.add(line)
                print("  " + line)
    if not found:
        print("(no JS/JSON response in the HAR; browse the authenticated JS/JSON endpoints and recapture)")


# ---- entry point inventory (WSTG-INFO-06) ------------------------------------

# Requests for these are static resources, not entry points.
_STATIC_RE = re.compile(r"\.(css|js|mjs|map|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|"
                        r"mp4|webm|mp3|wav|pdf)$", re.I)
_ANON_ROLE_RE = re.compile(r"^(anon|anonymous|public|guest-anon|nologin|no-login|unauth)", re.I)
_STAMP_RE = re.compile(r"[-_]\d{8}[-_]?\d{4,6}$")
_STATE_GET_RE = re.compile(r"(logout|signout|sign-out|log-out|delete|remove|destroy|cancel|unsubscribe|"
                           r"approve|reject|confirm|activate|reset)", re.I)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_TOKEN_SEG_RE = re.compile(r"^[A-Za-z0-9_\-=.]{20,}$")
_AUTH_HEADERS = ("authorization", "x-api-key", "x-auth-token", "x-access-token")


def _role(file_name: str) -> str:
    """Role label from a HAR file name: `wstg capture --role user` saves `user-<stamp>.har`."""
    stem = file_name[:-4] if file_name.lower().endswith(".har") else file_name
    return _STAMP_RE.sub("", stem) or stem


def _template(path: str) -> str:
    """Path with ID-like segments replaced (<id>, <uuid>, <hex>, <token>), so /user/123 and
    /user/456 are one entry point.
    Long random segments (tokens) are replaced too, so they are never printed."""
    out = []
    for seg in path.split("/"):
        if re.fullmatch(r"\d+", seg):
            seg = "<id>"
        elif _UUID_RE.match(seg):
            seg = "<uuid>"
        elif _HEX_RE.match(seg):
            seg = "<hex>"
        elif _TOKEN_SEG_RE.match(seg) and re.search(r"\d", seg) and re.search(r"[A-Za-z]", seg):
            seg = "<token>"
        out.append(seg)
    return "/".join(out) or "/"


def _json_paths(value, prefix: str = "") -> list[str]:
    """Dotted names of the scalar fields of a JSON body (array items as `[]`), values dropped."""
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            out += _json_paths(v, f"{prefix}.{k}" if prefix else str(k))
        return out
    if isinstance(value, list):
        out = []
        for v in value[:20]:
            out += _json_paths(v, prefix + "[]")
        return list(dict.fromkeys(out))
    return [prefix or "(scalar body)"]


def _body_params(req: dict) -> tuple[list[tuple[str, str]], bool]:
    """([(location, name)], has file upload) for the request body, names only."""
    post = req.get("postData") or {}
    mime = str(post.get("mimeType") or "").lower()
    params, upload = [], False
    for p in post.get("params") or []:
        name = str(p.get("name") or "")
        if not name:
            continue
        if p.get("fileName") is not None:
            upload = True
            params.append(("file", name))
        else:
            params.append(("multipart" if "multipart" in mime else "form", name))
    text = post.get("text") or ""
    if not params and text:
        if "json" in mime or text.lstrip()[:1] in ("{", "["):
            try:
                params += [("json", n) for n in _json_paths(json.loads(text))]
            except ValueError:
                params.append(("body", mime or "unparsed"))
        elif "xml" in mime or text.lstrip().startswith("<"):
            names = re.findall(r"<([A-Za-z_][\w.:-]*)[\s/>]", text)
            params += [("xml", n) for n in dict.fromkeys(names)] or [("xml", "(body)")]
        elif "x-www-form-urlencoded" in mime:
            params += [("form", kv.split("=", 1)[0]) for kv in text.split("&") if kv]
        elif "multipart" in mime:
            params.append(("multipart", "(body not parsed)"))
        else:
            params.append(("body", mime or "unknown type"))
    if "multipart" in mime and re.search(r'filename="', text):
        upload = True
    return params, upload


def view_entry_points(files: list[Path], host: str = "") -> None:
    """Draft entry point inventory (WSTG-INFO-06): one row per method and path template,
    with parameter names and where they are sent, whether login looks required, and marks
    for state-changing requests and file uploads. Names only, never values.

    LOGIN is a first guess from the HAR alone: `no` when the entry point was seen in an
    anonymous HAR (file name starting with anon/anonymous/public) or was sent without any
    cookie or auth header; `likely` when it was only ever seen logged in with credentials.
    Confirm `likely` rows with the cookie-less replay (step 6 of WSTG-INFO-06)."""
    host = host.lower().split(":")[0]
    rows: dict[tuple[str, str], dict] = {}
    other_hosts: dict[str, int] = {}
    static = 0
    cookies_seen: dict[str, int] = {}
    headers_seen: dict[str, int] = {}
    roles: list[str] = []
    for label, entries in _iter(files):
        role = _role(label)
        anon = bool(_ANON_ROLE_RE.match(role))
        roles.append(f"{label} -> {role}{' (anonymous)' if anon else ''}")
        for e in entries:
            req = e.get("request") or {}
            _, h, path, qnames = _url_parts(str(req.get("url", "")))
            h = h.split("@")[-1].split(":")[0]
            if host and h != host:
                other_hosts[h] = other_hosts.get(h, 0) + 1
                continue
            if _STATIC_RE.search(path):
                static += 1
                continue
            method = str(req.get("method", "?")).upper()
            key = (method, _template(path or "/"))
            row = rows.setdefault(key, {"params": {}, "roles": set(), "anon": False, "noauth": False,
                                        "auth": False, "upload": False, "status": set(),
                                        "host": h})
            row["roles"].add(role)
            row["anon"] |= anon
            for n in qnames:
                row["params"].setdefault(("query", n), None)
            body, upload = _body_params(req)
            for loc_name in body:
                row["params"].setdefault(loc_name, None)
            row["upload"] |= upload
            ck = [str(c.get("name", "")) for c in req.get("cookies") or [] if c.get("name")]
            hdrs = [str(x.get("name", "")).lower() for x in req.get("headers") or []]
            auth_hdrs = [x for x in hdrs if x in _AUTH_HEADERS]
            custom = [x for x in hdrs if x.startswith("x-") or x == "authorization"]
            for n in ck:
                cookies_seen[n] = cookies_seen.get(n, 0) + 1
            for n in custom:
                headers_seen[n] = headers_seen.get(n, 0) + 1
                row["params"].setdefault(("header", n), None)
            if ck or auth_hdrs:
                row["auth"] = True
            else:
                row["noauth"] = True
            status = (e.get("response") or {}).get("status")
            if status:
                row["status"].add(str(status))

    print("== HAR files (role)")
    for r in roles or ["(no readable HAR file)"]:
        print("  " + r)
    if not any(_ANON_ROLE_RE.match(_role(r.split(" -> ")[0])) for r in roles):
        print("  ! no anonymous HAR (capture one with `wstg capture TARGET --role anon`);"
              " without it the login column is only a guess from cookies")
    print()
    print(f"== Entry points{' on ' + host if host else ''} (method, path, login, parameters [location], notes)")
    if not rows:
        print("  (no entry point in the HAR)")
    for (method, path), row in sorted(rows.items(), key=lambda kv: (kv[0][1], kv[0][0])):
        if row["anon"]:
            login = "no (anonymous HAR)"
        elif row["noauth"]:
            login = "no (sent without cookies)"
        else:
            login = "likely (seen only logged in)"
        by_loc: dict[str, list[str]] = {}
        for loc, name in row["params"]:
            by_loc.setdefault(loc, []).append(name)
        params = "; ".join(f"{loc}: {', '.join(names)}" for loc, names in by_loc.items()) or "-"
        notes = []
        if method in _STATE_METHODS:
            notes.append("STATE-CHANGING")
        elif method == "GET" and _STATE_GET_RE.search(path):
            notes.append("STATE-CHANGING GET? (skip in replay)")
        if row["upload"]:
            notes.append("FILE UPLOAD")
        notes.append("status " + ",".join(sorted(row["status"])) if row["status"] else "no response")
        notes.append("roles " + ",".join(sorted(row["roles"])))
        prefix = "" if host else row["host"]
        print(f"  {method:7} {prefix}{path}\n"
              f"          login: {login}\n"
              f"          params: {params}\n"
              f"          notes: {'; '.join(notes)}")
    print()
    print(f"== Summary: {len(rows)} entry points, "
          f"{sum(1 for r in rows.values() if not r['anon'] and not r['noauth'])} likely need login, "
          f"{sum(1 for k in rows if k[0] in _STATE_METHODS)} state-changing, "
          f"{sum(1 for r in rows.values() if r['upload'])} with file upload; {static} static requests skipped")
    if cookies_seen:
        print("  cookies sent (name: requests): "
              + ", ".join(f"{n}: {c}" for n, c in sorted(cookies_seen.items())))
    if headers_seen:
        print("  custom/auth request headers (name: requests): "
              + ", ".join(f"{n}: {c}" for n, c in sorted(headers_seen.items())))
    if other_hosts:
        print("  other hosts skipped (host: requests): "
              + ", ".join(f"{n}: {c}" for n, c in sorted(other_hosts.items(), key=lambda kv: -kv[1])[:20]))


_VIEWS = {"cookies": view_cookies, "urls": view_urls, "cleartext": view_cleartext,
          "forms": view_forms, "xssi": view_xssi, "entry-points": view_entry_points}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2 or args[0] not in _VIEWS:
        print(f"usage: wstg-har {{{'|'.join(_VIEWS)}}} [--host HOST] FILE.har ...", file=sys.stderr)
        return 2
    view, rest, host = args[0], args[1:], ""
    if rest[:1] == ["--host"]:
        if len(rest) < 3:
            print("usage: --host needs a host name and at least one FILE.har", file=sys.stderr)
            return 2
        host, rest = rest[1], rest[2:]
    files = [Path(a) for a in rest]
    if view == "entry-points":
        view_entry_points(files, host)
    else:
        _VIEWS[view](files)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
