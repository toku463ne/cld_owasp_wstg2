"""wstg-ffuf: judge ffuf JSON (catch-all answers left out), synthetic results only."""
from __future__ import annotations

import json

from wstg import ffufcheck as ff

BASE = "https://www.example.com"


def res(word, status=200, length=1000, words=50, lines=20, ctype="text/html", redirect=""):
    return {"input": {"FUZZ": word}, "url": f"{BASE}/{word}", "status": status, "length": length,
            "words": words, "lines": lines, "content-type": ctype, "redirectlocation": redirect}


def write(tmp_path, results, name="ffuf-backup.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"commandline": "ffuf ...", "results": results}))
    return p


def run(capsys, *argv):
    code = ff.main([str(a) for a in argv])
    return code, capsys.readouterr().out


def test_catch_all_is_left_out_and_real_backup_kept(tmp_path, capsys):
    # 300 short words all answered with the same soft-404 page (length varies: the page echoes the path)
    noise = [res(f"w{i}", length=1000 + i % 7) for i in range(300)]
    real = [res("index.php.bak", length=4321, words=300, lines=120, ctype="application/octet-stream"),
            res("admin", status=301, length=0, words=1, lines=1, redirect=f"{BASE}/admin/")]
    code, out = run(capsys, "--backup", write(tmp_path, noise + real))
    assert code == 0
    assert "CATCH-ALL" in out and "300  catch-all response" in out
    assert f"STRONG  200      4321  application/octet-stream  {BASE}/index.php.bak" in out
    assert f"CHECK   301" in out and "-> /FUZZ/" in out
    assert "w17" not in out.split("## Candidates")[1]
    assert out.strip().endswith("verdict: CANDIDATES 2 (STRONG 1)")


def test_redirect_of_everything_to_login_is_one_group(tmp_path, capsys):
    hits = [res(f"p{i}", status=302, length=0, words=1, lines=1, redirect=f"{BASE}/login?next=/p{i}")
            for i in range(50)]
    code, out = run(capsys, write(tmp_path, hits, "ffuf-content.json"))
    assert "302 words=1 lines=1 type=text/html -> /login  CATCH-ALL" in out
    assert "verdict: NO-CANDIDATE" in out


def test_extension_ignored_and_html_archive_left_out(tmp_path, capsys):
    hits = [res("app", length=800, words=40), res("app.bak", length=800, words=40),
            res("app.old", length=800, words=40), res("site.zip", length=500, words=30, lines=9),
            res("db.sql~", length=9000, words=10, lines=3, ctype="text/plain")]
    code, out = run(capsys, "--backup", write(tmp_path, hits))
    assert "2  answers like its base name (extension ignored)  e.g. app.bak, app.old" in out
    assert "1  archive name answered with an HTML page  e.g. site.zip" in out
    assert "STRONG  200      9000  text/plain" in out and f"{BASE}/db.sql~" in out
    assert f"CHECK   200       800  text/html                 {BASE}/app\n" in out   # the base page itself


def test_baseline_404_look_alike(tmp_path, capsys):
    h404 = tmp_path / "http-404"
    h404.mkdir()
    (h404 / "stdout.txt").write_text("HTTP/1.1 200 OK\r\n")
    (h404 / "body.html").write_text("x" * 2000)
    hits = [res("a", length=2010, words=7), res("b", length=1990, words=9), res("c", length=5000, words=99)]
    code, out = run(capsys, "--baseline", h404, write(tmp_path, hits, "ffuf-content.json"))
    assert "default 404: status 200, 2000 bytes" in out
    assert "2  same as the default 404 page  e.g. a, b" in out
    assert "verdict: CANDIDATES 1 (STRONG 1)" in out


def test_no_result_and_missing_json(tmp_path, capsys):
    code, out = run(capsys, write(tmp_path, []))
    assert code == 0 and "verdict: NO-RESULT" in out
    d = tmp_path / "partial"
    d.mkdir()
    (d / "stdout.txt").write_text("a\naa\naaa\n")
    code, out = run(capsys, "--backup", d / "ffuf-backup.json")
    assert code == 3 and "input missing" in out and "PARTIAL: stdout.txt lists 3 names" in out
    assert "verdict: INCOMPLETE" in out
