"""CBC padding-oracle probe (WSTG-CRYP-02): codecs, mutation, and a loopback oracle."""
from __future__ import annotations

import base64
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import cryp


# ---- unit: codecs, detection, mutation -------------------------------------------


@pytest.mark.parametrize("codec_name, value", [
    ("hex", bytes(range(16)).hex()),
    ("base64", base64.b64encode(bytes(range(32))).decode()),
    ("base64url", base64.urlsafe_b64encode(bytes([0xfb, 0xff] * 16)).decode().replace("=", "")),
])
def test_codec_round_trip(codec_name, value):
    got = cryp.decode_candidate(value)
    assert got is not None
    codec, raw = got
    assert codec.name == codec_name
    # Re-encoding the decoded bytes reproduces a value that decodes to the same bytes.
    again = codec.encode(raw, value)
    assert codec.decode(again.rstrip("=") if codec_name != "hex" else again) == raw


def test_urltoken_round_trip():
    raw = bytes(range(16)) + bytes(range(16))
    enc = cryp._urltoken_encode(raw, "")
    assert enc[-1].isdigit()
    assert cryp._urltoken_decode(enc) == raw


def test_decode_rejects_plaintext_and_short_values():
    assert cryp.decode_candidate(base64.b64encode(b"hello world this is plain text!!").decode()) is None
    assert cryp.decode_candidate(base64.b64encode(b"tiny").decode()) is None  # < one block


def test_decode_prefers_16_byte_multiple():
    # 24 bytes is a multiple of 8 but not 16; 32 bytes is a multiple of 16.
    assert cryp.decode_candidate(base64.b64encode(bytes(range(24))).decode())[1].__len__() == 24
    codec, raw = cryp.decode_candidate(base64.b64encode(bytes(range(32))).decode())
    assert len(raw) == 32 and len(raw) % 16 == 0


def test_mutate_breaks_padding_but_keeps_it_for_garbled():
    raw = bytes(range(16)) + bytes(range(13)) + b"\x03\x03\x03"   # valid PKCS#7 pad = 3
    pad, gar = cryp.mutate(raw, 16)
    assert pad[-1] != raw[-1]                     # last byte (padding) changed
    assert gar[-3:] == raw[-3:]                   # padding bytes untouched
    assert gar[0] != raw[0]                       # content of the last block garbled


# ---- integration: a loopback padding oracle --------------------------------------


def _pkcs7_ok(raw: bytes) -> bool:
    n = raw[-1] if raw else 0
    return 1 <= n <= 16 and raw[-n:] == bytes([n]) * n


class Oracle(BaseHTTPRequestHandler):
    leaky = True            # True: tell bad padding apart; False: constant response

    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        value = next((p.split("=", 1)[1] for p in cookie.split(";")
                      if p.strip().startswith("enc=")), "")
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            raw = b""
        if self.leaky and not _pkcs7_ok(raw):
            body = b"padding error"
            self.send_response(403)
        else:
            body = b"ok " + b"x" * 200
            self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def serve():
    def start(leaky: bool):
        Oracle.leaky = leaky
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Oracle)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv
    srvs = []
    yield lambda leaky=True: srvs.append(s := start(leaky)) or f"http://127.0.0.1:{s.server_port}"
    for s in srvs:
        s.shutdown()


def _http_root(tmp_path, b64_value: str):
    d = tmp_path / "http-root"
    d.mkdir()
    (d / "stdout.txt").write_text(f"HTTP/1.1 200 OK\r\nSet-Cookie: enc={b64_value}; Path=/\r\n")
    (d / "body.html").write_text("<html><body>ok</body></html>")
    return d


def _token() -> str:
    raw = bytes(range(16)) + bytes(range(13)) + b"\x03\x03\x03"   # 32 bytes, valid pad = 3
    return base64.b64encode(raw).decode()


def test_probe_flags_a_padding_oracle(tmp_path, serve, capsys):
    base = serve(leaky=True)
    root = _http_root(tmp_path, _token())
    rc = cryp.main(["padding-probe", "--base", base + "/", "--http-root", str(root), "--repeat", "2"])
    out = capsys.readouterr().out
    assert rc == 0
    assert 'cookie "enc" (base64, decoded=32, block=16, anonymous)' in out
    assert "SUSPECTED ORACLE" in out
    assert "403 (bad padding) vs 200 (garbled content)" in out
    assert "1 candidate(s) with a suspected padding-oracle signal" in out


def test_probe_reports_no_signal_when_responses_match(tmp_path, serve, capsys):
    base = serve(leaky=False)
    root = _http_root(tmp_path, _token())
    rc = cryp.main(["padding-probe", "--base", base + "/", "--http-root", str(root), "--repeat", "2"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no oracle signal" in out
    assert "0 candidate(s) with a suspected padding-oracle signal" in out


def test_probe_records_when_no_candidate(tmp_path, serve, capsys):
    base = serve(leaky=True)
    root = tmp_path / "http-root"
    root.mkdir()
    (root / "stdout.txt").write_text("HTTP/1.1 200 OK\r\nSet-Cookie: sid=plain-short-value; Path=/\r\n")
    rc = cryp.main(["padding-probe", "--base", base + "/", "--http-root", str(root)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no encrypted-looking value found" in out
