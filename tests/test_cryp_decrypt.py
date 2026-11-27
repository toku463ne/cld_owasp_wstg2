"""WSTG-CRYP-02 step 4: one-block decrypt against a loopback CBC padding oracle.

A toy block cipher (XOR with a key; invertible) stands in for AES so the test needs no
crypto dependency: the padding-oracle attack works against any deterministic block cipher.
"""
from __future__ import annotations

import base64
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from wstg import cryp

BS = 16
KEY = bytes(range(1, BS + 1))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _block_decrypt(block: bytes) -> bytes:       # D(x) = x XOR KEY (its own inverse)
    return _xor(block, KEY)


def _pad(data: bytes) -> bytes:
    n = BS - (len(data) % BS) or BS
    return data + bytes([n]) * n


def cbc_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    """IV | C1 | C2 | ... with C_i = E(P_i XOR C_{i-1}); E = D here."""
    prev, out = iv, bytearray(iv)
    for i in range(0, len(_pad(plaintext)), BS):
        block = _pad(plaintext)[i:i + BS]
        c = _xor(_xor(block, prev), KEY)         # E(P_i XOR prev)
        out += c
        prev = c
    return bytes(out)


def cbc_padding_ok(raw: bytes) -> bool:
    if len(raw) < 2 * BS or len(raw) % BS:
        return False
    blocks = [raw[i:i + BS] for i in range(0, len(raw), BS)]
    plain = b"".join(_xor(_block_decrypt(blocks[i]), blocks[i - 1]) for i in range(1, len(blocks)))
    n = plain[-1]
    return 1 <= n <= BS and plain[-n:] == bytes([n]) * n


class Oracle(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie", "")
        value = next((p.split("=", 1)[1] for p in cookie.split(";") if p.strip().startswith("enc=")), "")
        try:
            raw = base64.b64decode(value + "=" * (-len(value) % 4))
        except Exception:
            raw = b""
        if cbc_padding_ok(raw):
            body = b"ok " + b"x" * 200
            self.send_response(200)
        else:
            body = b"padding error"
            self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def serve():
    srvs = []

    def start():
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Oracle)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        srvs.append(srv)
        return f"http://127.0.0.1:{srv.server_port}"
    yield start
    for s in srvs:
        s.shutdown()


SECRET = b"id=42;admin=yes"          # one block after PKCS#7 padding (15 bytes -> pad 1)


def _http_root(tmp_path):
    value = base64.b64encode(cbc_encrypt(SECRET, iv=bytes(range(16, 32)))).decode()
    d = tmp_path / "http-root"
    d.mkdir()
    (d / "stdout.txt").write_text(f"HTTP/1.1 200 OK\r\nSet-Cookie: enc={value}; Path=/\r\n")
    (d / "body.html").write_text("<html><body>ok</body></html>")
    return d, value


def test_last_block_is_recovered(tmp_path, serve, capsys):
    base = serve()
    root, _ = _http_root(tmp_path)
    rc = cryp.main(["padding-decrypt", "--base", base + "/", "--http-root", str(root), "--candidate", "1"])
    out = capsys.readouterr().out
    assert rc == 0
    last = cryp._pad(SECRET)[-16:] if hasattr(cryp, "_pad") else None
    # the recovered plaintext block equals the padded secret's last 16 bytes
    pad = 16 - (len(SECRET) % 16) or 16
    expected = SECRET + bytes([pad]) * pad
    assert f"plaintext:" in out and expected[-16:].hex() in out
    assert "id=42;admin=yes" in out                       # shown without padding


def test_list_sends_nothing(tmp_path, serve, capsys):
    base = serve()
    root, _ = _http_root(tmp_path)
    rc = cryp.main(["padding-decrypt", "--base", base + "/", "--http-root", str(root), "--list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '1\tcookie "enc" (base64, decoded=32, block=16, anonymous)' in out


def test_candidate_out_of_range(tmp_path, serve):
    base = serve()
    root, _ = _http_root(tmp_path)
    assert cryp.main(["padding-decrypt", "--base", base + "/", "--http-root", str(root), "--candidate", "9"]) == 2


def test_single_block_is_refused(tmp_path, serve):
    base = serve()
    d = tmp_path / "http-root"
    d.mkdir()
    one = base64.b64encode(os.urandom(16)).decode()
    (d / "stdout.txt").write_text(f"HTTP/1.1 200 OK\r\nSet-Cookie: enc={one}; Path=/\r\n")
    (d / "body.html").write_text("<html></html>")
    assert cryp.main(["padding-decrypt", "--base", base + "/", "--http-root", str(d), "--candidate", "1"]) == 2


def test_stop_file_halts_the_attack(tmp_path, serve, capsys):
    base = serve()
    root, _ = _http_root(tmp_path)
    stop = tmp_path / "stop"
    stop.write_text("save")               # already present: stop at the first check
    rc = cryp.main(["padding-decrypt", "--base", base + "/", "--http-root", str(root),
                    "--candidate", "1", "--stop-file", str(stop)])
    assert rc == 3
    assert "stopped before the block was finished" in capsys.readouterr().out


def test_pause_applies_to_every_query(tmp_path, serve, monkeypatch):
    """--pause sleeps between individual oracle queries, not only between repeats
    (decrypt uses repeat=1, so a per-repeat-only pause would never fire)."""
    base = serve()
    root, _ = _http_root(tmp_path)
    naps = []
    monkeypatch.setattr(cryp.time, "sleep", lambda s: naps.append(s))
    rc = cryp.main(["padding-decrypt", "--base", base + "/", "--http-root", str(root),
                    "--candidate", "1", "--pause", "0.5"])
    assert rc == 0
    # one block = 16 bytes; many queries, each paced by ~0.5s (all but the first)
    assert len(naps) > 16 and all(abs(s - 0.5) < 1e-9 for s in naps)
