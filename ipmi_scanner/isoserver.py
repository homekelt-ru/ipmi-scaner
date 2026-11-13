"""Раздача образов (.iso/.img) из каталога по HTTP — BMC скачивает их отсюда (Scripted Media URL).

Только чтение, только файлы с расширением .iso/.img из корня каталога, без листинга,
поддерживается Range (часть BMC качает образ кусками).
"""
from __future__ import annotations

import logging
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

log = logging.getLogger(__name__)
EXTS = (".iso", ".img")
CHUNK = 1024 * 1024


def list_files(root: str) -> list[dict]:
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return []
    out = []
    for n in names:
        p = os.path.join(root, n)
        if n.lower().endswith(EXTS) and not n.startswith(".") and os.path.isfile(p):
            out.append({"name": n, "size": os.path.getsize(p)})
    return out


def make_handler(root: str):
    real_root = os.path.realpath(root)

    class Handler(BaseHTTPRequestHandler):
        server_version = "ipmi-scanner-iso"

        def log_message(self, fmt, *args):
            log.info("ISO %s %s", self.address_string(), fmt % args)

        def do_HEAD(self):
            self._serve(head=True)

        def do_GET(self):
            self._serve(head=False)

        def _fail(self, code: int, extra: dict | None = None) -> None:
            self.send_response(code)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _serve(self, head: bool) -> None:
            name = unquote(urlparse(self.path).path.lstrip("/"))
            if not name or "/" in name or "\\" in name or name.startswith(".") or not name.lower().endswith(EXTS):
                return self._fail(404)
            path = os.path.realpath(os.path.join(real_root, name))
            if os.path.dirname(path) != real_root or not os.path.isfile(path):
                return self._fail(404)
            size = os.path.getsize(path)
            start, end, status = 0, size - 1, 200
            rng = self.headers.get("Range")
            if rng:
                m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
                if m and (m.group(1) or m.group(2)):
                    s, e = m.groups()
                    if not s:
                        start = max(0, size - int(e))
                    else:
                        start = int(s)
                        end = min(int(e), size - 1) if e else size - 1
                    if start > end or start >= size:
                        return self._fail(416, {"Content-Range": f"bytes */{size}"})
                    status = 206
            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(end - start + 1))
            if status == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if head:
                return
            try:
                with open(path, "rb") as f:
                    f.seek(start)
                    left = end - start + 1
                    while left > 0:
                        chunk = f.read(min(CHUNK, left))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        left -= len(chunk)
            except (BrokenPipeError, ConnectionResetError):
                pass  # BMC закрыла соединение

    return Handler


def make_server(root: str, listen: str, port: int) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer((listen, port), make_handler(root))
    srv.daemon_threads = True
    return srv


def start(cfg) -> ThreadingHTTPServer:
    os.makedirs(cfg.dir, exist_ok=True)
    srv = make_server(cfg.dir, cfg.listen, cfg.port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    log.info("Библиотека образов: %s -> http://%s:%d/", cfg.dir, cfg.listen, cfg.port)
    return srv
