"""Веб-панель и JSON API на стандартном http.server."""
from __future__ import annotations

import base64
import hmac
import json
import logging
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .config import Config
from .service import ScanService
from .storage import Storage

log = logging.getLogger(__name__)
INDEX_HTML = (Path(__file__).parent / "static" / "index.html").read_bytes()


def make_handler(cfg: Config, storage: Storage, service: ScanService):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ipmi-scanner"

        def log_message(self, fmt, *args):
            log.debug("%s %s", self.address_string(), fmt % args)

        # --- helpers ---
        def _authorized(self) -> bool:
            if not cfg.web.password:
                return True
            h = self.headers.get("Authorization", "")
            if not h.startswith("Basic "):
                return False
            try:
                user, _, pwd = base64.b64decode(h[6:]).decode().partition(":")
            except Exception:
                return False
            ok_user = hmac.compare_digest(user.encode(), cfg.web.username.encode())
            ok_pwd = hmac.compare_digest(pwd.encode(), cfg.web.password.encode())
            return ok_user and ok_pwd

        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, status: int = 200) -> None:
            self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _guard(self) -> bool:
            if self._authorized():
                return True
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.send_header("WWW-Authenticate", 'Basic realm="IPMI scanner", charset="UTF-8"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        def _body(self) -> dict | None:
            # требуем JSON — это заодно защищает от CSRF простыми формами
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                return None
            n = int(self.headers.get("Content-Length") or 0)
            if n > 64 * 1024:
                return None
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return None
            return data if isinstance(data, dict) else None

        def _creds(self, body: dict) -> None:
            ip = str(body.get("ip", ""))
            if body.get("clear"):
                storage.delete_creds(ip)
                self._json({"ok": True})
                return
            user, pwd = body.get("username"), body.get("password")
            if not isinstance(user, str) or not user.strip() or len(user) > 128 \
                    or (pwd is not None and (not isinstance(pwd, str) or len(pwd) > 256)):
                self._json({"ok": False, "message": "Некорректный логин или пароль"}, 400)
                return
            err = storage.set_creds(ip, user.strip(), pwd)
            self._json({"ok": err is None, "message": err or "Сохранено"}, 200 if err is None else 400)

        def _collect(self, body: dict) -> None:
            if body.get("all"):
                ips = [h["ip"] for h in storage.hosts()
                       if h["online"] and (h["has_creds"] or service.has_default_creds())]
                if not ips:
                    self._json({"ok": False, "message": "Нет BMC с заданными логином и паролем"}, 409)
                    return
            else:
                ip = str(body.get("ip", ""))
                if not storage.host_exists(ip):
                    self._json({"ok": False, "message": "Хост не найден"}, 404)
                    return
                ips = [ip]
            ok, msg = service.collect_async(ips)
            self._json({"ok": ok, "message": msg}, 200 if ok else 409)

        # --- routes ---
        def do_GET(self):
            if not self._guard():
                return
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
            elif path == "/api/hosts":
                self._json(storage.hosts())
            elif path == "/api/scans":
                self._json(storage.scans())
            elif path == "/api/status":
                self._json({
                    "running": service.running,
                    "next_run": service.next_run,
                    "networks": cfg.scan.networks,
                    "interval_minutes": cfg.scan.interval_minutes,
                    "now": time.time(),
                    "collecting": service.collecting,
                    "default_creds": service.has_default_creds(),
                })
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            if not self._guard():
                return
            path = urlparse(self.path).path
            body = self._body()
            if body is None:
                self._json({"error": "ожидается JSON"}, 400)
                return
            if path == "/api/scan":
                targets = body.get("targets")
                if isinstance(targets, str):
                    targets = [t for t in targets.replace(",", " ").split() if t]
                if targets is not None and not (isinstance(targets, list) and all(isinstance(t, str) for t in targets)):
                    self._json({"error": "targets: список строк"}, 400)
                    return
                ok, msg = service.start_async(targets or None)
                self._json({"ok": ok, "message": msg}, 200 if ok else 409)
            elif path == "/api/note":
                ok = storage.set_note(str(body.get("ip", "")), str(body.get("note", "")))
                self._json({"ok": ok}, 200 if ok else 404)
            elif path in ("/api/creds", "/api/collect"):
                # без пароля панели принимать пароли BMC можно только на loopback
                if not cfg.web.password and cfg.web.listen not in ("127.0.0.1", "localhost", "::1"):
                    self._json({"error": "Вход в BMC отключён: задайте пароль панели (web.password)"}, 403)
                    return
                if path == "/api/creds":
                    self._creds(body)
                else:
                    self._collect(body)
            elif path == "/api/delete":
                ok = storage.delete_host(str(body.get("ip", "")))
                self._json({"ok": ok}, 200 if ok else 404)
            else:
                self._json({"error": "not found"}, 404)

    return Handler


def serve(cfg: Config, storage: Storage, service: ScanService) -> None:
    httpd = ThreadingHTTPServer((cfg.web.listen, cfg.web.port), make_handler(cfg, storage, service))
    httpd.daemon_threads = True
    if not cfg.web.password and cfg.web.listen not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Веб-панель слушает %s без пароля! Задайте web.password в конфиге.", cfg.web.listen)
    log.info("Веб-панель: http://%s:%d/", cfg.web.listen, cfg.web.port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
