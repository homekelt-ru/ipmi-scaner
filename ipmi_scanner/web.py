"""Веб-панель и JSON API на стандартном http.server."""
from __future__ import annotations

import base64
import hmac
import json
import logging
import os
import re
import shutil
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import isoserver
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

        def _open_ok(self) -> bool:
            """Изменяющие операции без пароля панели разрешены только на loopback."""
            if not cfg.web.password and cfg.web.listen not in ("127.0.0.1", "localhost", "::1"):
                self._json({"error": "Операция отключена: задайте пароль панели (web.password)"}, 403)
                return False
            return True

        def _upload(self, query: dict) -> None:
            """Приём образа потоком: тело запроса — сам файл (application/octet-stream)."""
            if not self._open_ok():
                return
            if not cfg.iso.dir:
                self._json({"ok": False, "message": "Библиотека образов выключена (IPMI_ISO_DIR)"}, 400)
                return
            name = (query.get("name") or [""])[0]
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", name) or not name.lower().endswith(isoserver.EXTS):
                self._json({"ok": False, "message": "Имя файла: латиница, цифры, . _ - и расширение .iso или .img"}, 400)
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0:
                self._json({"ok": False, "message": "Пустой файл или нет Content-Length"}, 400)
                return
            if length > cfg.iso.max_gb * 1024 ** 3:
                self._json({"ok": False, "message": f"Файл больше лимита {cfg.iso.max_gb:g} ГБ"}, 413)
                self.close_connection = True
                return
            os.makedirs(cfg.iso.dir, exist_ok=True)
            if shutil.disk_usage(cfg.iso.dir).free < length + 200 * 1024 ** 2:
                self._json({"ok": False, "message": "Недостаточно места на диске"}, 507)
                self.close_connection = True
                return
            final = os.path.join(cfg.iso.dir, name)
            if os.path.exists(final):
                self._json({"ok": False, "message": "Файл с таким именем уже есть — сначала удалите его"}, 409)
                self.close_connection = True
                return
            tmp = os.path.join(cfg.iso.dir, f".{name}.part")
            got = 0
            try:
                with open(tmp, "wb") as f:
                    while got < length:
                        chunk = self.rfile.read(min(1024 * 1024, length - got))
                        if not chunk:
                            break
                        f.write(chunk)
                        got += len(chunk)
                if got != length:
                    raise OSError("загрузка прервана")
                os.replace(tmp, final)
            except OSError as e:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                self.close_connection = True
                self._json({"ok": False, "message": f"Не удалось сохранить: {e}"}, 500)
                return
            log.info("Загружен образ %s (%d байт)", name, length)
            self._json({"ok": True, "file": {"name": name, "size": length}})

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

        def _media(self, body: dict) -> None:
            ip, op = str(body.get("ip", "")), body.get("action")
            if not storage.host_exists(ip):
                self._json({"ok": False, "message": "Хост не найден"}, 404)
                return
            if op not in ("status", "insert", "eject"):
                self._json({"ok": False, "message": "action: status | insert | eject"}, 400)
                return
            url = None
            if op == "insert":
                name, raw = body.get("file"), body.get("url")
                if name:
                    known = {f["name"] for f in isoserver.list_files(cfg.iso.dir)} if cfg.iso.dir else set()
                    if name not in known:
                        self._json({"ok": False, "message": "Файл не найден в библиотеке образов"}, 400)
                        return
                    url = service.iso_url(ip, name)
                elif isinstance(raw, str) and re.fullmatch(r"https?://[^\s\x00-\x1f]{1,1000}", raw.strip()):
                    url = raw.strip()
                else:
                    self._json({"ok": False, "message": "Укажите файл из библиотеки или URL образа (http/https)"}, 400)
                    return
            res = service.media(ip, op, url, bool(body.get("boot_once")))
            ok = "error" not in res
            self._json({"ok": ok, "message": res.get("error") or res.get("message", ""),
                        "media": res.get("media", []), "url": url}, 200 if ok else 502)

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
            elif path == "/api/iso":
                ip = parse_qs(urlparse(self.path).query).get("ip", [None])[0]
                files = isoserver.list_files(cfg.iso.dir) if cfg.iso.dir else []
                for f in files:
                    f["url"] = service.iso_url(ip, f["name"])
                self._json({"enabled": bool(cfg.iso.dir), "port": cfg.iso.port,
                            "max_gb": cfg.iso.max_gb, "files": files})
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
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/api/iso/upload":
                self._upload(parse_qs(parsed.query))
                return
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
            elif path in ("/api/creds", "/api/collect", "/api/media"):
                # без пароля панели принимать пароли BMC можно только на loopback
                if not cfg.web.password and cfg.web.listen not in ("127.0.0.1", "localhost", "::1"):
                    self._json({"error": "Вход в BMC отключён: задайте пароль панели (web.password)"}, 403)
                    return
                if path == "/api/creds":
                    self._creds(body)
                elif path == "/api/media":
                    self._media(body)
                else:
                    self._collect(body)
            elif path == "/api/iso/delete":
                if not self._open_ok():
                    return
                name = str(body.get("name", ""))
                known = {f["name"] for f in isoserver.list_files(cfg.iso.dir)} if cfg.iso.dir else set()
                if name not in known:
                    self._json({"ok": False, "message": "Файл не найден"}, 404)
                    return
                os.remove(os.path.join(cfg.iso.dir, name))
                self._json({"ok": True})
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
