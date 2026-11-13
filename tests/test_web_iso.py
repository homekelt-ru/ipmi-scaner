import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ipmi_scanner import isoserver, web  # noqa: E402
from ipmi_scanner.config import Config  # noqa: E402
from ipmi_scanner.service import ScanService  # noqa: E402
from ipmi_scanner.storage import Storage  # noqa: E402

DATA = os.urandom(3 * 1024 * 1024 + 123)


class UploadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = Config()
        cfg.iso.dir = os.path.join(cls.tmp.name, "iso")
        cfg.iso.host = "10.9.8.7"
        cfg.iso.max_gb = 0.01  # ~10 МБ
        cls.cfg = cfg
        st = Storage(os.path.join(cls.tmp.name, "t.db"))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.make_handler(cfg, st, ScanService(cfg, st)))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.iso = isoserver.make_server(cfg.iso.dir if os.makedirs(cfg.iso.dir, exist_ok=True) is None else "", "127.0.0.1", 0)
        threading.Thread(target=cls.iso.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.iso.shutdown(); cls.tmp.cleanup()

    def call(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, (json.loads(data) if data else {})

    def upload(self, name, data):
        return self.call("POST", f"/api/iso/upload?name={name}", data, {"Content-Type": "application/octet-stream"})

    def test_upload_list_url_serve_delete(self):
        st, r = self.upload("ubuntu-24.04.iso", DATA)
        self.assertEqual((st, r["ok"]), (200, True))
        st, r = self.call("GET", "/api/iso?ip=10.1.1.1")
        f = r["files"][0]
        self.assertEqual((f["name"], f["size"]), ("ubuntu-24.04.iso", len(DATA)))
        self.assertEqual(f["url"], "http://10.9.8.7:8624/ubuntu-24.04.iso")
        c = http.client.HTTPConnection("127.0.0.1", self.iso.server_port)  # файл реально раздаётся
        c.request("GET", "/ubuntu-24.04.iso")
        self.assertEqual(c.getresponse().read(), DATA)
        self.assertEqual(self.upload("ubuntu-24.04.iso", b"x")[0], 409)  # не перезаписывать
        hdr = {"Content-Type": "application/json"}
        self.assertEqual(self.call("POST", "/api/iso/delete", json.dumps({"name": "ubuntu-24.04.iso"}), hdr)[0], 200)
        self.assertEqual(self.call("GET", "/api/iso")[1]["files"], [])
        self.assertEqual(os.listdir(self.cfg.iso.dir), [])  # временных .part не осталось

    def test_rejects(self):
        for name in ("a.txt", "..%2Fx.iso", "bad%20name.iso", ".hid.iso", ""):
            self.assertEqual(self.upload(name, b"data")[0], 400, name)
        try:  # сервер отвечает 413 и сразу закрывает соединение, не вычитывая тело
            self.assertEqual(self.upload("big.iso", b"\0" * (11 * 1024 * 1024))[0], 413)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.assertEqual(self.call("POST", "/api/iso/delete", json.dumps({"name": "../t.db"}), {"Content-Type": "application/json"})[0], 404)
        self.assertEqual(os.listdir(self.cfg.iso.dir), [])


if __name__ == "__main__":
    unittest.main()
