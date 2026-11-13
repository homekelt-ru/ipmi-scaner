import http.client
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ipmi_scanner import isoserver  # noqa: E402

DATA = bytes(range(256)) * 40


class IsoServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = os.path.join(cls.tmp.name, "iso")
        os.mkdir(root)
        open(os.path.join(root, "os.iso"), "wb").write(DATA)
        open(os.path.join(root, "notes.txt"), "wb").write(b"x")
        open(os.path.join(cls.tmp.name, "secret.iso"), "wb").write(b"secret")
        os.symlink(os.path.join(cls.tmp.name, "secret.iso"), os.path.join(root, "link.iso"))
        cls.root = root
        cls.srv = isoserver.make_server(root, "127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.tmp.cleanup()

    def get(self, path, method="GET", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=5)
        c.request(method, path, headers=headers or {})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r, body

    def test_list(self):
        self.assertEqual([f["name"] for f in isoserver.list_files(self.root)], ["link.iso", "os.iso"])

    def test_full_and_head(self):
        r, body = self.get("/os.iso")
        self.assertEqual((r.status, body), (200, DATA))
        r, body = self.get("/os.iso", "HEAD")
        self.assertEqual((r.status, body, r.getheader("Content-Length")), (200, b"", str(len(DATA))))

    def test_range(self):
        r, body = self.get("/os.iso", headers={"Range": "bytes=10-19"})
        self.assertEqual((r.status, body), (206, DATA[10:20]))
        self.assertEqual(r.getheader("Content-Range"), f"bytes 10-19/{len(DATA)}")
        r, body = self.get("/os.iso", headers={"Range": "bytes=-5"})
        self.assertEqual(body, DATA[-5:])
        r, _ = self.get("/os.iso", headers={"Range": "bytes=999999-"})
        self.assertEqual(r.status, 416)

    def test_forbidden(self):
        for path in ("/notes.txt", "/", "/..%2Fsecret.iso", "/%2e%2e/secret.iso", "/link.iso", "/missing.iso", "/.hidden.iso"):
            r, _ = self.get(path)
            self.assertEqual(r.status, 404, path)


if __name__ == "__main__":
    unittest.main()
