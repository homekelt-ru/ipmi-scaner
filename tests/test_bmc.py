import json
import os
import sys
import tempfile
import threading
import time
import unittest
from base64 import b64encode
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipmi_scanner import bmc  # noqa: E402
from ipmi_scanner.config import Config  # noqa: E402
from ipmi_scanner.scanner import HostResult  # noqa: E402
from ipmi_scanner.service import ScanService  # noqa: E402
from ipmi_scanner.storage import Storage  # noqa: E402

TREE = {
    "/redfish/v1/": {"RedfishVersion": "1.6.0", "@odata.id": "/redfish/v1/",
                     "Systems": {"@odata.id": "/redfish/v1/Systems"},
                     "Managers": {"@odata.id": "/redfish/v1/Managers"},
                     "Chassis": {"@odata.id": "/redfish/v1/Chassis"}},
    "/redfish/v1/Systems": {"Members": [{"@odata.id": "/redfish/v1/Systems/1"}]},
    "/redfish/v1/Systems/1": {
        "Manufacturer": "Supermicro", "Model": "X11DPU", "SerialNumber": "S123", "PowerState": "On",
        "Status": {"Health": "OK"}, "BiosVersion": "3.4", "ProcessorSummary": {"Count": 2, "Model": "Xeon"},
        "MemorySummary": {"TotalSystemMemoryGiB": 128}},
    "/redfish/v1/Managers": {"Members": [{"@odata.id": "/redfish/v1/Managers/1"}]},
    "/redfish/v1/Managers/1": {"FirmwareVersion": "1.73.06", "Model": "ASPEED"},
    "/redfish/v1/Chassis": {"Members": [{"@odata.id": "/redfish/v1/Chassis/1"}]},
    "/redfish/v1/Chassis/1": {"Thermal": {"@odata.id": "/redfish/v1/Chassis/1/Thermal"},
                              "Power": {"@odata.id": "/redfish/v1/Chassis/1/Power"}},
    "/redfish/v1/Chassis/1/Thermal": {
        "Temperatures": [{"Name": "CPU1 Temp", "ReadingCelsius": 41, "Status": {"Health": "OK"}}],
        "Fans": [{"Name": "FAN1", "Reading": 5400, "ReadingUnits": "RPM"}]},
    "/redfish/v1/Chassis/1/Power": {"PowerControl": [{"PowerConsumedWatts": 212}]},
}
VM1, VM2 = "/redfish/v1/Managers/1/VirtualMedia/1", "/redfish/v1/Managers/1/VirtualMedia/2"
TREE["/redfish/v1/Managers/1"]["VirtualMedia"] = {"@odata.id": "/redfish/v1/Managers/1/VirtualMedia"}
TREE["/redfish/v1/Managers/1/VirtualMedia"] = {"Members": [{"@odata.id": VM1}, {"@odata.id": VM2}]}
TREE[VM1] = {"Id": "1", "Name": "Virtual Floppy", "MediaTypes": ["Floppy"], "Image": None, "Inserted": False}
TREE[VM2] = {"Id": "2", "Name": "Virtual CD", "MediaTypes": ["CD", "DVD"], "Image": None, "Inserted": False,
             "Actions": {"#VirtualMedia.InsertMedia": {"target": VM2 + "/Actions/VirtualMedia.InsertMedia"},
                         "#VirtualMedia.EjectMedia": {"target": VM2 + "/Actions/VirtualMedia.EjectMedia"}}}
USER, PWD = "ADMIN", "s3cret"
EXPECTED = "Basic " + b64encode(f"{USER}:{PWD}".encode()).decode()


class FakeRedfish(BaseHTTPRequestHandler):
    hits = 0

    def log_message(self, *a):
        pass

    def do_GET(self):
        FakeRedfish.hits += 1
        # корень отвечает без входа, остальное — только с верными данными (как у реальных BMC)
        if self.path != "/redfish/v1/" and self.headers.get("Authorization") != EXPECTED:
            self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers()
            return
        body = TREE.get(self.path)
        if body is None:
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _write_handler(self):
    if self.headers.get("Authorization") != EXPECTED:
        self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers()
        return
    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
    code = 204
    if self.command == "POST" and self.path == VM2 + "/Actions/VirtualMedia.InsertMedia":
        TREE[VM2].update(Image=body["Image"], Inserted=True)
    elif self.command == "POST" and self.path == VM2 + "/Actions/VirtualMedia.EjectMedia":
        TREE[VM2].update(Image=None, Inserted=False)
    elif self.command == "PATCH" and self.path == "/redfish/v1/Systems/1":
        TREE[self.path]["Boot"] = body["Boot"]
    else:
        code = 404
    self.send_response(code); self.send_header("Content-Length", "0"); self.end_headers()


FakeRedfish.do_POST = FakeRedfish.do_PATCH = _write_handler


class RedfishTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeRedfish)
        cls.host = f"127.0.0.1:{cls.srv.server_port}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        bmc.SCHEME = "http"

    @classmethod
    def tearDownClass(cls):
        bmc.SCHEME = "https"
        cls.srv.shutdown()

    def test_collect_ok(self):
        r = bmc.collect(self.host, USER, PWD, timeout=3)
        self.assertNotIn("error", r)
        self.assertEqual(r["source"], "redfish")
        self.assertEqual(r["system"]["model"], "X11DPU")
        self.assertEqual(r["system"]["memory_gib"], 128)
        self.assertEqual(r["bmc"]["firmware"], "1.73.06")
        self.assertEqual(r["power_watts"], 212)
        self.assertEqual([s["name"] for s in r["sensors"]], ["CPU1 Temp", "FAN1"])

    def test_wrong_password_single_attempt(self):
        FakeRedfish.hits = 0
        r = bmc.collect(self.host, USER, "wrong", timeout=3)
        self.assertIn("Неверный логин", r["error"])
        self.assertLessEqual(FakeRedfish.hits, 2)  # корень + одна попытка входа, без повторов

    def test_service_stores_info_and_hides_password(self):
        with tempfile.TemporaryDirectory() as d:
            st = Storage(os.path.join(d, "t.db"))
            sid = st.start_scan(["x"])
            st.finish_scan(sid, ["x"], [HostResult(ip=self.host)])
            cfg = Config()
            svc = ScanService(cfg, st)
            # без логина — понятная ошибка
            svc.collect_async([self.host]); self._wait(svc)
            self.assertEqual(st.hosts()[0]["info_error"], "Не заданы логин и пароль")
            # свой логин
            self.assertIsNone(st.set_creds(self.host, USER, PWD))
            svc.collect_async([self.host]); self._wait(svc)
            h = st.hosts()[0]
            self.assertEqual(h["info"]["system"]["serial"], "S123")
            self.assertIsNone(h["info_error"])
            self.assertTrue(h["has_creds"])
            self.assertNotIn(PWD, json.dumps(h))
            # смена логина без пароля сохраняет прежний пароль
            self.assertIsNone(st.set_creds(self.host, USER, ""))
            self.assertEqual(st.get_creds(self.host), (USER, PWD))
            # логин по умолчанию из конфига
            st.delete_creds(self.host)
            cfg.bmc.username, cfg.bmc.password = USER, PWD
            svc.collect_async([self.host]); self._wait(svc)
            self.assertEqual(st.hosts()[0]["info"]["system"]["model"], "X11DPU")
            self.assertEqual(oct(os.stat(os.path.join(d, "t.db")).st_mode & 0o777), "0o600")

    @staticmethod
    def _wait(svc):
        for _ in range(100):
            if not svc.collecting:
                return
            time.sleep(0.05)
        raise AssertionError("сбор не завершился")


class MediaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        RedfishTest.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        RedfishTest.tearDownClass.__func__(cls)

    def test_media_flow(self):
        url = "http://10.0.0.5:8624/os.iso"
        r = bmc.media(self.host, USER, PWD, "status", timeout=3)
        cd = [m for m in r["media"] if "CD" in m["types"]][0]
        self.assertFalse(cd["inserted"])
        r = bmc.media(self.host, USER, PWD, "insert", url=url, boot_once=True, timeout=3)
        self.assertNotIn("error", r)
        cd = [m for m in r["media"] if "CD" in m["types"]][0]
        self.assertEqual((cd["inserted"], cd["image"]), (True, url))
        self.assertEqual(TREE["/redfish/v1/Systems/1"]["Boot"]["BootSourceOverrideTarget"], "Cd")
        self.assertIn("разовая загрузка", r["message"])
        r = bmc.media(self.host, USER, PWD, "eject", timeout=3)
        cd = [m for m in r["media"] if "CD" in m["types"]][0]
        self.assertFalse(cd["inserted"])

    def test_media_wrong_password(self):
        r = bmc.media(self.host, USER, "bad", "insert", url="http://x/a.iso", timeout=3)
        self.assertIn("Неверный логин", r["error"])
        self.assertIsNone(TREE[VM2]["Image"])


class HardwareFallbackTest(unittest.TestCase):
    """На BMC без ProcessorSummary/MemorySummary процессоры и память считаются по модулям."""

    def test_sums_processors_and_dimms(self):
        tree = {
            "/redfish/v1/": {"RedfishVersion": "1.0", "Systems": {"@odata.id": "/S"}},
            "/S": {"Members": [{"@odata.id": "/S/1"}]},
            "/S/1": {"Model": "DL380", "Processors": {"@odata.id": "/P"}, "Memory": {"@odata.id": "/M"},
                     "ProcessorSummary": {}, "MemorySummary": {}},
            "/P": {"Members": [{"@odata.id": "/P/1"}, {"@odata.id": "/P/2"}, {"@odata.id": "/P/3"}]},
            "/P/1": {"Model": "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", "ProcessorType": "CPU"},
            "/P/2": {"Model": "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", "ProcessorType": "CPU"},
            "/P/3": {"Status": {"State": "Absent"}, "ProcessorType": "CPU"},  # пустой сокет
            "/M": {"Members": [{"@odata.id": f"/M/{i}"} for i in range(1, 6)]},
            "/M/1": {"CapacityMiB": 32768}, "/M/2": {"CapacityMiB": 32768},
            "/M/3": {"CapacityMiB": 32768}, "/M/4": {"CapacityMiB": 32768},
            "/M/5": {"Status": {"State": "Absent"}, "CapacityMiB": 0},
        }

        def get(path):
            if path not in tree:
                raise bmc.Unavailable("HTTP 404")
            return tree[path]

        r = bmc.collect_redfish("x", "u", "p", 1, get=get)["system"]
        self.assertEqual(r["cpu_count"], 2)
        self.assertIn("E5-2680 v4", r["cpu_model"])
        self.assertEqual(r["memory_gib"], 128)


class IpmitoolParseTest(unittest.TestCase):
    def test_parse_kv_first_wins(self):
        kv = bmc.parse_kv("Product Name          : X11\nProduct Serial : A1\nProduct Name : other\n")
        self.assertEqual(kv["Product Name"], "X11")
        self.assertEqual(kv["Product Serial"], "A1")

    def test_parse_sdr(self):
        s = bmc.parse_sdr(
            "CPU Temp         | 45 degrees C      | ok\n"
            "FAN1             | 5400 RPM          | ok\n"
            "PS1 Pwr          | 212 Watts         | ok\n"
            "12V              | 12.1 Volts        | ok\n"
            "Fan2             | no reading        | ns\n"
            "Chassis Intru    | 0x00              | ok\n")
        self.assertEqual([x["name"] for x in s], ["CPU Temp", "FAN1", "PS1 Pwr", "12V", "Chassis Intru"])
        self.assertEqual((s[0]["value"], s[0]["unit"]), (45, "°C"))
        self.assertEqual((s[3]["value"], s[3]["unit"]), (12.1, "V"))


if __name__ == "__main__":
    unittest.main()
