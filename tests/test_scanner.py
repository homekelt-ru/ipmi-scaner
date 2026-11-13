import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake_bmc import FakeBMC, asf_pong, auth_cap_response  # noqa: E402
from ipmi_scanner import protocol, scanner  # noqa: E402
from ipmi_scanner.storage import Storage  # noqa: E402


class ProtocolTest(unittest.TestCase):
    def test_request_bytes(self):
        # эталонный пакет, который шлют ipmitool / nmap ipmi-version
        self.assertEqual(
            protocol.build_auth_cap_request().hex(),
            "0600ff070000000000000000000920" "18c88100388e04b5",
        )

    def test_parse_auth_caps_v2(self):
        kind, c = protocol.parse_response(auth_cap_response(auth=0x97, flags=0x04, ext=0x03, oem=674))
        self.assertEqual(kind, "ipmi")
        self.assertTrue(c.ipmi_v2 and c.ipmi_v15)
        self.assertTrue(c.auth_none and c.auth_md2 and c.auth_md5 and c.auth_password)
        self.assertTrue(c.non_null_usernames)
        self.assertFalse(c.anonymous_login)
        self.assertEqual(protocol.vendor_by_iana(c.oem_id), "Dell")

    def test_parse_v15_only(self):
        _, c = protocol.parse_response(auth_cap_response(auth=0x17, flags=0x03, ext=0))
        self.assertTrue(c.ipmi_v15)
        self.assertFalse(c.ipmi_v2)
        self.assertTrue(c.anonymous_login and c.null_usernames)

    def test_parse_error(self):
        _, c = protocol.parse_response(auth_cap_response(cc=0xCC))
        self.assertEqual(c.completion_code, 0xCC)

    def test_parse_asf(self):
        kind, p = protocol.parse_response(asf_pong(10876))
        self.assertEqual(kind, "asf")
        self.assertTrue(p.ipmi_supported)
        self.assertEqual(protocol.vendor_by_iana(p.enterprise), "Supermicro")

    def test_garbage(self):
        for junk in (b"", b"\x00" * 30, b"\x06\x00\xff\x07\x00", os.urandom(64)):
            protocol.parse_response(junk)  # не должно падать


class TargetsTest(unittest.TestCase):
    def test_expand(self):
        self.assertEqual(len(scanner.expand_targets(["10.0.0.0/24"])), 254)
        self.assertEqual(scanner.expand_targets(["10.0.0.1-3"]), ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(scanner.expand_targets(["10.0.0.5", "10.0.0.5/32"]), ["10.0.0.5"])
        with self.assertRaises(ValueError):
            scanner.expand_targets(["10.0.0.0/8"])

    def test_contains(self):
        self.assertTrue(scanner.target_contains(["10.0.0.0/24"], "10.0.0.7"))
        self.assertTrue(scanner.target_contains(["10.0.0.1-10"], "10.0.0.10"))
        self.assertFalse(scanner.target_contains(["10.0.0.1-10"], "10.0.0.11"))


class ScanTest(unittest.TestCase):
    def test_scan_finds_fake_bmc(self):
        with FakeBMC(oem=10876) as bmc:
            res = scanner.scan(["127.0.0.1", "127.0.0.2"], timeout=0.5, port=bmc.port)
        self.assertEqual([r.ip for r in res], ["127.0.0.1"])
        r = res[0]
        self.assertTrue(r.ipmi.ipmi_v2)
        self.assertEqual(r.vendor, "Supermicro")
        self.assertIsNotNone(r.asf)

    def test_scan_v15_fallback(self):
        with FakeBMC(only_v15=True) as bmc:
            res = scanner.scan(["127.0.0.1"], timeout=0.5, port=bmc.port)
        self.assertEqual(res[0].ipmi.completion_code, 0)
        self.assertFalse(res[0].ipmi.ipmi_v2)

    def test_name_and_note(self):
        with tempfile.TemporaryDirectory() as d:
            st = Storage(os.path.join(d, "t.db"))
            with FakeBMC() as bmc:
                res = scanner.scan(["127.0.0.1"], timeout=0.3, port=bmc.port)
            sid = st.start_scan(["127.0.0.1"])
            st.finish_scan(sid, ["127.0.0.1"], res)
            self.assertTrue(st.set_meta("127.0.0.1", name="  Стойка 3, DB-1 "))
            self.assertTrue(st.set_meta("127.0.0.1", note="диск заменён"))
            h = st.hosts()[0]
            self.assertEqual((h["name"], h["note"]), ("Стойка 3, DB-1", "диск заменён"))
            self.assertNotIn("warnings", h)
            self.assertFalse(st.set_meta("9.9.9.9", name="x"))
            sid = st.start_scan(["127.0.0.1"])  # повторный скан не стирает название и комментарий
            st.finish_scan(sid, ["127.0.0.1"], res)
            h = st.hosts()[0]
            self.assertEqual((h["name"], h["note"]), ("Стойка 3, DB-1", "диск заменён"))

    def test_storage_online_offline(self):
        with tempfile.TemporaryDirectory() as d:
            st = Storage(os.path.join(d, "t.db"))
            with FakeBMC() as bmc:
                res = scanner.scan(["127.0.0.1"], timeout=0.3, port=bmc.port)
            sid = st.start_scan(["127.0.0.0/30"])
            st.finish_scan(sid, ["127.0.0.0/30"], res)
            self.assertEqual(st.hosts()[0]["online"], 1)
            self.assertEqual(st.scans()[0]["new"], 1)
            sid = st.start_scan(["127.0.0.0/30"])
            st.finish_scan(sid, ["127.0.0.0/30"], [])
            self.assertEqual(st.hosts()[0]["online"], 0)


if __name__ == "__main__":
    unittest.main()
