"""Эмулятор BMC для тестов: отвечает на Get Channel Auth Capabilities и ASF Ping."""
from __future__ import annotations

import socket
import struct
import threading


def _chk(b: bytes) -> int:
    return (-sum(b)) & 0xFF


def auth_cap_response(cc: int = 0, auth: int = 0x97, flags: int = 0x04, ext: int = 0x03, oem: int = 0) -> bytes:
    head = bytes([0x81, 0x07 << 2])
    data = bytes([0x01, auth, flags, ext]) + oem.to_bytes(3, "little") + b"\x00" if cc == 0 else b""
    body = bytes([0x20, 0x00, 0x38, cc]) + data
    msg = head + bytes([_chk(head)]) + body + bytes([_chk(body)])
    return b"\x06\x00\xff\x07" + struct.pack("<BIIB", 0, 0, 0, len(msg)) + msg


def asf_pong(enterprise: int = 10876, ipmi: bool = True) -> bytes:
    payload = struct.pack(">IIBB", enterprise, 0, (0x80 if ipmi else 0) | 0x01, 0x00) + b"\x00" * 6
    return b"\x06\x00\xff\x06" + struct.pack(">IBBBB", 4542, 0x40, 0, 0, len(payload)) + payload


class FakeBMC:
    """only_v15=True — ведёт себя как старый BMC: ошибка 0xCC на запрос с битом IPMI 2.0."""

    def __init__(self, host: str = "127.0.0.1", only_v15: bool = False, oem: int = 0, enterprise: int = 10876):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.only_v15 = only_v15
        self.oem = oem
        self.enterprise = enterprise
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join()
        self.sock.close()

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            if data[3] == 0x06:
                self.sock.sendto(asf_pong(self.enterprise), addr)
            elif data[3] == 0x07 and len(data) > 20 and data[19] == 0x38:
                channel = data[20]
                if self.only_v15 and channel & 0x80:
                    self.sock.sendto(auth_cap_response(cc=0xCC), addr)
                elif self.only_v15:
                    self.sock.sendto(auth_cap_response(auth=0x17, flags=0x03, oem=self.oem), addr)
                else:
                    self.sock.sendto(auth_cap_response(oem=self.oem), addr)
