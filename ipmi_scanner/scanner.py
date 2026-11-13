"""Сканер сети: рассылает IPMI/ASF-пробы по UDP/623 и собирает ответы.

Один неблокирующий UDP-сокет на весь скан: пакеты отправляются с
ограничением скорости, ответы сопоставляются по IP источника.
"""
from __future__ import annotations

import ipaddress
import logging
import select
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Iterable

from . import protocol, redfish

log = logging.getLogger(__name__)

MAX_TARGETS = 1 << 20


def expand_targets(specs: Iterable[str]) -> list[str]:
    """CIDR (10.0.0.0/24), диапазон (10.0.0.1-10.0.0.50 или 10.0.0.1-50), одиночный IP."""
    seen: dict[str, None] = {}
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        if "-" in spec:
            start_s, end_s = spec.split("-", 1)
            start = ipaddress.IPv4Address(start_s.strip())
            end_s = end_s.strip()
            if "." not in end_s:  # 10.0.0.1-50
                end_s = start_s.rsplit(".", 1)[0] + "." + end_s
            end = ipaddress.IPv4Address(end_s)
            if int(end) < int(start):
                raise ValueError(f"Неверный диапазон: {spec}")
            if int(end) - int(start) > MAX_TARGETS:
                raise ValueError(f"Слишком большой диапазон: {spec}")
            for n in range(int(start), int(end) + 1):
                seen[str(ipaddress.IPv4Address(n))] = None
        else:
            net = ipaddress.IPv4Network(spec, strict=False)
            if net.num_addresses > MAX_TARGETS:
                raise ValueError(f"Слишком большая сеть: {spec}")
            hosts = net.hosts() if net.num_addresses > 2 else iter(net)
            for ip in hosts:
                seen[str(ip)] = None
        if len(seen) > MAX_TARGETS:
            raise ValueError("Слишком много адресов для одного скана")
    return list(seen)


def target_contains(specs: Iterable[str], ip: str) -> bool:
    addr = ipaddress.IPv4Address(ip)
    for spec in specs:
        spec = spec.strip()
        if "-" in spec:
            s, e = spec.split("-", 1)
            e = e.strip()
            if "." not in e:
                e = s.rsplit(".", 1)[0] + "." + e
            if int(ipaddress.IPv4Address(s.strip())) <= int(addr) <= int(ipaddress.IPv4Address(e)):
                return True
        elif spec and addr in ipaddress.IPv4Network(spec, strict=False):
            return True
    return False


@dataclass
class HostResult:
    ip: str
    mac: str | None = None
    ipmi: protocol.AuthCapabilities | None = None
    asf: protocol.AsfPong | None = None
    redfish: dict | None = None
    vendor: str | None = None
    product: str | None = None

    def finalize(self) -> None:
        rf = self.redfish or {}
        self.vendor = (
            rf.get("vendor")
            or (protocol.vendor_by_iana(self.ipmi.oem_id) if self.ipmi else None)
            or (protocol.vendor_by_iana(self.asf.enterprise) if self.asf else None)
        )
        self.product = rf.get("product")

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "product": self.product,
            "ipmi": self.ipmi.to_dict() if self.ipmi else None,
            "asf": self.asf.to_dict() if self.asf else None,
            "redfish": self.redfish,
        }


def read_arp_table() -> dict[str, str]:
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].lower()
    except OSError:
        pass
    return table


class _Prober:
    def __init__(self, port: int, rate: int):
        self.port = port
        self.rate = max(1, rate)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(False)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        self.ipmi: dict[str, protocol.AuthCapabilities] = {}
        self.asf: dict[str, protocol.AsfPong] = {}
        self._sent = 0
        self._t0 = time.monotonic()

    def close(self) -> None:
        self.sock.close()

    def _handle(self, ip: str, data: bytes) -> None:
        parsed = protocol.parse_response(data)
        if not parsed:
            return
        kind, obj = parsed
        if kind == "ipmi":
            prev = self.ipmi.get(ip)
            # успешный ответ важнее ответа с ошибкой
            if prev is None or prev.completion_code != 0:
                self.ipmi[ip] = obj
        else:
            self.asf[ip] = obj

    def drain(self, wait: float = 0.0) -> None:
        deadline = time.monotonic() + wait
        while True:
            remaining = deadline - time.monotonic()
            r, _, _ = select.select([self.sock], [], [], max(0.0, remaining))
            if not r:
                if remaining <= 0:
                    return
                continue
            while True:
                try:
                    data, (ip, _port) = self.sock.recvfrom(4096)
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    break
                self._handle(ip, data)
            if time.monotonic() >= deadline:
                return

    def send(self, ip: str, packet: bytes) -> None:
        for _ in range(100):
            try:
                self.sock.sendto(packet, (ip, self.port))
                break
            except BlockingIOError:
                self.drain(0.01)
            except OSError as e:  # broadcast, недоступная сеть и т.п.
                log.debug("sendto %s: %s", ip, e)
                return
        self._sent += 1
        ahead = self._sent / self.rate - (time.monotonic() - self._t0)
        if ahead > 0:
            self.drain(ahead)
        elif self._sent % 256 == 0:
            self.drain(0)


def scan(
    targets: Iterable[str],
    *,
    timeout: float = 1.5,
    retries: int = 1,
    rate: int = 1000,
    use_redfish: bool = False,
    redfish_timeout: float = 3.0,
    port: int = protocol.RMCP_PORT,
) -> list[HostResult]:
    ips = expand_targets(targets)
    if not ips:
        return []
    log.info("Скан %d адресов (rate=%d pps, timeout=%.1fs, retries=%d)", len(ips), rate, timeout, retries)
    p = _Prober(port, rate)
    try:
        req_v2 = protocol.build_auth_cap_request(ipmi2=True)
        req_v1 = protocol.build_auth_cap_request(ipmi2=False)
        ping = protocol.build_asf_ping()
        for _attempt in range(retries + 1):
            pending = [ip for ip in ips if ip not in p.ipmi]
            if not pending:
                break
            for ip in pending:
                p.send(ip, req_v2)
                if ip not in p.asf:
                    p.send(ip, ping)
            p.drain(timeout)
        # BMC только с IPMI 1.5 отвечают ошибкой на запрос с битом IPMI 2.0
        for _attempt in range(retries + 1):
            fallback = [ip for ip, c in p.ipmi.items() if c.completion_code != 0]
            fallback += [ip for ip, a in p.asf.items() if a.ipmi_supported and ip not in p.ipmi]
            if not fallback:
                break
            for ip in fallback:
                p.send(ip, req_v1)
            p.drain(timeout)
    finally:
        p.close()

    found = set(p.ipmi) | {ip for ip, a in p.asf.items() if a.ipmi_supported}
    arp = read_arp_table()
    results = []
    for ip in sorted(found, key=lambda s: tuple(int(x) for x in s.split("."))):
        results.append(HostResult(ip=ip, mac=arp.get(ip), ipmi=p.ipmi.get(ip), asf=p.asf.get(ip)))

    if use_redfish and results:
        with ThreadPoolExecutor(max_workers=32) as ex:
            for host, info in zip(results, ex.map(lambda h: redfish.probe(h.ip, redfish_timeout), results)):
                host.redfish = info
    for host in results:
        host.finalize()
    log.info("Найдено BMC: %d", len(results))
    return results
