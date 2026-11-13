"""Сборка и разбор пакетов RMCP / IPMI 1.5 / ASF для обнаружения BMC.

Используются два запроса, не требующих логина:
  * IPMI "Get Channel Authentication Capabilities" (NetFn App, cmd 0x38) —
    отвечает любой BMC, сообщает версии IPMI и включённые методы аутентификации;
  * ASF/RMCP Presence Ping — отвечает многие BMC, сообщает IANA производителя.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, asdict

RMCP_PORT = 623
ASF_IANA = 4542

RMCP_HEADER_ASF = b"\x06\x00\xff\x06"
RMCP_HEADER_IPMI = b"\x06\x00\xff\x07"

# Номера IANA Enterprise -> производитель (наиболее частые у серверов).
IANA_VENDORS = {
    2: "IBM",
    11: "HP / HPE",
    42: "Sun Microsystems",
    111: "Oracle",
    231: "Fujitsu",
    343: "Intel",
    674: "Dell",
    2011: "Huawei",
    5771: "Cisco",
    7244: "Quanta",
    10876: "Supermicro",
    15370: "Gigabyte",
    19046: "Lenovo",
    20974: "AMI",
    37945: "Inspur",
}


def _checksum(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def build_auth_cap_request(ipmi2: bool = True, seq: int = 0) -> bytes:
    """Get Channel Authentication Capabilities (сессия не нужна).

    ipmi2=True выставляет бит запроса расширенных данных IPMI 2.0;
    старые BMC (только 1.5) отвечают на него ошибкой — тогда шлём ipmi2=False.
    """
    channel = 0x8E if ipmi2 else 0x0E  # 0x0E = текущий канал
    priv = 0x04  # Administrator
    head = bytes([0x20, 0x06 << 2])  # rsAddr=BMC, NetFn=App, LUN 0
    body = bytes([0x81, (seq << 2) & 0xFC, 0x38, channel, priv])
    msg = head + bytes([_checksum(head)]) + body + bytes([_checksum(body)])
    session = struct.pack("<BIIB", 0, 0, 0, len(msg))  # authtype none, seq 0, id 0
    return RMCP_HEADER_IPMI + session + msg


def build_asf_ping(tag: int = 0) -> bytes:
    return RMCP_HEADER_ASF + struct.pack(">IBBBB", ASF_IANA, 0x80, tag & 0xFF, 0, 0)


@dataclass
class AuthCapabilities:
    completion_code: int
    channel: int = 0
    ipmi_v15: bool = False
    ipmi_v2: bool = False
    auth_none: bool = False
    auth_md2: bool = False
    auth_md5: bool = False
    auth_password: bool = False
    auth_oem: bool = False
    anonymous_login: bool = False
    null_usernames: bool = False
    non_null_usernames: bool = False
    user_level_auth_disabled: bool = False
    per_message_auth_disabled: bool = False
    kg_set: bool = False
    oem_id: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AsfPong:
    enterprise: int
    oem: int
    ipmi_supported: bool
    asf_version: int
    supported_interactions: int

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_ipmi(data: bytes) -> AuthCapabilities | None:
    if len(data) < 14:
        return None
    off = 4
    authtype = data[off]
    off += 1 + 4 + 4  # authtype, seq, session id
    if authtype not in (0x00, 0x06):
        off += 16  # auth code
    if authtype == 0x06:  # RMCP+ заголовок нам на этот запрос не ожидается
        return None
    if len(data) <= off:
        return None
    msg_len = data[off]
    msg = data[off + 1 : off + 1 + msg_len]
    # rqAddr, netFn/LUN, chk, rsAddr, seq, cmd, cc, data..., chk
    if len(msg) < 8 or msg[5] != 0x38 or (msg[1] >> 2) != 0x07:
        return None
    cc = msg[6]
    d = msg[7:-1]
    if cc != 0 or len(d) < 8:
        return AuthCapabilities(completion_code=cc)
    ext = bool(d[1] & 0x80)
    return AuthCapabilities(
        completion_code=cc,
        channel=d[0] & 0x0F,
        ipmi_v15=bool(d[3] & 0x01) if ext else True,
        ipmi_v2=bool(d[3] & 0x02) if ext else False,
        auth_none=bool(d[1] & 0x01),
        auth_md2=bool(d[1] & 0x02),
        auth_md5=bool(d[1] & 0x04),
        auth_password=bool(d[1] & 0x10),
        auth_oem=bool(d[1] & 0x20),
        anonymous_login=bool(d[2] & 0x01),
        null_usernames=bool(d[2] & 0x02),
        non_null_usernames=bool(d[2] & 0x04),
        user_level_auth_disabled=bool(d[2] & 0x08),
        per_message_auth_disabled=bool(d[2] & 0x10),
        kg_set=bool(d[2] & 0x20),
        oem_id=d[4] | (d[5] << 8) | (d[6] << 16),
    )


def _parse_asf(data: bytes) -> AsfPong | None:
    if len(data) < 12:
        return None
    iana, mtype, _tag, _res, dlen = struct.unpack(">IBBBB", data[4:12])
    if iana != ASF_IANA or mtype != 0x40 or dlen < 10 or len(data) < 12 + 10:
        return None
    enterprise, oem, entities, interactions = struct.unpack(">IIBB", data[12:22])
    return AsfPong(
        enterprise=enterprise,
        oem=oem,
        ipmi_supported=bool(entities & 0x80),
        asf_version=entities & 0x0F,
        supported_interactions=interactions,
    )


def parse_response(data: bytes) -> tuple[str, AuthCapabilities | AsfPong] | None:
    """Возвращает ("ipmi", AuthCapabilities) | ("asf", AsfPong) | None."""
    if len(data) < 4 or data[0] != 0x06:
        return None
    cls = data[3] & 0x1F
    if cls == 0x07:
        r = _parse_ipmi(data)
        return ("ipmi", r) if r else None
    if cls == 0x06:
        r = _parse_asf(data)
        return ("asf", r) if r else None
    return None


def vendor_by_iana(num: int | None) -> str | None:
    if not num or num == ASF_IANA:
        return None
    return IANA_VENDORS.get(num, f"IANA {num}")
