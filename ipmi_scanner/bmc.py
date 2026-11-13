"""Вход в BMC с учётными данными и сбор информации.

Основной путь — Redfish (HTTPS, Basic Auth). Если Redfish недоступен —
запасной путь через ipmitool (IPMI 2.0 lanplus). Одна попытка входа на BMC:
при неверном пароле повторов нет, чтобы не заблокировать учётную запись.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
import subprocess
import time
import urllib.error
import urllib.request

SCHEME = "https"  # в тестах подменяется на http
MAX_SENSORS = 300

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # у BMC почти всегда самоподписанный сертификат


class AuthError(Exception):
    pass


class Unavailable(Exception):
    pass


# ---------------------------------------------------------------- Redfish

def _rf_get(host: str, path: str, auth: str, timeout: float) -> dict:
    req = urllib.request.Request(
        f"{SCHEME}://{host}{path}",
        headers={"Accept": "application/json", "Authorization": auth, "User-Agent": "ipmi-scanner"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            data = json.loads(r.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise AuthError() from None
        raise Unavailable(f"HTTP {e.code}") from None
    except Exception as e:
        raise Unavailable(str(e) or type(e).__name__) from None
    if not isinstance(data, dict):
        raise Unavailable("неожиданный ответ")
    return data


def _link(d: dict, key: str) -> str | None:
    v = d.get(key)
    return v.get("@odata.id") if isinstance(v, dict) else None


def _first_member(get, path: str) -> dict:
    members = get(path).get("Members") or []
    if members and isinstance(members[0], dict) and members[0].get("@odata.id"):
        return get(members[0]["@odata.id"])
    return {}


def _best_effort(fn):
    try:
        return fn()
    except Unavailable:
        return {}


def collect_redfish(host: str, username: str, password: str, timeout: float, get=None) -> dict:
    auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    get = get or (lambda p: _rf_get(host, p, auth, timeout))
    root = get("/redfish/v1/")
    if "RedfishVersion" not in root and "@odata.id" not in root:
        raise Unavailable("не Redfish")
    # первый запрос, который требует входа: на нём неверный пароль даёт 401
    s = _first_member(get, _link(root, "Systems") or "/redfish/v1/Systems")
    m = _best_effort(lambda: _first_member(get, _link(root, "Managers") or "/redfish/v1/Managers"))
    c = _best_effort(lambda: _first_member(get, _link(root, "Chassis") or "/redfish/v1/Chassis"))
    thermal = _best_effort(lambda: get(_link(c, "Thermal"))) if _link(c, "Thermal") else {}
    power = _best_effort(lambda: get(_link(c, "Power"))) if _link(c, "Power") else {}

    ps = s.get("ProcessorSummary") or {}
    ms = s.get("MemorySummary") or {}
    system = {
        "manufacturer": s.get("Manufacturer"),
        "model": s.get("Model"),
        "serial": s.get("SerialNumber") or c.get("SerialNumber"),
        "part_number": s.get("PartNumber") or s.get("SKU"),
        "hostname": s.get("HostName"),
        "power_state": s.get("PowerState"),
        "health": (s.get("Status") or {}).get("Health"),
        "bios_version": s.get("BiosVersion"),
        "cpu_count": ps.get("Count"),
        "cpu_model": ps.get("Model"),
        "memory_gib": ms.get("TotalSystemMemoryGiB"),
    }
    sensors = []
    for t in thermal.get("Temperatures") or []:
        if isinstance(t, dict) and t.get("ReadingCelsius") is not None:
            sensors.append({"name": t.get("Name"), "value": t["ReadingCelsius"], "unit": "°C",
                            "status": (t.get("Status") or {}).get("Health")})
    for f in thermal.get("Fans") or []:
        if isinstance(f, dict) and f.get("Reading") is not None:
            unit = {"RPM": "RPM", "Percent": "%"}.get(f.get("ReadingUnits"), f.get("ReadingUnits") or "")
            sensors.append({"name": f.get("Name") or f.get("FanName"), "value": f["Reading"], "unit": unit,
                            "status": (f.get("Status") or {}).get("Health")})
    pc = power.get("PowerControl")
    pc = pc[0] if isinstance(pc, list) and pc and isinstance(pc[0], dict) else {}
    return {
        "source": "redfish",
        "collected": time.time(),
        "system": system,
        "bmc": {"firmware": m.get("FirmwareVersion"), "model": m.get("Model")},
        "power_watts": pc.get("PowerConsumedWatts"),
        "sensors": sensors[:MAX_SENSORS],
    }


# ---------------------------------------------------------------- ipmitool

_AUTH_MARKERS = ("rakp", "invalid user name", "unauthorized name", "password invalid", "authentication")


def _ipmitool(host: str, username: str, password: str, args: list[str], timeout: float) -> tuple[int, str, str]:
    # пароль — через переменную окружения (-E), чтобы он не попал в список процессов
    cmd = ["ipmitool", "-I", "lanplus", "-H", host, "-U", username, "-E",
           "-N", "3", "-R", "1", *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, "IPMI_PASSWORD": password})
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    return p.returncode, p.stdout, p.stderr


def parse_kv(text: str) -> dict[str, str]:
    """Разбор строк «Ключ : значение»; при повторах побеждает первое значение."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if " : " in line:
            k, v = line.split(" : ", 1)
            out.setdefault(k.strip(), v.strip())
    return out


def parse_sdr(text: str) -> list[dict]:
    sensors = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 3:
            continue
        name, reading, status = parts[:3]
        if not name or reading in ("", "no reading", "disabled") or status == "ns":
            continue
        m = re.match(r"^(-?\d+(?:\.\d+)?)\s*(.*)$", reading)
        if m:
            num = float(m.group(1))
            value = int(num) if num.is_integer() else num
            unit = m.group(2).replace("degrees C", "°C").replace("Volts", "V").strip()
        else:
            value, unit = reading, ""
        sensors.append({"name": name, "value": value, "unit": unit, "status": status})
    return sensors


def collect_ipmitool(host: str, username: str, password: str, timeout: float) -> dict:
    rc, out, err = _ipmitool(host, username, password, ["mc", "info"], timeout)
    if rc != 0:
        if any(x in err.lower() for x in _AUTH_MARKERS):
            raise AuthError()
        raise Unavailable((err.strip().splitlines() or ["нет ответа"])[-1][:200])
    mc = parse_kv(out)

    def run(args):
        rc, o, _ = _ipmitool(host, username, password, args, timeout)
        return o if rc == 0 else ""

    fru = parse_kv(run(["fru", "print"]))
    chassis = parse_kv(run(["chassis", "status"]))
    sensors = parse_sdr(run(["sdr", "list"]))
    power = chassis.get("System Power")
    watts = next((s["value"] for s in sensors
                  if s["unit"].lower().startswith("watt") and re.search(r"pwr|power", s["name"], re.I)), None)
    return {
        "source": "ipmitool",
        "collected": time.time(),
        "system": {
            "manufacturer": fru.get("Product Manufacturer") or fru.get("Board Mfg"),
            "model": fru.get("Product Name") or fru.get("Board Product"),
            "serial": fru.get("Product Serial") or fru.get("Board Serial"),
            "part_number": fru.get("Product Part Number") or fru.get("Board Part Number"),
            "power_state": power.capitalize() if power else None,
            "health": None,
        },
        "bmc": {"firmware": mc.get("Firmware Revision"), "model": mc.get("Product ID")},
        "power_watts": watts,
        "sensors": sensors[:MAX_SENSORS],
    }


# ---------------------------------------------------------------- вход

def collect(host: str, username: str, password: str, timeout: float = 15.0) -> dict:
    """Возвращает данные BMC либо {"error": "..."}; не бросает исключений."""
    try:
        return collect_redfish(host, username, password, timeout)
    except AuthError:
        return {"error": "Неверный логин или пароль (Redfish)"}
    except Unavailable as e:
        rf_err = str(e)
    except Exception as e:  # некорректный ответ BMC и т.п.
        rf_err = f"{type(e).__name__}: {e}"
    if not shutil.which("ipmitool"):
        return {"error": f"Redfish недоступен ({rf_err}), ipmitool не установлен"}
    try:
        return collect_ipmitool(host, username, password, timeout)
    except AuthError:
        return {"error": "Неверный логин или пароль (IPMI)"}
    except Unavailable as e:
        return {"error": f"Redfish: {rf_err}; IPMI: {e}"}
    except Exception as e:
        return {"error": f"Redfish: {rf_err}; IPMI: {type(e).__name__}: {e}"}
