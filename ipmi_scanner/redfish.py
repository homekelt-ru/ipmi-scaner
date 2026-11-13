"""Анонимный запрос к Redfish service root (/redfish/v1/) — даёт производителя и модель."""
from __future__ import annotations

import json
import ssl
import urllib.request

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE  # у BMC почти всегда самоподписанный сертификат


def probe(ip: str, timeout: float = 3.0) -> dict | None:
    req = urllib.request.Request(
        f"https://{ip}/redfish/v1/",
        headers={"Accept": "application/json", "User-Agent": "ipmi-scanner"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
            if resp.status != 200:
                return None
            data = json.loads(resp.read(256 * 1024))
    except Exception:
        return None
    if not isinstance(data, dict) or "RedfishVersion" not in data and "@odata.id" not in data:
        return None
    oem = data.get("Oem")
    vendor = data.get("Vendor") or (next(iter(oem), None) if isinstance(oem, dict) and oem else None)
    return {
        "version": data.get("RedfishVersion"),
        "vendor": vendor,
        "product": data.get("Product"),
        "uuid": data.get("UUID"),
        "name": data.get("Name"),
    }
