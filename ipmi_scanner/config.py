from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field


@dataclass
class ScanConfig:
    networks: list[str] = field(default_factory=list)
    interval_minutes: int = 60
    timeout: float = 1.5
    retries: int = 1
    rate: int = 1000
    redfish: bool = True
    redfish_timeout: float = 3.0


@dataclass
class WebConfig:
    listen: str = "127.0.0.1"
    port: int = 8623
    username: str = "admin"
    password: str = ""


@dataclass
class BmcConfig:
    # учётные данные по умолчанию для BMC, у которых нет своих
    username: str = ""
    password: str = ""
    timeout: float = 15.0
    max_parallel: int = 8


@dataclass
class Config:
    scan: ScanConfig = field(default_factory=ScanConfig)
    web: WebConfig = field(default_factory=WebConfig)
    bmc: BmcConfig = field(default_factory=BmcConfig)
    database: str = "./data/ipmi.db"


# Переменные окружения перекрывают конфиг (удобно для Docker).
_ENV = {
    "IPMI_NETWORKS": ("scan", "networks", lambda s: [x for x in s.replace(",", " ").split() if x]),
    "IPMI_INTERVAL_MINUTES": ("scan", "interval_minutes", int),
    "IPMI_TIMEOUT": ("scan", "timeout", float),
    "IPMI_RETRIES": ("scan", "retries", int),
    "IPMI_RATE": ("scan", "rate", int),
    "IPMI_REDFISH": ("scan", "redfish", lambda s: s.strip().lower() in ("1", "true", "yes", "on")),
    "IPMI_WEB_LISTEN": ("web", "listen", str),
    "IPMI_WEB_PORT": ("web", "port", int),
    "IPMI_WEB_USERNAME": ("web", "username", str),
    "IPMI_WEB_PASSWORD": ("web", "password", str),
    "IPMI_DATABASE": (None, "database", str),
    "IPMI_BMC_USERNAME": ("bmc", "username", str),
    "IPMI_BMC_PASSWORD": ("bmc", "password", str),
    "IPMI_BMC_TIMEOUT": ("bmc", "timeout", float),
    "IPMI_BMC_MAX_PARALLEL": ("bmc", "max_parallel", int),
}


def load(path: str | None) -> Config:
    cfg = Config()
    if path:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
        for k, v in raw.get("scan", {}).items():
            if hasattr(cfg.scan, k):
                setattr(cfg.scan, k, v)
        for k, v in raw.get("web", {}).items():
            if hasattr(cfg.web, k):
                setattr(cfg.web, k, v)
        for k, v in raw.get("bmc", {}).items():
            if hasattr(cfg.bmc, k):
                setattr(cfg.bmc, k, v)
        cfg.database = raw.get("storage", {}).get("database", cfg.database)
    for env, (section, key, conv) in _ENV.items():
        val = os.environ.get(env)
        if val is None or val == "":
            continue
        target = getattr(cfg, section) if section else cfg
        setattr(target, key, conv(val))
    return cfg
