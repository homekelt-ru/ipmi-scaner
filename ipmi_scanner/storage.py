"""Хранилище результатов в SQLite."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time

from .scanner import HostResult, target_contains

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    ip          TEXT PRIMARY KEY,
    mac         TEXT,
    vendor      TEXT,
    product     TEXT,
    data        TEXT NOT NULL,
    warnings    TEXT NOT NULL DEFAULT '[]',
    online      INTEGER NOT NULL DEFAULT 1,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    note        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    started   REAL NOT NULL,
    finished  REAL,
    targets   TEXT NOT NULL,
    found     INTEGER,
    new       INTEGER,
    error     TEXT
);
"""


class Storage:
    def __init__(self, path: str):
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    def start_scan(self, targets: list[str]) -> int:
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO scans (started, targets) VALUES (?, ?)", (time.time(), json.dumps(targets))
            )
            self.db.commit()
            return cur.lastrowid

    def finish_scan(self, scan_id: int, targets: list[str], results: list[HostResult] | None, error: str | None = None) -> None:
        now = time.time()
        new = 0
        with self._lock:
            if results is not None:
                found_ips = set()
                for h in results:
                    found_ips.add(h.ip)
                    d = h.to_dict()
                    exists = self.db.execute("SELECT 1 FROM hosts WHERE ip=?", (h.ip,)).fetchone()
                    if not exists:
                        new += 1
                    self.db.execute(
                        """INSERT INTO hosts (ip, mac, vendor, product, data, warnings, online, first_seen, last_seen)
                           VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                           ON CONFLICT(ip) DO UPDATE SET
                             mac=COALESCE(excluded.mac, hosts.mac), vendor=COALESCE(excluded.vendor, hosts.vendor),
                             product=COALESCE(excluded.product, hosts.product), data=excluded.data,
                             warnings=excluded.warnings, online=1, last_seen=excluded.last_seen""",
                        (h.ip, h.mac, h.vendor, h.product, json.dumps(d, ensure_ascii=False),
                         json.dumps(h.warnings, ensure_ascii=False), now, now),
                    )
                # хосты из просканированных сетей, которые не ответили, — offline
                for row in self.db.execute("SELECT ip FROM hosts WHERE online=1").fetchall():
                    if row["ip"] not in found_ips and target_contains(targets, row["ip"]):
                        self.db.execute("UPDATE hosts SET online=0 WHERE ip=?", (row["ip"],))
            self.db.execute(
                "UPDATE scans SET finished=?, found=?, new=?, error=? WHERE id=?",
                (now, len(results) if results is not None else None, new, error, scan_id),
            )
            self.db.commit()

    def hosts(self) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM hosts").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["data"] = json.loads(d["data"])
            d["warnings"] = json.loads(d["warnings"])
            out.append(d)
        out.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
        return out

    def set_note(self, ip: str, note: str) -> bool:
        with self._lock:
            cur = self.db.execute("UPDATE hosts SET note=? WHERE ip=?", (note[:500], ip))
            self.db.commit()
            return cur.rowcount > 0

    def delete_host(self, ip: str) -> bool:
        with self._lock:
            cur = self.db.execute("DELETE FROM hosts WHERE ip=?", (ip,))
            self.db.commit()
            return cur.rowcount > 0

    def scans(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["targets"] = json.loads(d["targets"])
            out.append(d)
        return out
