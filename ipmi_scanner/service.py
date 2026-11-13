"""Запуск сканов (по кнопке и по расписанию) с защитой от параллельного запуска."""
from __future__ import annotations

import logging
import threading
import time

from concurrent.futures import ThreadPoolExecutor

from . import bmc, scanner
from .config import Config
from .storage import Storage

log = logging.getLogger(__name__)


class ScanService:
    def __init__(self, cfg: Config, storage: Storage):
        self.cfg = cfg
        self.storage = storage
        self._lock = threading.Lock()
        self.running: dict | None = None
        self.next_run: float | None = None
        self._stop = threading.Event()
        self._clock = threading.Lock()
        self._collecting: set[str] = set()

    @property
    def collecting(self) -> list[str]:
        with self._clock:
            return sorted(self._collecting)

    def has_default_creds(self) -> bool:
        return bool(self.cfg.bmc.username and self.cfg.bmc.password)

    def collect_async(self, ips: list[str]) -> tuple[bool, str]:
        """Сбор данных с BMC в фоне: по одной попытке входа на каждый."""
        with self._clock:
            ips = [ip for ip in ips if ip not in self._collecting]
            if not ips:
                return False, "Сбор данных уже выполняется"
            self._collecting.update(ips)
        threading.Thread(target=self._collect_many, args=(ips,), daemon=True).start()
        return True, f"Сбор данных: {len(ips)} BMC"

    def _collect_many(self, ips: list[str]) -> None:
        workers = max(1, min(self.cfg.bmc.max_parallel, len(ips)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(self._collect_one, ips))

    def _collect_one(self, ip: str) -> None:
        try:
            creds = self.storage.get_creds(ip)
            if not creds and self.has_default_creds():
                creds = (self.cfg.bmc.username, self.cfg.bmc.password)
            if not creds:
                self.storage.set_info(ip, None, "Не заданы логин и пароль")
                return
            res = bmc.collect(ip, creds[0], creds[1], timeout=self.cfg.bmc.timeout)
            if "error" in res:
                self.storage.set_info(ip, None, res["error"])
            else:
                self.storage.set_info(ip, res, None)
        except Exception as e:
            log.exception("Сбор данных с %s", ip)
            self.storage.set_info(ip, None, f"Внутренняя ошибка: {type(e).__name__}")
        finally:
            with self._clock:
                self._collecting.discard(ip)

    def start_async(self, targets: list[str] | None = None) -> tuple[bool, str]:
        targets = targets or self.cfg.scan.networks
        if not targets:
            return False, "Не заданы сети для сканирования"
        try:
            count = len(scanner.expand_targets(targets))
        except ValueError as e:
            return False, str(e)
        if not self._lock.acquire(blocking=False):
            return False, "Скан уже выполняется"
        self.running = {"targets": targets, "started": time.time(), "count": count}
        threading.Thread(target=self._run, args=(targets,), daemon=True).start()
        return True, f"Скан запущен: {count} адресов"

    def _run(self, targets: list[str]) -> None:
        scan_id = self.storage.start_scan(targets)
        try:
            s = self.cfg.scan
            results = scanner.scan(
                targets, timeout=s.timeout, retries=s.retries, rate=s.rate,
                use_redfish=s.redfish, redfish_timeout=s.redfish_timeout,
            )
            self.storage.finish_scan(scan_id, targets, results)
        except Exception as e:
            log.exception("Ошибка скана")
            self.storage.finish_scan(scan_id, targets, None, error=str(e))
        finally:
            self.running = None
            self._lock.release()

    def scheduler_loop(self) -> None:
        interval = self.cfg.scan.interval_minutes * 60
        if interval <= 0 or not self.cfg.scan.networks:
            log.info("Плановое сканирование выключено")
            return
        self.next_run = time.time() + 5
        while not self._stop.is_set():
            if time.time() >= self.next_run:
                ok, msg = self.start_async()
                log.info("Плановый скан: %s", msg)
                self.next_run = time.time() + interval
            self._stop.wait(5)

    def stop(self) -> None:
        self._stop.set()
