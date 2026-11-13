"""CLI: python -m ipmi_scanner {scan,serve,list}"""
from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading

from . import config as config_mod, scanner


def cmd_scan(args, cfg) -> int:
    targets = args.targets or cfg.scan.networks
    if not targets:
        print("Укажите сети: python -m ipmi_scanner scan 10.0.0.0/24", file=sys.stderr)
        return 2
    results = scanner.scan(
        targets,
        timeout=args.timeout or cfg.scan.timeout,
        retries=cfg.scan.retries if args.retries is None else args.retries,
        rate=args.rate or cfg.scan.rate,
        use_redfish=args.redfish or (cfg.scan.redfish and not args.no_redfish),
        redfish_timeout=cfg.scan.redfish_timeout,
        port=args.port,
    )
    if args.save:
        from .storage import Storage
        st = Storage(cfg.database)
        sid = st.start_scan(targets)
        st.finish_scan(sid, targets, results)
    if args.json:
        print(json.dumps([r.to_dict() for r in results], ensure_ascii=False, indent=2))
        return 0
    if not results:
        print("BMC не найдены.")
        return 0
    print(f"{'IP':<16} {'MAC':<18} {'IPMI':<9} {'Производитель':<18} {'Модель':<24} Предупреждения")
    for r in results:
        i = r.ipmi
        if i and i.completion_code == 0:
            ver = "/".join(v for v, ok in (("1.5", i.ipmi_v15), ("2.0", i.ipmi_v2)) if ok)
        else:
            ver = "ASF" if not i else f"cc={i.completion_code:#x}"
        print(f"{r.ip:<16} {r.mac or '-':<18} {ver:<9} {(r.vendor or '-')[:18]:<18} "
              f"{(r.product or '-')[:24]:<24} {'; '.join(r.warnings) or '-'}")
    print(f"\nНайдено: {len(results)}")
    return 0


def cmd_list(args, cfg) -> int:
    from .storage import Storage
    hosts = Storage(cfg.database).hosts()
    if args.json:
        print(json.dumps(hosts, ensure_ascii=False, indent=2))
        return 0
    for h in hosts:
        state = "online " if h["online"] else "offline"
        print(f"{h['ip']:<16} {state} {h['mac'] or '-':<18} {(h['vendor'] or '-'):<18} {h['product'] or '-'}")
    print(f"\nВсего: {len(hosts)}")
    return 0


def cmd_serve(args, cfg) -> int:
    from .service import ScanService
    from .storage import Storage
    from . import web
    if args.listen:
        cfg.web.listen = args.listen
    if args.port:
        cfg.web.port = args.port
    storage = Storage(cfg.database)
    service = ScanService(cfg, storage)
    threading.Thread(target=service.scheduler_loop, daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        web.serve(cfg, storage, service)
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ipmi-scanner", description="Поиск серверов с IPMI (BMC) в сети")
    ap.add_argument("-c", "--config", help="путь к config.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="разовый скан")
    s.add_argument("targets", nargs="*", help="CIDR, диапазон или IP (по умолчанию — сети из конфига)")
    s.add_argument("--json", action="store_true", help="вывод в JSON")
    s.add_argument("--redfish", action="store_true", help="опросить Redfish на найденных BMC")
    s.add_argument("--no-redfish", action="store_true")
    s.add_argument("--save", action="store_true", help="сохранить результат в базу")
    s.add_argument("--timeout", type=float)
    s.add_argument("--retries", type=int)
    s.add_argument("--rate", type=int, help="пакетов в секунду")
    s.add_argument("--port", type=int, default=623, help=argparse.SUPPRESS)

    l = sub.add_parser("list", help="показать сохранённые BMC")
    l.add_argument("--json", action="store_true")

    w = sub.add_parser("serve", help="веб-панель + плановые сканы")
    w.add_argument("--listen")
    w.add_argument("--port", type=int)

    args = ap.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    cfg = config_mod.load(args.config)
    return {"scan": cmd_scan, "list": cmd_list, "serve": cmd_serve}[args.cmd](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
