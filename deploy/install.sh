#!/usr/bin/env bash
# Установка/обновление IPMI Scanner как systemd-сервиса. Запускать от root из корня проекта.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST=/opt/ipmi-scanner
CFG=/etc/ipmi-scanner/config.toml

python3 -c 'import sys; assert sys.version_info >= (3, 11), "нужен Python 3.11+"'

id ipmi-scanner &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin ipmi-scanner

mkdir -p "$DST" /etc/ipmi-scanner /var/lib/ipmi-scanner
rm -rf "$DST/ipmi_scanner"
cp -r "$SRC/ipmi_scanner" "$DST/"
find "$DST" -name __pycache__ -prune -exec rm -rf {} +
chown -R ipmi-scanner:ipmi-scanner /var/lib/ipmi-scanner

if [[ ! -f "$CFG" ]]; then
    sed 's#^database = .*#database = "/var/lib/ipmi-scanner/ipmi.db"#' "$SRC/config.example.toml" > "$CFG"
    chmod 640 "$CFG"
    chgrp ipmi-scanner "$CFG"
    echo "Создан $CFG — укажите в нём сети (scan.networks)."
fi

install -m 644 "$SRC/deploy/ipmi-scanner.service" /etc/systemd/system/ipmi-scanner.service
systemctl daemon-reload
systemctl enable ipmi-scanner
systemctl restart ipmi-scanner
systemctl --no-pager status ipmi-scanner | head -5
