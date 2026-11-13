# Установка IPMI Scanner на AlmaLinux 10

Все команды выполняются от root. Сервер должен иметь сетевой доступ к сетям, где находятся BMC
(UDP/623, а для определения модели — TCP/443).

## 1. Установка Docker

```bash
# убрать podman/runc, если стоят: они конфликтуют с пакетами Docker
dnf remove -y podman buildah runc 2>/dev/null || true

dnf install -y dnf-plugins-core git
dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

systemctl enable --now docker
docker --version && docker compose version
```

## 2. Загрузка проекта

Публичный репозиторий клонируется напрямую:

```bash
git clone https://github.com/homekelt-ru/ipmi-scaner.git /opt/ipmi-scanner
```

Для приватного репозитория нужен deploy key (доступ только на чтение к одному репозиторию):

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/ipmi_scanner_deploy -C "ipmi-scanner@$(hostname)"
cat ~/.ssh/ipmi_scanner_deploy.pub
# GitHub → репозиторий → Settings → Deploy keys → Add deploy key → вставить ключ

cat >> ~/.ssh/config <<'EOF'
Host github-ipmi
    HostName github.com
    User git
    IdentityFile ~/.ssh/ipmi_scanner_deploy
    IdentitiesOnly yes
EOF

git clone git@github-ipmi:homekelt-ru/ipmi-scaner.git /opt/ipmi-scanner
```

## 3. Настройка

```bash
cd /opt/ipmi-scanner
cp .env.example .env
chmod 600 .env
vi .env
```

Обязательно поменяйте:

| Параметр | Значение |
|---|---|
| `IPMI_NETWORKS` | ваши сети с BMC, например `10.10.0.0/24 10.20.0.1-100` |
| `IPMI_INTERVAL_MINUTES` | как часто сканировать, минут (`0` — только вручную) |
| `IPMI_WEB_LISTEN` | `127.0.0.1` — панель только через SSH-туннель; `0.0.0.0` — открыть наружу |
| `IPMI_WEB_PASSWORD` | **обязателен**, если `IPMI_WEB_LISTEN=0.0.0.0` |

## 4. Запуск

```bash
cd /opt/ipmi-scanner
docker compose up -d --build
docker compose ps        # STATUS должен стать (healthy)
docker compose logs -f
```

Контейнер запускается в режиме `restart: unless-stopped` и сам поднимается после перезагрузки сервера.

## 5. Firewall (только если панель открыта наружу)

Контейнер использует сеть хоста, поэтому порт открывается в firewalld хоста.
Лучше разрешить доступ только с доверенных адресов:

```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="203.0.113.10/32" port port="8623" protocol="tcp" accept'
# или для всех (не рекомендуется):
# firewall-cmd --permanent --add-port=8623/tcp
firewall-cmd --reload
```

Для самого сканирования ничего открывать не нужно: ответы BMC на исходящие запросы firewalld
пропускает автоматически.

Если `IPMI_WEB_LISTEN=127.0.0.1`, панель открывается через туннель с вашего компьютера:

```bash
ssh -L 8623:127.0.0.1:8623 root@<сервер>
# затем в браузере: http://127.0.0.1:8623/
```

## 6. Образы ISO (виртуальный CD/DVD)

Образы загружаются через веб-панель: блок **«Библиотека образов (ISO)» → «Загрузить образ»**.
После загрузки сервис показывает ссылку для BMC (её можно вставить в *Scripted Media URL* в iLO).
Файлы хранятся в томе Docker `ipmi_ipmi-data` (каталог `/data/images`), отдельно копировать на сервер ничего не нужно.

BMC скачивает образы с сервиса по HTTP, поэтому порт 8624 должен быть доступен **из сети BMC**
(на сервере с сервисом он открывается так):

```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<сеть BMC, напр. 10.10.0.0/24>" port port="8624" protocol="tcp" accept'
firewall-cmd --reload
```

## 7. Проверка

```bash
# разовый скан из контейнера с выводом в консоль
docker compose run --rm ipmi-scanner scan 10.10.0.0/24 --redfish

# список сохранённых BMC
docker compose exec ipmi-scanner python -m ipmi_scanner list
```

## Обновление

```bash
cd /opt/ipmi-scanner
git pull
docker compose up -d --build
docker image prune -f
```

## Резервная копия базы

```bash
docker compose exec ipmi-scanner python -c \
  "import sqlite3; sqlite3.connect('/data/ipmi.db').backup(sqlite3.connect('/data/backup.db'))"
docker cp ipmi-scanner:/data/backup.db ./ipmi-backup-$(date +%F).db
```

## Возможные проблемы

- **BMC не находятся.** Проверьте с сервера `ping` до BMC и что UDP/623 не режется по пути.
  Если есть `ipmitool`, выполните `ipmitool -I lanplus -H <ip> -U x -P x chassis status`:
  ошибка аутентификации означает, что BMC доступен.
- **Порт 8623 занят.** Поменяйте `IPMI_WEB_PORT` в `.env` и выполните `docker compose up -d`.
- **SELinux и свой config.toml.** При монтировании файла добавьте суффикс `:Z`:
  `- ./config.toml:/app/config.toml:ro,Z`.
