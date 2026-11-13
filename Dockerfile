FROM python:3.12-slim

LABEL org.opencontainers.image.title="ipmi-scanner" \
      org.opencontainers.image.description="Поиск серверов с IPMI (BMC) в сети"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IPMI_DATABASE=/data/ipmi.db \
    IPMI_WEB_LISTEN=0.0.0.0 \
    IPMI_WEB_PORT=8623 \
    IPMI_ISO_DIR=/data/images \
    IPMI_ISO_PORT=8624

RUN apt-get update \
 && apt-get install -y --no-install-recommends ipmitool \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10623 --home-dir /app --shell /usr/sbin/nologin scanner \
 && mkdir -p /data && chown scanner /data

WORKDIR /app
COPY ipmi_scanner/ ./ipmi_scanner/

USER scanner
VOLUME ["/data"]
EXPOSE 8623 8624

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["python", "-m", "ipmi_scanner.healthcheck"]

ENTRYPOINT ["python", "-m", "ipmi_scanner"]
CMD ["serve"]
