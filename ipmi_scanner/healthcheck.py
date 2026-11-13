"""Проверка живости веб-панели для Docker HEALTHCHECK (401 тоже считается живым)."""
import os
import sys
import urllib.error
import urllib.request

port = os.environ.get("IPMI_WEB_PORT", "8623")
listen = os.environ.get("IPMI_WEB_LISTEN", "127.0.0.1")
host = "127.0.0.1" if listen in ("0.0.0.0", "", "::") else listen
try:
    urllib.request.urlopen(f"http://{host}:{port}/api/status", timeout=3)
except urllib.error.HTTPError as e:
    sys.exit(0 if e.code == 401 else 1)
except Exception:
    sys.exit(1)
