"""What a browser doesn't report about a site: detected technologies, favicon hash, CDN and web
server, from one plain request with ProjectDiscovery's httpx (HTTPX_BIN in .env, else on PATH)."""

import json
import os
import shutil
from pathlib import Path

from .. import config  # noqa: F401  (loads .env before HTTPX_BIN is read)
from ..util import run

HTTPX = os.environ.get("HTTPX_BIN") or shutil.which("httpx") or str(Path.home() / "go/bin/httpx")


def http_fingerprint(domain: str) -> dict:
    """{} when httpx is missing or the host didn't answer."""
    if not Path(HTTPX).exists():
        return {}
    raw = run([HTTPX, "-u", domain, "-silent", "-json", "-no-color", "-title", "-tech-detect", "-sc",
               "-cl", "-location", "-favicon", "-web-server", "-timeout", "20", "-retries", "1"], timeout=90)
    line = next((ln for ln in raw.splitlines() if ln.startswith("{")), "")
    try:
        rec = json.loads(line)
    except ValueError:
        return {}
    return {"tech": rec.get("tech"), "cdn_name": rec.get("cdn_name"), "favicon_mmh3": rec.get("favicon"),
            "webserver": rec.get("webserver"), "content_length": rec.get("content_length"),
            "location": rec.get("location")}
