#!/usr/bin/env python3
"""
Evidence for reporting a domain: one ZIP with everything collected about its page (screenshot,
HTML as served, rendered DOM, CSS), the collected record and AI analysis, and a MANIFEST.txt
giving each file's SHA-256 checksum, so the receiver can verify nothing changed after capture.

Also reads hard indicators straight out of the page - password and payment-card fields, and
where its forms submit - which back a report up without relying on the AI.
"""

import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

CARD_FIELD = re.compile(r"cc-?(number|csc|exp)|card.?num|cvv|cvc|tarjeta", re.I)
PACKAGED_NAMES = {"screenshot": "screenshot.png", "html": "page.html", "dom": "dom.html", "css": "styles.css"}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def page_indicators(markup: str, page_url: str | None) -> dict:
    """Password fields, payment-card fields, and the hosts the page's forms submit to."""
    soup = BeautifulSoup(markup or "", "html.parser")
    inputs = soup.find_all("input")

    def described(i):
        return " ".join(str(i.get(k) or "") for k in ("name", "id", "autocomplete", "placeholder"))

    targets = set()
    for form in soup.find_all("form"):
        target = urljoin(page_url or "", (form.get("action") or "").strip())
        if host := urlsplit(target).hostname:
            targets.add(host)
    return {"page_host": urlsplit(page_url or "").hostname,
            "forms": len(soup.find_all("form")),
            "password_fields": sum(1 for i in inputs if (i.get("type") or "").lower() == "password"),
            "card_fields": sum(1 for i in inputs if CARD_FIELD.search(described(i))),
            "form_targets": sorted(targets)}


def build(run_dir: Path, rec: dict, analysis: dict | None, out_zip: Path) -> dict:
    """Write the evidence ZIP for one domain of a run; returns its path, checksum and contents."""
    run_dir = Path(run_dir)
    members: dict[str, bytes] = {}
    for kind, path in ((rec.get("screenshot") or {}).get("files") or {}).items():
        file = Path(path) if Path(path).is_absolute() else run_dir / path
        if file.is_file():
            members[PACKAGED_NAMES.get(kind, file.name)] = file.read_bytes()
    members["record.json"] = json.dumps(rec, indent=2, ensure_ascii=False).encode("utf-8")
    if analysis:
        members["analysis.json"] = json.dumps(analysis, indent=2, ensure_ascii=False).encode("utf-8")

    meta = (rec.get("screenshot") or {}).get("meta") or {}
    checksums = {name: sha256(data) for name, data in members.items()}
    manifest = [f"Evidence for {rec.get('domain')}",
                f"Final URL: {meta.get('final_url') or '-'}",
                f"Captured: {meta.get('rendered_at') or rec.get('collected_at') or '-'}",
                f"Packaged: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
                "", "SHA-256 checksums:"]
    manifest += [f"{checksums[name]}  {len(members[name]):>9}  {name}" for name in members]
    members["MANIFEST.txt"] = ("\n".join(manifest) + "\n").encode("utf-8")

    out_zip = Path(out_zip)
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return {"zip": out_zip, "sha256": sha256(out_zip.read_bytes()), "files": checksums}
