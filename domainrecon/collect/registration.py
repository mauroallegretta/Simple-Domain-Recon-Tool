"""Registration date, expiry, registrar and statuses: RDAP first, port-43 whois as the fallback."""

import re
from datetime import datetime, timezone

import requests
from dateutil import parser as dateparser

from ..util import field, run

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

# whois creation-date labels, in preference order. First hit in the output wins:
# registries commonly list the domain block before contact/nameserver blocks.
WHOIS_CREATED_PATTERNS = [
    r"^\s*creation date:\s*(.+)$",
    r"^\s*created on:\s*(.+)$",
    r"^\s*created date:\s*(.+)$",
    r"^\s*created:\s*(.+)$",
    r"^\s*registered on:\s*(.+)$",
    r"^\s*registered:\s*(.+)$",
    r"^\s*registration date:\s*(.+)$",
    r"^\s*domain record activated:\s*(.+)$",
    r"^\s*domain registration date:\s*(.+)$",
    r"^\s*record created on:\s*(.+)$",
    r"^\s*activated:\s*(.+)$",
    r"^\s*data di creazione:\s*(.+)$",
    r"^\s*fecha de creaci[oó]n:\s*(.+)$",
    r"^\s*date d'enregistrement:\s*(.+)$",
    r"^\s*anniversary:\s*(.+)$",
]


def iso_date(text: str) -> str | None:
    text = text.strip().rstrip(".")
    if not text:
        return None
    try:
        dt = dateparser.parse(text, fuzzy=True)
    except Exception:
        return None
    if not dt:
        return None
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc)
    if not (1985 <= dt.year <= datetime.now(timezone.utc).year + 1):
        return None
    return dt.date().isoformat()


def rdap_lookup(domain: str) -> dict:
    """RDAP via rdap.org, which redirects to the authoritative registry."""
    out = {"created": field(), "expires": field(), "registrar": field(), "statuses": field()}
    try:
        r = requests.get(
            f"https://rdap.org/domain/{domain}",
            headers={"Accept": "application/rdap+json", "User-Agent": UA},
            timeout=25,
            allow_redirects=True,
        )
        if r.status_code != 200:
            for k in out:
                out[k]["error"] = f"rdap http {r.status_code}"
            return out
        data = r.json()
    except Exception as e:
        for k in out:
            out[k]["error"] = f"rdap: {type(e).__name__}: {e}"
        return out

    for ev in data.get("events") or []:
        action = (ev.get("eventAction") or "").lower()
        date = iso_date(str(ev.get("eventDate") or ""))
        if action == "registration" and date:
            out["created"] = field(date, "rdap")
        elif action == "expiration" and date:
            out["expires"] = field(date, "rdap")

    for ent in data.get("entities") or []:
        roles = [str(x).lower() for x in (ent.get("roles") or [])]
        if "registrar" not in roles:
            continue
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                    out["registrar"] = field(item[3], "rdap")
                    break

    statuses = [str(s) for s in (data.get("status") or [])]
    if statuses:
        out["statuses"] = field(statuses, "rdap")
    if out["created"]["value"] is None and out["created"]["error"] is None:
        out["created"]["error"] = "no registration event in rdap response"
    return out


def whois_lookup(domain: str) -> dict:
    """Fallback for TLDs with no RDAP (most ccTLDs, e.g. .it/.es)."""
    out = {"created": field(), "expires": field(), "registrar": field(), "statuses": field()}
    text = run(["whois", domain], timeout=45)
    if not text.strip():
        for k in out:
            out[k]["error"] = "whois returned nothing"
        return out
    if re.search(r"(no match|not found|no data found|no entries found|status:\s*(free|available))",
                 text, re.I):
        for k in out:
            out[k]["error"] = "domain appears unregistered per whois"
        return out

    lines = text.splitlines()
    for pat in WHOIS_CREATED_PATTERNS:
        rx = re.compile(pat, re.I)
        for line in lines:
            m = rx.match(line)
            if m:
                d = iso_date(m.group(1))
                if d:
                    out["created"] = field(d, "whois")
                    break
        if out["created"]["value"]:
            break

    for pat in [r"^\s*(?:registry )?expiry date:\s*(.+)$", r"^\s*expires(?: on)?:\s*(.+)$",
                r"^\s*expiration date:\s*(.+)$", r"^\s*expire date:\s*(.+)$",
                r"^\s*paid-till:\s*(.+)$", r"^\s*renewal date:\s*(.+)$",
                r"^\s*valid until:\s*(.+)$"]:
        rx = re.compile(pat, re.I)
        for line in lines:
            m = rx.match(line)
            if m and iso_date(m.group(1)):
                out["expires"] = field(iso_date(m.group(1)), "whois")
                break
        if out["expires"]["value"]:
            break

    for pat in [r"^\s*registrar:\s*(.+)$", r"^\s*sponsoring registrar:\s*(.+)$",
                r"^\s*registrar name:\s*(.+)$"]:
        rx = re.compile(pat, re.I)
        for line in lines:
            m = rx.match(line)
            if m and m.group(1).strip():
                out["registrar"] = field(m.group(1).strip(), "whois")
                break
        if out["registrar"]["value"]:
            break
    if not out["registrar"]["value"]:
        # .it and friends put the registrar in an indented block under a bare "Registrar" heading
        for i, line in enumerate(lines):
            if re.match(r"^registrar\s*$", line, re.I):
                for nxt in lines[i + 1:i + 8]:
                    m = re.match(r"^\s+(?:organization|name):\s*(.+)$", nxt, re.I)
                    if m and m.group(1).strip():
                        out["registrar"] = field(m.group(1).strip(), "whois")
                        break
                break

    statuses = [m.group(1).strip() for m in
                (re.match(r"^\s*(?:domain )?status:\s*(.+)$", ln, re.I) for ln in lines) if m]
    if statuses:
        out["statuses"] = field(statuses, "whois")
    if out["created"]["value"] is None:
        out["created"]["error"] = "no creation date matched in whois output"
    return out


def registration(domain: str) -> dict:
    r = rdap_lookup(domain)
    if r["created"]["value"]:
        return r
    w = whois_lookup(domain)
    # keep whichever source actually answered, field by field
    merged = {}
    for k in r:
        merged[k] = w[k] if w[k]["value"] is not None else r[k]
        if merged[k]["value"] is None and w[k]["error"]:
            merged[k] = field(None, None, f"{r[k]['error'] or 'rdap: no value'} | {w[k]['error']}")
    return merged
