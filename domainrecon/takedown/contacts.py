#!/usr/bin/env python3
"""
Who to report an abusive website to: the abuse desk of the domain's registrar, the abuse desk
of the network hosting the site (or of the CDN in front of it), and the blocklists browsers
check. Nothing is sent from here.

Contacts come from RDAP: the registrar abuse contact that ICANN requires gTLD registrars to
publish, and the abuse contact the regional internet registry (RIPE, ARIN, APNIC...) holds
for the IP's network. TLDs without RDAP (many ccTLDs) fall back to whois.

Usage:  python -m domainrecon.takedown.contacts DOMAIN [IP]
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.takedown.contacts", run_name="__main__", alter_sys=True)
    sys.exit()

import re
import subprocess
import sys
from dataclasses import asdict, dataclass

import requests

RDAP = "https://rdap.org"
HEADERS = {"Accept": "application/rdap+json", "User-Agent": "domain-recon abuse-contact lookup"}

# CDNs answer for the sites behind them and forward abuse reports to the real host; they
# prefer their own form to their mailbox.
CDN_FORMS = {"AS13335": ("Cloudflare", "https://abuse.cloudflare.com/")}

# Where the blocklists browsers check take reports: (name, channel, address, only for case types).
BLOCKLISTS = [
    ("Google Safe Browsing", "form", "https://safebrowsing.google.com/safebrowsing/report_phish/", None),
    ("Microsoft SmartScreen", "form", "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site", None),
    ("Netcraft", "form", "https://report.netcraft.com/report", None),
    ("APWG", "email", "reportphishing@apwg.org", {"phishing"}),
]


@dataclass(frozen=True)
class Contact:
    kind: str            # registrar | hosting | cdn | blocklist
    name: str
    channel: str         # email | form | unknown (nothing published)
    address: str | None  # mailbox or form URL
    source: str          # where it was found


# --------------------------------------------------------------------------
# RDAP
# --------------------------------------------------------------------------

def _rdap(path: str) -> dict | None:
    try:
        r = requests.get(f"{RDAP}/{path}", headers=HEADERS, timeout=25)
        return r.json() if r.ok else None
    except (requests.RequestException, ValueError):
        return None


def _vcard(entity: dict, key: str) -> list[str]:
    vcard = (entity.get("vcardArray") or [None, []])[1]
    return [item[3] for item in vcard
            if isinstance(item, list) and len(item) > 3 and item[0] == key and isinstance(item[3], str) and item[3]]


def _walk(entities):
    """Entities and the entities nested in them (registries nest abuse contacts differently)."""
    for e in entities or []:
        yield e
        yield from _walk(e.get("entities"))


def _abuse_email(entities) -> str | None:
    for e in _walk(entities):
        if "abuse" in (e.get("roles") or []) and (emails := _vcard(e, "email")):
            return emails[0]
    return None


def _whois_abuse_email(domain: str) -> str | None:
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=45).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"abuse[^:\n]*:\s*([\w.+-]+@[\w-]+(?:\.[\w-]+)+)", out, re.I)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# the contacts
# --------------------------------------------------------------------------

def registrar_contact(domain: str, known_name: str | None = None) -> Contact:
    data = _rdap(f"domain/{domain}")
    if data:
        registrar = next((e for e in data.get("entities") or [] if "registrar" in (e.get("roles") or [])), {})
        name = (_vcard(registrar, "fn") or [known_name or "the registrar"])[0]
        email = _abuse_email(registrar.get("entities")) or _abuse_email(data.get("entities"))
        return Contact("registrar", name, "email" if email else "unknown", email, "RDAP")
    email = _whois_abuse_email(domain)
    return Contact("registrar", known_name or "the registrar", "email" if email else "unknown", email, "whois")


def hosting_contact(ip: str, asn: str | None = None, as_name: str | None = None) -> Contact:
    if asn in CDN_FORMS:
        name, form = CDN_FORMS[asn]
        return Contact("cdn", name, "form", form, f"{asn} is the {name} CDN")
    data = _rdap(f"ip/{ip}")
    if not data:
        return Contact("hosting", as_name or ip, "unknown", None, "RDAP unavailable")
    email = _abuse_email(data.get("entities"))
    owner = next((_vcard(e, "fn")[0] for e in _walk(data.get("entities"))
                  if "registrant" in (e.get("roles") or []) and _vcard(e, "fn")), None)
    name = owner or as_name or data.get("name") or ip
    return Contact("hosting", name, "email" if email else "unknown", email, f"RDAP, network {data.get('handle') or data.get('name')}")


def blocklist_contacts(case_type: str | None) -> list[Contact]:
    return [Contact("blocklist", name, channel, address, "known reporting channel")
            for name, channel, address, only in BLOCKLISTS if not only or case_type in only]


def site_address(rec: dict) -> dict | None:
    """The address the site is served from - first IPv4 of the domain, else of www, else IPv6 -
    with its ASN and network owner as collected by collect/profile.py."""
    found = (rec.get("dns") or {}).get("value") or {}
    for key in ("apex_A", "www_A", "apex_AAAA", "www_AAAA"):
        if found.get(key):
            return found[key][0]
    return None


def find(rec: dict, case_type: str | None) -> list[Contact]:
    """Every place to report the domain of a collected record to, in the order to use them."""
    registrar = ((rec.get("registration") or {}).get("registrar") or {}).get("value")
    contacts = [registrar_contact(rec["domain"], registrar)]
    if address := site_address(rec):
        contacts.append(hosting_contact(address["ip"], address.get("asn"), address.get("as_name")))
    return contacts + blocklist_contacts(case_type)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) not in (1, 2):
        print(__doc__)
        return 2
    contacts = [registrar_contact(argv[0])]
    if len(argv) == 2:
        contacts.append(hosting_contact(argv[1]))
    for c in contacts:
        print(asdict(c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
