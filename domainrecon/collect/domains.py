"""Domain names: normalising what users type, reading lists, and the registrable domain."""

import re
from pathlib import Path

import idna
import tldextract

TLDX = tldextract.TLDExtract()


def registrable(host: str) -> str:
    """The domain someone registered, per the Public Suffix List: www.shop.brand.co.uk -> brand.co.uk."""
    return TLDX(host.rstrip(".")).top_domain_under_public_suffix or host.rstrip(".")


def has_public_suffix(domain: str) -> bool:
    """Whether the name ends in a real TLD/public suffix (brand.com yes, domains.txt no)."""
    return bool(TLDX(domain).suffix)


def normalise(raw: str) -> str | None:
    """URL/whitespace/case tolerant -> bare punycode domain, or None if unusable."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", s)  # scheme
    s = s.split("/")[0].split("?")[0].split("#")[0]      # path/query/fragment
    s = s.split("@")[-1]                                 # userinfo or an email address
    s = s.split(":")[0]                                  # port
    s = s.strip(".").lower()
    if not s or "." not in s:
        return None
    try:
        s = idna.encode(s, uts46=True).decode("ascii")
    except Exception:
        try:
            s = s.encode("idna").decode("ascii")
        except Exception:
            pass  # keep as-is; DNS/whois may still cope
    if not re.fullmatch(r"[a-z0-9.\-_]+", s):
        return None
    return s


def read_domains(path: Path) -> list[str]:
    """The usable domains of a text file, one per line ('#' comments ok), in order, without repeats."""
    seen, out = set(), []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        d = normalise(line)
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out
