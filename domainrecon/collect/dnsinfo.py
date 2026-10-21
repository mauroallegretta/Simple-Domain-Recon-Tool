"""
DNS: the resolvers every lookup goes to, A/AAAA records with reverse PTR and ASN, nameservers.

Every lookup goes to fixed resolvers (1.1.1.1, then 8.8.8.8), never to this machine's own, so
results don't change with where the tool runs (VPN, corporate or filtering DNS). DNS_RESOLVERS
in .env overrides them, and --resolvers overrides both.
"""

import argparse
import ipaddress
import os

import dns.exception
import dns.resolver

from .. import config  # noqa: F401  (loads .env before DNS_RESOLVERS is read)
from ..util import field

DEFAULT_RESOLVERS = "1.1.1.1,8.8.8.8"

RESOLVER = dns.resolver.Resolver(configure=False)
RESOLVER.nameservers = DEFAULT_RESOLVERS.split(",")
RESOLVER.timeout = 5     # seconds per server, as dig +time=5 did
RESOLVER.lifetime = 10   # whole lookup, fallback server included


def parse_resolvers(text: str) -> list[str]:
    """'1.1.1.1, 8.8.8.8' -> ['1.1.1.1', '8.8.8.8']. Only IP addresses are accepted."""
    servers = [s.strip() for s in text.split(",") if s.strip()]
    if not servers:
        raise argparse.ArgumentTypeError("no DNS resolver given")
    for s in servers:
        try:
            ipaddress.ip_address(s)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{s!r} is not an IP address") from None
    return servers


def add_resolvers_arg(ap: argparse.ArgumentParser) -> None:
    """--resolvers wins over DNS_RESOLVERS in .env, which wins over DEFAULT_RESOLVERS."""
    ap.add_argument("--resolvers", type=parse_resolvers,
                    default=os.environ.get("DNS_RESOLVERS") or DEFAULT_RESOLVERS,
                    help="comma-separated DNS servers for every lookup, tried in order "
                         f"(default: DNS_RESOLVERS from .env, else {DEFAULT_RESOLVERS})")


def use_resolvers(servers: list[str]) -> None:
    RESOLVER.nameservers = servers


def resolvers_label() -> str:
    return "DNS @ " + ", ".join(map(str, RESOLVER.nameservers))


def lookup(name: str, rdtype: str) -> list:
    """Records of one type for name; [] when the name or that record type doesn't exist.
    Raises dns.exception.DNSException when no resolver gave an answer (timeout, SERVFAIL)."""
    try:
        return list(RESOLVER.resolve(name, rdtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def first_txt(name: str) -> str:
    """First TXT record of name as text; '' when there is none or the lookup failed."""
    try:
        recs = lookup(name, "TXT")
    except dns.exception.DNSException:
        return ""
    return b"".join(recs[0].strings).decode("utf-8", "replace") if recs else ""


def dns_error(e: dns.exception.DNSException) -> str:
    if isinstance(e, dns.exception.Timeout):
        return f"timed out after {RESOLVER.lifetime:g}s"
    return f"{type(e).__name__}: {e}"


def cymru_asn(ip: str) -> dict:
    """Free, keyless ASN lookup over DNS (Team Cymru)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version == 4:
        q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    else:
        q = ".".join(reversed(addr.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
    txt = first_txt(q)
    if not txt:
        return {}
    parts = [p.strip() for p in txt.split("|")]
    if len(parts) < 3:
        return {}
    asn = parts[0].split()[0] if parts[0] else None
    info = {"asn": f"AS{asn}" if asn else None, "prefix": parts[1] or None,
            "cc": parts[2] or None}
    if asn:
        name = first_txt(f"AS{asn}.asn.cymru.com")
        if name:
            np = [p.strip() for p in name.split("|")]
            if len(np) >= 5:
                info["as_name"] = np[4]
    return info


def ptr(ip: str) -> str | None:
    try:
        return RESOLVER.resolve_address(ip)[0].target.to_text().rstrip(".")
    except dns.exception.DNSException:
        return None


def nameservers(domain: str) -> dict:
    try:
        ns = [r.target.to_text().rstrip(".") for r in lookup(domain, "NS")]
    except dns.exception.DNSException as e:
        return field(None, resolvers_label(), dns_error(e))
    return field(ns, resolvers_label())


def own_asn_set(dns_value: dict) -> set[str]:
    out = set()
    for recs in (dns_value or {}).values():
        for rec in recs or []:
            if rec.get("asn"):
                out.add(rec["asn"])
    return out


def addresses(domain: str) -> dict:
    result, errors = {}, []
    for name, label in ((domain, "apex"), (f"www.{domain}", "www")):
        for rtype in ("A", "AAAA"):
            try:
                ips = [r.address for r in lookup(name, rtype)]
            except dns.exception.DNSException as e:
                ips = []
                errors.append(f"{name} {rtype}: {dns_error(e)}")
            recs = []
            for ip in ips:
                rec = {"ip": ip, "ptr": ptr(ip)}
                rec.update(cymru_asn(ip))
                recs.append(rec)
            result[f"{label}_{rtype}"] = recs
    return field(result, f"{resolvers_label()} + Team Cymru DNS", "; ".join(errors) or None)
