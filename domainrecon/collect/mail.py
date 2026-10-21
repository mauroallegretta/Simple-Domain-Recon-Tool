"""MX records, and who runs the domain's mail: the owner, a known provider, both, or nobody."""

import dns.exception

from ..util import field
from .dnsinfo import cymru_asn, dns_error, lookup, resolvers_label
from .domains import registrable

# MX registrable domain -> human-readable mail provider.
MAIL_PROVIDERS = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "microsoft.com": "Microsoft",
    "office365.us": "Microsoft 365 (GCC)",
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint Essentials",
    "mimecast.com": "Mimecast",
    "mimecast.co.za": "Mimecast",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "yandex.net": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "mail.ru": "Mail.ru",
    "ovh.net": "OVH",
    "ionos.com": "IONOS",
    "ionos.de": "IONOS",
    "1and1.com": "IONOS (1&1)",
    "kundenserver.de": "IONOS",
    "secureserver.net": "GoDaddy",
    "domaincontrol.com": "GoDaddy",
    "registrar-servers.com": "Namecheap (PrivateEmail)",
    "privateemail.com": "Namecheap (PrivateEmail)",
    "mailgun.org": "Mailgun (transactional)",
    "sendgrid.net": "SendGrid (transactional)",
    "mandrillapp.com": "Mandrill (transactional)",
    "postmarkapp.com": "Postmark (transactional)",
    "barracudanetworks.com": "Barracuda",
    "messagelabs.com": "Broadcom/Symantec MessageLabs",
    "emailsrvr.com": "Rackspace Email",
    "hostedemail.com": "Openwave / hosted",
    "qq.com": "Tencent Exmail",
    "aliyun.com": "Alibaba Mail",
    "mxhichina.com": "Alibaba Mail",
    "protonmail.ch": "Proton Mail",
    "proton.me": "Proton Mail",
    "fastmail.com": "Fastmail",
    "messagingengine.com": "Fastmail",
    "improvmx.com": "ImprovMX (forwarding)",
    "forwardemail.net": "ForwardEmail (forwarding)",
    "titan.email": "Titan Email",
    "hostinger.com": "Hostinger",
    "siteground.biz": "SiteGround",
    "arsys.net": "Arsys",
    "acens.net": "Acens",
    "cloudflare.net": "Cloudflare Email Routing",
    "strato.de": "Strato",
    "aruba.it": "Aruba",
    "register.it": "Register.it",
    "telecomitalia.it": "TIM",
}


def mx_host_asn(host: str) -> str | None:
    try:
        ips = [r.address for r in lookup(host, "A")]
    except dns.exception.DNSException:
        return None
    return cymru_asn(ips[0]).get("asn") if ips else None


def classify_mx(domain: str, hosts: list[tuple[int, str]], own_asns: set[str] | None = None) -> dict:
    own = registrable(domain)
    own_asns = own_asns or set()
    entries, providers, has_self, has_third = [], set(), False, False
    for pref, host in hosts:
        h = host.rstrip(".")
        if h in ("", "."):
            entries.append({"preference": pref, "host": ".", "kind": "null-mx",
                            "registrable": None, "provider": "null MX (RFC 7505: accepts no mail)"})
            continue
        reg = registrable(h)
        note = None
        if reg == own or h.endswith("." + own) or h == own:
            kind, provider = "proprietary", f"self-hosted under {own}"
            has_self = True
        elif reg in MAIL_PROVIDERS:
            kind, provider = "third-party", MAIL_PROVIDERS[reg]
            providers.add(provider)
            has_third = True
        else:
            # Unrecognised mail domain: it may still be the organisation's own
            # infrastructure under a sibling domain (e.g. brand.com -> brand-infra.net).
            # Same origin ASN as the web site is a strong signal of self-operation.
            mx_asn = mx_host_asn(h)
            if mx_asn and own_asns and mx_asn in own_asns:
                kind = "proprietary"
                provider = f"self-operated under sibling domain {reg} (same {mx_asn} as the web site)"
                has_self = True
            else:
                kind = "third-party"
                provider = f"unrecognised third party ({reg})"
                note = ("not a known mail provider; ASN differs from the web site"
                        if mx_asn else "not a known mail provider; MX host did not resolve")
                providers.add(provider)
                has_third = True
        entry = {"preference": pref, "host": h, "kind": kind,
                 "registrable": reg, "provider": provider}
        if note:
            entry["note"] = note
        entries.append(entry)

    if not entries:
        posture = "none"
    elif all(e["kind"] == "null-mx" for e in entries):
        posture = "null-mx"
    elif has_self and has_third:
        posture = "mixed"
    elif has_self:
        posture = "proprietary"
    else:
        posture = "third-party"
    return {"posture": posture, "records": entries, "providers": sorted(providers)}


def mx_lookup(domain: str, own_asns: set[str] | None = None) -> dict:
    source = f"{resolvers_label()} + Public Suffix List"
    try:
        hosts = sorted((r.preference, r.exchange.to_text()) for r in lookup(domain, "MX"))
    except dns.exception.DNSException as e:
        return field(None, source, dns_error(e))
    return field(classify_mx(domain, hosts, own_asns), source)
