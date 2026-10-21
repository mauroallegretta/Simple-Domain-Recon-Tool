#!/usr/bin/env python3
"""
Ready-to-send prose about a checked domain, in English or Spanish: the facts of summary.py
written as a couple of paragraphs that can be pasted into an email or a report.

Registration, addresses, mail and whether there was content to assess are worded here from
the collected record, so they are always exact. Only the description of the page (and the
comparison with a monitored domain) comes from the AI analysis, which writes it in both
languages; analyses made before that fall back to the English description.

Usage:  python -m domainrecon.report.narrative runs/<run> [--lang en|es]
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.report.narrative", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import summary

LANGUAGES = ("en", "es")
MONTHS = {
    "en": ["January", "February", "March", "April", "May", "June", "July", "August",
           "September", "October", "November", "December"],
    "es": ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto",
           "septiembre", "octubre", "noviembre", "diciembre"],
}
# Said of a page that loaded when no AI description was asked for: an analyst overrides it
# after checking the screenshot.
STANDING_VERDICT = {
    "en": "The content is not related to the monitored company, and there is no evidence of domain impersonation.",
    "es": "El contenido no está relacionado con la empresa monitoreada y no hay evidencia de suplantación de dominio.",
}


@dataclass
class Facts:
    domain: str
    checked_at: str | None = None
    registered: str | None = None
    registrar: str | None = None
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    dns_failed: bool = False
    mail: str | None = None            # posture: none, null-mx, proprietary, third-party, mixed; None = unknown
    mail_failed: bool = False
    mail_hosts: list[str] = field(default_factory=list)
    mail_providers: list[str] = field(default_factory=list)
    content: str = "loaded"            # summary.content_state()
    content_detail: str | None = None
    analysis_failed: bool = False
    purpose: dict = field(default_factory=dict)      # language -> text
    monitored: str | None = None
    comparison: dict = field(default_factory=dict)   # language -> text
    same_owner: str | None = None


def facts(rec: dict, analysis: dict | None = None) -> Facts:
    def value(f):
        return f.get("value") if isinstance(f, dict) else None

    reg = rec.get("registration") or {}
    dns = rec.get("dns") or {}
    found = dns.get("value") or {}
    mx_field = rec.get("mx") or {}
    mx = mx_field.get("value") or {}
    state, detail = summary.content_state(rec)
    result = (analysis or {}).get("result") or {}

    def ips(rtype):
        return list(dict.fromkeys(r["ip"] for key in (f"apex_{rtype}", f"www_{rtype}") for r in found.get(key) or []))

    return Facts(
        domain=rec.get("domain", "?"), checked_at=rec.get("collected_at"),
        registered=value(reg.get("created")), registrar=value(reg.get("registrar")),
        ipv4=ips("A"), ipv6=ips("AAAA"), dns_failed=bool(dns.get("error")),
        mail=mx.get("posture"), mail_failed=bool(mx_field.get("error")) and not mx,
        mail_hosts=[r["host"] for r in mx.get("records") or [] if r.get("kind") != "null-mx"],
        mail_providers=mx.get("providers") or [],
        content=state, content_detail=detail,
        analysis_failed=analysis is not None and not result,
        purpose={k: v for k, v in (("en", result.get("purpose")), ("es", result.get("purpose_es"))) if v},
        monitored=(analysis or {}).get("monitored") if result.get("comparison") else None,
        comparison={k: v for k, v in (("en", result.get("comparison")), ("es", result.get("comparison_es"))) if v},
        same_owner=result.get("same_owner"))


# --------------------------------------------------------------------------
# wording helpers
# --------------------------------------------------------------------------

def date_text(iso: str, lang: str) -> str:
    try:
        d = datetime.strptime(iso[:10], "%Y-%m-%d")
    except (TypeError, ValueError):
        return iso
    month = MONTHS[lang][d.month - 1]
    return f"{d.day} {month} {d.year}" if lang == "en" else f"{d.day} de {month} de {d.year}"


def when_text(iso: str | None, lang: str) -> str | None:
    if not iso:
        return None
    time = iso[11:16] if len(iso) >= 16 else ""
    if not time:
        return date_text(iso, lang)
    return f"{date_text(iso, lang)} at {time} UTC" if lang == "en" else f"{date_text(iso, lang)} a las {time} UTC"


def _list(items: list[str], lang: str) -> str:
    if len(items) <= 1:
        return "".join(items)
    return f"{', '.join(items[:-1])} {'and' if lang == 'en' else 'y'} {items[-1]}"


def _addresses(kind: str, ips: list[str], lang: str) -> str:
    if lang == "en":
        return f"the {kind} address{'es' if len(ips) > 1 else ''} {_list(ips, lang)}"
    return (f"las direcciones {kind} {_list(ips, lang)}" if len(ips) > 1
            else f"la dirección {kind} {ips[0]}")


# --------------------------------------------------------------------------
# English
# --------------------------------------------------------------------------

def _english(f: Facts) -> str:
    d = f.domain
    if f.registered and f.registrar:
        reg = f"The domain {d} was registered on {date_text(f.registered, 'en')} through the registrar {f.registrar}."
    elif f.registered:
        reg = f"The domain {d} was registered on {date_text(f.registered, 'en')}; its registrar is not available."
    elif f.registrar:
        reg = f"The registration date of the domain {d} is not available; its registrar is {f.registrar}."
    else:
        reg = f"Registration data for the domain {d} (date and registrar) is not available."

    if f.ipv4 and f.ipv6:
        addr = f"It resolves to {_addresses('IPv4', f.ipv4, 'en')} and to {_addresses('IPv6', f.ipv6, 'en')}."
    elif f.ipv4:
        addr = f"It resolves to {_addresses('IPv4', f.ipv4, 'en')}; no IPv6 (AAAA) record was found."
    elif f.ipv6:
        addr = f"It resolves to {_addresses('IPv6', f.ipv6, 'en')}; no IPv4 (A) record was found."
    elif f.dns_failed:
        addr = "Its IP addresses could not be determined because the DNS lookup failed."
    else:
        addr = "It does not resolve to any IPv4 or IPv6 address."

    hosts, providers = _list(f.mail_hosts, "en"), _list(f.mail_providers, "en")
    mail = {
        "none": "It has no MX records, so no mail server is configured to receive email for it.",
        "null-mx": "It publishes a null MX record, explicitly declaring that it does not accept email.",
        "proprietary": f"Its email is handled by its own mail servers ({hosts}).",
        "third-party": f"Its email is handled by a third-party provider, {providers} ({hosts}).",
        "mixed": f"Its email is handled partly by its own mail servers and partly by a third party "
                 f"({providers}); the mail servers are {hosts}.",
    }.get(f.mail) or ("Its mail (MX) configuration could not be determined because the DNS lookup failed."
                      if f.mail_failed else "Its mail (MX) configuration is not available.")

    if f.content == "unregistered":
        content = "The domain appears not to be registered, so it was not visited and its content could not be assessed."
    elif f.content == "http_error":
        content = f"When visited, the site answered with an HTTP error ({f.content_detail}), so there was no content to assess."
    elif f.content == "no_screenshot":
        why = f" ({f.content_detail})" if f.content_detail else ""
        content = f"The site could not be visited{why}, so its content could not be assessed."
    elif f.content == "blank":
        content = "The site was reachable but showed a blank page, so there was no content to assess."
    elif f.purpose:
        content = f"Regarding its content: {f.purpose['en']}"
    elif f.analysis_failed:
        content = "The site was reachable and showed content, but it has not been assessed automatically."
    else:
        content = STANDING_VERDICT["en"]

    paragraphs = [f"{reg} {addr} {mail}", content]
    if f.monitored and f.comparison:
        owner = {"likely": "likely belong to the same owner",
                 "possible": "may belong to the same owner, although the data is not conclusive",
                 "unlikely": "appear to belong to different owners"}.get(f.same_owner)
        text = f"Compared with {f.monitored}: {f.comparison['en']}"
        if owner:
            text += f" Based on registration and network data, the two domains {owner}."
        paragraphs.append(text)
    if when := when_text(f.checked_at, "en"):
        paragraphs.append(f"(Checked on {when}.)")
    return "\n\n".join(paragraphs)


# --------------------------------------------------------------------------
# Spanish
# --------------------------------------------------------------------------

def _spanish(f: Facts) -> str:
    d = f.domain
    if f.registered and f.registrar:
        reg = f"El dominio {d} fue registrado el {date_text(f.registered, 'es')} a través del registrador {f.registrar}."
    elif f.registered:
        reg = f"El dominio {d} fue registrado el {date_text(f.registered, 'es')}; su registrador no está disponible."
    elif f.registrar:
        reg = f"La fecha de registro del dominio {d} no está disponible; su registrador es {f.registrar}."
    else:
        reg = f"Los datos de registro del dominio {d} (fecha y registrador) no están disponibles."

    if f.ipv4 and f.ipv6:
        addr = f"Resuelve a {_addresses('IPv4', f.ipv4, 'es')} y a {_addresses('IPv6', f.ipv6, 'es')}."
    elif f.ipv4:
        addr = f"Resuelve a {_addresses('IPv4', f.ipv4, 'es')}; no se encontró ningún registro IPv6 (AAAA)."
    elif f.ipv6:
        addr = f"Resuelve a {_addresses('IPv6', f.ipv6, 'es')}; no se encontró ningún registro IPv4 (A)."
    elif f.dns_failed:
        addr = "No fue posible determinar sus direcciones IP porque la consulta DNS falló."
    else:
        addr = "No resuelve a ninguna dirección IPv4 ni IPv6."

    hosts, providers = _list(f.mail_hosts, "es"), _list(f.mail_providers, "es")
    mail = {
        "none": "No tiene registros MX, por lo que no hay ningún servidor de correo configurado para recibir correo electrónico.",
        "null-mx": "Publica un registro MX nulo, con el que declara explícitamente que no acepta correo electrónico.",
        "proprietary": f"Su correo electrónico se gestiona con servidores propios ({hosts}).",
        "third-party": f"Su correo electrónico lo gestiona un proveedor externo, {providers} ({hosts}).",
        "mixed": f"Su correo electrónico se gestiona en parte con servidores propios y en parte con un proveedor "
                 f"externo ({providers}); los servidores de correo son {hosts}.",
    }.get(f.mail) or ("No fue posible determinar su configuración de correo (MX) porque la consulta DNS falló."
                      if f.mail_failed else "Su configuración de correo (MX) no está disponible.")

    if f.content == "unregistered":
        content = "El dominio parece no estar registrado, por lo que no se visitó y no fue posible evaluar su contenido."
    elif f.content == "http_error":
        content = f"Al visitarlo, el sitio respondió con un error HTTP ({f.content_detail}), por lo que no había contenido que evaluar."
    elif f.content == "no_screenshot":
        why = f" ({f.content_detail})" if f.content_detail else ""
        content = f"No fue posible visitar el sitio{why}, por lo que no se pudo evaluar su contenido."
    elif f.content == "blank":
        content = "El sitio respondió, pero mostró una página en blanco, por lo que no había contenido que evaluar."
    elif f.purpose.get("es"):
        content = f"En cuanto a su contenido: {f.purpose['es']}"
    elif f.purpose:
        content = f"En cuanto a su contenido (descripción disponible solo en inglés): {f.purpose['en']}"
    elif f.analysis_failed:
        content = "El sitio respondió y mostró contenido, pero no ha sido evaluado automáticamente."
    else:
        content = STANDING_VERDICT["es"]

    paragraphs = [f"{reg} {addr} {mail}", content]
    if f.monitored and f.comparison:
        owner = {"likely": "probablemente pertenecen al mismo titular",
                 "possible": "podrían pertenecer al mismo titular, aunque los datos no son concluyentes",
                 "unlikely": "parecen pertenecer a titulares distintos"}.get(f.same_owner)
        compared = f.comparison.get("es") or f"(solo en inglés) {f.comparison['en']}"
        text = f"En comparación con {f.monitored}: {compared}"
        if owner:
            text += f" Según los datos de registro y de red, ambos dominios {owner}."
        paragraphs.append(text)
    if when := when_text(f.checked_at, "es"):
        paragraphs.append(f"(Revisado el {when}.)")
    return "\n\n".join(paragraphs)


def narrative(rec: dict, analysis: dict | None = None, lang: str = "en") -> str:
    """The prose for one domain. analysis: its ai/analysis.py record, or None (no AI step)."""
    text = (_spanish if lang == "es" else _english)(facts(rec, analysis))
    return re.sub(r"\.\.(?=\s|$)", ".", text)  # a name ending in "." (e.g. "Inc.") closing a sentence


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m domainrecon.report.narrative",
                                 description="Print ready-to-send prose for every domain of a run.")
    ap.add_argument("run", type=Path)
    ap.add_argument("--lang", choices=LANGUAGES, default="en")
    args = ap.parse_args(argv)
    order = json.loads((args.run / "domains.json").read_text()) if (args.run / "domains.json").exists() else []
    files = sorted((args.run / "raw").glob("*.json"),
                   key=lambda p: (order.index(p.stem) if p.stem in order else len(order), p.stem))
    texts = []
    for f in files:
        rec = json.loads(f.read_text(encoding="utf-8"))
        af = args.run / "analysis" / f.name
        analysis = json.loads(af.read_text(encoding="utf-8")) if af.exists() else None
        if analysis is not None and "result" not in analysis:  # older runs saved the bare result
            analysis = {"result": analysis, "error": None}
        texts.append(narrative(rec, analysis, args.lang))
    print("\n\n---\n\n".join(texts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
