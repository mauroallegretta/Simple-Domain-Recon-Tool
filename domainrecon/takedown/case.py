#!/usr/bin/env python3
"""
Takedown preparation - phase 1, nothing is sent. Decide whether a checked domain is worth
reporting, then build its case under runs/<run>/takedown/<domain>/:

    case.json                         the decision, contacts, drafts and evidence checksums
    evidence-<domain>.zip             everything collected about the page, with SHA-256 checksums
    drafts/NN-<recipient>.<lang>.txt  the report, in English and Spanish
    drafts/NN-<recipient>.<lang>.eml  the same as an unsent email with the evidence attached, for
                                      recipients with a mailbox (Outlook opens it as a draft)

A takedown is proposed only when the domain was compared with a monitored domain, its page
loaded, and the AI judged it an impersonation of that domain (phishing, malware or brand
impersonation) rather than a likely defensive registration by the brand itself.

Contacts: contacts.py. Evidence: evidence.py. Wording: templates/takedown/<recipient>.<lang>.txt.
The signature comes from REPORTER_NAME, REPORTER_ORG and REPORTER_EMAIL in .env, and
TAKEDOWN_ATTACHMENT names a file (e.g. a trademark registration or an authorisation letter)
attached to every draft email.

Usage:  ./recon takedown runs/<run> [DOMAIN ...] [--force]
        (no DOMAIN: every proposed domain of the run; --force: also those not proposed)
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.takedown.case", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import json
import mimetypes
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from string import Template

from .. import config
from ..collect.domains import registrable
from ..report import narrative, summary
from ..util import run_path
from . import contacts, evidence

TEMPLATES = config.TEMPLATES / "takedown"
TEMPLATE_FOR = {"registrar": "registrar", "hosting": "hosting", "cdn": "hosting", "blocklist": "blocklist"}
CASE_TYPES = ("phishing", "malware", "brand_impersonation")

WORDS = {
    "en": {
        "title": {"phishing": "Phishing", "malware": "Malware distribution", "brand_impersonation": "Brand impersonation"},
        "case": {
            "phishing": "It is being used for phishing: the site impersonates {m} to obtain visitors' credentials or personal data.",
            "malware": "It is being used to distribute malicious software while impersonating {m}.",
            "brand_impersonation": "It is being used to impersonate {m} and can mislead its customers.",
        },
        "hosted": {"hosting": "hosted on your network ({where})", "cdn": "served through your network ({where})"},
        "monitored": "the monitored brand",
        "shows": "What the page shows", "compared": "Comparison with {m}", "english_only": "",
        "registered": "Domain {d}: registered on {date} through {registrar}",
        "registered_date": "Domain {d}: registered on {date}",
        "registrar_only": "Domain {d}: registrar {registrar}",
        "registered_unknown": "Domain {d}: registration data not available",
        "visited": "Page visited: {url}", "redirected": " (reached from {chain})",
        "served": "Served from: {where}",
        "password": "Password fields on the page: {n}", "card": "Payment card fields on the page: {n}",
        "forms": "Forms submit to: {hosts}", "other_domain": " (a different domain)",
        "signals": "Signals noted in the review: {signals}",
        "signature": ("[your name]", "[organisation]", "[email]"),
    },
    "es": {
        "title": {"phishing": "phishing", "malware": "distribución de malware", "brand_impersonation": "suplantación de marca"},
        "case": {
            "phishing": "Se está utilizando para phishing: el sitio suplanta a {m} para obtener credenciales o datos personales de los visitantes.",
            "malware": "Se está utilizando para distribuir software malicioso suplantando a {m}.",
            "brand_impersonation": "Se está utilizando para suplantar a {m} y puede inducir a error a sus clientes.",
        },
        "hosted": {"hosting": "alojado en su red ({where})", "cdn": "servido a través de su red ({where})"},
        "monitored": "la marca monitoreada",
        "shows": "Qué muestra la página", "compared": "Comparación con {m}", "english_only": "(en inglés) ",
        "registered": "Dominio {d}: registrado el {date} a través de {registrar}",
        "registered_date": "Dominio {d}: registrado el {date}",
        "registrar_only": "Dominio {d}: registrador {registrar}",
        "registered_unknown": "Dominio {d}: datos de registro no disponibles",
        "visited": "Página visitada: {url}", "redirected": " (a la que se llegó desde {chain})",
        "served": "Servida desde: {where}",
        "password": "Campos de contraseña en la página: {n}", "card": "Campos de tarjeta de pago en la página: {n}",
        "forms": "Los formularios envían los datos a: {hosts}", "other_domain": " (otro dominio)",
        "signals": "Indicios observados en la revisión (en inglés): {signals}",
        "signature": ("[su nombre]", "[organización]", "[correo electrónico]"),
    },
}


class NotProposed(Exception):
    pass


@dataclass(frozen=True)
class Qualification:
    proposed: bool
    case_type: str | None
    priority: str | None   # high (phishing or malware, impersonation likely) or medium
    reason: str


def qualify(rec: dict, analysis: dict | None) -> Qualification:
    """Whether to propose a takedown, from what was collected and the AI's verdict. No I/O."""
    result = (analysis or {}).get("result") or {}
    case_type, monitored = result.get("case_type"), (analysis or {}).get("monitored")

    def no(reason):
        return Qualification(False, case_type, None, reason)

    state, detail = summary.content_state(rec)
    if state != "loaded":  # checked first: with no content there is nothing to compare or report
        return no({"unregistered": "the domain appears unregistered", "http_error": f"the site answered {detail}",
                   "no_screenshot": "the site could not be visited", "blank": "the page is blank"}[state])
    if not monitored:
        return no("not compared with a monitored domain")
    if not result:
        return no("no AI analysis of the page")
    if "impersonation" not in result:
        return no("analysed before impersonation verdicts existed: check it again")
    if result.get("same_owner") == "likely":
        return no(f"likely {monitored}'s own domain")
    if result.get("impersonation") == "unlikely":
        return no(f"no impersonation of {monitored} found")
    if case_type == "parked":
        return no("parked lookalike: abuse desks rarely act; consider a URS/UDRP complaint or keep monitoring")
    if case_type == "unrelated":
        return no(f"content unrelated to {monitored}")
    case_type = case_type if case_type in CASE_TYPES else "brand_impersonation"
    likely = result.get("impersonation") == "likely"
    priority = "high" if likely and case_type in ("phishing", "malware") else "medium"
    return Qualification(True, case_type, priority,
                         f"{case_type.replace('_', ' ')}, impersonation {result.get('impersonation')}")


# --------------------------------------------------------------------------
# drafts
# --------------------------------------------------------------------------

def _where(address: dict | None) -> str:
    if not address:
        return "-"
    network = " ".join(x for x in (address.get("asn"), address.get("as_name")) if x)
    return f"{address['ip']} ({network})" if network else address["ip"]


def _values(rec: dict, analysis: dict | None, contact, lang: str, case_type: str,
            indicators: dict, evidence_file: str) -> dict:
    w, d = WORDS[lang], rec["domain"]
    meta = (rec.get("screenshot") or {}).get("meta") or {}
    url = meta.get("final_url") or f"https://{d}/"
    facts = narrative.facts(rec, analysis)
    m = (analysis or {}).get("monitored") or w["monitored"]

    def localized(texts: dict) -> str | None:
        if texts.get(lang):
            return texts[lang]
        return f"{w['english_only']}{texts['en']}" if texts.get("en") else None

    description = []
    if purpose := localized(facts.purpose):
        description.append(f"{w['shows']}: {purpose}")
    if (comparison := localized(facts.comparison)) and (analysis or {}).get("monitored"):
        description.append(f"{w['compared'].format(m=m)}: {comparison}")

    date = narrative.date_text(facts.registered, lang) if facts.registered else None
    if date and facts.registrar:
        lines = [w["registered"].format(d=d, date=date, registrar=facts.registrar)]
    elif date:
        lines = [w["registered_date"].format(d=d, date=date)]
    elif facts.registrar:
        lines = [w["registrar_only"].format(d=d, registrar=facts.registrar)]
    else:
        lines = [w["registered_unknown"].format(d=d)]
    redirects = meta.get("redirects") or []
    lines.append(w["visited"].format(url=url) + (w["redirected"].format(chain=" → ".join(redirects)) if redirects else ""))
    if address := contacts.site_address(rec):
        lines.append(w["served"].format(where=_where(address)))
    if indicators["password_fields"]:
        lines.append(w["password"].format(n=indicators["password_fields"]))
    if indicators["card_fields"]:
        lines.append(w["card"].format(n=indicators["card_fields"]))
    if indicators["form_targets"]:
        page = registrable(indicators["page_host"] or d)
        hosts = [h + (w["other_domain"] if registrable(h) != page else "") for h in indicators["form_targets"]]
        lines.append(w["forms"].format(hosts=", ".join(hosts)))
    if signals := ((analysis or {}).get("result") or {}).get("signals"):
        lines.append(w["signals"].format(signals="; ".join(signals)))

    sign = [os.environ.get(k) or placeholder
            for k, placeholder in zip(("REPORTER_NAME", "REPORTER_ORG", "REPORTER_EMAIL"), w["signature"])]
    return {"title": w["title"][case_type], "domain": d, "url": url,
            "case_sentence": w["case"][case_type].format(m=m),
            "description": "\n\n".join(description),
            "captured": narrative.when_text(meta.get("rendered_at") or rec.get("collected_at"), lang) or "-",
            "evidence": "\n".join(f"- {line}" for line in lines),
            "evidence_file": evidence_file, "recipient": contact.name,
            "hosted": w["hosted"].get(contact.kind, "").format(where=_where(contacts.site_address(rec))),
            "signature": "\n".join(sign), "signature_inline": ", ".join(sign)}


def render(kind: str, lang: str, values: dict) -> tuple[str, str]:
    """(subject, body) of a draft; the template's first line is its subject."""
    text = Template((TEMPLATES / f"{TEMPLATE_FOR[kind]}.{lang}.txt").read_text(encoding="utf-8")).safe_substitute(values)
    first, _, body = text.partition("\n")
    return first.split(":", 1)[1].strip(), body.strip() + "\n"


def write_eml(path: Path, subject: str, body: str, to: str | None, attachments: list[Path]) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    if to:
        msg["To"] = to
    if sender := os.environ.get("REPORTER_EMAIL"):
        msg["From"] = sender
    msg["X-Unsent"] = "1"  # mail clients that honour it (Outlook) open the file as a draft to send
    msg.set_content(body)
    for file in attachments:
        maintype, subtype = (mimetypes.guess_type(file.name)[0] or "application/octet-stream").split("/", 1)
        msg.add_attachment(file.read_bytes(), maintype=maintype, subtype=subtype, filename=file.name)
    path.write_bytes(bytes(msg))


# --------------------------------------------------------------------------
# the case
# --------------------------------------------------------------------------

def load(run_dir: Path, domain: str) -> tuple[dict, dict | None]:
    rec = json.loads((Path(run_dir) / "raw" / f"{domain}.json").read_text(encoding="utf-8"))
    path = Path(run_dir) / "analysis" / f"{domain}.json"
    analysis = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    if analysis is not None and "result" not in analysis:  # older runs saved the bare result
        analysis = {"result": analysis, "error": None}
    return rec, analysis


def prepare_case(run_dir: Path, domain: str, force: bool = False) -> dict:
    """Build (or rebuild) the takedown case of one domain of a run. Raises NotProposed when the
    domain doesn't qualify, unless force. Paths in the returned case are relative to run_dir."""
    run_dir = Path(run_dir)
    rec, analysis = load(run_dir, domain)
    q = qualify(rec, analysis)
    if not q.proposed and not force:
        raise NotProposed(q.reason)
    case_type = q.case_type if q.case_type in CASE_TYPES else "brand_impersonation"

    case_dir = run_dir / "takedown" / domain
    drafts_dir = case_dir / "drafts"
    if drafts_dir.exists():
        shutil.rmtree(drafts_dir)  # a re-prepared case replaces its drafts
    drafts_dir.mkdir(parents=True)
    zip_path = case_dir / f"evidence-{domain}.zip"
    ev = evidence.build(run_dir, rec, analysis, zip_path)

    shot = rec.get("screenshot") or {}
    screenshot = run_path(run_dir, shot.get("path"))
    if screenshot and screenshot.is_file() and screenshot.resolve().is_relative_to(run_dir.resolve()):
        screenshot = screenshot.resolve().relative_to(run_dir.resolve()).as_posix()
    else:
        screenshot = None
    page_file = (shot.get("files") or {}).get("dom") or (shot.get("files") or {}).get("html")
    markup = run_path(run_dir, page_file).read_text(encoding="utf-8", errors="replace") if page_file else ""
    indicators = evidence.page_indicators(markup, (shot.get("meta") or {}).get("final_url"))
    attachments = [zip_path]
    if extra := os.environ.get("TAKEDOWN_ATTACHMENT"):  # a relative path is relative to the project folder
        extra = Path(extra).expanduser()
        extra = extra if extra.is_absolute() else config.ROOT / extra
        if extra.is_file():
            attachments.append(extra)

    def rel(path):
        return path.relative_to(run_dir).as_posix()

    drafts = []
    for i, contact in enumerate(contacts.find(rec, case_type), 1):
        stem = f"{i:02d}-{re.sub(r'[^a-z0-9]+', '-', contact.name.lower()).strip('-')[:40] or contact.kind}"
        draft = {**asdict(contact), "subject": {}, "body": {}, "files": {}}
        for lang in narrative.LANGUAGES:
            subject, body = render(contact.kind, lang, _values(rec, analysis, contact, lang, case_type,
                                                               indicators, zip_path.name))
            text = drafts_dir / f"{stem}.{lang}.txt"
            text.write_text(f"{subject}\n\n{body}", encoding="utf-8")
            eml = None
            if contact.channel == "email":
                eml = drafts_dir / f"{stem}.{lang}.eml"
                write_eml(eml, subject, body, contact.address, attachments)
            draft["subject"][lang], draft["body"][lang] = subject, body
            draft["files"][lang] = {"text": rel(text), "eml": rel(eml) if eml else None}
        drafts.append(draft)

    case = {"domain": domain, "monitored": (analysis or {}).get("monitored"),
            "prepared_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "qualification": asdict(q), "forced": not q.proposed, "case_type": case_type,
            "indicators": indicators, "screenshot": screenshot, "attachments": [p.name for p in attachments],
            "evidence": {"zip": rel(zip_path), "sha256": ev["sha256"], "files": ev["files"]},
            "drafts": drafts}
    (case_dir / "case.json").write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    return case


def load_case(run_dir: Path, domain: str) -> dict | None:
    path = Path(run_dir) / "takedown" / domain / "case.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


def list_cases(runs: Path) -> list[dict]:
    """One line per prepared case in every run under runs/, newest first."""
    cases = []
    for path in Path(runs).glob("*/takedown/*/case.json"):
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        drafts = case.get("drafts") or []
        cases.append({"run": path.parents[2].name, "domain": case["domain"], "monitored": case.get("monitored"),
                      "case_type": case.get("case_type"), "priority": (case.get("qualification") or {}).get("priority"),
                      "forced": case.get("forced"), "prepared_at": case.get("prepared_at"),
                      "recipients": len(drafts), "mailboxes": sum(1 for d in drafts if d.get("channel") == "email")})
    return sorted(cases, key=lambda c: c["prepared_at"] or "", reverse=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="recon takedown",
                                 description="Prepare takedown cases (evidence and draft reports); sends nothing.")
    ap.add_argument("run", type=Path, help="run folder, e.g. runs/gui-2026-10-21-120000Z")
    ap.add_argument("domains", nargs="*", help="domains of the run (default: every proposed one)")
    ap.add_argument("--force", action="store_true", help="prepare a case even when no takedown is proposed")
    args = ap.parse_intermixed_args(argv)  # --force may come before or after the domains
    domains = args.domains or [p.stem for p in sorted((args.run / "raw").glob("*.json"))]
    for d in domains:
        try:
            case = prepare_case(args.run, d, force=args.force)
        except FileNotFoundError:
            print(f"{d}: not in this run", file=sys.stderr)
            continue
        except NotProposed as e:
            print(f"{d}: no takedown proposed - {e}")
            continue
        print(f"{d}: {case['case_type'].replace('_', ' ')} case prepared in {args.run / 'takedown' / d}")
        for draft in case["drafts"]:
            print(f"    {draft['kind']:9} {draft['name'][:40]:40} {draft['channel']:7} {draft['address'] or '(no contact published)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
