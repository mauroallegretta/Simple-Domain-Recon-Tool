#!/usr/bin/env python3
"""
Plain-English summary of what collect/profile.py collected for a domain, one line per fact:
registration date, registrar, IPv4 and IPv6 addresses, mail (MX), and the content: why there
is none to assess, or - given an ai/analysis.py record - the AI's description of the page.
Whatever is missing says so instead of being left out.

Usage:  python -m domainrecon.report.summary runs/<run>   (prints every domain in the run, with
                                                          runs/<run>/analysis/<domain>.json if present)
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.report.summary", run_name="__main__", alter_sys=True)
    sys.exit()

import json
import re
import sys
from http import HTTPStatus
from pathlib import Path

NOT_AVAILABLE = "not available"

# Standing conclusion for a page that loaded: an analyst overrides it after checking the screenshot.
DEFAULT_CONTENT_VERDICT = ("The content is not related to the monitored company; "
                           "there is no evidence of domain impersonation.")


def _value(field):
    return field.get("value") if isinstance(field, dict) else field


def _http(status: int) -> str:
    try:
        return f"{status} {HTTPStatus(status).phrase}"
    except ValueError:
        return str(status)


def registration_lines(rec: dict) -> list[str]:
    reg = rec.get("registration") or {}
    return [f"Registration date: {_value(reg.get('created')) or NOT_AVAILABLE}",
            f"Registrar: {_value(reg.get('registrar')) or NOT_AVAILABLE}"]


def address_lines(rec: dict) -> list[str]:
    dns = rec.get("dns") or {}
    found, error = dns.get("value") or {}, dns.get("error") or ""
    lines = []
    for label, rtype in (("IPv4 (A)", "A"), ("IPv6 (AAAA)", "AAAA")):
        records = (found.get(f"apex_{rtype}") or []) + (found.get(f"www_{rtype}") or [])
        ips = list(dict.fromkeys(r["ip"] for r in records))
        if ips:
            lines.append(f"{label}: {', '.join(ips)}")
        elif re.search(rf" {rtype}: ", error) or (error and not found):
            lines.append(f"{label}: {NOT_AVAILABLE} (DNS lookup failed)")
        else:
            lines.append(f"{label}: {NOT_AVAILABLE}")
    return lines


def mail_line(rec: dict) -> str:
    field = rec.get("mx") or {}
    mx = field.get("value") or {}
    posture = mx.get("posture")
    if posture is None:
        return f"Mail (MX): {NOT_AVAILABLE}" + (" (DNS lookup failed)" if field.get("error") else "")
    hosts = ", ".join(r["host"] for r in mx.get("records") or [] if r["kind"] != "null-mx")
    providers = ", ".join(mx.get("providers") or [])
    return "Mail (MX): " + {
        "none": "none - the domain has no MX records, so no mail server is set up for it",
        "null-mx": "none - the domain publishes a null MX, declaring that it accepts no email",
        "proprietary": f"{hosts}, run by the domain owner",
        "third-party": f"{hosts}, handled by a third party ({providers})",
        "mixed": f"{hosts}, partly run by the domain owner and partly by a third party ({providers})",
    }.get(posture, hosts)


def content_state(rec: dict) -> tuple[str, str | None]:
    """Whether there is content to assess: ("unregistered", None), ("http_error", "404 Not Found"),
    ("no_screenshot", error or None), ("blank", None), or ("loaded", None)."""
    if rec.get("likely_unregistered"):
        return "unregistered", None
    shot = rec.get("screenshot") or {}
    try:
        status = int((shot.get("meta") or {}).get("status"))
    except (TypeError, ValueError):
        status = None
    if status and status >= 400:
        return "http_error", _http(status)
    if not shot.get("path"):
        return "no_screenshot", shot.get("error")
    page = rec.get("page") or {}
    if not (page.get("title") or "").strip() and not (page.get("text") or "").strip():
        return "blank", None
    return "loaded", None


def content_problem(rec: dict) -> str | None:
    """The Content line when there is nothing to assess; None when the page loaded and can be described."""
    state, detail = content_state(rec)
    return {
        "unregistered": "Content: none - the domain appears unregistered, so it was not visited and could not be assessed.",
        "http_error": f"Content: the site answered with an HTTP error ({detail}), so there is no content to assess.",
        "no_screenshot": f"Content: none - no screenshot could be taken{f' ({detail})' if detail else ''}, "
                         "so the content could not be assessed.",
        "blank": "Content: the page is blank, so there is no content to assess.",
    }.get(state)


def content_lines(rec: dict, analysis: dict | None = None) -> list[str]:
    """analysis: an ai/analysis.py record for the page ({"result": {...}, "error": ...}), or None
    when no AI description was asked for - then the standing verdict is used."""
    if problem := content_problem(rec):
        return [problem]
    if analysis is None:
        return [f"Content: {DEFAULT_CONTENT_VERDICT}"]
    if analysis.get("error") or not analysis.get("result"):
        return [f"Content: the page loaded, but the AI description failed ({analysis.get('error')})"]
    result = analysis["result"]
    lines = [f"Content: {result.get('purpose') or NOT_AVAILABLE}",
             f"Page type: {result.get('page_type') or NOT_AVAILABLE} "
             f"(AI description, {result.get('confidence') or 'unknown'} confidence)"]
    if result.get("comparison"):
        lines.append(f"Comparison with {analysis.get('monitored')}: {result['comparison']}")
    if result.get("same_owner"):
        lines.append(f"Same owner as {analysis.get('monitored')}: {result['same_owner']} - "
                     f"{result.get('ownership') or 'no explanation given'}")
    if result.get("impersonation"):
        kind = (result.get("case_type") or "").replace("_", " ")
        lines.append(f"Impersonation of {analysis.get('monitored')}: {result['impersonation']}"
                     + (f" ({kind})" if kind else ""))
    if result.get("signals"):
        lines.append(f"Notable signals: {'; '.join(result['signals'])}")
    return lines


def summary(rec: dict, analysis: dict | None = None) -> str:
    reused = rec.get("reused_from")
    note = [f"Reused from the check of {reused['checked_at']} (run {reused['run']}), not checked again"] \
        if reused else []
    return "\n".join([*note, *registration_lines(rec), *address_lines(rec), mail_line(rec),
                      *content_lines(rec, analysis)])


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__)
        return 2
    run = Path(argv[0])
    order = json.loads((run / "domains.json").read_text()) if (run / "domains.json").exists() else []
    files = sorted((run / "raw").glob("*.json"), key=lambda p: (order.index(p.stem) if p.stem in order else len(order), p.stem))
    for f in files:
        rec = json.loads(f.read_text(encoding="utf-8"))
        af = run / "analysis" / f.name
        analysis = json.loads(af.read_text(encoding="utf-8")) if af.exists() else None
        print(f"{rec['domain']}\n{summary(rec, analysis)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
