"""
One self-contained JSON record per input domain - what `recon check -o results.jsonl` writes, one
per line - and the plain-text block the terminal shows for it. Screenshots are never embedded:
"files" gives their paths, relative to the run folder in "run".

    domain, target, checked_at, reused_from
    registration   created, expires, registrar, statuses
    dns            ipv4, ipv6, nameservers, networks (ASN + owner), error
    mail           posture, servers, providers, error
    page           state (loaded | unregistered | http_error | no_screenshot | blank), detail,
                   final_url, status, title, redirects, technologies
    description    the AI's reading of the page (null without AI)
    comparison     with a target: {"made": true, text, text_es, same_owner, ownership,
                   impersonation, case_type} or {"made": false, "reason": ...}; null without target
    takedown       with a target: proposed, case_type, priority, reason
    ai             provider, model, error (null when the AI step didn't run)
    summary        the plain-English lines;  email: {"en": ..., "es": ...}
    run, files     where the evidence is

An input that was not checked (the target itself, or one of its own subdomains) gives
{"domain", "target", "skipped": reason}.
"""

from dataclasses import asdict
from pathlib import Path

from ..takedown.case import qualify
from . import narrative, summary

UNASSESSABLE = {"unregistered": "the domain appears unregistered", "no_screenshot": "the site could not be visited",
                "blank": "the page is blank"}


def _value(field):
    return field.get("value") if isinstance(field, dict) else None


def _shown(path: Path) -> str:
    """A path relative to the current folder when it is under it, else absolute."""
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return str(path.resolve())


def _comparison(rec: dict, analysis: dict | None, target: str) -> dict:
    state, detail = summary.content_state(rec)
    result = (analysis or {}).get("result") or {}
    if state != "loaded":
        reason = f"the site answered {detail}" if state == "http_error" else UNASSESSABLE[state]
    elif analysis is None:
        reason = "no AI analysis: set AI_API_KEY in .env"
    elif not result:
        reason = f"the AI analysis failed: {analysis.get('error')}"
    elif "comparison" not in result:
        reason = "the AI gave no comparison"
    else:
        return {"made": True, "text": result.get("comparison"), "text_es": result.get("comparison_es"),
                **{k: result.get(k) for k in ("same_owner", "ownership", "impersonation", "case_type")}}
    return {"made": False, "reason": reason}


def record(result, target: str | None, run_dir: Path) -> dict:
    """The JSON record of one checked domain (a pipeline.Result)."""
    rec, analysis, d = result.rec, result.analysis, result.domain
    reg = rec.get("registration") or {}
    found = _value(rec.get("dns")) or {}
    mx = _value(rec.get("mx")) or {}
    shot = rec.get("screenshot") or {}
    meta = shot.get("meta") or {}
    state, detail = summary.content_state(rec)
    ai = (analysis or {}).get("result") or {}

    def ips(rtype):
        return list(dict.fromkeys(r["ip"] for key in (f"apex_{rtype}", f"www_{rtype}") for r in found.get(key) or []))

    files = {"record": f"raw/{d}.json", **(shot.get("files") or {})}
    for name, path in (("analysis", f"analysis/{d}.json"), ("analysis_report", f"analysis/{d}.md")):
        if (Path(run_dir) / path).exists():
            files[name] = path

    return {
        "domain": d, "target": target, "checked_at": rec.get("collected_at"), "reused_from": rec.get("reused_from"),
        "registration": {k: _value(reg.get(k)) for k in ("created", "expires", "registrar", "statuses")},
        "dns": {"ipv4": ips("A"), "ipv6": ips("AAAA"), "nameservers": _value(rec.get("nameservers")) or [],
                "networks": sorted({f"{r['asn']} {r.get('as_name') or ''}".strip()
                                    for records in found.values() for r in records or [] if r.get("asn")}),
                "error": (rec.get("dns") or {}).get("error")},
        "mail": {"posture": mx.get("posture"),
                 "servers": [r["host"] for r in mx.get("records") or [] if r.get("kind") != "null-mx"],
                 "providers": mx.get("providers") or [], "error": (rec.get("mx") or {}).get("error")},
        "page": {"state": state, "detail": detail, "final_url": meta.get("final_url"), "status": meta.get("status"),
                 "title": (rec.get("page") or {}).get("title"), "redirects": meta.get("redirects") or [],
                 "technologies": meta.get("tech") or []},
        "description": {k: ai.get(k) for k in ("language", "page_type", "purpose", "purpose_es", "signals",
                                               "confidence", "notes")} if ai else None,
        "comparison": _comparison(rec, analysis, target) if target else None,
        "takedown": asdict(qualify(rec, analysis)) if target else None,
        "ai": {k: analysis.get(k) for k in ("provider", "model", "error")} if analysis else None,
        "summary": result.text,
        "email": {lang: result.email(lang) for lang in narrative.LANGUAGES},
        "run": _shown(Path(run_dir)),
        "files": files,
    }


def skipped(domain: str, target: str | None, reason: str) -> dict:
    return {"domain": domain, "target": target, "skipped": reason}


def text(rec: dict, email_lang: str | None = None) -> str:
    """The terminal's plain-text block for a record."""
    head = rec["domain"] + (f"  vs  {rec['target']}" if rec.get("target") else "")
    if rec.get("skipped"):
        return f"{head}\nNot checked: {rec['skipped']}"
    lines = [head, rec["summary"]]
    comparison = rec.get("comparison")
    if comparison and not comparison["made"]:
        lines.append(f"Comparison with {rec['target']}: not made - {comparison['reason']}")
    if t := rec.get("takedown"):
        lines.append(f"Takedown: proposed - {t['case_type'].replace('_', ' ')}, {t['priority']} priority"
                     if t["proposed"] else f"Takedown: not proposed - {t['reason']}")
    lines.append(f"Evidence: {rec['run']}/")
    if email_lang:
        lines += ["", rec["email"][email_lang]]
    return "\n".join(lines)
