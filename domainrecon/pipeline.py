"""
The whole recon for a list of domains - what the command line's `check` and the web app run:

  1. collect each domain (collect/profile.py): registration, DNS, MX, screenshot, page files
  2. when its page loaded and AI_API_KEY is set, describe it with AI (ai/analysis.py), from the
     screenshot plus the HTML/DOM/CSS cleaned by ai/clean.py
  3. with a target - the monitored domain - the AI also compares each page with it and judges,
     from both domains' registration and network facts, whether they share an owner (a brand's
     own defensive registration rather than impersonation); the target is rendered and looked
     up once per run
  4. a plain-English summary per domain (report/summary.py) saved as SUMMARY.txt, and the same
     findings as ready-to-send prose (report/narrative.py) in EMAIL-en.txt and EMAIL-es.txt

Results land in runs/<run>/: raw/, text/, pages/, analysis/ (AI records and reports) and
monitored/<target>/ (the reference render). Optionally every check is also appended to the
SQLite results database (store/results_db.py), which keeps each domain's history and can serve
recent checks back as a cache.
"""

import concurrent.futures as futures
import json
from dataclasses import dataclass
from pathlib import Path

from .ai import analysis as ai_analysis
from .ai import clean as page_clean
from .ai import report as ai_report
from .collect import capture
from .collect.dnsinfo import addresses, nameservers, own_asn_set
from .collect.mail import mx_lookup
from .collect.profile import profile
from .collect.registration import registration
from .report import narrative, summary
from .store import results_db
from .util import DIRECT_LEDGER_HEADER, log, note_contact, run_path


@dataclass(frozen=True)
class Monitored:
    domain: str
    screenshot: str | None  # its rendered home page; None when the render failed
    facts: dict             # ownership_facts() of the monitored domain


def ownership_facts(rec: dict, final_url: str | None = None) -> dict:
    """What a collected record says about who runs a domain: what the AI weighs to tell a
    brand's own defensive registrations from impersonation."""
    def value(field):
        return field.get("value") if isinstance(field, dict) else None

    reg = rec.get("registration") or {}
    found = value(rec.get("dns")) or {}
    mx = value(rec.get("mx")) or {}
    networks = {f"{r['asn']} {r.get('as_name') or ''}".strip()
                for records in found.values() for r in records or [] if r.get("asn")}
    return {"registrar": value(reg.get("registrar")),
            "registered": value(reg.get("created")),
            "nameservers": value(rec.get("nameservers")) or [],
            "hosting_networks": sorted(networks),
            "mail_servers": [r["host"] for r in mx.get("records") or [] if r.get("kind") != "null-mx"],
            "site_ends_up_at": final_url or ((rec.get("screenshot") or {}).get("meta") or {}).get("final_url")}


@dataclass(frozen=True)
class Result:
    domain: str
    rec: dict                  # what collect/profile.py collected
    analysis: dict | None      # the ai/analysis.py record, None when no AI description was made

    @property
    def text(self) -> str:
        return summary.summary(self.rec, self.analysis)

    def email(self, lang: str) -> str:
        """The same findings as prose to paste into an email, in "en" or "es"."""
        return narrative.narrative(self.rec, self.analysis, lang)

    @property
    def same_owner(self) -> str | None:
        return ((self.analysis or {}).get("result") or {}).get("same_owner")


def prepare_monitored(domain: str, root: Path, runlog: Path, direct_ledger: Path) -> Monitored:
    """Render the monitored site once as the reference picture, and look up its ownership facts."""
    cap = capture.capture(domain, root / "monitored" / domain)
    note_contact(direct_ledger, domain, f"{cap.status or cap.error} (monitored domain, reference render)")
    shot = str(root / "monitored" / domain / cap.files["screenshot"]) if "screenshot" in cap.files else None
    log(runlog, f"[monitored {domain}] reference render "
                + ("ok" if shot else f"FAILED ({cap.error}) - pages are compared by name only"))
    found = addresses(domain)
    rec = {"registration": registration(domain), "dns": found, "nameservers": nameservers(domain),
           "mx": mx_lookup(domain, own_asn_set(found.get("value")))}
    facts = ownership_facts(rec, cap.url)
    (root / "monitored" / domain / "ownership.json").write_text(json.dumps(facts, indent=2), encoding="utf-8")
    return Monitored(domain, shot, facts)


def describe(rec: dict, root: Path, runlog: Path, monitored: Monitored | None = None) -> dict | None:
    """AI description of a page that loaded - compared with the monitored domain when given -
    saved (record + report) in root/analysis/. None when the AI step is off (no AI_API_KEY)
    or there is no content to describe."""
    if not ai_analysis.configured() or summary.content_problem(rec):
        return None
    d, shot = rec["domain"], rec["screenshot"]
    files = shot.get("files") or {}
    page = page_clean.for_ai(**{kind: run_path(root, files[kind]).read_text(encoding="utf-8", errors="replace")
                                for kind in ("html", "dom", "css") if kind in files})
    out = root / "analysis" / f"{d}.json"
    comparison = {}
    if monitored:
        comparison = {"monitored": monitored.domain, "reference": monitored.screenshot,
                      "facts": {d: ownership_facts(rec), monitored.domain: monitored.facts}}
    record = ai_analysis.analyze(run_path(root, shot["path"]), **page, out=out, subject=d, **comparison)
    if record["error"]:
        log(runlog, f"[{d}] AI description FAILED: {record['error']}")
    else:
        ai_report.write(out)
        log(runlog, f"[{d}] AI description saved ({record['provider']}/{record['model']})")
    return record


def collect(domain: str, dirs: dict, runlog: Path, direct_ledger: Path,
            monitored: Monitored | None = None) -> Result:
    rec = profile(domain, dirs, runlog, direct_ledger)
    try:
        return Result(domain, rec, describe(rec, dirs["raw"].parent, runlog, monitored))
    except Exception as e:  # the collected facts still count when the AI step breaks
        log(runlog, f"[{domain}] AI description FAILED: {type(e).__name__}: {e}")
        return Result(domain, rec, {"result": None, "error": f"{type(e).__name__}: {e}"})


def reuse(db: results_db.ResultsDB, check, root: Path, runlog: Path) -> Result:
    """A stored check, put back into this run's folder as if just collected (no site contact)."""
    rec, analysis = db.restore(check, root)
    rec["reused_from"] = {"checked_at": check["checked_at"], "run": check["run"]}
    d = rec["domain"]
    (root / "raw" / f"{d}.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    if analysis:
        (root / "analysis" / f"{d}.json").write_text(json.dumps(analysis, indent=2, ensure_ascii=False),
                                                     encoding="utf-8")
    log(runlog, f"[{d}] reused the check of {check['checked_at']} (run {check['run']}) from the results database")
    return Result(d, rec, analysis)


def files_of(result: Result) -> list[str]:
    """The run files belonging to one domain, relative to the run folder."""
    shot = result.rec.get("screenshot") or {}
    return [*(shot.get("files") or {}).values(), f"text/{result.domain}.txt", f"analysis/{result.domain}.md"]


def run(domains: list[str], root: Path, *, monitored: str | None = None, workers: int = 5,
        db_path: str | None = None, cache_hours: float = 0) -> tuple[list[Result], Monitored | None]:
    """Recon every domain into root; results come back in input order. With db_path every new
    check is also appended to that results database, and checks younger than cache_hours are
    reused from it instead of visiting the site again."""
    dirs = {k: root / k for k in ("raw", "text", "reports", "pages", "analysis")}
    for p in dirs.values():
        p.mkdir(parents=True, exist_ok=True)
    runlog, direct_ledger = root / "run.log", root / "direct-contact.txt"
    if not direct_ledger.exists():
        direct_ledger.write_text(DIRECT_LEDGER_HEADER, encoding="utf-8")

    db = results_db.ResultsDB(db_path) if db_path else None
    try:
        results = {}
        for d in domains if db else []:
            if check := db.latest(d, monitored, cache_hours):
                results[d] = reuse(db, check, root, runlog)
        todo = [d for d in domains if d not in results]

        # The target is only rendered when something will be compared with it.
        reference = None
        if monitored and todo and ai_analysis.configured():
            reference = prepare_monitored(monitored, root, runlog, direct_ledger)
        with futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(todo)))) as pool:
            fut = {pool.submit(collect, d, dirs, runlog, direct_ledger, reference): d for d in todo}
            for f in futures.as_completed(fut):
                d = fut[f]
                try:
                    results[d] = f.result()
                except Exception as e:
                    log(runlog, f"[{d}] FATAL {type(e).__name__}: {e}")
                    results[d] = Result(d, {"domain": d, "registration": {},
                                            "screenshot": {"error": f"{type(e).__name__}: {e}"}}, None)

        ordered = [results[d] for d in domains]
        (root / "domains.json").write_text(json.dumps(domains, indent=2), encoding="utf-8")
        (root / "SUMMARY.txt").write_text("\n\n".join(f"{r.domain}\n{r.text}" for r in ordered) + "\n",
                                          encoding="utf-8")
        for lang in narrative.LANGUAGES:
            (root / f"EMAIL-{lang}.txt").write_text("\n\n---\n\n".join(r.email(lang) for r in ordered) + "\n",
                                                    encoding="utf-8")
        for r in ordered if db else []:
            if r.domain not in todo:  # reused checks are already stored
                continue
            db.save(domain=r.domain, run_dir=root, record=r.rec, analysis=r.analysis, summary=r.text,
                    monitored=monitored, files=files_of(r))
        if db and todo:
            log(runlog, f"appended {len(todo)} check(s) to the results database {db.path}")
    finally:
        if db:
            db.close()
    return ordered, reference
