#!/usr/bin/env python3
"""
Domains already checked, read from wherever results are kept: the results database when one
is configured (store/results_db.py), otherwise the run folders under runs/. Both sources answer the
same three questions - which domains, each one's checks, a check's screenshot - so callers
(the web app's history view) don't care which one is in use.

Usage:  ./recon history [DOMAIN]     (lists domains, or one domain's checks)
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.store.history", run_name="__main__", alter_sys=True)
    sys.exit()

import json
import sys
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..report import narrative, summary
from . import results_db


@dataclass(frozen=True)
class Check:
    domain: str
    check: str              # its id within the source: run folder name, or database row id
    checked_at: str
    run: str
    monitored: str | None
    same_owner: str | None
    summary: str
    email: dict             # language -> ready-to-send prose (report/narrative.py)
    has_screenshot: bool


def _emails(rec: dict, analysis: dict | None) -> dict:
    return {lang: narrative.narrative(rec, analysis, lang) for lang in narrative.LANGUAGES}


def _overview(checks: list[Check]) -> list[dict]:
    """One entry per domain, from its newest check, newest domains first."""
    by_domain: dict[str, list[Check]] = {}
    for c in checks:
        by_domain.setdefault(c.domain, []).append(c)
    rows = []
    for domain, cs in by_domain.items():
        last = max(cs, key=lambda c: c.checked_at)
        rows.append({"domain": domain, "checks": len(cs), "last_check": last.checked_at,
                     "monitored": last.monitored, "same_owner": last.same_owner})
    return sorted(rows, key=lambda r: r["last_check"], reverse=True)


class FolderHistory:
    """Every domain in every run folder under runs/."""

    def __init__(self, runs: Path):
        self.runs = Path(runs)
        self.source = "run folders"

    def _scan(self) -> list[tuple[Check, Path | None]]:
        found = []
        for raw in sorted(self.runs.glob("*/raw/*.json")):
            run_dir = raw.parent.parent
            try:
                rec = json.loads(raw.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if rec.get("reused_from"):  # a copy of an earlier check, not a check of its own
                continue
            analysis = self._analysis(run_dir / "analysis" / raw.name)
            result = (analysis or {}).get("result") or {}
            shot =self._screenshot_path(run_dir, (rec.get("screenshot") or {}).get("path"))
            found.append((Check(domain=rec.get("domain") or raw.stem, check=run_dir.name,
                                checked_at=rec.get("collected_at") or "", run=run_dir.name,
                                monitored=(analysis or {}).get("monitored"),
                                same_owner=result.get("same_owner"),
                                summary=summary.summary(rec, analysis), email=_emails(rec, analysis),
                                has_screenshot=shot is not None), shot))
        return found

    @staticmethod
    def _analysis(path: Path) -> dict | None:
        try:
            analysis = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        # older runs saved the bare result instead of an ai_analysis record
        return analysis if "result" in analysis else {"result": analysis, "error": None, "monitored": None}

    def _screenshot_path(self, run_dir: Path, path: str | None) -> Path | None:
        if not path:
            return None
        p = Path(path) if Path(path).is_absolute() else run_dir / path  # older runs kept absolute paths
        return p if p.is_file() and p.resolve().is_relative_to(self.runs.resolve()) else None

    def domains(self) -> list[dict]:
        return _overview([c for c, _ in self._scan()])

    def checks(self, domain: str) -> list[Check]:
        return sorted((c for c, _ in self._scan() if c.domain == domain), key=lambda c: c.checked_at, reverse=True)

    def screenshot(self, domain: str, check: str) -> bytes | None:
        shot = next((s for c, s in self._scan() if c.domain == domain and c.check == check), None)
        return shot.read_bytes() if shot else None


class DatabaseHistory:
    """Every check appended to the results database."""

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.source = f"results database {self.path.name}"

    def domains(self) -> list[dict]:
        with results_db.ResultsDB(self.path) as db:
            return [{"domain": r["domain"], "checks": r["checks"], "last_check": r["last_check"],
                     "monitored": r["monitored"], "same_owner": r["same_owner"]}
                    for r in db.latest_per_domain()]

    def checks(self, domain: str) -> list[Check]:
        with results_db.ResultsDB(self.path) as db:
            rows = db.history(domain)
        return [Check(domain=domain, check=str(r["id"]), checked_at=r["checked_at"], run=r["run"],
                      monitored=r["monitored"], same_owner=r["same_owner"], summary=r["summary"] or "",
                      email=_emails(json.loads(r["record"]), json.loads(r["analysis"]) if r["analysis"] else None),
                      has_screenshot=bool(r["has_screenshot"]))
                for r in reversed(rows)]

    def screenshot(self, domain: str, check: str) -> bytes | None:
        if not check.isdigit():
            return None
        with results_db.ResultsDB(self.path) as db:
            return db.screenshot(int(check), domain)


def open_history(runs: Path, db_path: str | None) -> FolderHistory | DatabaseHistory:
    """The database when one is configured, else the run folders - the same place results are saved to."""
    return DatabaseHistory(db_path) if db_path else FolderHistory(runs)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    hist = open_history(config.RUNS, results_db.default_db())
    print(f"source: {hist.source}\n")
    if argv:
        for c in hist.checks(argv[0].strip().lower()):
            print(f"=== {c.checked_at} (run {c.run}{', vs ' + c.monitored if c.monitored else ''})\n{c.summary}\n")
    else:
        for d in hist.domains():
            vs = f"  vs {d['monitored']}" if d["monitored"] else ""
            print(f"{d['domain']:40} {d['checks']:>3} check(s)  last {d['last_check']}{vs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
