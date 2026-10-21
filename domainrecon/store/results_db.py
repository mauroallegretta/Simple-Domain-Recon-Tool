#!/usr/bin/env python3
"""
Optional results database: every check of every domain, appended over time to one SQLite
file - for history (how a domain changed between checks) and as a cache (reuse a recent
check instead of visiting the site again). It is off unless RESULTS_DB (.env) or --db names
a file; without it everything stays in the run folders only. SQLite comes with Python, so
there is nothing to install, and any SQLite tool can open the file.

Kept per check: when, in which run, against which monitored domain; the collected record and
the AI analysis as JSON (queryable with SQLite's json_extract); the plain-English summary; a
few columns worth filtering on; and that domain's run files (screenshot, HTML, DOM, CSS,
text, AI report) compressed - so the database stays complete after run folders are deleted.

Usage:  ./recon db [--db FILE] domains          every domain checked: how often, when
        ./recon db [--db FILE] history DOMAIN   every check of one domain, oldest first
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.store.results_db", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import json
import os
import sqlite3
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id               INTEGER PRIMARY KEY,
    domain           TEXT NOT NULL,
    checked_at       TEXT NOT NULL,      -- UTC, e.g. 2026-10-21T11:00:12Z
    run              TEXT NOT NULL,      -- run folder name
    monitored        TEXT,               -- domain it was compared with; NULL = description only
    registered       TEXT,
    registrar        TEXT,
    http_status      INTEGER,
    final_url        TEXT,
    same_owner       TEXT,
    summary          TEXT,
    record           TEXT NOT NULL,      -- collected record (JSON)
    analysis         TEXT                -- AI analysis record (JSON); NULL when none was made
);
CREATE INDEX IF NOT EXISTS checks_by_domain ON checks (domain, checked_at);
CREATE TABLE IF NOT EXISTS files (
    check_id INTEGER NOT NULL REFERENCES checks (id),
    path     TEXT NOT NULL,              -- relative to the run folder, e.g. pages/x.com/screenshot.png
    data     BLOB NOT NULL,              -- zlib-compressed content
    PRIMARY KEY (check_id, path)
);
"""


def default_db() -> str | None:
    """RESULTS_DB from .env; a relative path there means relative to the project folder."""
    value = os.environ.get("RESULTS_DB")
    if not value:
        return None
    return value if Path(value).expanduser().is_absolute() else str(config.ROOT / value)


def add_args(ap: argparse.ArgumentParser) -> None:
    """--db and --cache-hours, defaulting to RESULTS_DB and RESULTS_CACHE_HOURS in .env."""
    ap.add_argument("--db", default=default_db(), metavar="FILE",
                    help="also append every check to this SQLite file (default: RESULTS_DB from .env; "
                         "unset = run folders only)")
    ap.add_argument("--cache-hours", type=float, default=float(os.environ.get("RESULTS_CACHE_HOURS") or 0),
                    help="with --db, reuse a domain's stored check when it is newer than this many hours "
                         "(default: RESULTS_CACHE_HOURS from .env, else 0 = always check again)")


def _utc(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class ResultsDB:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def save(self, *, domain: str, run_dir: Path, record: dict, analysis: dict | None,
             summary: str, monitored: str | None, files: list[str]) -> int:
        """Append one check. files: paths relative to run_dir to keep with it (missing ones skipped)."""
        def value(field):
            return field.get("value") if isinstance(field, dict) else None

        result = (analysis or {}).get("result") or {}
        meta = (record.get("screenshot") or {}).get("meta") or {}
        reg = record.get("registration") or {}
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO checks (domain, checked_at, run, monitored, registered, registrar, http_status, "
                "final_url, same_owner, summary, record, analysis) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (domain, record.get("collected_at") or _utc(datetime.now(timezone.utc)), Path(run_dir).name,
                 monitored, value(reg.get("created")), value(reg.get("registrar")), meta.get("status"),
                 meta.get("final_url"), result.get("same_owner"),
                 summary, json.dumps(record, ensure_ascii=False),
                 json.dumps(analysis, ensure_ascii=False) if analysis else None))
            for rel in files:
                path = Path(run_dir) / rel
                if path.is_file():
                    self.conn.execute("INSERT INTO files (check_id, path, data) VALUES (?, ?, ?)",
                                      (cur.lastrowid, rel, zlib.compress(path.read_bytes())))
        return cur.lastrowid

    def latest(self, domain: str, monitored: str | None, max_age_hours: float) -> sqlite3.Row | None:
        """The newest check of domain against the same monitored domain (or none), if it is
        younger than max_age_hours; None when there is none or caching is off (0)."""
        if max_age_hours <= 0:
            return None
        since = _utc(datetime.now(timezone.utc) - timedelta(hours=max_age_hours))
        return self.conn.execute(
            "SELECT * FROM checks WHERE domain = ? AND monitored IS ? AND checked_at >= ? "
            "ORDER BY checked_at DESC LIMIT 1", (domain, monitored, since)).fetchone()

    def restore(self, check: sqlite3.Row, run_dir: Path) -> tuple[dict, dict | None]:
        """Write a stored check's files into run_dir, at the same relative paths, and return
        its record and analysis."""
        for row in self.conn.execute("SELECT path, data FROM files WHERE check_id = ?", (check["id"],)):
            path = Path(run_dir) / row["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(zlib.decompress(row["data"]))
        return json.loads(check["record"]), json.loads(check["analysis"]) if check["analysis"] else None

    def domains(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT domain, COUNT(*) AS checks, MIN(checked_at) AS first_check, MAX(checked_at) AS last_check "
            "FROM checks GROUP BY domain ORDER BY last_check DESC").fetchall()

    def latest_per_domain(self) -> list[sqlite3.Row]:
        """One row per domain - its newest check, plus how many checks it has - newest first."""
        return self.conn.execute(
            "SELECT c.domain, n.checks, c.checked_at AS last_check, c.monitored, c.same_owner "
            "FROM checks c JOIN (SELECT domain, COUNT(*) AS checks, MAX(id) AS last_id FROM checks GROUP BY domain) n "
            "ON c.id = n.last_id ORDER BY c.checked_at DESC").fetchall()

    def history(self, domain: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT id, checked_at, run, monitored, http_status, final_url, registrar, "
            "same_owner, summary, record, analysis, EXISTS (SELECT 1 FROM files f WHERE f.check_id = checks.id "
            "AND f.path = json_extract(checks.record, '$.screenshot.path')) AS has_screenshot "
            "FROM checks WHERE domain = ? ORDER BY checked_at", (domain,)).fetchall()

    def screenshot(self, check_id: int, domain: str) -> bytes | None:
        """The screenshot stored with a check of domain, or None."""
        row = self.conn.execute(
            "SELECT f.data FROM checks c JOIN files f ON f.check_id = c.id "
            "AND f.path = json_extract(c.record, '$.screenshot.path') WHERE c.id = ? AND c.domain = ?",
            (check_id, domain)).fetchone()
        return zlib.decompress(row["data"]) if row else None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="recon db", description="Look into the results database.")
    ap.add_argument("--db", default=default_db(), metavar="FILE",
                    help="SQLite file (default: RESULTS_DB from .env)")
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("domains", help="every domain checked: how often, first and last check")
    hist = sub.add_parser("history", help="every check of one domain, oldest first")
    hist.add_argument("domain")
    args = ap.parse_args(argv)
    if not args.db or not Path(args.db).expanduser().exists():
        print("no results database: set RESULTS_DB in .env or pass --db FILE", file=sys.stderr)
        return 2

    with ResultsDB(args.db) as db:
        if args.command == "domains":
            rows = db.domains()
            print(f"{'domain':40} {'checks':>6}  first check           last check")
            for r in rows:
                print(f"{r['domain']:40} {r['checks']:>6}  {r['first_check']}  {r['last_check']}")
        else:
            rows = db.history(args.domain.strip().lower())
            for r in rows:
                compared = f", compared with {r['monitored']}" if r["monitored"] else ""
                print(f"=== check {r['id']}: {r['checked_at']} (run {r['run']}{compared})\n{r['summary']}\n")
    if not rows:
        print("nothing stored yet" if args.command == "domains" else f"no checks of {args.domain} stored")
    return 0


if __name__ == "__main__":
    sys.exit(main())
