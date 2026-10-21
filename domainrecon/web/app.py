#!/usr/bin/env python3
"""
domain-recon GUI: paste a list of domains, get a plain-English summary of what was found
for each. Optionally name the domain being monitored: every page is then also compared with
that domain's site, with a judgement on whether both domains share an owner (a brand's own
defensive registration). A history panel opens every domain already checked, read from
wherever results are kept (store/history.py): the results database when one is configured,
otherwise the run folders.

The recon itself is pipeline.run() - the same as `recon check` on the command line -
writing under runs/gui-<timestamp>/. This file only adds an HTTP server; the page itself is
static/index.html, and its fonts (Space Grotesk, IBM Plex Mono; SIL Open Font License) ship in
static/fonts/, so it needs nothing from the internet.

Usage:  ./recon web [--host 127.0.0.1] [--port 8765] [--resolvers IP[,IP...]]
                    [--db FILE [--cache-hours N]]
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.web.app", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import base64
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

from .. import config, pipeline
from ..collect.dnsinfo import add_resolvers_arg, use_resolvers
from ..collect.domains import normalise
from ..report import narrative
from ..store import history, results_db
from ..takedown import case as takedown
from ..util import run_path

RUNS = config.RUNS
PAGE = config.STATIC / "index.html"
FONTS = config.STATIC / "fonts"
RUN_NAME = re.compile(r"[A-Za-z0-9._-]+")

# Set once in main(): results database settings (--db / --cache-hours, by default from .env)
# and where the history panel reads from - the same place results are saved to.
DB_SETTINGS = {"db_path": None, "cache_hours": 0.0}
HISTORY: history.FolderHistory | history.DatabaseHistory = history.FolderHistory(RUNS)


def encode_screenshot(path: Path | None) -> str | None:
    if not path or not path.exists():
        return None
    return "data:image/png;base64," + base64.standard_b64encode(path.read_bytes()).decode("ascii")


def analyze(domain_lines: list[str], monitored_text: str = "") -> dict:
    monitored = normalise(monitored_text) if monitored_text.strip() else None
    if monitored_text.strip() and not monitored:
        return {"error": f"'{monitored_text.strip()}' is not a valid monitored domain."}
    domains = list(dict.fromkeys(d for d in map(normalise, domain_lines) if d and d != monitored))
    if not domains:
        return {"error": "No valid domain found in the text."}

    run_name = "gui-" + datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%SZ")
    root = RUNS / run_name
    results, _ = pipeline.run(domains, root, monitored=monitored, **DB_SETTINGS)

    reused = sum(1 for r in results if r.rec.get("reused_from"))
    header = " · ".join(part for part in (f"{len(domains)} domain{'s' if len(domains) != 1 else ''}",
                                          f"vs {monitored}" if monitored else "",
                                          f"{reused} from history" if reused else "",
                                          f"runs/{run_name}/") if part)
    return {"header": header, "run": run_name,
            "results": [{"domain": r.domain, "text": r.text, "same_owner": r.same_owner,
                         "email": {lang: r.email(lang) for lang in narrative.LANGUAGES},
                         "takedown": asdict(takedown.qualify(r.rec, r.analysis)) if monitored else None,
                         "screenshot": encode_screenshot(run_path(root, (r.rec.get("screenshot") or {}).get("path")))}
                        for r in results]}


def run_folder(name: str) -> Path | None:
    """An existing run folder from a name sent by the page - a bare name, never a path."""
    if not RUN_NAME.fullmatch(name or "") or set(name) == {"."}:
        return None
    folder = RUNS / name
    return folder if folder.is_dir() else None


def takedown_case(run_name: str, domain_text: str, force: bool) -> dict:
    run, domain = run_folder(run_name), normalise(domain_text or "")
    if not run or not domain:
        return {"error": "Unknown run or domain."}
    try:
        case = takedown.prepare_case(run, domain, force=force)
    except takedown.NotProposed as e:
        return {"error": f"No takedown proposed: {e}"}
    except FileNotFoundError:
        return {"error": "Unknown run or domain."}
    return case_payload(run_name, case)


def takedown_detail(run_name: str, domain_text: str) -> dict:
    run, domain = run_folder(run_name), normalise(domain_text or "")
    case = takedown.load_case(run, domain) if run and domain else None
    return case_payload(run_name, case) if case else {"error": "No such takedown case."}


def case_payload(run_name: str, case: dict) -> dict:
    """A case as the page needs it: the case itself plus links to its files."""
    def url(rel):
        return f"/api/takedown/file?run={quote(run_name)}&domain={quote(case['domain'])}&path={quote(rel)}" if rel else None
    return {"run": run_name, "case": case, "evidence_url": url(case["evidence"]["zip"]),
            "screenshot_url": url(case.get("screenshot")),
            "drafts": [{**d, "eml_url": {lang: url(f["eml"]) for lang, f in d["files"].items()}} for d in case["drafts"]]}


def takedown_file(run_name: str, domain_text: str, rel: str) -> tuple[bytes, str, str] | None:
    """(content, type, file name) of a file of a prepared case - only files the case lists."""
    run, domain = run_folder(run_name), normalise(domain_text or "")
    case = takedown.load_case(run, domain) if run and domain else None
    if not case:
        return None
    listed = {case["evidence"]["zip"], case.get("screenshot")} | {
        f[k] for d in case["drafts"] for f in d["files"].values() for k in ("text", "eml") if f.get(k)}
    if not rel or rel not in listed:
        return None
    path = run / rel
    kind = {".zip": "application/zip", ".eml": "message/rfc822", ".txt": "text/plain; charset=utf-8", ".png": "image/png"}
    return path.read_bytes(), kind.get(path.suffix, "application/octet-stream"), path.name


def check_json(c: history.Check) -> dict:
    url = f"/api/screenshot?domain={quote(c.domain)}&check={quote(c.check)}" if c.has_screenshot else None
    return {**asdict(c), "screenshot_url": url}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, content_type: str, cache: bool = False, download: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if cache:
            self.send_header("Cache-Control", "public, max-age=604800")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def do_GET(self):
        url = urlsplit(self.path)
        try:
            if url.path in ("/", "/index.html"):
                self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            elif url.path.startswith("/static/fonts/"):
                font = FONTS / Path(url.path).name  # only bare file names from the fonts folder
                if font.suffix == ".woff2" and font.is_file():
                    self._send(200, font.read_bytes(), "font/woff2", cache=True)
                else:
                    self._send(404, b"not found", "text/plain")
            elif url.path == "/api/history":
                self._json({"source": HISTORY.source, "domains": HISTORY.domains()})
            elif url.path.startswith("/api/history/"):
                domain = normalise(unquote(url.path.removeprefix("/api/history/"))) or ""
                self._json({"domain": domain, "checks": [check_json(c) for c in HISTORY.checks(domain)] if domain else []})
            elif url.path == "/api/screenshot":
                q = parse_qs(url.query)
                data = HISTORY.screenshot(q.get("domain", [""])[0], q.get("check", [""])[0])
                self._send(200, data, "image/png") if data else self._send(404, b"not found", "text/plain")
            elif url.path == "/api/takedown/file":
                q = parse_qs(url.query)
                found = takedown_file(*(q.get(k, [""])[0] for k in ("run", "domain", "path")))
                if found:  # images show in the page; everything else downloads
                    self._send(200, found[0], found[1], download=None if found[1].startswith("image/") else found[2])
                else:
                    self._send(404, b"not found", "text/plain")
            elif url.path == "/api/takedowns":
                self._json({"cases": takedown.list_cases(RUNS)})
            elif url.path.startswith("/api/takedowns/"):
                run_name, _, domain = unquote(url.path.removeprefix("/api/takedowns/")).partition("/")
                self._json(takedown_detail(run_name, domain))
            else:
                self._send(404, b"not found", "text/plain")
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)

    def do_POST(self):
        if self.path not in ("/api/analyze", "/api/takedown"):
            self._send(404, b"not found", "text/plain")
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
            if self.path == "/api/takedown":
                out = takedown_case(payload.get("run") or "", payload.get("domain") or "", bool(payload.get("force")))
            else:
                out = analyze((payload.get("domains") or "").splitlines(), payload.get("monitored") or "")
        except Exception as e:
            out = {"error": f"{type(e).__name__}: {e}"}
        self._json(out)


def main(argv: list[str] | None = None) -> int:
    global HISTORY
    ap = argparse.ArgumentParser(prog="recon web", description="The browser interface.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    add_resolvers_arg(ap)
    results_db.add_args(ap)
    args = ap.parse_args(argv)
    use_resolvers(args.resolvers)
    DB_SETTINGS.update(db_path=args.db, cache_hours=args.cache_hours)
    HISTORY = history.open_history(RUNS, args.db)
    RUNS.mkdir(exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    storage = (f"run folders + results database {args.db}"
               + (f", reusing checks younger than {args.cache_hours:g} h" if args.cache_hours > 0 else "")
               if args.db else "run folders only")
    print(f"domain-recon GUI at http://{args.host}:{args.port} "
          f"(DNS resolvers: {', '.join(args.resolvers)}; storage: {storage})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
