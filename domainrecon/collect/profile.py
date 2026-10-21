"""
Everything collected about one domain, written to a run folder - no AI involved:

  - registration date + registrar   (RDAP, falling back to whois port 43)
  - MX records + proprietary/third-party classification (DNS + Public Suffix List)
  - A / AAAA records, reverse PTR, ASN + network owner (DNS + Team Cymru DNS)
  - a screenshot plus the page's    (rendered from this machine in a headless browser,
    HTML, DOM and CSS                see capture.py; every visit goes in direct-contact.txt)
  - page title / meta / visible text and an offline language guess

Everything it finds goes to runs/<run>/raw/<domain>.json with a {value, source, error} shape per
field, so a failure in one stage never costs the others. File paths in it are relative to the
run folder (resolve them with util.run_path).

Usage:  ./recon collect domains.txt [--force] [--outdir DIR] [--run-name NAME] [--workers N]
                                    [--resolvers IP[,IP...]]
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.collect.profile", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import concurrent.futures as futures
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .. import config
from ..util import DIRECT_LEDGER_HEADER, field, log, note_contact, now_iso
from . import capture
from .dnsinfo import add_resolvers_arg, addresses, nameservers, own_asn_set, use_resolvers
from .domains import read_domains
from .fingerprint import http_fingerprint
from .mail import mx_lookup
from .page import detect_language, extract_text
from .registration import registration


def local_render(domain: str, page_dir: Path) -> dict:
    """Direct visit from this machine's IP: an httpx fingerprint, then a capture.py render
    that saves screenshot, raw HTML, rendered DOM and CSS into page_dir."""
    fp = http_fingerprint(domain)
    cap = capture.capture(domain, page_dir)
    meta = {"final_url": cap.url, "status": cap.status, "title": cap.title,
            "server": cap.server or fp.get("webserver"), "redirects": cap.redirects,
            "tech": fp.get("tech"), "content_length": fp.get("content_length"),
            "location": fp.get("location"), "cdn_name": fp.get("cdn_name"),
            "favicon_mmh3": fp.get("favicon_mmh3"), "rendered_at": cap.captured_at}
    ok = "screenshot" in cap.files
    return {"ok": ok, "meta": meta, "files": cap.files,
            "error": None if ok else cap.error or "the page loaded but no screenshot was saved"}


def profile(domain: str, dirs: dict, runlog: Path, direct_ledger: Path) -> dict:
    log(runlog, f"[{domain}] start")
    rec = {"domain": domain, "collected_at": now_iso()}

    try:
        rec["registration"] = registration(domain)
    except Exception as e:
        rec["registration"] = {"created": field(None, None, f"{type(e).__name__}: {e}")}
    created = rec["registration"].get("created", {}).get("value")
    log(runlog, f"[{domain}] registration: {created or 'unresolved'}")

    try:
        rec["dns"] = addresses(domain)
    except Exception as e:
        rec["dns"] = field(None, None, f"{type(e).__name__}: {e}")
    own_asns = own_asn_set(rec["dns"].get("value"))

    try:
        rec["nameservers"] = nameservers(domain)
    except Exception as e:
        rec["nameservers"] = field(None, None, f"{type(e).__name__}: {e}")

    try:
        rec["mx"] = mx_lookup(domain, own_asns)
    except Exception as e:
        rec["mx"] = field(None, None, f"{type(e).__name__}: {e}")
    if rec["mx"].get("value"):
        log(runlog, f"[{domain}] mx: {rec['mx']['value']['posture']}")

    # A domain that has no addresses, no nameservers and no creation date is almost
    # certainly unregistered. Don't waste a render (or a direct visit) on it.
    has_addr = any((rec["dns"].get("value") or {}).get(k) for k in
                   ("apex_A", "apex_AAAA", "www_A", "www_AAAA"))
    has_ns = bool(rec["nameservers"].get("value"))
    # A lookup that failed outright (timeout, SERVFAIL) is no evidence of absence.
    dns_failed = bool(rec["dns"].get("error") or rec["nameservers"].get("error"))
    unregistered = (not has_addr and not has_ns and not created and not dns_failed)
    rec["resolves"] = has_addr
    rec["likely_unregistered"] = unregistered

    if unregistered:
        reason = (rec["registration"].get("created", {}).get("error")
                  or "no A/AAAA, no NS, no creation date")
        rec["screenshot"] = {"provenance": None, "path": None,
                             "error": f"skipped: domain appears unregistered ({reason})"}
        rec["page"] = extract_text("")
        rec["language_offline"] = field(None, "lingua", "no page")
        (dirs["text"] / f"{domain}.txt").write_text(
            f"# {domain}\n(no page: domain appears unregistered)\n", encoding="utf-8")
        (dirs["raw"] / f"{domain}.json").write_text(
            json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
        log(runlog, f"[{domain}] appears UNREGISTERED - screenshot skipped, no direct contact")
        return rec

    page_dir, root = dirs["pages"] / domain, dirs["raw"].parent
    try:
        lr = local_render(domain, page_dir)
    except Exception as e:
        lr = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    meta = lr.get("meta") or {}
    note_contact(direct_ledger, domain, meta.get("status") or lr.get("error"))
    # Paths are kept relative to the run folder, so a run can be moved or archived whole.
    files = {kind: (page_dir / name).relative_to(root).as_posix() for kind, name in (lr.get("files") or {}).items()}
    page_file = files.get("dom") or files.get("html")  # page text comes from what a visitor sees
    body = (root / page_file).read_text(encoding="utf-8", errors="replace") if page_file else ""
    shot_info = {"provenance": "local headless render (direct from this IP)",
                 "scanned_at": meta.get("rendered_at") or now_iso(),
                 "path": files.get("screenshot"),
                 "files": files,
                 "meta": meta,
                 "error": None if lr.get("ok") else lr.get("error")}
    if lr.get("ok"):
        log(runlog, f"[{domain}] render ok: HTTP {meta.get('status')} {meta.get('final_url')}")
    else:
        log(runlog, f"[{domain}] render FAILED ({lr.get('error')})")

    rec["screenshot"] = shot_info
    page = extract_text(body)
    if not page["title"]:
        page["title"] = meta.get("title")
    rec["page"] = page
    rec["language_offline"] = detect_language(page["text"] or (page["title"] or ""))

    # human-readable text dump for the vision pass
    tp = dirs["text"] / f"{domain}.txt"
    parts = [f"# {domain}", f"title: {page['title'] or '-'}",
             f"html lang: {page['html_lang'] or '-'}",
             f"meta description: {page['description'] or '-'}"]
    for k, v in (page["og"] or {}).items():
        parts.append(f"{k}: {v}")
    parts += ["", "--- visible text ---", page["text"] or "(no body text captured)"]
    tp.write_text("\n".join(parts), encoding="utf-8")

    (dirs["raw"] / f"{domain}.json").write_text(
        json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
    log(runlog, f"[{domain}] done")
    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="recon collect",
                                 description="Collect registration, DNS, mail and page evidence per domain (no AI).")
    ap.add_argument("input", help="file with one domain per line (# comments ok)")
    ap.add_argument("--outdir", default=str(config.RUNS))
    ap.add_argument("--run-name", default=None, help="reuse an existing run directory to resume")
    ap.add_argument("--force", action="store_true", help="re-collect domains that already have raw JSON")
    ap.add_argument("--workers", type=int, default=5)
    add_resolvers_arg(ap)
    args = ap.parse_args(argv)
    use_resolvers(args.resolvers)

    src = Path(args.input).expanduser()
    if not src.exists():
        print(f"input file not found: {src}", file=sys.stderr)
        return 2
    domains = read_domains(src)
    if not domains:
        print("no usable domains in input", file=sys.stderr)
        return 2

    run_name = args.run_name or datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%SZ")
    root = Path(args.outdir).expanduser() / run_name
    dirs = {k: root / k for k in ("raw", "text", "reports", "pages")}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    runlog = root / "run.log"
    direct_ledger = root / "direct-contact.txt"
    if not direct_ledger.exists():
        direct_ledger.write_text(DIRECT_LEDGER_HEADER, encoding="utf-8")

    todo = [d for d in domains if args.force or not (dirs["raw"] / f"{d}.json").exists()]
    skipped = len(domains) - len(todo)
    log(runlog, f"run {run_name}: {len(domains)} domains, {len(todo)} to collect, {skipped} already done")
    log(runlog, f"DNS resolvers: {', '.join(args.resolvers)}")

    if todo:
        with futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            fut = {pool.submit(profile, d, dirs, runlog, direct_ledger): d for d in todo}
            for f in futures.as_completed(fut):
                try:
                    f.result()
                except Exception as e:
                    log(runlog, f"[{fut[f]}] FATAL {type(e).__name__}: {e}")

    (root / "domains.json").write_text(json.dumps(domains, indent=2), encoding="utf-8")
    log(runlog, f"collection finished -> {root}")
    print(f"Run directory: {root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
