"""
domain-recon command line. `check` is the default command, so the short forms are:

    ./recon suspicious-brand.com --target brand.com           one domain against the target (1 vs 1)
    ./recon domains.txt --target brand.com                    a list, as plain text
    ./recon domains.txt --target brand.com -o results.jsonl   a list, one JSON line per domain
    ./recon suspicious-brand.com                              no target: describe only

The target is the monitored domain the inputs may be imitating; each loaded page is compared with
it (this needs AI_API_KEY in .env). Results print to stdout as plain text, without screenshots;
progress goes to stderr. Every check also leaves its full evidence - screenshots, page files, AI
records - in runs/<run>/.

Other commands:
    web        the browser interface
    collect    collection only: no AI, no summary
    takedown   prepare takedown cases for a run (sends nothing)
    report     Markdown reports for a run
    history    domains already checked
    db         look into the results database
    analyze    ask the AI what one screenshot shows
    capture    render one URL into a folder

./recon COMMAND --help shows each command's options.
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[1])  # the project folder, not this one
    runpy.run_module("domainrecon.cli", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import importlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

COMMANDS = {
    "web": "domainrecon.web.app",
    "collect": "domainrecon.collect.profile",
    "takedown": "domainrecon.takedown.case",
    "report": "domainrecon.report.markdown",
    "history": "domainrecon.store.history",
    "db": "domainrecon.store.results_db",
    "analyze": "domainrecon.ai.analysis",
    "capture": "domainrecon.collect.capture",
}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0 if argv else 2
    if argv[0] == "check":
        return check(argv[1:])
    if argv[0] in COMMANDS:
        return importlib.import_module(COMMANDS[argv[0]]).main(argv[1:])
    return check(argv)


def _inputs(items: list[str]) -> tuple[list[str], list[str]]:
    """(domains, problems) from arguments that are each a domain or a file of domains."""
    from .collect.domains import has_public_suffix, normalise, read_domains

    domains, problems = [], []
    for item in items:
        path = Path(item).expanduser()
        if path.is_file():
            domains += read_domains(path)
        elif (d := normalise(item)) and has_public_suffix(d):
            domains.append(d)
        else:
            problems.append(f"{item} (no such file, and not a domain)")
    return list(dict.fromkeys(domains)), problems


def check(argv: list[str]) -> int:
    from . import config, pipeline, util
    from .ai import analysis as ai_analysis
    from .collect.dnsinfo import add_resolvers_arg, use_resolvers
    from .collect.domains import normalise, registrable
    from .report import export
    from .store import results_db

    ap = argparse.ArgumentParser(
        prog="recon [check]",
        description="Check domains - registration, DNS, mail, the rendered page and an AI description - "
                    "optionally comparing each with a target domain. Plain text to stdout, or JSONL.")
    ap.add_argument("inputs", nargs="+", metavar="DOMAIN_OR_FILE",
                    help="a domain, or a text file with one domain per line ('#' comments ok); several may be given")
    ap.add_argument("-t", "--target", "--monitor", dest="target", metavar="DOMAIN",
                    help="the monitored domain the inputs may be imitating: each page is compared with it "
                         "(needs AI_API_KEY)")
    ap.add_argument("-o", "--output", type=Path, metavar="FILE.jsonl",
                    help="write one JSON line per input domain to this file, instead of printing text")
    ap.add_argument("--jsonl", action="store_true", help="print JSON lines to stdout instead of text")
    ap.add_argument("--email", choices=("en", "es"), help="also print the ready-to-send email text in this language")
    ap.add_argument("-q", "--quiet", action="store_true", help="no progress lines on stderr")
    ap.add_argument("--outdir", type=Path, default=config.RUNS, help="where run folders go (default: runs/)")
    ap.add_argument("--run-name", help="name of the run folder (default: the UTC time)")
    ap.add_argument("--workers", type=int, default=5, help="domains checked in parallel (default: 5)")
    add_resolvers_arg(ap)
    results_db.add_args(ap)
    args = ap.parse_args(argv)

    domains, problems = _inputs(args.inputs)
    target = normalise(args.target) if args.target else None
    if args.target and not target:
        problems.append(f"{args.target} (target is not a domain)")
    if problems or not domains:
        print("recon: " + ("; ".join(problems) if problems else "no usable domain in the input"), file=sys.stderr)
        return 2

    # An input the target owns is not a lookalike of it: the target itself, or a subdomain of it.
    skipped = {}
    if target:
        for d in domains:
            if d == target:
                skipped[d] = "it is the target itself"
            elif registrable(d) == registrable(target):
                skipped[d] = f"it is part of the target's own domain {registrable(target)}"
        if not ai_analysis.configured():
            print(f"recon: note - comparing with {target} needs AI_API_KEY in .env; "
                  "only the collected facts will be reported", file=sys.stderr)
    to_check = [d for d in domains if d not in skipped]

    util.ECHO = not args.quiet
    use_resolvers(args.resolvers)
    root = args.outdir.expanduser() / (args.run_name or datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%SZ"))
    results = {}
    if to_check:
        checked, _ = pipeline.run(to_check, root, monitored=target, workers=args.workers,
                                  db_path=args.db, cache_hours=args.cache_hours)
        results = {r.domain: r for r in checked}
    records = [export.skipped(d, target, skipped[d]) if d in skipped else export.record(results[d], target, root)
               for d in domains]

    if args.output:
        args.output.expanduser().parent.mkdir(parents=True, exist_ok=True)
        with args.output.expanduser().open("w", encoding="utf-8") as fh:
            fh.writelines(json.dumps(rec, ensure_ascii=False) + "\n" for rec in records)
        print(f"recon: {len(records)} result(s) written to {args.output}", file=sys.stderr)
    elif args.jsonl:
        for rec in records:
            print(json.dumps(rec, ensure_ascii=False))
    else:
        print("\n\n".join(export.text(rec, args.email) for rec in records))
    return 0


if __name__ == "__main__":
    sys.exit(main())
