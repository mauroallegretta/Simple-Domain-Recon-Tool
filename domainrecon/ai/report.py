#!/usr/bin/env python3
"""
Turn saved AI analysis records (from ai/analysis.py) into readable reports by filling
the fixed template templates/ai_report.md with the result's key/values.

Usage:  python -m domainrecon.ai.report RECORD.json [RECORD.json ...]   (writes RECORD.md beside each)
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.ai.report", run_name="__main__", alter_sys=True)
    sys.exit()

import json
import sys
from pathlib import Path
from string import Template

from .. import config

TEMPLATE = Template((config.TEMPLATES / "ai_report.md").read_text(encoding="utf-8"))


def render(record: dict) -> str:
    if record.get("error"):
        raise ValueError(f"no report for {record.get('subject')}: the analysis failed ({record['error']})")
    result = record.get("result") or {}

    def value(key):
        v = result.get(key)
        return str(v).strip() if v not in (None, "", []) else "-"

    values = {key: value(key) for key in ("language", "page_type", "purpose", "confidence", "notes")}
    values["signals"] = "\n".join(f"- {s}" for s in result.get("signals") or []) or "None noted."
    values.update({key: record.get(key) or "-" for key in ("subject", "analyzed_at", "provider", "model")})
    values["inputs"] = ", ".join(record.get("inputs") or []) or "-"
    values["comparison"] = ""   # only analyses run against a monitored domain have one
    if record.get("monitored") and result.get("comparison"):
        values["comparison"] = (f"\n## Comparison with {record['monitored']}\n\n"
                                f"{value('comparison')}\n\n"
                                f"**Same owner:** {value('same_owner')} - {value('ownership')}\n")
    return TEMPLATE.safe_substitute(values)


def write(record_path: str | Path) -> Path:
    """Render the record saved at record_path into the .md file beside it."""
    record_path = Path(record_path)
    out = record_path.with_suffix(".md")
    out.write_text(render(json.loads(record_path.read_text(encoding="utf-8"))), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    failed = 0
    for arg in argv:
        try:
            print(f"wrote {write(arg)}")
        except (OSError, ValueError) as e:
            print(e, file=sys.stderr)
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
