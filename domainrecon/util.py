"""
Small helpers shared across the package: the {value, source, error} shape of every collected
fact, running a command, the run log and the direct-contact ledger, timestamps, and paths kept
relative to a run folder.
"""

import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

DIRECT_LEDGER_HEADER = ("# Domains this machine's IP visited to render them (unregistered ones are skipped).\n"
                        "# timestamp\tdomain\tHTTP status, or what went wrong\n")

ECHO = True  # also print run-log lines to stderr; the command line's --quiet turns it off

_lock = threading.Lock()


def field(value=None, source=None, error=None) -> dict:
    return {"value": value, "source": source, "error": error}


def run(cmd, timeout=30) -> str:
    """Run a command, returning stdout ('' on any failure)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(runlog: Path, msg: str) -> None:
    """Append a timestamped line to the run log (and stderr, unless ECHO is off)."""
    line = f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M:%SZ}  {msg}"
    with _lock:
        if ECHO:
            print(line, file=sys.stderr, flush=True)
        with runlog.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def note_contact(direct_ledger: Path, domain: str, outcome) -> None:
    """One line in direct-contact.txt per site this machine visited."""
    with _lock:
        with direct_ledger.open("a", encoding="utf-8") as fh:
            fh.write(f"{now_iso()}\t{domain}\t{outcome}\n")


def run_path(run: Path, path: str | None) -> Path | None:
    """A file path from a record, made usable: records keep paths relative to their run
    folder (runs collected before that change kept absolute ones, which pass through)."""
    return None if not path else Path(path) if Path(path).is_absolute() else Path(run) / path
