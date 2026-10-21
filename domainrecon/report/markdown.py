#!/usr/bin/env python3
"""
Markdown profiles of a run: one report per domain plus an index.

Reads   runs/<run>/raw/<domain>.json      (the collected evidence, from collect/profile.py)
    and runs/<run>/analysis/<domain>.json (the AI's reading of the page, from ai/analysis.py)
Writes  runs/<run>/reports/<domain>.md    and runs/<run>/INDEX.md

The analysis file is optional: without it the report still contains every hard fact and
simply marks the page analysis as pending. It is either an ai/analysis.py record, which
carries the analysis under "result", or (older runs) the bare analysis:

{
  "language":   "Italian (it)",
  "page_type":  "corporate site",
  "purpose":    "One or two sentences on what the site is for and who it serves.",
  "signals":    ["anything notable: credential form, brand lookalike, parked, ..."],
  "confidence": "high | medium | low",
  "notes":      "optional free text"
}

Usage:  ./recon report runs/<run-dir>
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.report.markdown", run_name="__main__", alter_sys=True)
    sys.exit()

import json
import sys
from pathlib import Path

POSTURE_LABEL = {
    "proprietary": "Proprietary (self-operated)",
    "third-party": "Third-party",
    "mixed": "Mixed (self-operated + third-party)",
    "null-mx": "Null MX - accepts no mail",
    "none": "No MX records",
}


def val(f, default="-"):
    """Unwrap a {value, source, error} field."""
    if not isinstance(f, dict):
        return f if f not in (None, "") else default
    v = f.get("value")
    if v in (None, "", [], {}):
        return default
    return v


def link(run: Path, path: str) -> str:
    """A run file as a link from reports/<domain>.md. Records keep paths relative to the run
    folder; older runs kept absolute ones."""
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.relative_to(run)
        except ValueError:
            return p.as_uri()
    return f"../{p.as_posix()}"


def src(f):
    return f.get("source") if isinstance(f, dict) else None


def ip_lines(recs):
    out = []
    for r in recs or []:
        bits = [f"`{r['ip']}`"]
        if r.get("asn"):
            bits.append(f"{r['asn']}" + (f" ({r['as_name']})" if r.get("as_name") else ""))
        if r.get("ptr"):
            bits.append(f"PTR `{r['ptr']}`")
        out.append(" - ".join(bits))
    return out


def short_ips(dns_value):
    v4 = [r["ip"] for r in (dns_value or {}).get("apex_A") or []]
    v6 = [r["ip"] for r in (dns_value or {}).get("apex_AAAA") or []]
    parts = []
    parts.append(", ".join(v4[:2]) + ("…" if len(v4) > 2 else "") if v4 else "no A")
    parts.append(f"{len(v6)}× AAAA" if v6 else "no AAAA")
    return " / ".join(parts)


def build_report(rec: dict, analysis: dict | None, run: Path) -> str:
    d = rec["domain"]
    reg = rec.get("registration") or {}
    dns = (rec.get("dns") or {}).get("value") or {}
    mx = (rec.get("mx") or {}).get("value") or {}
    shot = rec.get("screenshot") or {}
    page = rec.get("page") or {}
    meta = shot.get("meta") or {}

    L = [f"# {d}", ""]

    if rec.get("likely_unregistered"):
        L += ["> **This domain appears to be unregistered.** No A/AAAA, no nameservers "
              "and no creation date could be found.", ""]

    # --- summary line ---
    created = val(reg.get("created"))
    L += ["| | |", "|---|---|",
          f"| **Registered** | {created}"
          + (f" _(source: {src(reg.get('created'))})_" if src(reg.get("created")) else "") + " |",
          f"| **Registrar** | {val(reg.get('registrar'))} |",
          f"| **Expires** | {val(reg.get('expires'))} |",
          f"| **Mail (MX)** | {POSTURE_LABEL.get(mx.get('posture'), mx.get('posture') or '-')} |"]
    if mx.get("providers"):
        L.append(f"| **Mail provider** | {', '.join(mx['providers'])} |")
    L.append(f"| **Addresses** | {short_ips(dns)} |")
    if analysis:
        L += [f"| **Language** | {analysis.get('language', '-')} |",
              f"| **Page type** | {analysis.get('page_type', '-')} |"]
    L.append("")

    # --- page analysis ---
    L += ["## What this site is", ""]
    if analysis:
        L += [analysis.get("purpose", "-"), ""]
        if analysis.get("signals"):
            L += ["**Notable signals:**", ""]
            L += [f"- {s}" for s in analysis["signals"]]
            L.append("")
        if analysis.get("notes"):
            L += [analysis["notes"], ""]
        conf = analysis.get("confidence", "-")
        prov = shot.get("provenance") or "no screenshot"
        when = shot.get("scanned_at") or "-"
        L += [f"_Confidence: {conf}. Based on {prov}, captured {when}._", ""]
    else:
        L += ["_Page analysis pending._", ""]

    # --- screenshot ---
    L += ["## Screenshot", ""]
    if shot.get("path") and (run / shot["path"]).exists():  # an absolute path (older runs) wins the join
        L += [f"![screenshot of {d}]({link(run, shot['path'])})", "",
              f"- Source: {shot.get('provenance')}",
              f"- Captured: {shot.get('scanned_at')}"]
        if meta.get("redirects"):
            L.append(f"- Redirected from: {' → '.join(meta['redirects'])}")
        if meta.get("final_url"):
            L.append(f"- Final URL: {meta['final_url']}")
        if meta.get("status"):
            L.append(f"- HTTP status: {meta['status']}")
        saved = {kind: path for kind, path in (shot.get("files") or {}).items() if kind != "screenshot"}
        if saved:
            L.append("- Saved page: " + " · ".join(f"[{kind}]({link(run, path)})" for kind, path in saved.items()))
        L.append("")
    else:
        L += [f"_No screenshot: {shot.get('error') or 'not captured'}_", ""]

    # --- registration detail ---
    L += ["## Registration", ""]
    for label, key in (("Created", "created"), ("Expires", "expires"),
                       ("Registrar", "registrar"), ("Status", "statuses")):
        f = reg.get(key) or {}
        v = val(f)
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        line = f"- **{label}:** {v}"
        if src(f):
            line += f"  _(via {src(f)})_"
        if v == "-" and f.get("error"):
            line += f"  _({f['error']})_"
        L.append(line)
    L.append("")

    # --- mail ---
    L += ["## Mail (MX)", ""]
    if not mx.get("records"):
        err = (rec.get("mx") or {}).get("error")
        L += [f"MX lookup failed: {err}" if err else "No MX records.", ""]
    else:
        L += ["| Pref | Host | Type | Provider |", "|---|---|---|---|"]
        for r in mx["records"]:
            note = f" <br>_{r['note']}_" if r.get("note") else ""
            L.append(f"| {r['preference']} | `{r['host']}` | {r['kind']} | {r['provider']}{note} |")
        L += ["", f"**Posture:** {POSTURE_LABEL.get(mx.get('posture'), mx.get('posture'))}", ""]

    # --- dns ---
    L += ["## DNS", ""]
    for label, key in (("A (apex)", "apex_A"), ("AAAA (apex)", "apex_AAAA"),
                       ("A (www)", "www_A"), ("AAAA (www)", "www_AAAA")):
        lines = ip_lines(dns.get(key))
        if lines:
            L.append(f"**{label}**")
            L += [f"- {x}" for x in lines]
            L.append("")
    if not any(dns.get(k) for k in ("apex_A", "apex_AAAA", "www_A", "www_AAAA")):
        L += ["_No A or AAAA records resolved._", ""]
    ns = val((rec.get("nameservers") or {}))
    if ns != "-":
        L += ["**Nameservers**"] + [f"- `{n}`" for n in ns] + [""]
    for label, key in (("Address", "dns"), ("Nameserver", "nameservers")):
        if (rec.get(key) or {}).get("error"):
            L += [f"_{label} lookup failed: {rec[key]['error']}_", ""]
    if src(rec.get("dns")):
        L += [f"_Source: {src(rec['dns'])}_", ""]

    # --- page metadata ---
    L += ["## Page metadata", ""]
    L.append(f"- **Title:** {page.get('title') or '-'}")
    L.append(f"- **HTML lang:** {page.get('html_lang') or '-'}")
    L.append(f"- **Meta description:** {page.get('description') or '-'}")
    lo = (rec.get("language_offline") or {}).get("value")
    L.append(f"- **Offline language guess (lingua):** "
             f"{lo['name'] + ' (' + lo['iso'] + ')' if lo else '-'}")
    for k in ("server", "tech", "cdn_name", "favicon_mmh3"):
        if meta.get(k):
            v = ", ".join(meta[k]) if isinstance(meta[k], list) else meta[k]
            L.append(f"- **{k.replace('_', ' ').title()}:** {v}")
    L += ["", "---", "",
          f"_Evidence: [raw/{d}.json](../raw/{d}.json) · [text/{d}.txt](../text/{d}.txt) · "
          f"collected {rec.get('collected_at')}_", ""]
    return "\n".join(L)


def build_index(records: list[tuple[dict, dict | None]]) -> str:
    L = ["# Domain profiles", "",
         f"{len(records)} domains. Generated by `recon report`.", "",
         "| Domain | Registered | Mail | Addresses | Language | Page type |",
         "|---|---|---|---|---|---|"]
    for rec, an in records:
        d = rec["domain"]
        reg = (rec.get("registration") or {}).get("created") or {}
        mx = (rec.get("mx") or {}).get("value") or {}
        posture = POSTURE_LABEL.get(mx.get("posture"), mx.get("posture") or "-")
        if mx.get("providers"):
            posture += f" - {', '.join(mx['providers'])}"
        flag = " ⚠️ unregistered" if rec.get("likely_unregistered") else ""
        L.append(f"| [{d}](reports/{d}.md){flag} | {val(reg)} | {posture} | "
                 f"{short_ips((rec.get('dns') or {}).get('value'))} | "
                 f"{(an or {}).get('language', '-')} | {(an or {}).get('page_type', '-')} |")
    L += ["", "## Notes", "",
          "- **Registered** comes from RDAP where the TLD supports it, otherwise from port-43 whois.",
          "- **Mail** is classified by comparing each MX host's registrable domain (Public Suffix "
          "List) against the target's. An unrecognised mail domain on the *same ASN* as the web "
          "site is treated as self-operated infrastructure rather than a third party.",
          "- Screenshots, HTML, DOM and CSS come from a headless browser visit made from this "
          "machine (unregistered domains are not visited). See `direct-contact.txt` for every "
          "domain this machine contacted.", ""]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        print(__doc__)
        return 2
    run = Path(argv[0]).expanduser().resolve()
    raw_dir, rep_dir = run / "raw", run / "reports"
    an_dir = run / "analysis"
    if not raw_dir.is_dir():
        print(f"no raw/ directory under {run}", file=sys.stderr)
        return 2
    rep_dir.mkdir(exist_ok=True)
    an_dir.mkdir(exist_ok=True)

    order = []
    dj = run / "domains.json"
    if dj.exists():
        order = json.loads(dj.read_text())

    files = sorted(raw_dir.glob("*.json"), key=lambda p: (order.index(p.stem) if p.stem in order else 999, p.stem))
    records, missing = [], []
    for f in files:
        rec = json.loads(f.read_text(encoding="utf-8"))
        af = an_dir / f.name
        an = json.loads(af.read_text(encoding="utf-8")) if af.exists() else None
        if an and "result" in an:  # ai/analysis.py record (None on failure); older runs saved the bare result
            an = an["result"]
        if an is None and not rec.get("likely_unregistered"):
            missing.append(rec["domain"])
        (rep_dir / f"{rec['domain']}.md").write_text(build_report(rec, an, run), encoding="utf-8")
        records.append((rec, an))

    (run / "INDEX.md").write_text(build_index(records), encoding="utf-8")
    print(f"wrote {len(records)} reports + INDEX.md under {run}")
    if missing:
        print(f"awaiting vision analysis for {len(missing)}: {', '.join(missing)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
