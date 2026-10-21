#!/usr/bin/env python3
"""
Shrink a page's HTML, DOM and CSS to what says what the page is, before sending them
anywhere that bills by size (an AI model). Text in, text out: nothing is read from or
written to disk, so the saved originals stay complete.

Kept, because that's where recon signals live:
  - forms and inputs: where submitted data goes (action) and what is asked (password,
    card, OTP fields), hidden inputs
  - links, script / iframe / image sources, <base>, meta refresh, canonical, og:*, favicon:
    which other sites the page leans on - a clone often still links to the real brand
  - image alt and SVG labels (logos), visible and hidden text
  - HTML comments (kits keep lines like "saved from url=(0024)https://...")
  - the start of each inline script: enough to spot eval/atob obfuscation, a redirect,
    an exfiltration endpoint
Dropped, because it costs tokens and says nothing the screenshot doesn't:
  - styling: class, style, <style>; the CSS itself is reduced to the files and fonts it
    pulls in (distill_css)
  - SVG drawings, data: URIs, event handlers, data-* attributes, resource hints
  - layout-only wrappers, line breaks and runs of whitespace
The raw HTML is also dropped when it says the same as the rendered DOM (for_ai).

Usage:  python -m domainrecon.ai.clean FILE.html|FILE.css   (prints the cleaned text and the saving)
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.ai.clean", run_name="__main__", alter_sys=True)
    sys.exit()

import re
import sys
from pathlib import Path

from bs4 import BeautifulSoup, Comment

KEEP_ATTRS = {"href", "src", "action", "method", "type", "name", "id", "value", "placeholder", "alt",
              "title", "content", "property", "http-equiv", "rel", "lang", "for", "autocomplete",
              "aria-label", "role", "target", "hidden", "charset"}
DROP_TAGS = ["style", "canvas", "template"]
DROP_LINK_RELS = {"preload", "prefetch", "preconnect", "dns-prefetch", "modulepreload"}
BLOCK_WRAPPERS = {"div", "section", "article", "main", "header", "footer", "nav", "aside", "figure", "center"}
INLINE_WRAPPERS = {"span", "font", "b", "i", "u", "em", "strong", "small", "picture"}
VOID_TAGS = {"img", "input", "meta", "link", "base", "source", "iframe", "embed", "svg"}
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden", re.I)
GENERIC_FONTS = {"serif", "sans-serif", "monospace", "cursive", "fantasy", "system-ui", "inherit",
                 "initial", "unset", "emoji", "math", "ui-sans-serif", "ui-serif", "ui-monospace"}

MAX_VALUE = 200       # attribute values
MAX_SCRIPT = 300      # inline script bodies
MAX_JSON_LD = 1000    # structured data (organisation name, logo...) earns a bit more
MAX_COMMENT = 200
REDUNDANT = 0.9       # word overlap above which the raw HTML adds nothing to the DOM


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}…[+{len(text) - limit} chars]"


def _attr_value(value) -> str:
    value = " ".join(value) if isinstance(value, list) else str(value)
    if value.startswith("data:"):
        return value.split(",", 1)[0][:60] + ",…"
    return _cut(value, MAX_VALUE)


def clean_markup(markup: str) -> str:
    """HTML or a serialized DOM, reduced to its signal-bearing structure and text."""
    soup = BeautifulSoup(markup, "html.parser")

    for comment in soup.find_all(string=lambda s: isinstance(s, Comment)):
        text = " ".join(comment.split())
        if text.startswith("[if") or not text:   # IE conditional comments are layout, not signal
            comment.extract()
        else:
            comment.replace_with(Comment(_cut(text, MAX_COMMENT)))
    for tag in soup.find_all(DROP_TAGS):
        tag.decompose()
    for link in soup.find_all("link"):
        if DROP_LINK_RELS & set(link.get("rel") or []):
            link.decompose()
    for svg in soup.find_all("svg"):
        title = svg.find("title")
        label = svg.get("aria-label") or (title.get_text(strip=True) if title else "")
        stub = soup.new_tag("svg")
        if label:
            stub["aria-label"] = label
        svg.replace_with(stub)
    for script in soup.find_all("script"):
        body = " ".join((script.string or "").split())
        if body:
            json_ld = script.get("type") == "application/ld+json"
            script.string = _cut(body, MAX_JSON_LD if json_ld else MAX_SCRIPT)
    for br in soup.find_all(["br", "hr"]):
        br.replace_with(" ")

    for tag in soup.find_all(True):
        hidden = HIDDEN_STYLE.search(str(tag.get("style", "")))
        tag.attrs = {k: _attr_value(v) for k, v in tag.attrs.items() if k in KEEP_ATTRS}
        if hidden:
            tag["hidden"] = ""
    for tag in soup.find_all(BLOCK_WRAPPERS | INLINE_WRAPPERS):
        if not tag.attrs:
            if tag.name in BLOCK_WRAPPERS:   # keep words of adjacent blocks apart
                tag.insert_before(" ")
                tag.insert_after(" ")
            tag.unwrap()
    for tag in reversed(soup.find_all(True)):  # innermost first, so emptied parents go too
        if not tag.attrs and tag.name not in VOID_TAGS and not tag.find(True) and not tag.get_text(strip=True):
            tag.decompose()

    return " ".join(str(soup).split()).replace("> <", "><")


def distill_css(css: str) -> str:
    """What a stylesheet says beyond looks: what it imports, which files (logos, background
    images, fonts) it pulls in, and the font families it names."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    imports = re.findall(r"@import\s+(?:url\()?\s*['\"]?([^'\")\s;]+)", css, re.I)
    urls = [u.strip() for u in re.findall(r"url\(\s*['\"]?([^'\")]+?)['\"]?\s*\)", css, re.I)
            if not u.strip().startswith("data:")]
    fonts = [f.strip().strip("'\"") for decl in re.findall(r"font-family\s*:\s*([^;}]+)", css, re.I)
             for f in decl.split(",")]
    fonts = [f for f in fonts if f and f.lower() not in GENERIC_FONTS and not f.startswith("var(")]

    lines = ([f"@import {u}" for u in imports]
             + [f"url({u})" for u in urls if u not in imports]
             + ([f"font-family: {', '.join(dict.fromkeys(fonts))}"] if fonts else []))
    return "\n".join(dict.fromkeys(lines))


def _overlap(a: str, b: str) -> float:
    words_a, words_b = set(a.split()), set(b.split())
    return len(words_a & words_b) / max(1, len(words_a | words_b))


def for_ai(html: str | None = None, dom: str | None = None, css: str | None = None) -> dict:
    """Cleaned html/dom/css, ready for analysis.analyze(screenshot, **for_ai(...)).
    The raw HTML is left out when it says the same as the DOM (a page scripts don't change);
    when they differ - content built by scripts, cloaking, an obfuscated loader - both go."""
    html = clean_markup(html) if html else None
    dom = clean_markup(dom) if dom else None
    if html and dom and _overlap(html, dom) >= REDUNDANT:
        html = None
    return {"html": html or None, "dom": dom or None, "css": (distill_css(css) if css else None) or None}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(__doc__)
        return 2
    path = Path(argv[0])
    text = path.read_text(encoding="utf-8", errors="replace")
    cleaned = distill_css(text) if path.suffix == ".css" else clean_markup(text)
    print(cleaned)
    print(f"\n[{len(text):,} -> {len(cleaned):,} chars, {100 - 100 * len(cleaned) // max(1, len(text))}% smaller]",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
