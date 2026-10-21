"""A page's text - title, meta description, og tags, visible text - and an offline language guess."""

import re
import threading

from bs4 import BeautifulSoup

from ..util import field

_lingua = None
_lingua_lock = threading.Lock()


def extract_text(html: str) -> dict:
    out = {"title": None, "description": None, "og": {}, "html_lang": None, "text": ""}
    if not html.strip():
        return out
    soup = BeautifulSoup(html, "html.parser")
    if soup.title and soup.title.string:
        out["title"] = soup.title.string.strip()
    if soup.html and soup.html.get("lang"):
        out["html_lang"] = soup.html.get("lang")
    for tag in soup.find_all("meta"):
        name = (tag.get("name") or tag.get("property") or "").lower()
        content = (tag.get("content") or "").strip()
        if not content:
            continue
        if name == "description":
            out["description"] = content
        elif name.startswith("og:"):
            out["og"][name] = content
    for bad in soup(["script", "style", "noscript", "svg", "template"]):
        bad.decompose()
    text = re.sub(r"[ \t ]+", " ", soup.get_text("\n"))
    out["text"] = "\n".join(ln.strip() for ln in text.splitlines() if ln.strip())[:20000]
    return out


def detect_language(text: str) -> dict:
    sample = " ".join(text.split())[:3000]
    if len(sample) < 25:
        return field(None, "lingua", "not enough text to detect")
    global _lingua
    with _lingua_lock:
        if _lingua is None:
            from lingua import LanguageDetectorBuilder
            _lingua = LanguageDetectorBuilder.from_all_languages().build()
    try:
        lang = _lingua.detect_language_of(sample)
    except Exception as e:
        return field(None, "lingua", f"{type(e).__name__}: {e}")
    if lang is None:
        return field(None, "lingua", "no confident match")
    return field({"name": lang.name.title(), "iso": lang.iso_code_639_1.name.lower()}, "lingua")
