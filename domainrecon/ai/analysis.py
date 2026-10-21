#!/usr/bin/env python3
"""
AI page analysis: show an AI model a page screenshot - plus, optionally, the page's
HTML source, rendered DOM and CSS - and save what it says the page is.

The model is whichever service the key in AI_API_KEY (.env) belongs to; the service
is recognised from the key's prefix (see PROVIDERS). Optional settings:
  AI_MODEL     another model of that service (default: its recommended vision model)
  AI_PROVIDER  the service, for keys with no telling prefix (e.g. "mistral")
  AI_BASE_URL  any OpenAI-compatible endpoint, e.g. a local Ollama at
               http://localhost:11434/v1 (AI_MODEL is then required)
  AI_TIMEOUT   seconds per request (default 300)

Every service speaks one of two APIs - Anthropic's Messages API or the OpenAI-style
chat/completions one - so this is plain HTTP, no vendor SDK.

The saved record (see analyze) is what ai/report.py turns into a report.

Usage:  ./recon analyze SCREENSHOT [--html F] [--dom F] [--css F] [--out F]
                         [--subject DOMAIN] [--monitor DOMAIN [--reference F] [--facts F]]
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.ai.analysis", run_name="__main__", alter_sys=True)
    sys.exit()

import argparse
import base64
import io
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests
from PIL import Image

from .. import config  # noqa: F401  (loads .env before the AI_* settings are read)

PROMPT = """\
You are an OSINT analyst reviewing a web page. You get a screenshot of it and, when \
available, its HTML source, rendered DOM and CSS. Describe what the page is and what it \
shows, precisely, without claiming anything the evidence doesn't support.

Reply with only a JSON object (no markdown, no text around it) with exactly these keys:
{
  "language": "language of the page content, e.g. Spanish (es)",
  "page_type": "kind of page in a few words, e.g. corporate site, online shop, news portal, phishing page, parked domain",
  "purpose": "one or two sentences on what the page is and what it offers",
  "purpose_es": "the same as purpose, written in Spanish",
  "signals": ["notable signals: credential forms, impersonated brands, content unrelated to the domain, parking, detected technologies... Empty list if none."],
  "confidence": "high | medium | low",
  "notes": "anything else worth knowing, or an empty string"
}"""

# Appended to the prompt when the page is compared with the domain being monitored.
COMPARISON_PROMPT = """

The page may be imitating {monitored}, the legitimate domain being monitored for \
impersonation. Compare the two and add these keys to the JSON object:
  "comparison": one or two sentences on whether and how the page imitates {monitored}, \
weighing the domain names, logo and branding, layout and colours, content, and what the \
page asks visitors to do
  "comparison_es": the same as comparison, written in Spanish
  "same_owner": "likely | possible | unlikely" - whether both domains seem to belong to the \
same organisation, judged from the registration and network facts given (same registrar - \
especially brand-protection registrars such as MarkMonitor or CSC -, shared nameservers, \
hosting networks or mail servers, a redirect to {monitored}); "possible" when there is too \
little to tell
  "ownership": one sentence on the evidence for that judgement
  "impersonation": "likely | possible | unlikely" - whether the page passes itself off as \
{monitored} or its brand in a way that could mislead visitors
  "case_type": "phishing | malware | brand_impersonation | parked | unrelated" - phishing: asks \
for credentials, payment or personal data while posing as {monitored}; malware: pushes \
downloads or exploits; brand_impersonation: uses the name, brand or look of {monitored} to \
mislead without collecting data; parked: parked, for sale or without real content; unrelated: \
no link to {monitored}
When the same owner is likely, say in "comparison" that a defensive registration by the \
brand itself explains any resemblance better than impersonation."""

MAX_ATTACHMENT_CHARS = 20_000  # per HTML / DOM / CSS attachment
# Taller full-page captures are cut to their top part: providers reject very long images
# (Anthropic: over 8000 px) and shrink the rest until the text is unreadable anyway.
MAX_ASPECT = 2.5
MAX_SIDE = 8000
TIMEOUT = int(os.environ.get("AI_TIMEOUT") or 300)


@dataclass(frozen=True)
class Provider:
    name: str
    key_prefix: str | None
    api: str                    # "anthropic", or "openai" for chat/completions
    base_url: str
    default_model: str | None   # None: catalogue too broad to guess, AI_MODEL required


# First matching prefix wins, so the specific sk-ant- / sk-or- come before OpenAI's sk-.
PROVIDERS = (
    Provider("anthropic", "sk-ant-", "anthropic", "https://api.anthropic.com/v1", "claude-opus-5-5"),
    Provider("openrouter", "sk-or-", "openai", "https://openrouter.ai/api/v1", None),
    Provider("xai", "xai-", "openai", "https://api.x.ai/v1", None),
    Provider("groq", "gsk_", "openai", "https://api.groq.com/openai/v1", None),
    Provider("google", "AIza", "openai", "https://generativelanguage.googleapis.com/v1beta/openai",
             "gemini-3.8-flash"),
    Provider("openai", "sk-", "openai", "https://api.openai.com/v1", "gpt-6.1-sol"),
    Provider("mistral", None, "openai", "https://api.mistral.ai/v1", None),
)

# Claude models with server-side refusal fallback: a page that trips a safety classifier
# (phishing kits can) is retried on a fallback model within the same call.
REFUSAL_FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


class AIError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    key: str
    provider: str
    api: str
    base_url: str
    model: str

    @classmethod
    def from_env(cls) -> "Settings":
        def env(name):
            return (os.environ.get(name) or "").strip()

        key, model, base_url = env("AI_API_KEY"), env("AI_MODEL"), env("AI_BASE_URL").rstrip("/")
        if not key:
            raise AIError("AI_API_KEY is not set")
        if wanted := env("AI_PROVIDER").lower():
            p = next((p for p in PROVIDERS if p.name == wanted), None)
            if p is None:
                raise AIError(f"unknown AI_PROVIDER {wanted!r} (known: {', '.join(p.name for p in PROVIDERS)})")
        else:
            p = next((p for p in PROVIDERS if p.key_prefix and key.startswith(p.key_prefix)), None)
        if p is None and not base_url:
            raise AIError("can't tell the service from this key: set AI_PROVIDER or AI_BASE_URL")

        provider = p.name if p else "openai-compatible"
        model = model or (p.default_model if p else None)
        if not model:
            raise AIError(f"set AI_MODEL to a vision model of {provider}")
        return cls(key, provider, p.api if p else "openai", base_url or p.base_url, model)


def configured() -> bool:
    return bool((os.environ.get("AI_API_KEY") or "").strip())


# --------------------------------------------------------------------------
# request building
# --------------------------------------------------------------------------

def _image(path: Path) -> tuple[tuple[str, str], str]:
    """((media type, base64), crop note) for a PNG, JPEG, WEBP or GIF screenshot.
    The note is empty unless the image had to be cut to its top part."""
    data = path.read_bytes()
    with Image.open(io.BytesIO(data)) as im:
        w, h = im.size
        keep_w, keep_h = min(w, MAX_SIDE), min(h, MAX_SIDE, int(w * MAX_ASPECT))
        if (keep_w, keep_h) == (w, h):
            return (Image.MIME[im.format], base64.standard_b64encode(data).decode("ascii")), ""
        buf = io.BytesIO()
        im.crop((0, 0, keep_w, keep_h)).save(buf, "PNG")
    return ("image/png", base64.standard_b64encode(buf.getvalue()).decode("ascii")), \
        f"top {keep_w}x{keep_h} of {w}x{h}"


def _attachments(html: str | None, dom: str | None, css: str | None) -> tuple[str, list[str]]:
    """The text sent next to the screenshot, and the names of what it contains."""
    sections, names = [], []
    for name, label, fence, content in (("html", "HTML source", "html", html),
                                        ("dom", "Rendered DOM", "html", dom),
                                        ("css", "CSS", "css", css)):
        if not content:
            continue
        cut = len(content) > MAX_ATTACHMENT_CHARS
        sections.append(f"{label}{f' (first {MAX_ATTACHMENT_CHARS} characters)' if cut else ''}:\n"
                        f"```{fence}\n{content[:MAX_ATTACHMENT_CHARS]}\n```")
        names.append(name)
    return "\n\n".join(sections) or "Analyze the attached screenshot.", names


# --------------------------------------------------------------------------
# the two APIs
# --------------------------------------------------------------------------

def _post(s: Settings, path: str, headers: dict, body: dict) -> dict:
    try:
        r = requests.post(s.base_url + path, headers=headers, json=body, timeout=TIMEOUT)
    except requests.exceptions.Timeout:
        raise AIError(f"{s.provider} did not answer within {TIMEOUT}s") from None
    except requests.exceptions.RequestException as e:
        raise AIError(f"could not reach {s.provider}: {type(e).__name__}") from None
    if r.status_code != 200:
        try:
            msg = r.json()["error"]["message"]
        except Exception:
            msg = r.text[:300]
        raise AIError(f"{s.provider} HTTP {r.status_code}: {msg}")
    return r.json()


def _ask_anthropic(s: Settings, prompt: str, images: list[tuple[str, str]], text: str) -> str:
    content = [{"type": "image", "source": {"type": "base64", "media_type": media, "data": b64}}
               for media, b64 in images]
    headers = {"x-api-key": s.key, "anthropic-version": "2023-06-01"}
    body = {"model": s.model, "max_tokens": 16000, "system": prompt,
            "messages": [{"role": "user", "content": [*content, {"type": "text", "text": text}]}]}
    if s.model in REFUSAL_FALLBACK_MODELS:
        headers["anthropic-beta"] = "server-side-fallback-2026-07-01"
        body["fallbacks"] = "default"

    reply = _post(s, "/messages", headers, body)
    if reply.get("stop_reason") == "refusal":
        category = (reply.get("stop_details") or {}).get("category")
        raise AIError(f"the model declined to analyze the page ({category})")
    if reply.get("stop_reason") == "max_tokens":
        raise AIError("the reply was cut off (max_tokens)")
    return "".join(b.get("text", "") for b in reply.get("content") or [] if b.get("type") == "text")


def _ask_openai(s: Settings, prompt: str, images: list[tuple[str, str]], text: str) -> str:
    content = [{"type": "image_url", "image_url": {"url": f"data:{media};base64,{b64}"}}
               for media, b64 in images]
    body = {"model": s.model,
            "messages": [{"role": "system", "content": prompt},
                         {"role": "user", "content": [{"type": "text", "text": text}, *content]}]}

    reply = _post(s, "/chat/completions", {"Authorization": f"Bearer {s.key}"}, body)
    choice = (reply.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    if message.get("refusal"):
        raise AIError(f"the model declined to analyze the page: {message['refusal'][:200]}")
    if choice.get("finish_reason") == "length":
        raise AIError("the reply was cut off (token limit)")
    content = message.get("content") or ""
    if isinstance(content, list):  # some servers return content parts instead of a string
        content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
    return content


ASK = {"anthropic": _ask_anthropic, "openai": _ask_openai}


def _parse(reply: str) -> dict:
    """The JSON object in the reply, tolerating code fences or a sentence around it."""
    match = re.search(r"\{.*\}", reply, re.S)
    try:
        result = json.loads(match.group(0)) if match else None
    except json.JSONDecodeError:
        result = None
    if not isinstance(result, dict):
        raise AIError("the reply was not a JSON object")
    return result


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def _comparison_intro(subject: str, monitored: str, has_reference: bool) -> str:
    second = (f"The second image is the current home page of {monitored}, for comparison."
              if has_reference else
              f"No screenshot of {monitored} is available: compare from what you know about it "
              f"and from the domain names.")
    return (f"Domain under review: {subject}\nMonitored domain: {monitored}\n"
            f"The first image is the page under review. {second}")


def analyze(screenshot: str | Path, *, html: str | None = None, dom: str | None = None,
            css: str | None = None, prompt: str = PROMPT, out: str | Path | None = None,
            subject: str | None = None, monitored: str | None = None,
            reference: str | Path | None = None, facts: dict | None = None) -> dict:
    """Analyze one page. subject names it in the record (default: the screenshot's file name).

    With monitored - the legitimate domain the page may be imitating - the model also
    describes how the page compares with it (result key "comparison") and judges whether
    both domains have the same owner ("same_owner", "ownership");
    reference is a screenshot of the monitored site to compare against, and facts the known
    registration and network facts keyed by domain (registrar, nameservers, networks...),
    which tell a brand's own defensive registrations from impersonation. Without monitored
    the page is only described.

    Returns - and, given out, saves as JSON - the record:

        {"subject", "monitored", "analyzed_at", "provider", "model", "inputs",
         "result": {"language", "page_type", ...} or None,
         "error": None or what went wrong,
         "raw": the model's reply as received}

    AI problems never raise: they land in "error", so a batch keeps going."""
    screenshot = Path(screenshot)
    subject = subject or screenshot.stem
    text, attached = _attachments(html, dom, css)
    record = {"subject": subject, "monitored": monitored,
              "analyzed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "provider": None, "model": None, "inputs": ["screenshot", *attached],
              "result": None, "error": None, "raw": None}
    try:
        s = Settings.from_env()
        record.update(provider=s.provider, model=s.model)
        image, crop = _image(screenshot)
        images, notes = [image], []
        if crop:
            record["inputs"][0] = f"screenshot ({crop})"
            notes.append(f"The page screenshot is the {crop} pixels of a taller full-page capture.")
        if monitored:
            prompt += COMPARISON_PROMPT.format(monitored=monitored)
            if reference:
                ref_image, ref_crop = _image(Path(reference))
                images.append(ref_image)
                record["inputs"].append(f"reference screenshot of {monitored}" + (f" ({ref_crop})" if ref_crop else ""))
            notes.insert(0, _comparison_intro(subject, monitored, bool(reference)))
            if facts:
                notes.insert(1, "Registration and network facts:\n```json\n"
                                f"{json.dumps(facts, indent=2, ensure_ascii=False)}\n```")
                record["inputs"].append("registration and network facts")
        text = "\n\n".join([*notes, text])
        record["raw"] = ASK[s.api](s, prompt, images, text)
        record["result"] = _parse(record["raw"])
    except AIError as e:
        record["error"] = str(e)

    if out:
        Path(out).write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return record


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="recon analyze",
                                 description="Ask the AI service behind AI_API_KEY what a page screenshot shows.")
    ap.add_argument("screenshot", type=Path, help="PNG, JPEG, WEBP or GIF")
    ap.add_argument("--html", type=Path, help="file with the page's HTML source")
    ap.add_argument("--dom", type=Path, help="file with the page's rendered DOM")
    ap.add_argument("--css", type=Path, help="file with the page's CSS")
    ap.add_argument("--out", type=Path, help="where to save the record (default: SCREENSHOT.analysis.json)")
    ap.add_argument("--subject", help="the domain the screenshot belongs to (default: its file name)")
    ap.add_argument("--monitor", metavar="DOMAIN",
                    help="also compare the page with this monitored domain and judge whether they share an owner")
    ap.add_argument("--reference", type=Path, help="screenshot of the monitored domain to compare against")
    ap.add_argument("--facts", type=Path,
                    help="JSON file of registration/network facts keyed by domain, for the same-owner judgement")
    args = ap.parse_args(argv)
    for p in (args.screenshot, args.html, args.dom, args.css, args.reference, args.facts):
        if p and not p.exists():
            print(f"not found: {p}", file=sys.stderr)
            return 2

    def read(p):
        return p.read_text(encoding="utf-8", errors="replace") if p else None

    out = args.out or args.screenshot.with_suffix(".analysis.json")
    record = analyze(args.screenshot, html=read(args.html), dom=read(args.dom), css=read(args.css), out=out,
                     subject=args.subject, monitored=args.monitor, reference=args.reference,
                     facts=json.loads(read(args.facts)) if args.facts else None)
    print(json.dumps(record["result"] or {"error": record["error"]}, indent=2, ensure_ascii=False))
    by = f" ({record['provider']}/{record['model']})" if record["provider"] else ""
    print(f"saved to {out}{by}", file=sys.stderr)
    return 1 if record["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
