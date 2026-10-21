#!/usr/bin/env python3
"""
Visit a page once in a headless browser and save what it is made of:

    screenshot.png   full-page screenshot
    page.html        the main document exactly as the server sent it
    dom.html         the DOM after scripts ran - what a visitor actually gets
    styles.css       the stylesheets the page loaded, then its inline <style> blocks
    capture.json     how the visit went: final URL, status, redirects, server, errors

The CSS comes from the responses the browser downloaded anyway, so capturing it adds
no request to the site. Knows nothing about domains, runs or AI: give it a URL (or a
bare host, tried over https then http) and a directory.

Needs Playwright's browser once:  .venv/bin/playwright install chromium

Usage:  ./recon capture URL_OR_HOST OUT_DIR
"""

if __name__ == "__main__" and not __package__:  # run as a file: rerun it as part of the package
    import runpy
    import sys
    from pathlib import Path
    sys.path[0] = str(Path(__file__).resolve().parents[2])  # the project folder, not this one
    runpy.run_module("domainrecon.collect.capture", run_name="__main__", alter_sys=True)
    sys.exit()

import json
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import TimeoutError as PlaywrightTimeout
from playwright.sync_api import sync_playwright

# A plain desktop Chrome: kits that cloak against "HeadlessChrome" see an ordinary visitor.
DEFAULT_USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/156.0.0.0 Safari/537.36")
VIEWPORT = {"width": 1280, "height": 800}
FILES = {"screenshot": "screenshot.png", "html": "page.html", "dom": "dom.html", "css": "styles.css"}


@dataclass
class Capture:
    requested: str
    url: str | None = None                                # final URL, after redirects
    status: int | None = None
    title: str | None = None
    server: str | None = None
    redirects: list[str] = field(default_factory=list)    # URLs passed through before url
    stylesheets: list[str] = field(default_factory=list)  # stylesheet files the page loaded
    files: dict[str, str] = field(default_factory=dict)   # kind -> file name in out_dir, only what was saved
    captured_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    error: str | None = None


def capture(target: str, out_dir: str | Path, *, user_agent: str = DEFAULT_USER_AGENT,
            timeout: int = 30, settle: int = 5, full_page: bool = True) -> Capture:
    """Render target and save its files into out_dir. Never raises for the page's sake:
    whatever failed is in .error, and .files lists what was saved before that."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    urls = [target] if "://" in target else [f"https://{target}", f"http://{target}"]
    cap = Capture(requested=target)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                for url in urls:
                    cap = _visit(browser, url, out_dir, user_agent, timeout, settle, full_page)
                    if cap.status is not None:  # the site answered; http only when https didn't load at all
                        break
            finally:
                browser.close()
    except PlaywrightError as e:
        cap.error = f"browser: {_first_line(e)}"
    cap.requested = target
    (out_dir / "capture.json").write_text(json.dumps(asdict(cap), indent=2), encoding="utf-8")
    return cap


def _visit(browser, url: str, out_dir: Path, user_agent: str, timeout: int, settle: int,
           full_page: bool) -> Capture:
    cap = Capture(requested=url)
    context = browser.new_context(viewport=VIEWPORT, user_agent=user_agent, ignore_https_errors=True)
    page = context.new_page()
    sheets = []
    page.on("response", lambda r: sheets.append(r) if r.request.resource_type == "stylesheet" else None)
    try:
        response = page.goto(url, wait_until="load", timeout=timeout * 1000)
        if response is None:
            cap.error = "navigation produced no response"
            return cap
        try:
            page.wait_for_load_state("networkidle", timeout=settle * 1000)
        except PlaywrightTimeout:
            pass  # pages that keep polling never go idle; what has rendered by now is what we keep

        cap.url, cap.status = response.url, response.status
        cap.server = response.headers.get("server")
        cap.redirects = _redirect_chain(response)
        cap.title = page.title() or None

        page.screenshot(path=out_dir / FILES["screenshot"], full_page=full_page)
        cap.files["screenshot"] = FILES["screenshot"]
        _save(cap, out_dir, "dom", page.content())
        _save(cap, out_dir, "html", response.text())
        _save(cap, out_dir, "css", _stylesheets(page, sheets, cap))
    except PlaywrightError as e:
        cap.error = _first_line(e)
    finally:
        context.close()
    return cap


def _redirect_chain(response) -> list[str]:
    chain, request = [], response.request.redirected_from
    while request:
        chain.append(request.url)
        request = request.redirected_from
    return chain[::-1]


def _stylesheets(page, responses: list, cap: Capture) -> str:
    """Loaded stylesheet files first (each under a /* URL */ line), then inline <style> blocks."""
    parts = []
    for r in responses:
        try:
            parts.append(f"/* {r.url} */\n{r.text()}")
            cap.stylesheets.append(r.url)
        except PlaywrightError:
            parts.append(f"/* {r.url} - body not available */")
    inline = page.eval_on_selector_all("style", "els => els.map(e => e.textContent)")
    parts += [f"/* inline <style> {i} */\n{css}" for i, css in enumerate(inline, 1) if css.strip()]
    return "\n\n".join(parts)


def _save(cap: Capture, out_dir: Path, kind: str, text: str) -> None:
    if text.strip():
        path = out_dir / FILES[kind]
        path.write_text(text, encoding="utf-8")
        cap.files[kind] = FILES[kind]


def _first_line(e: Exception) -> str:
    return (getattr(e, "message", None) or str(e)).strip().splitlines()[0]


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(__doc__)
        return 2
    cap = capture(argv[0], argv[1])
    print(json.dumps(asdict(cap), indent=2))
    return 1 if cap.error else 0


if __name__ == "__main__":
    sys.exit(main())
