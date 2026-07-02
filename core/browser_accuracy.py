"""Browser-Backed Accuracy Mode (Roadmap E4).

Static HTML parsing misses the assets a single-page app only materializes after
its JavaScript runs — links, form targets and subresource hosts that live in the
*rendered* DOM. This module renders the page in a headless browser (Playwright)
purely to **parse those assets more accurately**, and measures the gap against
what static parsing found. It is an accuracy aid, never an evasion/bypass tool:
no header spoofing, no anti-detection, no unauthorized traffic — just a faithful
render of an in-scope page.

Design
------
- The DOM-asset extraction and the accuracy delta are **pure** functions over an
  HTML string, so the whole analysis is unit-tested offline with no browser.
- The browser render is an **injectable, feature-gated seam**: a test passes a
  ``render_fn``; in production it uses Playwright *only when installed*
  (``features.has_playwright``) and soft-degrades to a skip otherwise — the
  optional-dependency contract the rest of the app follows.
- Complements :mod:`core.dynamic_analyzer` (which intercepts network traffic);
  this reads the rendered DOM's asset graph, which that module does not.
"""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlsplit


# Tag/attribute pairs that carry a URL we care about for asset discovery.
_URL_ATTRS = {
    "a": "href",
    "form": "action",
    "script": "src",
    "link": "href",
    "img": "src",
    "iframe": "src",
    "source": "src",
}
_RESOURCE_TAGS = {"script", "link", "img", "iframe", "source"}


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.raw: List[tuple] = []   # (tag, url)

    def handle_starttag(self, tag: str, attrs) -> None:
        want = _URL_ATTRS.get(tag)
        if not want:
            return
        for name, value in attrs:
            if name == want and value:
                self.raw.append((tag, value.strip()))


def _apex(host: str) -> str:
    """A coarse registrable apex (last two labels) for internal/external split."""
    parts = [p for p in str(host or "").lower().split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else str(host or "").lower()


def _sorted(values) -> List[str]:
    return sorted({v for v in values if v})


def extract_dom_assets(html: str, base_url: str = "") -> Dict[str, Any]:
    """Extract the asset graph from an HTML document (pure).

    Returns ``{links, internal_links, external_hosts, forms, resource_hosts}``:
    absolute http(s) links (deduped/sorted), the split of internal vs external by
    the base URL's apex, form action URLs, and the hosts of subresources
    (script/img/link/iframe). URLs are resolved against ``base_url``.
    """
    if not isinstance(html, str) or not html:
        return {"links": [], "internal_links": [], "external_hosts": [],
                "forms": [], "resource_hosts": []}
    parser = _AssetParser()
    try:
        parser.feed(html)
    except Exception:
        pass  # a malformed fragment yields whatever parsed cleanly

    base_host = urlsplit(base_url).netloc.lower()
    base_apex = _apex(base_host)

    links: set[str] = set()
    forms: set[str] = set()
    resource_hosts: set[str] = set()
    internal: set[str] = set()
    external_hosts: set[str] = set()

    for tag, value in parser.raw:
        absolute = urljoin(base_url, value) if base_url else value
        scheme = urlsplit(absolute).scheme.lower()
        host = urlsplit(absolute).netloc.lower()
        if tag == "form":
            if scheme in ("http", "https", ""):
                forms.add(absolute)
            continue
        if scheme not in ("http", "https"):
            continue
        if tag == "a":
            links.add(absolute)
            if host and base_apex and _apex(host) == base_apex:
                internal.add(absolute)
            elif host:
                external_hosts.add(host)
        elif tag in _RESOURCE_TAGS and host:
            resource_hosts.add(host)

    return {
        "links": _sorted(links),
        "internal_links": _sorted(internal),
        "external_hosts": _sorted(external_hosts),
        "forms": _sorted(forms),
        "resource_hosts": _sorted(resource_hosts),
    }


_DELTA_KEYS = ("links", "internal_links", "external_hosts", "forms", "resource_hosts")


def accuracy_delta(static_assets: Dict[str, Any],
                   rendered_assets: Dict[str, Any]) -> Dict[str, Any]:
    """What the rendered DOM found beyond static parsing (pure).

    Returns per-category ``added`` lists plus a ``summary`` with static/rendered
    totals, the total added count and a rounded gain percentage — a concrete
    accuracy measure (how much a static-only scan would have missed).
    """
    static_assets = static_assets if isinstance(static_assets, dict) else {}
    rendered_assets = rendered_assets if isinstance(rendered_assets, dict) else {}
    added: Dict[str, List[str]] = {}
    static_total = 0
    rendered_total = 0
    added_total = 0
    for key in _DELTA_KEYS:
        s = set(static_assets.get(key) or [])
        r = set(rendered_assets.get(key) or [])
        extra = _sorted(r - s)
        added[key] = extra
        static_total += len(s)
        rendered_total += len(r)
        added_total += len(extra)
    gain_pct = round(100.0 * added_total / static_total, 1) if static_total else (
        100.0 if added_total else 0.0)
    return {
        "added": added,
        "summary": {
            "static_total": static_total,
            "rendered_total": rendered_total,
            "added_total": added_total,
            "gain_pct": gain_pct,
        },
    }


def build_browser_accuracy(*, static_html: str, rendered_html: str,
                           base_url: str = "") -> Dict[str, Any]:
    """Full accuracy view: static vs rendered assets + the delta between them."""
    static_assets = extract_dom_assets(static_html, base_url)
    rendered_assets = extract_dom_assets(rendered_html, base_url)
    delta = accuracy_delta(static_assets, rendered_assets)
    return {
        "base_url": base_url,
        "static": static_assets,
        "rendered": rendered_assets,
        "delta": delta,
    }


# --- browser render seam (feature-gated, injectable) -------------------------

def render_available() -> bool:
    """Whether a headless browser render is available (Playwright installed)."""
    try:
        from core import features
        return features.has_playwright()
    except Exception:
        return False


def capture_rendered_html(url: str, *,
                          render_fn: Optional[Callable[[str], str]] = None,
                          timeout_ms: int = 20000) -> Dict[str, Any]:
    """Render ``url`` and return ``{status, html[, reason/error]}``.

    ``render_fn`` (injected by tests) wins; otherwise a Playwright render runs
    only when available, else the result is ``status='unavailable'`` (soft
    degrade). Never raises — a render failure returns ``status='error'``.
    """
    if render_fn is not None:
        try:
            return {"status": "rendered", "html": render_fn(url) or ""}
        except Exception as exc:  # noqa: BLE001 — render is best-effort
            return {"status": "error", "error": str(exc), "html": ""}
    if not render_available():
        return {"status": "unavailable",
                "reason": "playwright not installed", "html": ""}
    try:
        return {"status": "rendered", "html": _playwright_render(url, timeout_ms) or ""}
    except Exception as exc:  # noqa: BLE001 — render is best-effort
        return {"status": "error", "error": str(exc), "html": ""}


def _playwright_render(url: str, timeout_ms: int = 20000) -> str:
    """Return the final rendered HTML of ``url`` via Playwright (sync wrapper).

    Only reached when Playwright is installed. Kept minimal (goto + content); the
    network-interception work lives in :mod:`core.dynamic_analyzer`.
    """
    import asyncio

    async def _run() -> str:
        from playwright.async_api import async_playwright
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                try:
                    await page.goto(url, timeout=timeout_ms, wait_until="networkidle")
                except Exception:
                    await page.goto(url, timeout=timeout_ms,
                                    wait_until="domcontentloaded")
                return await page.content()
            finally:
                await browser.close()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_run())
    finally:
        loop.close()
