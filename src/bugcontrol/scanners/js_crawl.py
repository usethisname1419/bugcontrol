from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
MODULEPRELOAD_RE = re.compile(
    r"""<link[^>]+rel\s*=\s*["'](?:modulepreload|preload)["'][^>]+href\s*=\s*["']([^"']+)["']"""
    r"""|<link[^>]+href\s*=\s*["']([^"']+)["'][^>]+rel\s*=\s*["'](?:modulepreload|preload)["']""",
    re.IGNORECASE,
)
INLINE_SCRIPT_RE = re.compile(
    r"""<script(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>""",
    re.IGNORECASE | re.DOTALL,
)
HREF_RE = re.compile(
    r"""(?:href|src|data-src|data-main)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
JS_REF_RE = re.compile(
    r"""(?P<u>(?:https?:)?//[^"'\\\s>]+\.js(?:\?[^"'\\\s>]*)?"""
    r"""|/[A-Za-z0-9_./\-]+\.js(?:\?[A-Za-z0-9_=&%.\-]*)?)""",
    re.IGNORECASE,
)
SOURCEMAP_RE = re.compile(
    r"""[#@]\s*sourceMappingURL\s*=\s*(\S+)""",
    re.IGNORECASE,
)
CHUNK_REF_RE = re.compile(
    r"""["']([^"']*?chunk[^"']*?\.js(?:\?[^"']*)?)["']""",
    re.IGNORECASE,
)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    (
        "aws_secret_key",
        re.compile(
            r"(?i)(?:aws)?[_-]?(?:secret|secret_access_key|secretkey)\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("google_oauth", re.compile(r"\b(ya29\.[0-9A-Za-z\-_]{20,})\b")),
    ("github_pat", re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("gitlab_pat", re.compile(r"\b(glpat-[A-Za-z0-9\-_]{20,})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    (
        "slack_webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    ("stripe_key", re.compile(r"\b((?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b")),
    ("twilio_sid", re.compile(r"\b(AC[0-9a-fA-F]{32})\b")),
    ("sendgrid_key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    ("mailgun_key", re.compile(r"\b(key-[0-9a-f]{32})\b")),
    (
        "discord_webhook",
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "jwt",
        re.compile(
            r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"
        ),
    ),
    ("openai_key", re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b")),
    ("npm_token", re.compile(r"\b(npm_[A-Za-z0-9]{36,})\b")),
    (
        "heroku_api_key",
        re.compile(
            r"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]?"
            r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"
        ),
    ),
    (
        "firebase",
        re.compile(r"\b([A-Za-z0-9_-]{20,}:[A-Za-z0-9_-]{140,})\b"),
    ),
    (
        "generic_api_key",
        re.compile(
            r"(?i)(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|"
            r"client[_-]?secret|app[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]"
            r"([A-Za-z0-9_\-]{16,})['\"]"
        ),
    ),
    (
        "basic_auth_url",
        re.compile(r"https?://[^/\s:'\"]+:[^/\s:'\"]+@[^/\s'\"]+"),
    ),
    (
        "azure_storage",
        re.compile(
            r"(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}"
        ),
    ),
]


@dataclass(slots=True)
class SecretHit:
    kind: str
    source: str
    match: str
    context: str


@dataclass
class SecretsScanResult:
    seed_urls: list[str] = field(default_factory=list)
    pages_fetched: int = 0
    js_scanned: int = 0
    js_discovered: int = 0
    bytes_scanned: int = 0
    hits: list[SecretHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    truncated_sources: list[str] = field(default_factory=list)

    def summary(self, max_hits: int = 40) -> str:
        lines = [
            f"seeds={len(self.seed_urls)} pages={self.pages_fetched} "
            f"js_discovered={self.js_discovered} js_scanned={self.js_scanned} "
            f"bytes={self.bytes_scanned} hits={len(self.hits)}",
        ]
        if self.truncated_sources:
            lines.append(f"truncated_reads={len(self.truncated_sources)}")
        if self.hits:
            lines.append("Findings:")
            for hit in self.hits[:max_hits]:
                lines.append(
                    f"  [{hit.kind}] {hit.source}\n"
                    f"    match={hit.match}\n"
                    f"    ctx={hit.context}"
                )
            if len(self.hits) > max_hits:
                lines.append(f"  ... +{len(self.hits) - max_hits} more")
        else:
            lines.append("Findings: (none)")
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"  {e}" for e in self.errors[:20])
        return "\n".join(lines)


def normalize_seed(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return urldefrag(url)[0]


def _same_site(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    if not pa.hostname or not pb.hostname:
        return False
    ha = pa.hostname.lower().removeprefix("www.")
    hb = pb.hostname.lower().removeprefix("www.")
    return ha == hb or ha.endswith("." + hb) or hb.endswith("." + ha)


def _abs_url(base: str, ref: str) -> str:
    ref = ref.strip().strip("\\").rstrip("\\")
    if ref.startswith("//"):
        scheme = urlparse(base).scheme or "https"
        ref = f"{scheme}:{ref}"
    return urldefrag(urljoin(base, ref))[0]


def _looks_like_js_url(url: str) -> bool:
    lower = url.lower()
    path = urlparse(url).path.lower()
    return (
        path.endswith((".js", ".mjs", ".map"))
        or ".js?" in lower
        or ".mjs?" in lower
        or ".map?" in lower
    )


def scan_text_for_secrets(
    text: str,
    source: str,
    *,
    max_hits: int,
    existing: list[SecretHit],
    seen_keys: set[tuple[str, str, str]],
) -> None:
    if len(existing) >= max_hits:
        return
    for kind, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            if len(existing) >= max_hits:
                return
            raw = m.group(1) if m.lastindex else m.group(0)
            key = (kind, source, raw[:120])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            ctx = text[start:end].replace("\n", " ").replace("\r", " ")
            existing.append(
                SecretHit(kind=kind, source=source, match=raw[:200], context=ctx[:180])
            )


def extract_js_refs(text: str, base_url: str) -> list[str]:
    found: list[str] = []
    for m in JS_REF_RE.finditer(text):
        found.append(_abs_url(base_url, m.group("u")))
    for m in CHUNK_REF_RE.finditer(text):
        found.append(_abs_url(base_url, m.group(1)))
    for m in SOURCEMAP_RE.finditer(text):
        sm = m.group(1).strip().rstrip("*/").strip()
        if sm and not sm.startswith("data:"):
            found.append(_abs_url(base_url, sm))
    return found


async def scan_stream_for_secrets(
    response: httpx.Response,
    source: str,
    *,
    chunk_size: int,
    overlap: int,
    max_bytes: int,
    max_hits: int,
    hits: list[SecretHit],
    seen_keys: set[tuple[str, str, str]],
    collect_refs: bool,
) -> tuple[int, list[str], bool]:
    """Stream body in chunks with overlap. Never retains the full body."""
    carry = ""
    refs: list[str] = []
    total = 0
    truncated = False
    max_carry = max(overlap, 4096)

    async for raw in response.aiter_bytes(chunk_size=chunk_size):
        if not raw:
            continue
        remain = max_bytes - total
        if remain <= 0:
            truncated = True
            break
        if len(raw) > remain:
            raw = raw[:remain]
            truncated = True
        total += len(raw)
        piece = raw.decode("utf-8", errors="replace")
        window = carry + piece
        scan_text_for_secrets(
            window, source, max_hits=max_hits, existing=hits, seen_keys=seen_keys
        )
        if collect_refs:
            refs.extend(extract_js_refs(window, source))
        carry = window[-max_carry:] if len(window) > max_carry else window
        if truncated:
            break

    return total, refs, truncated


async def _read_limited_text(
    client: httpx.AsyncClient,
    url: str,
    max_bytes: int,
) -> tuple[str, str, str, bool]:
    """Stream a URL into a size-capped string."""
    async with client.stream("GET", url) as resp:
        resp.raise_for_status()
        ctype = (resp.headers.get("content-type") or "").lower()
        final_url = str(resp.url)
        parts: list[bytes] = []
        total = 0
        truncated = False
        async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
            remain = max_bytes - total
            if remain <= 0:
                truncated = True
                break
            if len(chunk) > remain:
                parts.append(chunk[:remain])
                total += remain
                truncated = True
                break
            parts.append(chunk)
            total += len(chunk)
        text = b"".join(parts).decode("utf-8", errors="replace")
        return text, final_url, ctype, truncated


async def crawl_and_scan_secrets(
    seeds: list[str],
    *,
    max_pages: int = 80,
    max_js: int = 500,
    max_depth: int = 3,
    timeout: float = 15.0,
    chunk_bytes: int = 64 * 1024,
    overlap_bytes: int = 2048,
    max_bytes_per_resource: int = 2 * 1024 * 1024,
    max_concurrent: int = 2,
    max_hits: int = 200,
    user_agent: str = "bugcontrol-secrets/0.2",
) -> SecretsScanResult:
    """Live-crawl for JS; stream-scan with regex. No JS written to disk."""
    result = SecretsScanResult()
    normalized = [normalize_seed(s) for s in seeds if normalize_seed(s)]
    result.seed_urls = normalized
    if not normalized:
        result.errors.append("no valid seed URLs")
        return result

    origins = set(normalized)
    page_q: deque[tuple[str, int]] = deque((s, 0) for s in normalized)
    seen_pages: set[str] = set()
    seen_js: set[str] = set()
    js_q: deque[str] = deque()
    seen_keys: set[tuple[str, str, str]] = set()
    fetch_sem = asyncio.Semaphore(max_concurrent)

    async def enqueue_js(url: str, *, force: bool = False) -> None:
        url = urldefrag(url)[0]
        if not url or url in seen_js:
            return
        if not force and not _looks_like_js_url(url):
            return
        seen_js.add(url)
        result.js_discovered += 1
        js_q.append(url)

    async def drain_js(limit: int | None = None) -> None:
        n = 0
        while js_q and result.js_scanned < max_js:
            if limit is not None and n >= limit:
                break
            js_url = js_q.popleft()
            n += 1
            async with fetch_sem:
                await _scan_js_url(
                    client,
                    js_url,
                    result,
                    seen_keys,
                    enqueue_js,
                    chunk_bytes=chunk_bytes,
                    overlap_bytes=overlap_bytes,
                    max_bytes_per_resource=max_bytes_per_resource,
                    max_hits=max_hits,
                )

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": user_agent, "Accept": "*/*"},
        limits=httpx.Limits(
            max_connections=max_concurrent,
            max_keepalive_connections=max_concurrent,
        ),
    ) as client:
        while page_q or js_q:
            if js_q and result.js_scanned < max_js:
                await drain_js(limit=25)
                continue

            if not page_q or result.pages_fetched >= max_pages:
                await drain_js()
                break

            url, depth = page_q.popleft()
            url = urldefrag(url)[0]
            if url in seen_pages:
                continue
            seen_pages.add(url)

            async with fetch_sem:
                try:
                    html, final_url, ctype, truncated = await _read_limited_text(
                        client, url, max_bytes_per_resource
                    )
                except Exception as exc:
                    result.errors.append(f"page {url}: {exc}")
                    continue

            result.pages_fetched += 1
            if truncated:
                result.truncated_sources.append(final_url)

            if "javascript" in ctype or _looks_like_js_url(final_url):
                result.js_scanned += 1
                result.bytes_scanned += len(html.encode("utf-8", errors="ignore"))
                scan_text_for_secrets(
                    html,
                    final_url,
                    max_hits=max_hits,
                    existing=result.hits,
                    seen_keys=seen_keys,
                )
                for ref in extract_js_refs(html, final_url):
                    await enqueue_js(ref)
                del html
                continue

            for src in SCRIPT_SRC_RE.findall(html):
                await enqueue_js(_abs_url(final_url, src), force=True)
            for m in MODULEPRELOAD_RE.finditer(html):
                href = m.group(1) or m.group(2)
                if href:
                    await enqueue_js(_abs_url(final_url, href), force=True)

            for i, body in enumerate(INLINE_SCRIPT_RE.findall(html)):
                content = body.strip()
                if len(content) < 20:
                    continue
                source = f"inline:{final_url}#{i}"
                result.js_scanned += 1
                result.bytes_scanned += len(content)
                scan_text_for_secrets(
                    content,
                    source,
                    max_hits=max_hits,
                    existing=result.hits,
                    seen_keys=seen_keys,
                )
                for ref in extract_js_refs(content, final_url):
                    await enqueue_js(ref)

            for ref in extract_js_refs(html, final_url):
                await enqueue_js(ref)

            if depth < max_depth:
                for href in HREF_RE.findall(html):
                    link = _abs_url(final_url, href)
                    if not link.startswith(("http://", "https://")):
                        continue
                    if _looks_like_js_url(link):
                        await enqueue_js(link)
                        continue
                    path = urlparse(link).path.lower()
                    if path.endswith(
                        (
                            ".png",
                            ".jpg",
                            ".jpeg",
                            ".gif",
                            ".svg",
                            ".css",
                            ".woff",
                            ".woff2",
                            ".ico",
                            ".pdf",
                            ".zip",
                            ".webp",
                        )
                    ):
                        continue
                    if any(_same_site(link, o) for o in origins) and link not in seen_pages:
                        page_q.append((link, depth + 1))
            del html

    return result


async def _scan_js_url(
    client: httpx.AsyncClient,
    url: str,
    result: SecretsScanResult,
    seen_keys: set[tuple[str, str, str]],
    enqueue_js: Callable[..., Awaitable[None]],
    *,
    chunk_bytes: int,
    overlap_bytes: int,
    max_bytes_per_resource: int,
    max_hits: int,
) -> None:
    try:
        async with client.stream("GET", url) as resp:
            if resp.status_code >= 400:
                result.errors.append(f"js {url}: HTTP {resp.status_code}")
                return
            final_url = str(resp.url)
            nbytes, refs, truncated = await scan_stream_for_secrets(
                resp,
                final_url,
                chunk_size=chunk_bytes,
                overlap=overlap_bytes,
                max_bytes=max_bytes_per_resource,
                max_hits=max_hits,
                hits=result.hits,
                seen_keys=seen_keys,
                collect_refs=True,
            )
    except Exception as exc:
        result.errors.append(f"js {url}: {exc}")
        return

    result.js_scanned += 1
    result.bytes_scanned += nbytes
    if truncated:
        result.truncated_sources.append(url)
    for ref in refs:
        await enqueue_js(ref)
