import asyncio
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from bugcontrol.scanners.js_crawl import SECRET_PATTERNS, crawl_and_scan_secrets

HTML = b"""<html><head>
<script src="/static/app.js"></script>
<script>const API_KEY="sk_test_leak1234567890abcdef";</script>
</head><body><a href="/page2">x</a></body></html>"""
JS = (
    b'window.CFG={token:"ghp_abcdefghijklmnopqrstuvwxyz0123456789"};\n'
    b'const AWS="AKIAIOSFODNN7EXAMPLE";\n'
    b'//# sourceMappingURL=app.js.map\n'
)
SMAP = b'{"version":3,"file":"app.js","sources":["app.ts"],"mappings":"AAAA"}'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # noqa: ANN002
        return

    def do_GET(self) -> None:  # noqa: N802
        routes = {
            "/": HTML,
            "/page2": HTML,
            "/static/app.js": JS,
            "/static/app.js.map": SMAP,
        }
        body = routes.get(self.path, b"404")
        self.send_response(200 if self.path in routes else 404)
        ctype = (
            "application/javascript"
            if self.path.endswith((".js", ".map"))
            else "text/html"
        )
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)


async def main() -> None:
    assert len(SECRET_PATTERNS) >= 15, len(SECRET_PATTERNS)
    server = HTTPServer(("127.0.0.1", 8765), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    result = await crawl_and_scan_secrets(
        ["http://127.0.0.1:8765/"],
        max_pages=10,
        max_js=20,
        max_depth=2,
        max_concurrent=1,
    )
    print(result.summary())
    kinds = {h.kind for h in result.hits}
    assert result.js_discovered >= 1, result.summary()
    assert "github_pat" in kinds or "stripe_key" in kinds or "aws_access_key" in kinds, kinds
    server.shutdown()
    print("patterns", len(SECRET_PATTERNS), "OK")


if __name__ == "__main__":
    asyncio.run(main())
