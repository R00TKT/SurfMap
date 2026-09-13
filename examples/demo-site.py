#!/usr/bin/env python3
"""A deliberately imperfect target for demonstrating surfmap locally.

Serves a small site with a real directory structure, plus: login and upload
forms, a cookie with no HttpOnly/Secure/SameSite, a third-party script, a 301
redirect, a robots.txt-disallowed branch, JSON endpoints, and pages with and
without security headers.

It also carries material for `surfmap brute`: several files and a directory
that nothing links to, so they are reachable only by guessing a path, and a
/portal/ subtree that answers unknown paths with "200 OK" and a friendly error
page -- the soft-404 behaviour that makes naive path discovery report every
word in its list as a hit.

    python3 examples/demo-site.py 8421

Nothing here is a real application -- it exists so the crawler can be run
against a target that is unambiguously yours.
"""
import http.server
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8421

SECURE = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def page(title, body, headers=None):
    html = f"<html><head><title>{title}</title></head><body>{body}</body></html>"
    return ("text/html", html, headers or {})


def links(*paths):
    return " ".join(f'<a href="{p}">{p}</a>' for p in paths)


PAGES = {
    "/robots.txt": ("text/plain", "User-agent: *\nDisallow: /admin\nCrawl-delay: 0\n", {}),

    "/": ("text/html", f"""<html><head><title>Acme Portal</title>
        <script src="https://cdn.analytics.test/track.js"></script>
        <script>window.acme=1;</script></head><body>
        {links("/login", "/upload", "/legacy", "/admin/panel",
               "/account/profile", "/account/settings", "/account/billing/invoices",
               "/catalog/products", "/catalog/products/detail?id=42",
               "/docs/guide/intro", "/docs/guide/advanced", "/docs/api/reference",
               "/api/v1/users", "/api/v1/orders",
               "/search?q=widgets&page=1",
               "/reports/export?from=2024-01-01&to=2024-06-30&format=csv",
               "/redirect?next=https://partner.example.net/sso")}
        <a href="https://partner.example.net/sso">Partner SSO</a>
        </body></html>""", {}),

    "/login": ("text/html", """<html><head><title>Sign in</title></head><body>
        <form action="/session" method="post">
          <input name="email" type="email" required>
          <input name="password" type="password" required>
          <input name="csrf" type="hidden" value="s3cr3t-token-value">
        </form></body></html>""", {"Set-Cookie": "sid=abc123sessionvalue; Path=/"}),

    "/upload": ("text/html", """<html><head><title>Upload</title></head><body>
        <form action="/files" method="POST" enctype="multipart/form-data">
          <input name="doc" type="file" required>
          <input name="tag" type="text" maxlength="40">
        </form></body></html>""", {}),

    "/account/profile": page("Profile", links("/account/settings"),
                             {"Set-Cookie": "prefs=dark; Path=/; HttpOnly; Secure; SameSite=Lax"}),
    "/account/settings": ("text/html", """<html><head><title>Settings</title></head><body>
        <form action="https://billing.other-vendor.test/update" method="post">
          <input name="plan" type="text"><input name="token" type="hidden" value="xyz">
        </form></body></html>""", {}),
    "/account/billing/invoices": page("Invoices", links("/account/billing/invoices?year=2024")),

    "/catalog/products": page("Products", links("/catalog/products/detail?id=42",
                                                "/catalog/products/detail?id=99"), SECURE),
    "/catalog/products/detail": page("Product detail", "an item", SECURE),

    "/docs/guide/intro": page("Intro", links("/docs/guide/advanced"), SECURE),
    "/docs/guide/advanced": page("Advanced", links("/docs/api/reference"), SECURE),
    "/docs/api/reference": page("API reference", "reference", SECURE),

    "/search": page("Search", "results"),
    "/reports/export": page("Export", "report"),
    "/redirect": page("Redirector", "bounce"),
    "/session": page("Session", "posted"),
    "/files": page("Files", "posted"),
    "/new": page("Relocated", "moved here"),

    # --- Unlinked. Nothing on the site points at any of these, so a crawl
    # --- cannot reach them and only `surfmap brute` will.
    "/backup.sql": ("text/plain", "-- MySQL dump\nCREATE TABLE users (...);\n" * 8, {}),
    "/.env": ("text/plain", "APP_ENV=production\nDB_PASSWORD=hunter2\n", {}),
    "/config.php.bak": ("text/plain", "<?php $db_pass = 'changeme'; ?>\n", {}),
    "/internal/": page("Internal tools", "dashboards live here"),
    "/internal/metrics": ("application/json", '{"rps": 41.2, "errors": 0}', {}),
    "/portal/config.php": ("text/plain", "; portal configuration\n" * 6, {}),
}

# Unknown paths under this prefix get "200 OK" plus an apology instead of a 404.
SOFT_404_PREFIX = "/portal/"

JSON_PAGES = {
    "/api/v1/users": '{"users":[]}',
    "/api/v1/orders": '{"orders":[]}',
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, ctype, body, headers=None):
        payload = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/legacy":
            self.send_response(301)
            self.send_header("Location", "/new")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path in JSON_PAGES:
            self._send(200, "application/json", JSON_PAGES[path])
            return

        if path.startswith("/admin"):
            # Reachable, but robots.txt tells the crawler not to.
            self._send(200, "text/html", "<html><title>Admin</title></html>")
            return

        # `/internal` -> `/internal/`: how a server says "that is a directory",
        # and the signal surfmap uses to decide where to recurse.
        if path == "/internal":
            self.send_response(301)
            self.send_header("Location", "/internal/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Unlinked but real: exists, and says so without showing you anything.
        if path == "/server-status":
            self._send(403, "text/html", "<html><title>Forbidden</title></html>")
            return

        if path in PAGES:
            ctype, body, headers = PAGES[path]
            self._send(200, ctype + "; charset=utf-8", body, headers)
            return

        if path.startswith(SOFT_404_PREFIX):
            # The soft 404. The requested path is echoed back, so successive
            # misses differ slightly in length -- which is why surfmap compares
            # lengths with a tolerance rather than for equality.
            body = (f"<html><head><title>Page not found</title></head><body>"
                    f"<h1>Sorry</h1><p>Nothing at {path} on the portal. "
                    f"Try the <a href='/'>homepage</a>.</p></body></html>")
            self._send(200, "text/html", body)
            return

        self._send(404, "text/html", "<html><title>Not found</title></html>")


socketserver.ThreadingTCPServer.allow_reuse_address = True
print(f"demo site on http://127.0.0.1:{PORT}/", flush=True)
socketserver.ThreadingTCPServer(("127.0.0.1", PORT), Handler).serve_forever()
