"""EVAL-ONLY redirect service for the mcp-netproxy evaluation harness.

Not part of the proxy. Serves ``GET /redirect?to=<url>`` with a 302 to
``<url>`` so the eval can check whether a fetch that starts at an
innocuous host and is redirected to a ``.invalid`` sink is caught.
Started only via ``compose/eval.yml``.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlparse(self.path)
        target = parse_qs(url.query).get("to", [None])[0]
        if url.path != "/redirect" or not target:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Location", target)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9100), RedirectHandler).serve_forever()
