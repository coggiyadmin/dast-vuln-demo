#!/usr/bin/env python3
"""Zero-dependency runnable DAST target (D3, expanded) — SAST fixture AND runtime probe target.

The vulnerable `/vuln/*` routes concatenate user input into a sink (SAST detects these); the
`/safe/*` routes apply the sanitizer the engine credits (SAST + DAST agree they are clean). One
`/fn/*` route carries taint through a shape the static engine loses (SAST FN) but which is still
exploitable at runtime — the D6 recall-backstop case.

Runs with only the standard library:  python3 dast_server.py [port]
"""
from __future__ import annotations

import html
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ALLOWED_HOSTS = {"app.example.com"}
ALLOWED_CMDS = {"alpha", "beta"}
DATA_DIR = "/tmp/dast_root"


def _q(path: str) -> str:
    return (parse_qs(urlparse(path).query).get("q", [""]) or [""])[0]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _send(self, body: str, status: int = 200, location: str | None = None):
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        p = urlparse(self.path).path
        q = _q(self.path)
        try:
            # ── XSS (CWE-79) ─────────────────────────────────────────────────
            if p == "/vuln/xss":
                return self._send("<p>" + q + "</p>")                    # SINK — reflect raw
            if p == "/safe/xss":
                return self._send("<p>" + html.escape(q) + "</p>")       # escaped

            # ── open redirect (CWE-601) ──────────────────────────────────────
            if p == "/vuln/redirect":
                url = (parse_qs(urlparse(self.path).query).get("url", ["/"]) or ["/"])[0]
                return self._send("", 302, location=url)                 # SINK — attacker Location
            if p == "/safe/redirect":
                url = (parse_qs(urlparse(self.path).query).get("url", ["/"]) or ["/"])[0]
                host = urlparse(url).hostname
                return self._send("", 302, location=url if host in ALLOWED_HOSTS else "/")

            # ── command injection (CWE-78) ───────────────────────────────────
            if p == "/vuln/cmd":
                out = subprocess.run("echo " + q, shell=True, capture_output=True, text=True)  # SINK
                return self._send("<pre>" + out.stdout + "</pre>")
            if p == "/safe/cmd":
                if q not in ALLOWED_CMDS:
                    return self._send("<pre>rejected</pre>")
                out = subprocess.run(["echo", q], capture_output=True, text=True)  # argv, no shell
                return self._send("<pre>" + out.stdout + "</pre>")

            # ── path traversal (CWE-22) ──────────────────────────────────────
            if p == "/vuln/path":
                with open(os.path.join(DATA_DIR, q)) as f:               # SINK — no containment
                    return self._send("<pre>" + f.read() + "</pre>")
            if p == "/safe/path":
                name = os.path.basename(q)
                with open(os.path.join(DATA_DIR, name)) as f:            # basename strips traversal
                    return self._send("<pre>" + f.read() + "</pre>")

            # ── D6: FN recall backstop — taint through a shape SAST loses ─────
            if p == "/fn/cmd":
                parts = []
                for ch in q:                                              # loop-carried taint
                    parts.append(ch)
                acc = "".join(parts)
                out = subprocess.run("echo " + acc, shell=True, capture_output=True, text=True)  # SINK
                return self._send("<pre>" + out.stdout + "</pre>")

            return self._send("ok")
        except Exception as e:  # noqa
            return self._send("err:" + str(e), 500)


def main() -> int:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(os.path.join(DATA_DIR, "public.txt"), "w") as f:
        f.write("PUBLIC-DATA")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print(f"dast_server listening on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
