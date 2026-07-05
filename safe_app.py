"""SAFE mirrors (SAST fixture) — the sanitizer the engine credits, per category.

Correlates with `dast_server.py` `/safe/*` routes: SAST should scan these clean AND the DAST probe
should be blocked at runtime (D5 sanitizer runtime confirmation).
"""
import html
import os
import subprocess
from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)
ALLOWED_HOSTS = {"app.example.com"}
ALLOWED_CMDS = {"alpha", "beta"}


@app.get("/safe/xss")
def xss():
    q = request.args.get("q", "")
    return "<p>" + html.escape(q) + "</p>"              # escaped


@app.get("/safe/redirect")
def redir():
    url = request.args.get("url", "/")
    host = urlparse(url).hostname
    return redirect(url) if host in ALLOWED_HOSTS else redirect("/")


@app.get("/safe/cmd")
def cmd():
    q = request.args.get("q", "")
    if q not in ALLOWED_CMDS:
        return "rejected"
    subprocess.run(["echo", q], shell=False)            # argv, no shell
    return "ok"


@app.get("/safe/path")
def path():
    q = request.args.get("q", "")
    name = os.path.basename(q)                          # strip traversal
    return open("/tmp/dast_root/" + name).read()
