"""DAST TP routes (SAST fixture) — one vulnerable route per category.

Mirrors the runnable target `dast_server.py`; the SAST side scans this flask fixture, the DAST side
probes the running server, and `dast_runner.py` correlates the two by category.
"""
import subprocess
from flask import Flask, request, redirect

app = Flask(__name__)


@app.get("/vuln/xss")
def xss():
    q = request.args.get("q", "")                       # SOURCE
    return "<p>" + q + "</p>"                            # SINK CWE-79


@app.get("/vuln/redirect")
def redir():
    url = request.args.get("url", "/")
    return redirect(url)                                # SINK CWE-601


@app.get("/vuln/cmd")
def cmd():
    q = request.args.get("q", "")
    subprocess.call("echo " + q, shell=True)            # SINK CWE-78
    return "ok"


@app.get("/vuln/path")
def path():
    q = request.args.get("q", "")
    return open("/tmp/dast_root/" + q).read()           # SINK CWE-22


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
