"""DAST D6 recall-backstop fixture — taint through a shape the static engine loses.

SAST should scan this CLEAN (loop-carried taint not traced), yet the same route is exploitable at
runtime (dast_server.py /fn/cmd) — proving DAST as a false-negative backstop.
"""
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.get("/fn/cmd")
def fn_cmd():
    q = request.args.get("q", "")
    parts = []
    for ch in q:
        parts.append(ch)          # loop-carried taint
    acc = "".join(parts)
    subprocess.call("echo " + acc, shell=True)   # SINK CWE-78 — engine loses the loop
    return "ok"
