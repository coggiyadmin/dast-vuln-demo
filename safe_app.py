"""SAFE mirrors for DAST baseline."""
import html
from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)
ALLOWED = {"app.example.com"}

@app.get("/echo")
def echo():
    msg = request.args.get("msg", "")
    return f"<p>{html.escape(msg)}</p>"

@app.get("/redirect")
def redir():
    url = request.args.get("url", "/")
    host = urlparse(url).hostname
    if host in ALLOWED:
        return redirect(url)
    return redirect("/")
