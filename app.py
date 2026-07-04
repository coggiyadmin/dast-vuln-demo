"""DAST-01/DAST-02 TP routes — runtime confirmation scaffold."""
from flask import Flask, request, redirect
app = Flask(__name__)

@app.get("/echo")
def echo():
    msg = request.args.get("msg", "")  # SOURCE
    return f"<p>{msg}</p>"  # SINK CWE-79 — DAST should confirm at runtime

@app.get("/redirect")
def redir():
    url = request.args.get("url", "/")
    return redirect(url)  # SINK CWE-601

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
