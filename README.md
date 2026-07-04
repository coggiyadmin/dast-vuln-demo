# dast-vuln-demo — §10 D3 runnable app scaffold (INTAKE-62)

Minimal Dockerized app for SAST→DAST validation loop research.

## Run

```bash
docker compose up --build
curl 'http://localhost:8080/echo?msg=<script>alert(1)</script>'
```

## Probes (planned)

| ID | Route | Expected runtime signal |
|----|-------|-------------------------|
| DAST-01 | GET /echo | reflected XSS in body |
| DAST-02 | GET /redirect?url= | open redirect Location header |

## Safe baseline

`safe_app.py` uses `html.escape` and redirect allowlist — DAST should not fire.
