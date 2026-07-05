# dast-vuln-demo — SAST↔DAST validation (§10 D3–D6)

Runnable target that correlates the static verdict with runtime exploitability.

- `app.py` — SAST **vuln** fixtures (flask), one route per category.
- `safe_app.py` — SAST **safe** mirrors (the credited sanitizer per category).
- `fn_app.py` — a SAST **false negative** shape (loop-carried taint) still exploitable at runtime.
- `dast_server.py` — zero-dependency stdlib runtime target (`/vuln/*`, `/safe/*`, `/fn/*`).

Run the loop (D4 agreement matrix + D5 sanitizer runtime confirmation + D6 recall backstop):

```bash
python3 ~/workspace/cogniumhq/sast-validation/scripts/dast-regression/dast_runner.py
```

The 2×2 agreement matrix quantifies how well the static verdict predicts runtime exploitability —
including `FP∧blocked` (a SAST finding the DAST probe proves is a false positive) and `FN∧exploit`
(a static miss the DAST probe proves is exploitable).
