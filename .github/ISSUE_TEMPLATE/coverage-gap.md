---
name: Detection gap
about: A sensitive value LSDF missed, or a benign value it flagged
labels: coverage
---

**Do not paste real credentials, PHI, customer data, or raw audit lines.** Use a synthetic example with the same shape.

- LSDF version / image tag:
- Profile (`default`, `broad-pii`, `broad-pii-ml`, `healthcare`, ...):
- Surface (user message, system prompt, RAG chunk, tool result, model output, stream, tool-call arguments, reasoning, trace):
- Synthetic example of the value shape:
- Expected: detected / not detected
- Observed:
- Output of `docker compose run --rm cli doctor` (trimmed):
