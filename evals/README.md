# Evaluation Fixtures

The bundled evaluation files contain synthetic detector fixtures. Some values are intentionally shaped like SSNs, card numbers, medical record numbers, API keys, or other sensitive entities so LSDF can measure detection, redaction, blocking, tokenization, and known-gap behavior.

Do not add real credentials, PHI, customer data, employee data, or private documents to these files. New fixtures should be clearly synthetic and should not use real provider keys.

The coding focused battery is an explicit, separate characterization set of 25
synthetic cases. Run it when evaluating coding traffic with:

```text
docker compose run --rm cli eval evals/coding_matrix.json --format markdown
```

It covers assignments, diffs, hard identifiers, escaped JSON, tool arguments,
base64 containment, and two declared decoding gaps (a whitespace wrapped
base64 carrier and a URL data carrier). The report keeps those known gaps
separate from ordinary misses and reports unwanted mutations and JSON text
mutations. Passing this small synthetic battery does not establish general
coding coverage, model safety, or release wide accuracy.
