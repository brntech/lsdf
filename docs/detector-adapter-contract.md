# Detector Adapter Contract

Date: 2026-04-29

LSDF detectors receive one text surface at a time and return spans that can be mapped into policy entities. OpenAI privacy-filter is the bundled optional ML reference adapter, and application-supplied detectors can use the same contract.

## Contract

A detector should expose:

- `detector_id`: stable implementation identifier.
- `detector_family`: stable family name used by policies and reports.
- `entities`: set of LSDF entity names the detector may emit.
- `scan(surface)`: returns zero or more findings for the supplied text surface.

Each finding should include:

- LSDF entity, surface name, JSON pointer, start offset, end offset, and confidence.
- The matched value for in-memory transformation only.
- Detector family/id and safe metadata for provenance.

Audit events, metrics, demo output, proof bundles, and public reports must use safe finding dictionaries that omit raw matched values.

## ML Span Mapping

Token-classification models usually emit category, start, end, and score fields. Adapters should normalize those spans, apply a confidence threshold where appropriate, merge adjacent same-category fragments, and map model categories to LSDF entities.

The bundled OpenAI privacy-filter adapter maps categories such as private email, phone, address, date, person, account-number-like identifiers, and secret labels into LSDF entities. Application-supplied adapters can use a different model as long as they emit compatible findings.

## Provider Injection

Library callers and tests can inject custom detector providers through the existing detector registry path. To make a custom family name (e.g. `medical-ner`) pass policy validation, call `register_detector_family(name)` from `lsdf` once at application start before any `load_policy()` or `Firewall(...)` call — the function is idempotent, mutates the live family list shared by the policy and registry validators, and accepts an optional `specificity` to influence overlap resolution. Gateway runtime plugin loading is not implemented; production gateway deployments should use the built-in detector families, the optional Docker image, or a small application wrapper that constructs `Firewall` with custom providers and `register_detector_family()` for any custom family names.

## Installed adapter settings

The registry consumes `required` as an availability setting. The installed GLiNER and privacy-filter builders also accept their documented family settings. The installed Presidio builder currently uses fixed defaults; other `detection.settings.presidio` entries are not forwarded. Use a custom provider when you need a different Presidio analyzer configuration.

## Operational Requirements

Optional ML detectors should stay Docker-managed, report unavailable dependencies clearly, and avoid downloading model artifacts during normal tests unless an operator explicitly configures the cache. Detector metadata should identify the model or implementation without exposing prompts, payload text, or matched sensitive values.

Streaming adapters should be safe under a bounded holdback window. The bundled `broad-pii-ml` profile scans stream chunks for safety, but teams should measure CPU latency on representative streaming traffic before enabling optional ML enforcement at scale.

## Worked Example — Medical NER (`medical-ner`)

The bundled `medical-regex` detector is intentionally lightweight pattern matching and is not full HIPAA de-identification. Healthcare deployments should plug in a dedicated medical NER model. See `docs/medical-ner-adapter-recipe.md` for a runnable code stub showing how to wire med7 / MedSpaCy / Medical-BERT into LSDF as a `medical-ner` detector family without modifying core LSDF code — provider, detector, build factory, registry wiring, and policy snippet, with the model-loading lines deliberately stubbed as `# your implementation here`.
