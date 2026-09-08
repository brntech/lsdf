# Contributing

Thank you for your interest in contributing to LLM Sensitive Data Firewall.

Contributions are welcome in:

- Threat models for sensitive-data leakage in LLM apps
- Policy examples for healthcare, HR, finance, legal, telecom, and SaaS
- Recognizer ideas for PII, PHI, PCI, credentials, and business-confidential data
- Evaluation datasets and leakage test cases
- Architecture feedback
- Documentation improvements
- Integration examples for OpenAI-compatible providers and application frameworks

## Pull Request Process

1. Open an issue or draft PR for larger changes so maintainers can discuss scope early.
2. Keep each PR focused on one behavior, policy, detector, corpus, or documentation improvement.
3. Include tests or a clear explanation when a change is documentation-only.
4. Update user-facing docs when behavior, commands, policies, eval output, or operational guidance changes.
5. Keep generated artifacts reproducible with the commands documented near the artifact.

## Test Expectations

LSDF development is Docker-first. Run tests through Docker Compose from the repository root:

```bash
docker compose run --rm test
```

Use focused Docker Compose test invocations while iterating, then run the full suite before requesting review. Do not install LSDF dependencies, optional detector packages, Torch, Transformers, Presidio, or model tooling into your host Python environment just to run project checks.

## Two-Layer Test Discipline

LSDF separates detector capability from composed profile promises.

The foundation layer lives in `tests/foundation/fixtures/`, `policies/subtype-emission-manifest.yaml`, and `docs/system-recall.md`. It measures each detector and entity pair in isolation against synthetic fixtures. If you add or change a detector's emitted entity, update the manifest floor and foundation fixture together.

Fixture size follows detector behavior. Regex, entropy, XPIA, and medical-regex detectors are evaluated with 7-15 cases per detector/entity pair because their matching logic is deterministic and pinned by focused unit tests. ML and contextual detectors require at least 30 positive and 15 negative synthetic cases per detector/entity pair so recall and specificity floors have meaningful signal.

The subtype manifest `version` is a schema/vocabulary version, not the LSDF release tag. Do not bump it solely because a release number changes.

The assembly layer lives in profile YAML `gate_promise:` blocks and `EVAL.md`. It measures whether a composed profile keeps its end-to-end promise against the named evaluation corpora. Do not move profile corpora into the subtype manifest, and do not move per-detector floors into `gate_promise:`.

Reserved subtypes have no foundation floor until a detector actually emits them, or until an optional ML adapter labels the subtype precisely enough to carry its own foundation contract. Keep non-emitted reserved vocabulary documented as reserved, not as placeholder floor entries.

The `out_of_scope: true` flag marks a `(detector, entity)` pair where this detector_id slot is preempted by a sibling detector_id in the same scanner. The engine may surface a low-level match (for example, the inline XML regex matching a `<passport>` tag), but the overlap resolver collapses dual-emissions to the anchored sibling that carries the foundation floor. Out-of-scope is distinct from a coverage gap: the architectural promise is met by the sibling detector, not by closing fixture authorship. Do not "fix" the overlap resolver to surface preempted slots — the manifest assumes they stay silent.

## DCO Sign-Off

All commits must include a Developer Certificate of Origin sign-off. Use:

```bash
git commit -s
```

The resulting commit message must contain a `Signed-off-by:` trailer using the name and email you are contributing under. By signing off, you certify that you have the right to submit the contribution under this project's license.

## Licensing

LSDF is licensed under Apache-2.0. By contributing code, docs, tests, examples, policies, or evaluation fixtures, you agree that your contribution is provided under the same license unless a file clearly states otherwise. Do not add third-party corpora, snippets, or generated artifacts unless their license permits redistribution in this repository and attribution is documented.

## Code Style

- Prefer the existing module layout and small, testable functions.
- Keep policy behavior explicit: detector families find candidates; policy rules decide actions.
- Preserve raw-value-safe defaults for audit, metrics, reports, demos, screenshots, and committed fixtures.
- Add comments only when they clarify non-obvious behavior.
- Keep public docs and examples free of private planning notes, internal task labels, and real provider secrets.

## Sensitive Data Warning

Do not include real credentials, real PHI, real customer data, real employee data, or private documents in issues, examples, commits, or test data.

Use clearly synthetic fixtures when a detector needs realistic structure, and keep raw fixture values out of reports, audit output, metrics, screenshots, and demo media.
