# Medical NER Adapter Recipe

The bundled `medical-regex` detector is intentionally lightweight pattern matching — selected ICD-like codes, lab-value strings, and medication-dosage patterns — and is explicitly **not** full HIPAA de-identification. Healthcare deployments should plug in a dedicated medical NER model.

This recipe shows how to wire a medical NER model (med7 / MedSpaCy / Medical-BERT / a custom token classifier) into LSDF as a `medical-ner` detector family without modifying core LSDF code. The code below is a **runnable stub** — it compiles against the existing `Finding`, `Surface`, and detector-registry types, but the model-loading lines are illustrative pseudocode marked clearly as `# your implementation here`. Treat this as bring-your-own (BYO).

The recipe deliberately does not ship as part of LSDF. Medical NER models vary in licensing, weight provenance, and clinical-validation status — picking one is a deployment decision, not a default.

## Naming convention

The LSDF naming rule names detector families by implementation class:

- `medical-regex` (already shipped) — detector family for the lightweight regex/pattern detector.
- `medical-ner` (your implementation) — detector family for an ML-based medical NER adapter. Use this string in your dataclass `detector_family` attribute and in any policy file that enables it.

If you ship multiple medical NER adapters in parallel (e.g. one for English clinical notes, another for radiology dictation), distinguish them via `detector_id` (e.g. `medical-ner.med7-en`, `medical-ner.med7-radiology`) while sharing the `medical-ner` family.

## Step 0 — register the family

`medical-ner` is **not** a built-in LSDF detector family — a vanilla policy that lists `medical-ner` in `detectors.enabled_families` will raise `ValueError: Unknown detector family: medical-ner` from both `lsdf.policy.load_policy()` and `lsdf.detectors.build_detector_registry()`.

LSDF exposes a public extension point for custom families:

```python
from lsdf import register_detector_family

register_detector_family("medical-ner", specificity=78)
```

Call this once, at application start-up, before any `load_policy()` or `Firewall(...)` construction. After registration:

- `medical-ner` passes both validators (registry build and policy load).
- The `specificity=78` value plumbs into overlap resolution — a `medical-ner` finding outranks a generic `regex`-family finding (specificity 80 vs 78 leaves `regex` slightly higher; tune to your preference). Defaults to 50 if omitted.
- Calling `register_detector_family("medical-ner")` again is a no-op (idempotent), so the call is safe in module-import code.

You still must supply the runtime implementation via `detector_providers` (steps 2-5 below) — registration alone tells LSDF the name is valid, not what it does. Building a registry with a registered family but no provider raises a clear `ValueError` that points at `detector_providers`.

The rest of this recipe assumes step 0 has run.

## Step 1 — entity map

Pick the LSDF entities your model's category labels map onto. The bundled `policies/healthcare.yaml` entity allow-list includes `MRN`, `PHI`, `PERSON`, `DATE_OF_BIRTH`, `ADDRESS`, plus the cross-cutting `EMAIL`/`PHONE`/`SECRET`/etc. — your medical NER adapter can emit any of those out of the box. If you want finer-grained categories like `MEDICATION` or `DOSAGE`, those are **adapter-defined**: add them to the `entities:` list in your custom policy YAML, otherwise `_validate_rules` at `src/lsdf/policy.py:249` rejects rules that reference unknown entities. Map your model's categories conservatively — mismatch causes either policy underfire (mapping unknown categories away) or detector noise (mapping unrelated medical concepts onto `PHI`).

```python
# medical_ner_adapter.py — your operator-side implementation file.

MED7_ENTITY_MAP = {
    "DRUG": "MEDICATION",
    "STRENGTH": "DOSAGE",
    "DOSAGE": "DOSAGE",
    "FREQUENCY": "DOSAGE",
    "ROUTE": "MEDICATION",
    "FORM": "MEDICATION",
    "DURATION": "DOSAGE",
}
```

Categories not in this map will be dropped before any LSDF policy sees them.

## Step 2 — the provider

A `MedicalNERProvider` wraps whatever model loader / pipeline / API client you use. LSDF calls it via `__call__(text)` and expects a list of dicts with `category`, `start`, `end`, `score` fields. The reference adapter goes through a `_span_from_result` normalization step (see `src/lsdf/scanners/openai_privacy_filter.py:191`) that accepts several alias keys (`entity_group`, `entity`, `label`, `start_offset`/`end_offset`, `confidence`); since this private helper lives inside the bundled adapter, your `__call__` should normalize to the canonical `category`/`start`/`end`/`score` shape directly rather than relying on alias support.

```python
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MedicalNERProvider:
    pipeline: Any  # whatever model handle you load below

    def __call__(self, text: str) -> list[dict[str, Any]]:
        if not text:
            return []
        # your implementation here:
        # raw = self.pipeline(text)
        # return [
        #     {
        #         "category": result["entity_group"],   # e.g. "DRUG"
        #         "start": int(result["start"]),
        #         "end": int(result["end"]),
        #         "score": float(result["score"]),
        #     }
        #     for result in raw
        # ]
        return []
```

## Step 3 — the detector

This is the type LSDF actually consumes. It is a frozen dataclass with the four required attributes (`detector_id`, `detector_family`, `entities`, `scan(surface)`). Mirror the structure of `OpenAIPrivacyFilterDetector` in `src/lsdf/scanners/openai_privacy_filter.py` — the same `_merge_spans` and `_finding_from_span` patterns apply.

```python
from lsdf.surfaces import Surface
from lsdf.types import Finding


@dataclass(frozen=True)
class MedicalNERDetector:
    provider: MedicalNERProvider
    score_threshold: float | None = 0.85   # tune via FP-lever sweep, see docs/fp-lever-sweep-2026-04-29.md
    merge_gap: int = 1
    provider_metadata: dict[str, Any] | None = None

    detector_id: str = "medical-ner.med7-en"
    detector_family: str = "medical-ner"
    entities: frozenset = frozenset(MED7_ENTITY_MAP.values())

    def scan(self, surface: Surface) -> list[Finding]:
        spans = self.provider(surface.value)
        normalized = [
            span for span in spans
            if span.get("category") in MED7_ENTITY_MAP
            and (self.score_threshold is None or span["score"] >= self.score_threshold)
            and 0 <= span["start"] < span["end"] <= len(surface.value)
        ]
        # `_merge_spans` and `_finding_from_span` from
        # src/lsdf/scanners/openai_privacy_filter.py are good prior art.
        # For a stub, emit findings one-per-span without merging:
        return [
            Finding(
                entity=MED7_ENTITY_MAP[span["category"]],
                surface=surface.name,
                pointer=surface.pointer,
                json_pointer=surface.json_pointer,
                start=span["start"],
                end=span["end"],
                value=surface.value[span["start"]:span["end"]],
                confidence=float(span["score"]),
                detector_id=self.detector_id,
                detector_family=self.detector_family,
                metadata={
                    "ner_category": span["category"],
                    "specificity": 80,   # adjust per your model's measured precision
                    **(self.provider_metadata or {}),
                },
            )
            for span in normalized
        ]
```

## Step 4 — the build factory (model loading is BYO)

A factory function loads your model exactly once and returns the detector. Mirror `build_installed_openai_privacy_filter_detector` in style — env-var configurable, `local_files_only=True` by default to avoid implicit downloads, raise a clear `RuntimeError` when the model cache is missing.

```python
import os


def build_med7_medical_ner_detector(
    *,
    model_name: str | None = None,
    score_threshold: float | None = None,
    local_files_only: bool | None = None,
) -> MedicalNERDetector:
    model_name = model_name or os.environ.get(
        "LSDF_MEDICAL_NER_MODEL", "kormilitzin/en_core_med7_lg"
    )

    # your implementation here — example sketch with spaCy / med7:
    #
    #     import spacy
    #     pipeline = spacy.load(model_name)
    #
    # or for a Hugging Face token classifier:
    #
    #     from transformers import (
    #         AutoModelForTokenClassification,
    #         AutoTokenizer,
    #         pipeline,
    #     )
    #     tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=local_files_only)
    #     model = AutoModelForTokenClassification.from_pretrained(model_name, local_files_only=local_files_only)
    #     pipeline = pipeline("token-classification", model=model, tokenizer=tokenizer, aggregation_strategy="simple")
    #
    # On failure, raise RuntimeError with an operator-actionable message
    # naming the env var and the cache path.

    pipeline = None  # replace with your loaded handle
    return MedicalNERDetector(
        provider=MedicalNERProvider(pipeline=pipeline),
        score_threshold=score_threshold or 0.85,
        provider_metadata={
            "implementation": "your-implementation-here",
            "model_name": model_name,
        },
    )
```

## Step 5 — register with the firewall

LSDF discovers detectors via the registry path. With step 0's `register_detector_family("medical-ner")` call already applied at application start, the simplest wiring (library or test) is to construct the firewall with a `detector_providers` dict that maps the family name to a callable returning your detector instance:

```python
from lsdf import Firewall, load_policy, register_detector_family

# Step 0 — must precede any load_policy / Firewall construction.
register_detector_family("medical-ner", specificity=78)

firewall = Firewall(
    load_policy("policies/your-medical.yaml"),  # the policy from step 6
    detector_providers={
        "medical-ner": lambda: build_med7_medical_ner_detector(),
    },
)
```

Production gateway deployments do not yet expose runtime plugin loading as a public interface (see `docs/detector-adapter-contract.md` § "Provider Injection"). Until that lands, the supported path for production gateway-ml is a small application wrapper that constructs `Firewall` via the example above, then runs LSDF as a library inside your service rather than via the bundled `gateway-ml` Compose target.

## Step 6 — the policy

Add `medical-ner` to your policy's `detectors.enabled_families` and add any adapter-specific entity names to its `entities:` list (otherwise `_validate_rules` rejects rules referencing them). Wire it onto the surfaces where medical content actually appears (typically `input.messages`, `input.rag_context`, and `output.content`). The bundled `policies/healthcare.yaml` profile is the right baseline.

The example below assumes your wrapper has already done step 0 (called `register_detector_family("medical-ner")` and is constructing `Firewall` with `detector_providers={"medical-ner": ...}`). Without that prerequisite, `load_policy()` will raise on this YAML.

```yaml
# policies/your-medical.yaml
extends: healthcare
entities:
  # inherit healthcare's identity entities, plus the adapter-defined ones:
  - MRN
  - PHI
  - PERSON
  - DATE_OF_BIRTH
  - MEDICATION
  - DOSAGE
detectors:
  enabled_families:
    - medical-regex
    - medical-ner
rules:
  - id: redact-medications-in-output
    when:
      surface: output.content
      entity: MEDICATION
    action: redact
    severity: medium
```

## Validation checklist

Before treating your `medical-ner` adapter as production-ready:

1. Run `cli eval-report` with your policy enabled and confirm the threat-corpus containment doesn't regress.
2. Run `cli fp-lever-table` if your model exposes a score threshold; pick the threshold that satisfies recall on your validation corpus while minimizing FPs (see the existing sweep at `docs/fp-lever-sweep-2026-04-29.md` for the same exercise on the optional `openai_privacy_filter`).
3. Run `cli benchmark examples/openai_request.json --iterations 50` to measure latency. Medical NER models are typically heavier than the regex layer; budget the holdback window accordingly.
4. Confirm `safe_dict()` output on a real finding does not leak the matched span text — `Finding.value` is for in-memory transformation only, audit/proof artifacts must use the safe shape.
5. Add adapter-specific tests that mock the provider with deterministic spans so CI can exercise the wiring without the real model cache.

## Validation corpus

`evals/medical_phi_replay.json` ships a 30-case sanitised clinical-PHI replay corpus spread across four sub-specialties (primary care, radiology, oncology, mental health) plus two cross-domain edge cases. 15 cases the bundled `medical-regex` baseline catches (ICD codes with clinical context, lab values, six-drug-list medication-dosage shapes, diagnosis-prefix free-text) and 15 cases marked `known_gap: true` that the regex layer cannot catch (medication names without dosages, drug names outside the six-drug list, free-text symptom narratives, procedure mentions, condition narratives in RAG context, TNM staging, chemotherapy regimens, targeted-therapy mentions, imaging-finding free text, CPT procedure codes, and suicidality narratives). Each sub-domain carries both baseline-catchable and known-gap cases so an operator can isolate "does my radiology-tuned NER close the radiology gaps without regressing the radiology baseline?" before deciding which adapter family to ship. Operators wiring a `medical-ner` adapter via this recipe can:

1. Run the corpus through their adapter-augmented Firewall and verify `known_gap_leaked_after` drops on the 15 NER-required cases — that is the recipe's "did my NER adapter close the documented gap?" signal. **Important**: the leakage drop only materialises if the operator's policy YAML (step 6 above) declares the adapter-defined entities (`MEDICATION`, `DOSAGE`, etc.) in `entities:` *and* has rules with `redact` / `block` / `tokenize` actions targeting those entities on the relevant surfaces. `register_detector_family()` alone produces findings; without policy rules the action defaults to `allow` and the transformed payload is unchanged, leaving `known_gap_leaked_after` flat.
2. Re-run the same corpus through the bundled default profile (no NER adapter) and confirm the 15 baseline cases still redact cleanly — that is the regression guard against the regex layer drifting under future detector changes.
3. Filter the corpus by `domain` (one of `primary-care`, `radiology`, `oncology`, `mental-health`, `cross-domain`) before running through a sub-specialty-tuned adapter, so the per-domain leakage delta is comparable across adapter candidates (med7-en for general English clinical notes, RadBERT for radiology dictation, BlueBERT or BiomedBERT for oncology, Mental-BERT for psychiatric notes).

The corpus is intentionally compact — large enough to surface obvious adapter regressions across multiple clinical sub-specialties, small enough to read end-to-end. Operators with proprietary clinical validation sets should treat this as a smoke test, not a benchmark.

## Why no merged implementation in LSDF

Bundling a medical NER model means picking one — and "one" is a clinical-validation choice that varies by jurisdiction, language, sub-specialty (radiology / oncology / primary care / mental health), and weight licensing. Until LSDF has a measured comparison across med7 / MedSpaCy / Medical-BERT / RadBERT / Mental-BERT on a sanitized clinical corpus (analogous to the sanitized credential-leak replay corpus at `evals/piece_b_replay.json`, with the 30-case `evals/medical_phi_replay.json` as the per-sub-specialty starting point), the BYO recipe is the honest default.
