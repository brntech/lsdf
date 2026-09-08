"""Sanitised medical-PHI replay corpus contract.

Pins the structure and baseline coverage of `evals/medical_phi_replay.json`
so that:

  1. The corpus stays parseable JSON with a stable case-shape (id, category,
     domain, surface, payload, sensitive_values, expected_entities,
     expected_absent).
  2. The medical-regex baseline cases redact cleanly under the bundled
     default profile — `sensitive_values_leaked_after` over the baseline
     subset stays at 0 and every case fires at least one PHI finding.
  3. The known-gap cases are deliberately marked `known_gap: true` and the
     replay harness records them as documented gaps that the medical-NER
     adapter recipe (`docs/medical-ner-adapter-recipe.md`) is intended to
     close — not as silent failures.
  4. The corpus spans four clinical sub-domains (primary-care, radiology,
     oncology, mental-health) plus a cross-domain split, with each domain
     carrying both baseline-catchable and known-gap cases so the corpus
     is usable as a per-sub-specialty regression target for adapter
     selection (med7 vs MedSpaCy vs Medical-BERT vs RadBERT, etc.).
"""

import json
import unittest
from collections import Counter
from pathlib import Path

from lsdf import Firewall, load_policy

CORPUS_PATH = Path("evals") / "medical_phi_replay.json"
PHI_SUBTYPES = frozenset(
    {
        "MEDICATION",
        "MEDICAL_CONDITION",
        "BLOOD_TYPE",
        "HEALTH_INSURANCE_ID",
        "LAB_VALUE",
        "ICD_CODE",
        "DIAGNOSIS_TEXT",
        "MRN",
        "OTHER_PHI",
    }
)

EXPECTED_DOMAINS = frozenset(
    {"primary-care", "radiology", "oncology", "mental-health", "cross-domain"}
)


class MedicalPhiReplayCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
        cls.firewall = Firewall(load_policy("policies/default.yaml"))

    def test_corpus_is_parseable_and_has_thirty_cases(self):
        self.assertEqual(self.corpus["name"], "medical_phi_replay")
        self.assertEqual(len(self.corpus["cases"]), 30)

    def test_corpus_advertises_expected_domains_in_metadata(self):
        domains = self.corpus.get("domains")
        self.assertIsNotNone(
            domains,
            "corpus metadata is missing the top-level 'domains' list — readers "
            "rely on it to enumerate the sub-specialty coverage without "
            "scanning every case",
        )
        self.assertEqual(set(domains), EXPECTED_DOMAINS)

    def test_corpus_carries_balanced_baseline_and_gap_cases(self):
        baseline = [c for c in self.corpus["cases"] if not c.get("known_gap")]
        gap = [c for c in self.corpus["cases"] if c.get("known_gap")]
        self.assertEqual(len(baseline), 15)
        self.assertEqual(len(gap), 15)

    def test_each_case_has_required_fields(self):
        required = {
            "id",
            "category",
            "domain",
            "surface",
            "payload",
            "sensitive_values",
            "expected_entities",
            "expected_surfaces",
            "expected_absent",
        }
        for case in self.corpus["cases"]:
            with self.subTest(case_id=case.get("id")):
                missing = required - set(case)
                self.assertFalse(
                    missing,
                    f"case {case.get('id')!r} missing required fields: {sorted(missing)}",
                )
                self.assertIn(case["domain"], EXPECTED_DOMAINS)

    def test_every_domain_has_both_baseline_and_gap_coverage(self):
        # Adapter selection requires a per-sub-specialty baseline-vs-gap split
        # so an operator can ask "does my radiology-tuned NER close the
        # radiology gaps without regressing the radiology baseline?". The
        # cross-domain split deliberately carries both flavours too — multi-
        # surface cases are how realistic adapter mistakes surface.
        baseline_domains = Counter(
            c["domain"] for c in self.corpus["cases"] if not c.get("known_gap")
        )
        gap_domains = Counter(
            c["domain"] for c in self.corpus["cases"] if c.get("known_gap")
        )
        for domain in EXPECTED_DOMAINS:
            with self.subTest(domain=domain):
                self.assertGreaterEqual(
                    baseline_domains[domain],
                    1,
                    f"domain {domain!r} has no medical-regex-baseline case — "
                    f"adapter regression cannot be measured here",
                )
                self.assertGreaterEqual(
                    gap_domains[domain],
                    1,
                    f"domain {domain!r} has no known-gap case — adapter uplift "
                    f"cannot be measured here",
                )

    def test_baseline_subset_redacts_with_no_sensitive_leakage(self):
        baseline = [c for c in self.corpus["cases"] if not c.get("known_gap")]
        report = self.firewall.evaluate(baseline)
        self.assertEqual(
            report["sensitive_values_leaked_after"],
            0,
            f"Baseline cases (medical-regex coverage) leaked under default profile: "
            f"{[r for r in report['results'] if r.get('sensitive_values_leaked_after')]}",
        )
        # Surface-name + entity-name + action-name failures don't show up in
        # the leakage counter but do show up in `failed`. Including this
        # assertion catches structural payload bugs (e.g. wrong RAG-context
        # shape that routes findings to the wrong surface) that the leakage
        # counter alone would silently absorb.
        self.assertEqual(
            report["failed"],
            0,
            f"Baseline cases produced non-leakage failures (surface/entity/"
            f"action mismatches): "
            f"{[r['failures'] for r in report['results'] if r.get('failures')]}",
        )

    def test_baseline_cases_each_fire_at_least_one_phi_finding(self):
        baseline = [c for c in self.corpus["cases"] if not c.get("known_gap")]
        for case in baseline:
            with self.subTest(case_id=case["id"]):
                result = self.firewall.inspect(case["payload"])
                phi_findings = [f for f in result.findings if f.entity in PHI_SUBTYPES]
                self.assertTrue(
                    phi_findings,
                    f"baseline case {case['id']!r} produced no PHI findings — "
                    f"medical-regex regression?",
                )

    def test_known_gap_cases_record_as_documented_gaps_not_failures(self):
        gap_cases = [c for c in self.corpus["cases"] if c.get("known_gap")]
        report = self.firewall.evaluate(gap_cases)
        # Every gap case should leak (that's the definition of the gap), but
        # the failures must be swallowed by the known_gap tracking — `failed`
        # stays at 0 because all failures are absorbed by `known_gap_would_fail`.
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["known_gap_cases"], 15)
        self.assertGreaterEqual(report["known_gap_leaked_after"], 1)

    def test_corpus_carries_no_real_phi_or_real_patient_identifiers(self):
        # Sanity: synthetic-corpus rule. Real-looking patient names ("John Smith")
        # or real-looking SSN/MRN strings shouldn't appear. The regex layer
        # already covers shape-faithful SSN/MRN catching, but the cultural
        # contract is that medical_phi_replay.json must be obviously synthetic
        # to anyone reading the file.
        text = CORPUS_PATH.read_text(encoding="utf-8")
        # No real-looking 9-digit SSN format outside zero-padded fixture form.
        self.assertNotIn("123-45-6789", text)
        # No real-looking name pairs hardcoded — patients are referred to as
        # "patient" / "Pt" in narrative, never with proper names.
        self.assertNotIn("John Smith", text)
        self.assertNotIn("Jane Doe", text)


if __name__ == "__main__":
    unittest.main()
