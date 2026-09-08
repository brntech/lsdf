# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import re
from dataclasses import dataclass

from ..surfaces import Surface
from ..types import Finding
from .regex import _has_context_word


# Clinical context anchors for ambiguous PHI patterns (ICD codes, lab markers,
# medication-dosage strings). Picked to keep "Patient takes metformin 500mg"
# and "Eval case ... clinical detail metformin 500mg" firing while suppressing
# "metformin 500mg as a synthetic example" or "Release J45.909 ... milestone".
PHI_CLINICAL_CONTEXT = (
    "patient",
    "clinical",
    "history",
    "treatment",
    "physician",
    "doctor",
    "prescribed",
    "rx",
    "medication",
    "discharge",
    "diagnosis",
    "condition",
    "symptoms",
    "chart",
    "record",
    "mrn",
    "dob",
    "lab",
    "labs",
    "radiology",
    "imaging",
    "mri",
    "ct",
    "oncology",
    "chemo",
    "chemotherapy",
    "regimen",
    "therapy",
    "mental",
    "psychiatric",
    "suicidal",
)


@dataclass(frozen=True)
class MedicalPattern:
    pattern: re.Pattern[str]
    confidence: float
    group: int = 0
    pattern_name: str = "medical-regex"
    context_words: tuple[str, ...] = ()
    context_window: int = 60
    context_boost: float = 0.0
    context_required: bool = False


class MedicalPHIScanner:
    """Regex-based PHI pattern scanner. Pairs with optional medical-NER adapters."""

    detector_id = "medical-regex.phi_pattern"
    detector_family = "medical-regex"
    entities = frozenset(
        {
            "DIAGNOSIS_TEXT",
            "ICD_CODE",
            "LAB_VALUE",
            "MEDICAL_CONDITION",
            "MEDICATION",
            "OTHER_PHI",
        }
    )

    def __init__(self, patterns: list[MedicalPattern] | None = None):
        self.patterns = patterns or default_medical_patterns()

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for pattern in self.patterns:
            for match in pattern.pattern.finditer(surface.value):
                value = match.group(pattern.group)
                context_hit = _has_context_word(
                    surface.value,
                    match.start(pattern.group),
                    match.end(pattern.group),
                    pattern.context_words,
                    pattern.context_window,
                )
                if pattern.context_required and not context_hit:
                    continue
                confidence = pattern.confidence
                if context_hit and pattern.context_boost:
                    confidence = min(1.0, confidence + pattern.context_boost)
                findings.append(
                    Finding(
                        entity=_entity_for_pattern(pattern.pattern_name),
                        surface=surface.name,
                        pointer=surface.pointer,
                        start=match.start(pattern.group),
                        end=match.end(pattern.group),
                        value=value,
                        confidence=confidence,
                        json_pointer=surface.json_pointer,
                        detector_id="medical-regex.phi_pattern",
                        detector_family="medical-regex",
                        metadata={"pattern_name": pattern.pattern_name, "specificity": 70},
                    )
                )
        return findings


def _entity_for_pattern(pattern_name: str) -> str:
    return {
        "diagnosis_text": "DIAGNOSIS_TEXT",
        "condition_context": "MEDICAL_CONDITION",
        "condition_phrase": "MEDICAL_CONDITION",
        "icd_code": "ICD_CODE",
        "lab_value": "LAB_VALUE",
        "medication_dosage": "MEDICATION",
        "oncology_therapy": "MEDICATION",
        "imaging_finding": "DIAGNOSIS_TEXT",
        "procedure_code": "OTHER_PHI",
        "medication_label": "MEDICATION",
    }.get(pattern_name, "OTHER_PHI")


def default_medical_patterns() -> list[MedicalPattern]:
    return [
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:diagnosis|dx|condition|medical\s+condition|problem\s+list)\s*[:=]\s*([A-Za-z][A-Za-z0-9 ,/\-]{3,80})"
            ),
            0.78,
            group=1,
            pattern_name="diagnosis_text",
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:patient|diagnosed\s+with|history\s+of|treated\s+for)\s+"
                r"(?:has|reports|with|for|of)?\s*"
                r"(diabetes|hypertension|asthma|cancer|depression|anxiety|"
                r"migraine|epilepsy|copd|pneumonia|arthritis|renal\s+failure|"
                r"heart\s+failure|congestive\s+heart\s+failure|pulmonary\s+edema|"
                r"disc\s+herniation|post-traumatic\s+stress\s+disorder|"
                r"major\s+depressive\s+disorder|stroke|pregnancy|allergy|hiv)\b"
            ),
            0.82,
            group=1,
            pattern_name="condition_context",
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:congestive\s+heart\s+failure|pulmonary\s+edema|"
                r"disc\s+herniation|post-traumatic\s+stress\s+disorder|"
                r"major\s+depressive\s+disorder|passive\s+suicidal\s+ideation|"
                r"safety\s+plan|HER2\s+status)\b"
            ),
            0.80,
            pattern_name="condition_phrase",
            context_words=PHI_CLINICAL_CONTEXT,
            context_window=100,
            context_required=True,
        ),
        MedicalPattern(
            re.compile(r"\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?\b"),
            0.76,
            pattern_name="icd_code",
            context_words=PHI_CLINICAL_CONTEXT,
            context_window=100,
            context_required=True,
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:HbA1c|eGFR|LDL|HDL|creatinine)\s*[:=]?\s*\d+(?:\.\d+)?\s*(?:%|mg/dL|mL/min/1\.73m2)?\b"
            ),
            0.82,
            pattern_name="lab_value",
            context_words=PHI_CLINICAL_CONTEXT,
            context_window=100,
            context_required=True,
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:metformin|lisinopril|atorvastatin|insulin|warfarin|albuterol|"
                r"amlodipine|omeprazole|levothyroxine|gabapentin|prednisone|"
                r"hydrochlorothiazide|losartan|sertraline|fluoxetine|"
                r"amoxicillin|azithromycin|ibuprofen|acetaminophen)\s+"
                r"\d+(?:\.\d+)?\s*(?:mg|mcg|units|iu|ml)\b"
            ),
            0.84,
            pattern_name="medication_dosage",
            context_words=PHI_CLINICAL_CONTEXT,
            context_window=100,
            context_required=True,
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:pembrolizumab|trastuzumab\s+deruxtecan|"
                r"FOLFOX\s+cycle\s+\d+)\b"
            ),
            0.84,
            pattern_name="oncology_therapy",
            context_words=PHI_CLINICAL_CONTEXT,
            context_window=100,
            context_required=True,
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:MRI\s+(?:brain|lumbar\s+spine)\s+"
                r"(?:with|without)\s+(?:gadolinium|contrast)|"
                r"\d+(?:\.\d+)?\s*cm\s+spiculated\s+mass)\b"
            ),
            0.82,
            pattern_name="imaging_finding",
            context_words=PHI_CLINICAL_CONTEXT,
            context_window=100,
            context_required=True,
        ),
        MedicalPattern(
            re.compile(r"(?i)\b(?:CPT|procedure\s+code)\s*[:#=]?\s*(\d{5})\b"),
            0.80,
            group=1,
            pattern_name="procedure_code",
        ),
        MedicalPattern(
            re.compile(
                r"(?i)\b(?:medication|meds?|rx|prescribed)\s*[:=]\s*"
                r"([A-Za-z][A-Za-z0-9 ,/\-.]{3,80})"
            ),
            0.80,
            group=1,
            pattern_name="medication_label",
        ),
    ]
