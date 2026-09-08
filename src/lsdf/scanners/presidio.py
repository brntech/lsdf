# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..surfaces import Surface
from ..types import Finding

PRESIDIO_ENTITY_MAP = {
    "CREDIT_CARD": "CREDIT_CARD",
    "EMAIL_ADDRESS": "EMAIL",
    "IBAN_CODE": "IBAN",
    "LOCATION": "ADDRESS",
    "MEDICAL_LICENSE": "OTHER_PHI",
    "PERSON": "PERSON",
    "PHONE_NUMBER": "PHONE",
    "US_BANK_NUMBER": "BANK_ACCOUNT",
    "US_SSN": "US_SSN",
}


@dataclass(frozen=True)
class PresidioDetector:
    analyzer: Any
    language: str = "en"
    score_threshold: float | None = None
    requested_entities: tuple[str, ...] | None = None

    detector_id = "presidio.analyzer"
    detector_family = "presidio"
    entities = frozenset(PRESIDIO_ENTITY_MAP.values())

    def scan(self, surface: Surface) -> list[Finding]:
        results = self.analyzer.analyze(
            text=surface.value,
            entities=list(self.requested_entities) if self.requested_entities else None,
            language=self.language,
        )
        findings: list[Finding] = []
        for result in results or []:
            finding = self._finding_from_result(surface, result)
            if finding is not None:
                findings.append(finding)
        return findings

    def _finding_from_result(self, surface: Surface, result: Any) -> Finding | None:
        entity_type = str(_field(result, "entity_type", "UNKNOWN"))
        start = int(_field(result, "start", 0))
        end = int(_field(result, "end", 0))
        score = float(_field(result, "score", 0.0))
        if self.score_threshold is not None and score < self.score_threshold:
            return None
        if start < 0 or end > len(surface.value) or start >= end:
            return None
        entity = PRESIDIO_ENTITY_MAP.get(entity_type)
        if entity is None:
            return None
        metadata = {
            "presidio_entity_type": entity_type,
            "specificity": 75,
        }
        for field in ("recognizer_name", "recognizer_identifier"):
            value = _field(result, field)
            if value:
                metadata[field] = str(value)
        return Finding(
            entity=entity,
            surface=surface.name,
            pointer=surface.pointer,
            json_pointer=surface.json_pointer,
            start=start,
            end=end,
            value=surface.value[start:end],
            confidence=score,
            detector_id=f"presidio.{entity_type.lower()}",
            detector_family=self.detector_family,
            metadata=metadata,
        )


def build_installed_presidio_detector() -> PresidioDetector:
    try:
        from presidio_analyzer import AnalyzerEngine
    except ImportError as exc:
        raise RuntimeError(
            "Install presidio-analyzer to enable detector family 'presidio'"
        ) from exc
    try:
        return PresidioDetector(AnalyzerEngine())
    except Exception as exc:  # pragma: no cover - depends on optional NLP install shape.
        raise RuntimeError(
            "Unable to initialize Presidio AnalyzerEngine. Build the optional Docker "
            "profile so the NLP model is installed, or provide detector_providers "
            "for mocked/custom output."
        ) from exc


def _field(result: Any, name: str, default: Any = None) -> Any:
    if isinstance(result, dict):
        return result.get(name, default)
    return getattr(result, name, default)
