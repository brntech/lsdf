# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Protocol

from ..surfaces import Surface
from ..types import Finding


GLINER_ENTITY_MAP = {
    "person": "PERSON",
    "name": "PERSON",
    "full name": "PERSON",
    "address": "ADDRESS",
    "private address": "ADDRESS",
    "postal code": "ADDRESS",
    "date of birth": "DATE_OF_BIRTH",
    "birth date": "DATE_OF_BIRTH",
    "phone number": "PHONE",
    "mobile phone number": "PHONE",
    "landline phone number": "PHONE",
    "email": "EMAIL",
    "email address": "EMAIL",
    "social security number": "US_SSN",
    "social_security_number": "US_SSN",
    "national id number": "NATIONAL_ID",
    "tax identification number": "TAX_ID",
    "identity card number": "NATIONAL_ID",
    "passport number": "PASSPORT",
    "driver's license number": "DRIVER_LICENSE",
    "student id": "STUDENT_ID",
    "student identifier": "STUDENT_ID",
    "employee id": "EMPLOYEE_ID",
    "employee identifier": "EMPLOYEE_ID",
    "customer id": "CUSTOMER_ID",
    "customer identifier": "CUSTOMER_ID",
    "user id": "USER_ID",
    "user identifier": "USER_ID",
    "license plate": "LICENSE_PLATE",
    "vehicle registration plate": "LICENSE_PLATE",
    "form id": "OTHER_INTERNAL_ID",
    "certificate number": "OTHER_INTERNAL_ID",
    "health insurance id number": "HEALTH_INSURANCE_ID",
    "health insurance number": "HEALTH_INSURANCE_ID",
    "national health insurance number": "HEALTH_INSURANCE_ID",
    "medical condition": "MEDICAL_CONDITION",
    "medication": "MEDICATION",
    "blood type": "BLOOD_TYPE",
    "medical record number": "MRN",
    "patient id": "MRN",
    "bank account number": "BANK_ACCOUNT",
    "iban": "IBAN",
    "credit card number": "CREDIT_CARD",
    "cvv": "CREDIT_CARD",
    "cvc": "CREDIT_CARD",
}

DEFAULT_GLINER_LABELS = tuple(GLINER_ENTITY_MAP)
DEFAULT_GLINER_MODEL = "E3-JSI/gliner-multi-pii-domains-v1"
DEFAULT_GLINER_THRESHOLD = 0.45
DEFAULT_MAX_CHARS = 1400
DEFAULT_STRIDE_CHARS = 350
DEFAULT_ENTITY_THRESHOLDS = {
    "PERSON": 0.52,
    "ADDRESS": 0.42,
    "DATE_OF_BIRTH": 0.40,
    "BLOOD_TYPE": 0.38,
    "HEALTH_INSURANCE_ID": 0.38,
    "MEDICAL_CONDITION": 0.38,
    "MEDICATION": 0.38,
    "MRN": 0.38,
}


class GLiNERModel(Protocol):
    def predict_entities(
        self,
        text: str,
        labels: list[str] | tuple[str, ...],
        *,
        threshold: float,
    ) -> list[dict[str, Any]]:
        ...


@dataclass(frozen=True)
class GLiNERDetector:
    model: GLiNERModel
    labels: tuple[str, ...] = DEFAULT_GLINER_LABELS
    threshold: float = DEFAULT_GLINER_THRESHOLD
    entity_thresholds: dict[str, float] | None = None
    label_map: dict[str, str] | None = None
    model_name: str = DEFAULT_GLINER_MODEL
    max_chars: int = DEFAULT_MAX_CHARS
    stride_chars: int = DEFAULT_STRIDE_CHARS

    detector_id = "gliner.pii_phi"
    detector_family = "gliner"
    entities = frozenset(GLINER_ENTITY_MAP.values())

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, int, str]] = set()
        for chunk_start, chunk_text in _chunk_text(
            surface.value,
            max_chars=max(1, int(self.max_chars)),
            stride_chars=max(0, int(self.stride_chars)),
        ):
            spans = self.model.predict_entities(
                chunk_text,
                self.labels,
                threshold=self.threshold,
            )
            for span in spans:
                finding = self._finding_from_span(surface, span, offset=chunk_start)
                if finding is None:
                    continue
                key = (
                    finding.entity,
                    finding.start,
                    finding.end,
                    finding.detector_id,
                )
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        return findings

    def _finding_from_span(
        self,
        surface: Surface,
        span: dict[str, Any],
        *,
        offset: int = 0,
    ) -> Finding | None:
        label = str(span.get("label") or span.get("entity") or span.get("entity_group") or "").strip()
        canonical = self._canonical_entity(label)
        if canonical is None:
            return None
        start = int(span.get("start", 0)) + offset
        end = int(span.get("end", 0)) + offset
        if start < 0 or end > len(surface.value) or start >= end:
            return None
        score = float(span.get("score", span.get("confidence", self.threshold)))
        threshold = (self.entity_thresholds or {}).get(canonical, self.threshold)
        if score < threshold:
            return None
        value = surface.value[start:end]
        if _is_label_echo(value, canonical, label):
            return None
        return Finding(
            entity=canonical,
            surface=surface.name,
            pointer=surface.pointer,
            start=start,
            end=end,
            value=value,
            confidence=score,
            json_pointer=surface.json_pointer,
            detector_id=f"gliner.{_slug(label)}",
            detector_family=self.detector_family,
            metadata={
                "gliner_label": label,
                "model_name": self.model_name,
                "specificity": 77,
            },
        )

    def _canonical_entity(self, label: str) -> str | None:
        configured = self.label_map or {}
        if label in configured:
            return configured[label]
        lowered = label.lower().replace("_", " ").strip()
        return configured.get(lowered) or GLINER_ENTITY_MAP.get(lowered)


def build_installed_gliner_detector(
    *,
    model_name: str | None = None,
    threshold: float | None = None,
    labels: list[str] | tuple[str, ...] | None = None,
    entity_thresholds: dict[str, float] | None = None,
    label_map: dict[str, str] | None = None,
    local_files_only: bool | None = None,
    max_chars: int | None = None,
    stride_chars: int | None = None,
) -> GLiNERDetector:
    model_name = model_name or os.environ.get("LSDF_GLINER_MODEL", DEFAULT_GLINER_MODEL)
    threshold = float(
        threshold
        if threshold is not None
        else os.environ.get("LSDF_GLINER_THRESHOLD", DEFAULT_GLINER_THRESHOLD)
    )
    if local_files_only is None:
        local_files_only = _env_bool("LSDF_GLINER_LOCAL_FILES_ONLY", True)
    try:
        from gliner import GLiNER
    except Exception as exc:  # pragma: no cover - optional dependency.
        raise RuntimeError(
            "Install gliner and cache a supported model to enable detector family 'gliner'"
        ) from exc
    try:
        try:
            model = GLiNER.from_pretrained(model_name, local_files_only=local_files_only)
        except TypeError:
            model = GLiNER.from_pretrained(model_name)
    except Exception as exc:  # pragma: no cover - optional model cache shape.
        cache_note = "cached locally" if local_files_only else "downloadable/available"
        raise RuntimeError(
            f"Unable to load GLiNER model '{model_name}' ({cache_note}). "
            "Set LSDF_GLINER_MODEL or provide detector_providers for mocked/custom output."
        ) from exc
    return GLiNERDetector(
        model=model,
        labels=tuple(labels or DEFAULT_GLINER_LABELS),
        threshold=threshold,
        entity_thresholds=_float_thresholds(entity_thresholds),
        label_map=label_map,
        model_name=model_name,
        max_chars=int(
            max_chars
            if max_chars is not None
            else os.environ.get("LSDF_GLINER_MAX_CHARS", DEFAULT_MAX_CHARS)
        ),
        stride_chars=int(
            stride_chars
            if stride_chars is not None
            else os.environ.get("LSDF_GLINER_STRIDE_CHARS", DEFAULT_STRIDE_CHARS)
        ),
    )


def _float_thresholds(value: dict[str, float] | None) -> dict[str, float] | None:
    if value is None:
        return None
    return {str(key): float(threshold) for key, threshold in value.items()}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _chunk_text(text: str, *, max_chars: int, stride_chars: int) -> list[tuple[int, str]]:
    if len(text) <= max_chars:
        return [(0, text)]
    chunks: list[tuple[int, str]] = []
    start = 0
    overlap = min(stride_chars, max_chars - 1)
    step = max_chars - overlap
    while start < len(text):
        end = min(len(text), start + max_chars)
        if start > 0:
            boundary = _left_boundary(text, start, max(start - 120, 0))
            # If alignment would repeat a window, keep the unaligned step.
            # Advancing by one character instead would amplify model calls.
            if boundary > chunks[-1][0]:
                start = boundary
            end = min(len(text), start + max_chars)
        chunks.append((start, text[start:end]))
        if end >= len(text):
            break
        start += step
    return chunks


def _left_boundary(text: str, start: int, floor: int) -> int:
    for idx in range(start, floor, -1):
        if text[idx - 1].isspace():
            return idx
    return start


def _slug(label: str) -> str:
    return "".join(char.lower() if char.isalnum() else "_" for char in label).strip("_") or "entity"


def _is_label_echo(value: str, canonical: str, label: str) -> bool:
    normalized = value.strip().lower().replace("_", " ")
    if not normalized:
        return True
    canonical_label = canonical.lower().replace("_", " ")
    gliner_label = label.lower().replace("_", " ").strip()
    return normalized in {canonical_label, gliner_label}
