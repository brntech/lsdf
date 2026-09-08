# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

from .scanners.entropy import EntropySecretScanner
from .scanners.contextual import ContextualAnchoredScanner, ContextualBroadScanner
from .scanners.medical import MedicalPHIScanner
from .scanners.regex import RegexScanner
from .scanners.xpia import XPIAScanner
from .surfaces import Surface
from .types import Finding

DEPENDENCY_LIGHT_DETECTOR_FAMILIES = ("regex", "entropy", "medical-regex", "contextual-anchored")
OPT_IN_DETECTOR_FAMILIES = ("xpia", "contextual-broad")
OPTIONAL_DETECTOR_FAMILIES = ("presidio", "gliner", "openai_privacy_filter")
KNOWN_DETECTOR_FAMILIES = (
    DEPENDENCY_LIGHT_DETECTOR_FAMILIES
    + OPT_IN_DETECTOR_FAMILIES
    + OPTIONAL_DETECTOR_FAMILIES
)

# Custom detector families registered at runtime via register_detector_family().
# Read-side access goes through known_detector_families(); both detectors.py
# and policy.py validate against the live union, not the builtin tuple alone.
# The lock guards the check-then-mutate sequence inside register_detector_family
# against concurrent startup-time registration from multi-threaded workers (the
# CPython GIL makes individual list/dict ops atomic, but not the compound
# membership-test + append + dict-write sequence below).
_REGISTERED_DETECTOR_FAMILIES: list[str] = []
_REGISTRATION_LOCK = threading.Lock()

_FAMILY_SPECIFICITY = {
    "regex": 80,
    "presidio": 75,
    "openai_privacy_filter": 75,
    "gliner": 77,
    "medical-regex": 70,
    "xpia": 65,
    "contextual-anchored": 76,
    "contextual-broad": 62,
    "entropy": 50,
}


def known_detector_families() -> tuple[str, ...]:
    """All detector family names LSDF will accept in a policy.

    The builtin tuple ``KNOWN_DETECTOR_FAMILIES`` plus any custom families
    registered via :func:`register_detector_family`. Internal validators in
    ``detectors.build_detector_registry`` and ``policy.load_policy`` call this
    getter rather than the builtin tuple so registered families pass through.
    """
    return KNOWN_DETECTOR_FAMILIES + tuple(_REGISTERED_DETECTOR_FAMILIES)


def register_detector_family(name: str, *, specificity: int = 50) -> None:
    """Register a custom detector family name as a first-class extension.

    After registration, a policy may list ``name`` in
    ``detectors.enabled_families`` and ``Firewall(detector_providers={name: ...})``
    will wire it. Idempotent — calling with an already-known name is a no-op.

    The optional ``specificity`` (0-100) ranks findings from this family in
    overlap resolution against findings from other families. Defaults to 50,
    midway between the bundled families (``entropy``=50, ``xpia``=65,
    ``regex``=80). Callers can override per-finding via ``metadata["specificity"]``.
    """
    if not isinstance(name, str):
        raise TypeError(
            f"Detector family name must be a string, got {type(name).__name__}"
        )
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("Detector family name must be non-empty")
    with _REGISTRATION_LOCK:
        if cleaned in known_detector_families():
            return
        _REGISTERED_DETECTOR_FAMILIES.append(cleaned)
        _FAMILY_SPECIFICITY[cleaned] = int(specificity)


def _clear_registered_detector_families() -> None:
    """Test helper — drop all custom registrations. Not part of the public API."""
    with _REGISTRATION_LOCK:
        for family in _REGISTERED_DETECTOR_FAMILIES:
            _FAMILY_SPECIFICITY.pop(family, None)
        _REGISTERED_DETECTOR_FAMILIES.clear()


class Detector(Protocol):
    detector_id: str
    detector_family: str
    entities: frozenset[str]

    def scan(self, surface: Surface) -> list[Finding]:
        ...


class DetectorUnavailableError(ValueError):
    pass


DetectorProvider = Detector | Callable[[], Detector]
DetectorProviders = Mapping[str, DetectorProvider]


# Public-figure deny-list for PERSON entities.
#
# A PERSON finding whose value matches one of these names — case-insensitive,
# whitespace-collapsed — is dropped from the registry's output. The intent is
# names that are clearly public figures: their identities are not private data
# in the LSDF threat model. Keep the list small, widely-recognized, and
# uncontroversial; extend at deploy time via env var
# LSDF_PERSON_DENY_LIST_EXTRA (semicolon-separated additional names) when the
# in-tree list is too narrow.
_DEFAULT_PERSON_DENY_LIST = frozenset(
    name.lower()
    for name in (
        # AI / large-tech CEOs
        "Sam Altman",
        "Satya Nadella",
        "Sundar Pichai",
        "Mark Zuckerberg",
        "Elon Musk",
        "Tim Cook",
        "Jensen Huang",
        "Fei-Fei Li",
        "Andrew Ng",
        "Lina Khan",
        "Andy Jassy",
        # AI lab leadership / well-known researchers
        "Dario Amodei",
        "Daniela Amodei",
        "Demis Hassabis",
        "Andrej Karpathy",
        "Yann LeCun",
        "Geoffrey Hinton",
        "Ilya Sutskever",
        "Mira Murati",
        # Founders / historical tech public figures
        "Bill Gates",
        "Steve Jobs",
        "Jeff Bezos",
        "Larry Page",
        "Sergey Brin",
        "Grace Hopper",
        "Ada Lovelace",
        "Alan Turing",
        "Margaret Hamilton",
    )
)


def _person_deny_list() -> frozenset[str]:
    extra = os.environ.get("LSDF_PERSON_DENY_LIST_EXTRA", "")
    if not extra.strip():
        return _DEFAULT_PERSON_DENY_LIST
    extras = (item.strip().lower() for item in extra.split(";"))
    return _DEFAULT_PERSON_DENY_LIST | frozenset(item for item in extras if item)


_PERSON_SPAN_CONNECTORS_RE = re.compile(r"\band\b|[\s,;/&]+", re.IGNORECASE)


def _is_public_figure(value: str) -> bool:
    """True if the value is exclusively composed of public-figure names + connectors.

    Handles two shapes:
      1. A single deny-list name ("Sam Altman") — direct match after normalization.
      2. A merged multi-name ML span ("Sam Altman, Satya Nadella, and Jensen
         Huang") — removes each matched deny-list entry and checks that the
         residue is connectors only (commas, "and", whitespace). If any unknown
         name remains in the residue, the finding passes through (don't auto-
         suppress when an unknown person is bundled with a public figure).
    """
    if not value:
        return False
    normalized = " ".join(value.split()).lower()
    deny = _person_deny_list()
    if normalized in deny:
        return True
    residue = normalized
    matched_any = False
    for name in sorted(deny, key=len, reverse=True):
        if name and name in residue:
            residue = residue.replace(name, " ")
            matched_any = True
    if not matched_any:
        return False
    cleaned = _PERSON_SPAN_CONNECTORS_RE.sub("", residue).strip()
    return cleaned == ""


@dataclass(frozen=True)
class DetectorRegistry:
    detectors: tuple[Detector, ...]

    def scan(self, surface: Surface) -> list[Finding]:
        findings: list[Finding] = []
        for order, detector in enumerate(self.detectors):
            for finding in detector.scan(surface):
                findings.append(_normalize_finding(finding, detector, order))
        findings.extend(_proximity_lift(findings, surface))
        resolved = _resolve_overlaps(findings)
        return [
            finding
            for finding in resolved
            if not (finding.entity == "PERSON" and _is_public_figure(finding.value))
        ]

    def summary(self) -> dict[str, list[str]]:
        return {
            "detector_ids": [detector.detector_id for detector in self.detectors],
            "detector_families": [detector.detector_family for detector in self.detectors],
        }


def build_detector_registry(
    enabled_families: str | list[str] | tuple[str, ...] | None = None,
    detector_providers: DetectorProviders | None = None,
    detector_settings: Mapping[str, Mapping[str, object]] | None = None,
) -> DetectorRegistry:
    if isinstance(enabled_families, str):
        enabled_families = [enabled_families]
    families = tuple(enabled_families or DEPENDENCY_LIGHT_DETECTOR_FAMILIES)
    detectors: list[Detector] = []
    providers = detector_providers or {}
    settings = detector_settings or {}
    for family in families:
        active_families = known_detector_families()
        if family not in active_families:
            valid = ", ".join(active_families)
            raise ValueError(
                f"Unknown detector family: {family}. Valid detector families: {valid}"
            )
        if family in providers:
            detectors.append(_provider_detector(family, providers[family]))
            continue
        family_settings = settings.get(family, {})
        try:
            if family == "presidio":
                detectors.append(_build_installed_presidio_detector())
                continue
            if family == "gliner":
                detectors.append(_build_installed_gliner_detector(family_settings))
                continue
            if family == "openai_privacy_filter":
                detectors.append(
                    _build_installed_openai_privacy_filter_detector(family_settings)
                )
                continue
        except DetectorUnavailableError:
            if family_settings.get("required") is False:
                continue
            raise
        if family in _REGISTERED_DETECTOR_FAMILIES:
            raise ValueError(
                f"Detector family '{family}' is registered via "
                f"register_detector_family() but no provider was supplied. "
                f"Pass detector_providers={{'{family}': <Detector>}} to "
                f"build_detector_registry() (or to Firewall.__init__) so the "
                f"family has a runtime implementation."
            )
        detectors.append(_build_builtin_detector(family))
    return DetectorRegistry(tuple(detectors))


def _provider_detector(family: str, provider: DetectorProvider) -> Detector:
    detector = provider() if callable(provider) else provider
    if detector.detector_family != family:
        raise ValueError(
            f"Detector provider for family '{family}' returned family "
            f"'{detector.detector_family}'"
        )
    return detector


def _build_installed_presidio_detector() -> Detector:
    from .scanners.presidio import build_installed_presidio_detector

    try:
        return build_installed_presidio_detector()
    except RuntimeError as exc:
        raise DetectorUnavailableError(str(exc)) from exc


def _build_installed_gliner_detector(settings: Mapping[str, object]) -> Detector:
    from .scanners.gliner import build_installed_gliner_detector

    try:
        return build_installed_gliner_detector(**dict(settings))
    except RuntimeError as exc:
        raise DetectorUnavailableError(str(exc)) from exc


def _build_installed_openai_privacy_filter_detector(settings: Mapping[str, object]) -> Detector:
    from .scanners.openai_privacy_filter import (
        build_installed_openai_privacy_filter_detector,
    )

    try:
        kwargs = {key: value for key, value in dict(settings).items() if key != "required"}
        return build_installed_openai_privacy_filter_detector(**kwargs)
    except RuntimeError as exc:
        raise DetectorUnavailableError(str(exc)) from exc


def _build_builtin_detector(family: str) -> Detector:
    if family == "regex":
        return RegexScanner()
    if family == "entropy":
        return EntropySecretScanner()
    if family == "medical-regex":
        return MedicalPHIScanner()
    if family == "contextual-anchored":
        return ContextualAnchoredScanner()
    if family == "contextual-broad":
        return ContextualBroadScanner()
    if family == "xpia":
        return XPIAScanner()
    raise AssertionError(f"Unhandled detector family: {family}")


def _normalize_finding(finding: Finding, detector: Detector, order: int) -> Finding:
    metadata = dict(finding.metadata or {})
    metadata.setdefault("registry_order", order)
    detector_id = finding.detector_id
    if detector_id == "unknown":
        detector_id = detector.detector_id
    detector_family = finding.detector_family
    if detector_family == "unknown":
        detector_family = detector.detector_family
    return Finding(
        entity=finding.entity,
        surface=finding.surface,
        pointer=finding.pointer,
        start=finding.start,
        end=finding.end,
        value=finding.value,
        confidence=finding.confidence,
        json_pointer=finding.json_pointer,
        detector_id=detector_id,
        detector_family=detector_family,
        metadata=metadata,
    )


def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    for finding in findings:
        duplicate = False
        overlapping_indexes: list[int] = []
        for idx, existing in enumerate(kept):
            if _exact_duplicate(existing, finding):
                duplicate = True
                break
            if _overlaps(existing, finding):
                overlapping_indexes.append(idx)
        if duplicate:
            continue
        if not overlapping_indexes:
            kept.append(finding)
            continue
        candidates = [finding, *(kept[idx] for idx in overlapping_indexes)]
        winner = sorted(candidates, key=_ranking, reverse=True)[0]
        if winner is finding:
            for idx in sorted(overlapping_indexes, reverse=True):
                kept.pop(idx)
            kept.append(finding)
    return sorted(
        kept,
        key=lambda item: int((item.metadata or {}).get("registry_order", 0)),
    )


def _exact_duplicate(left: Finding, right: Finding) -> bool:
    return (
        left.entity == right.entity
        and left.pointer == right.pointer
        and left.json_pointer == right.json_pointer
        and left.start == right.start
        and left.end == right.end
        and left.value == right.value
    )


def _overlaps(left: Finding, right: Finding) -> bool:
    if left.pointer != right.pointer or left.json_pointer != right.json_pointer:
        return False
    return left.start < right.end and right.start < left.end


def _ranking(finding: Finding) -> tuple[int, float, int]:
    return (
        _specificity(finding),
        finding.confidence,
        -int((finding.metadata or {}).get("registry_order", 0)),
    )


def _specificity(finding: Finding) -> int:
    metadata = finding.metadata or {}
    if "specificity" in metadata:
        return int(metadata["specificity"])
    return _FAMILY_SPECIFICITY.get(finding.detector_family, 0)


_PROXIMITY_ENTITIES = frozenset(
    {
        "PERSON",
        "ADDRESS",
        "DATE_OF_BIRTH",
        "MEDICATION",
        "MEDICAL_CONDITION",
        "LAB_VALUE",
        "ICD_CODE",
        "DIAGNOSIS_TEXT",
        "MRN",
        "OTHER_PHI",
    }
)
_PROXIMITY_WINDOW = 150
_PERSON_CANDIDATE_RE = re.compile(
    r"\b[A-ZÀ-ÝŽ][A-Za-zÀ-ÿŽž'\-]{1,30}(?:\s+[A-ZÀ-ÝŽ][A-Za-zÀ-ÿŽž'\-]{1,30}){1,3}\b"
)
_ADDRESS_CANDIDATE_RE = re.compile(
    r"\b\d{1,6}\s+[A-ZÀ-ÝŽ][A-Za-zÀ-ÿŽž0-9.'\-]{1,30}"
    r"(?:\s+[A-Za-zÀ-ÿŽž0-9.'\-]{1,30}){0,8}"
    r"\s+(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Boulevard|Blvd|Way|Court|Ct|Straat|Strasse|Straße|Rue|Calle|Via)\b",
    re.IGNORECASE,
)
_DOB_CANDIDATE_RE = re.compile(
    r"\b(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|"
    r"\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4})\b",
    re.IGNORECASE,
)
_PHI_CANDIDATE_RE = re.compile(
    r"\b(?:diabetes|hypertension|asthma|cancer|depression|anxiety|"
    r"metformin|lisinopril|atorvastatin|insulin|warfarin|albuterol|"
    r"creatinine|HbA1c|eGFR|LDL|HDL)\b(?:\s+\d+(?:\.\d+)?\s*(?:mg|mcg|units|%|mg/dL))?",
    re.IGNORECASE,
)


def _proximity_lift(findings: list[Finding], surface: Surface) -> list[Finding]:
    anchors = [
        finding
        for finding in findings
        if finding.detector_family == "regex" and finding.entity in _PROXIMITY_ENTITIES
    ]
    if not anchors:
        return []
    lifted: list[Finding] = []
    for anchor in anchors:
        left = max(0, anchor.start - _PROXIMITY_WINDOW)
        right = min(len(surface.value), anchor.end + _PROXIMITY_WINDOW)
        lifted.extend(
            _candidate_findings(
                surface,
                left,
                right,
                anchor,
                "PERSON",
                _PERSON_CANDIDATE_RE,
            )
        )
        lifted.extend(
            _candidate_findings(
                surface,
                left,
                right,
                anchor,
                "ADDRESS",
                _ADDRESS_CANDIDATE_RE,
            )
        )
        lifted.extend(
            _candidate_findings(
                surface,
                left,
                right,
                anchor,
                "DATE_OF_BIRTH",
                _DOB_CANDIDATE_RE,
            )
        )
        lifted.extend(
            _candidate_findings(
                surface,
                left,
                right,
                anchor,
                "OTHER_PHI",
                _PHI_CANDIDATE_RE,
            )
        )
    return lifted


def _candidate_findings(
    surface: Surface,
    left: int,
    right: int,
    anchor: Finding,
    entity: str,
    pattern: re.Pattern[str],
) -> list[Finding]:
    text = surface.value[left:right]
    findings: list[Finding] = []
    for match in pattern.finditer(text):
        start = left + match.start()
        end = left + match.end()
        value = surface.value[start:end]
        if start == anchor.start and end == anchor.end and entity == anchor.entity:
            continue
        if _candidate_is_too_generic(entity, value):
            continue
        findings.append(
            Finding(
                entity=entity,
                surface=surface.name,
                pointer=surface.pointer,
                start=start,
                end=end,
                value=value,
                confidence=0.72,
                json_pointer=surface.json_pointer,
                detector_id=f"regex.proximity_{entity.lower()}",
                detector_family="regex",
                metadata={
                    "specificity": 67,
                    "anchor_entity": anchor.entity,
                    "anchor_detector_id": anchor.detector_id,
                },
            )
        )
    return findings


def _candidate_is_too_generic(entity: str, value: str) -> bool:
    if entity == "PERSON":
        words = value.split()
        if len(words) < 2:
            return True
        lowered = value.lower()
        return lowered.startswith(("the ", "this ", "source ", "patient "))
    if entity == "ADDRESS":
        return not any(char.isdigit() for char in value)
    return False
